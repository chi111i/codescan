# Batch processor for embedding operations with dynamic size adjustment
# Based on ACI (augmented-codebase-indexer) best practices

import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Callable, TypeVar, Generic, Tuple
from abc import ABC, abstractmethod

from .interface import (
    EmbeddingClientInterface,
    EmbeddingResult,
    EmbeddingUsage,
    BatchSizeError,
    RetryableError,
)
from .retry import RetryConfig, RetryExecutor, EMBEDDING_RETRY_CONFIG

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class BatchConfig:
    """Configuration for batch processing

    Attributes:
        initial_batch_size: Starting batch size for processing
        min_batch_size: Minimum allowed batch size
        max_batch_size: Maximum allowed batch size
        recovery_factor: Factor to increase batch size after success (0-1)
        reduction_factor: Factor to reduce batch size on token limit error (0-1)
        success_threshold: Number of successful batches before attempting recovery
        max_tokens_estimate: Estimated max tokens per text (for preemptive sizing)
        max_concurrent_batches: Maximum number of concurrent API requests
    """
    initial_batch_size: int = 150  # Increased from 50 for better throughput
    min_batch_size: int = 10
    max_batch_size: int = 300
    recovery_factor: float = 0.1  # Recover 10% per success
    reduction_factor: float = 0.5  # Halve on token limit error
    success_threshold: int = 3    # Successes before recovery attempt
    max_tokens_estimate: int = 512  # Conservative estimate per text
    max_concurrent_batches: int = 3  # Concurrent API requests


@dataclass
class BatchStats:
    """Statistics for batch processing"""
    total_texts: int = 0
    processed_texts: int = 0
    total_batches: int = 0
    successful_batches: int = 0
    failed_batches: int = 0
    batch_size_reductions: int = 0
    batch_size_increases: int = 0
    total_tokens_used: int = 0
    current_batch_size: int = 0


class BatchProcessor:
    """Batch processor with dynamic size adjustment

    Features:
    - Dynamic batch size adjustment based on API responses
    - Automatic size reduction on token limit errors (HTTP 413)
    - Gradual recovery after successful batches
    - Progress callback support
    - Comprehensive statistics tracking
    """

    def __init__(
        self,
        client: EmbeddingClientInterface,
        config: Optional[BatchConfig] = None,
        retry_config: Optional[RetryConfig] = None
    ):
        """Initialize batch processor

        Args:
            client: Embedding client to use
            config: Batch processing configuration
            retry_config: Retry configuration for individual batches
        """
        self.client = client
        self.config = config or BatchConfig()
        self.retry_config = retry_config or EMBEDDING_RETRY_CONFIG
        self.retry_executor = RetryExecutor(self.retry_config)

        self._current_batch_size = self.config.initial_batch_size
        self._consecutive_successes = 0
        self._stats = BatchStats()

    @property
    def current_batch_size(self) -> int:
        """Get current batch size"""
        return self._current_batch_size

    @property
    def stats(self) -> BatchStats:
        """Get processing statistics"""
        return self._stats

    def reset_stats(self) -> None:
        """Reset processing statistics"""
        self._stats = BatchStats()

    async def process(
        self,
        texts: List[str],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> EmbeddingResult:
        """Process texts in batches with dynamic sizing and concurrency

        Args:
            texts: List of texts to embed
            progress_callback: Optional callback(processed, total) for progress updates

        Returns:
            Combined EmbeddingResult with all embeddings

        Raises:
            EmbeddingError: If processing fails after all retries
        """
        if not texts:
            return EmbeddingResult(
                embeddings=[],
                model=self.client.model_name,
                usage=EmbeddingUsage()
            )

        self._stats.total_texts = len(texts)
        self._stats.processed_texts = 0
        self._stats.current_batch_size = self._current_batch_size

        # Use concurrent processing if enabled
        if self.config.max_concurrent_batches > 1:
            return await self._process_concurrent(texts, progress_callback)
        else:
            return await self._process_sequential(texts, progress_callback)

    async def _process_concurrent(
        self,
        texts: List[str],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> EmbeddingResult:
        """Process batches concurrently using semaphore

        Uses asyncio.Semaphore to limit concurrent API requests.
        """
        total = len(texts)
        semaphore = asyncio.Semaphore(self.config.max_concurrent_batches)

        # Split into batches upfront
        batches: List[Tuple[int, List[str]]] = []
        i = 0
        while i < total:
            batch = texts[i:i + self._current_batch_size]
            batches.append((i, batch))
            i += len(batch)

        # Results storage with order preservation
        results: List[Optional[EmbeddingResult]] = [None] * len(batches)
        processed_count = 0
        lock = asyncio.Lock()

        async def process_batch(batch_idx: int, start_idx: int, batch: List[str]):
            nonlocal processed_count
            async with semaphore:
                try:
                    result = await self._process_batch_with_retry(batch)

                    async with lock:
                        results[batch_idx] = result
                        processed_count += len(batch)
                        self._stats.processed_texts = processed_count
                        self._stats.successful_batches += 1
                        self._stats.total_batches += 1
                        self._consecutive_successes += 1
                        self._maybe_increase_batch_size()

                        if progress_callback:
                            progress_callback(processed_count, total)

                except BatchSizeError as e:
                    async with lock:
                        self._reduce_batch_size(e.suggested_batch_size)
                        self._consecutive_successes = 0
                        self._stats.batch_size_reductions += 1
                    logger.warning(
                        f"Batch size reduced to {self._current_batch_size} "
                        f"due to token limit"
                    )
                    raise

                except Exception as e:
                    async with lock:
                        self._stats.failed_batches += 1
                        self._stats.total_batches += 1
                    logger.error(f"Batch processing failed: {e}")
                    raise

        # Process all batches with retries for batch size errors
        max_retries = 5
        retry_count = 0

        while retry_count < max_retries:
            try:
                tasks = [
                    process_batch(idx, start_idx, batch)
                    for idx, (start_idx, batch) in enumerate(batches)
                    if results[idx] is None  # Skip already processed
                ]

                if not tasks:
                    break

                await asyncio.gather(*tasks)
                break

            except BatchSizeError:
                retry_count += 1
                # Rebuild batches with new size
                batches = []
                i = 0
                batch_idx = 0
                while i < total:
                    if results[batch_idx] is not None if batch_idx < len(results) else True:
                        batch_idx += 1
                        continue
                    batch = texts[i:i + self._current_batch_size]
                    batches.append((i, batch))
                    i += len(batch)
                results = [None] * len(batches)
                continue

        # Merge results
        all_embeddings: List[List[float]] = []
        total_usage = EmbeddingUsage()

        for result in results:
            if result is not None:
                all_embeddings.extend(result.embeddings)
                total_usage.prompt_tokens += result.usage.prompt_tokens
                total_usage.total_tokens += result.usage.total_tokens

        self._stats.current_batch_size = self._current_batch_size
        self._stats.total_tokens_used = total_usage.total_tokens

        return EmbeddingResult(
            embeddings=all_embeddings,
            model=self.client.model_name,
            usage=total_usage
        )

    async def _process_sequential(
        self,
        texts: List[str],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> EmbeddingResult:
        """Process texts sequentially (original implementation)"""
        all_embeddings: List[List[float]] = []
        total_usage = EmbeddingUsage()
        i = 0

        while i < len(texts):
            batch = texts[i:i + self._current_batch_size]
            batch_size = len(batch)

            try:
                # Process batch with retry logic
                result = await self._process_batch_with_retry(batch)

                # Success - update state
                all_embeddings.extend(result.embeddings)
                total_usage.prompt_tokens += result.usage.prompt_tokens
                total_usage.total_tokens += result.usage.total_tokens

                i += batch_size
                self._stats.processed_texts = i
                self._stats.successful_batches += 1
                self._stats.total_batches += 1
                self._stats.total_tokens_used = total_usage.total_tokens
                self._consecutive_successes += 1

                # Try to recover batch size
                self._maybe_increase_batch_size()

                # Progress callback
                if progress_callback:
                    progress_callback(i, len(texts))

            except BatchSizeError as e:
                # Token limit exceeded - reduce batch size
                self._reduce_batch_size(e.suggested_batch_size)
                self._consecutive_successes = 0
                self._stats.batch_size_reductions += 1
                logger.warning(
                    f"Batch size reduced to {self._current_batch_size} "
                    f"due to token limit"
                )
                # Don't increment i - retry with smaller batch

            except Exception as e:
                # Other errors after retries exhausted
                self._stats.failed_batches += 1
                self._stats.total_batches += 1
                logger.error(f"Batch processing failed: {e}")
                raise

        self._stats.current_batch_size = self._current_batch_size

        return EmbeddingResult(
            embeddings=all_embeddings,
            model=self.client.model_name,
            usage=total_usage
        )

    async def _process_batch_with_retry(
        self,
        batch: List[str]
    ) -> EmbeddingResult:
        """Process a single batch with retry logic

        Args:
            batch: Texts to process in this batch

        Returns:
            EmbeddingResult for this batch

        Raises:
            BatchSizeError: If batch is too large
            EmbeddingError: On other errors after retries
        """
        async def do_embed():
            return await self.client.embed_batch(batch)

        def on_retry(error: Exception, attempt: int, delay: float):
            logger.info(
                f"Retrying batch (attempt {attempt + 1}), "
                f"waiting {delay:.2f}s"
            )

        return await self.retry_executor.execute(do_embed, on_retry)

    def _reduce_batch_size(self, suggested_size: Optional[int] = None) -> None:
        """Reduce batch size due to token limit

        Args:
            suggested_size: Suggested new size (if available from error)
        """
        if suggested_size and suggested_size > self.config.min_batch_size:
            self._current_batch_size = min(
                suggested_size,
                int(self._current_batch_size * self.config.reduction_factor)
            )
        else:
            self._current_batch_size = max(
                self.config.min_batch_size,
                int(self._current_batch_size * self.config.reduction_factor)
            )

    def _maybe_increase_batch_size(self) -> None:
        """Attempt to increase batch size after successful batches"""
        if self._consecutive_successes < self.config.success_threshold:
            return

        if self._current_batch_size >= self.config.max_batch_size:
            return

        # Gradual recovery
        increase = max(1, int(self._current_batch_size * self.config.recovery_factor))
        new_size = min(
            self.config.max_batch_size,
            self._current_batch_size + increase
        )

        if new_size > self._current_batch_size:
            self._current_batch_size = new_size
            self._consecutive_successes = 0
            self._stats.batch_size_increases += 1
            logger.debug(f"Batch size increased to {self._current_batch_size}")


class CachedBatchProcessor:
    """Batch processor with cache integration

    Wraps BatchProcessor to check cache before embedding and
    store results after embedding.
    """

    def __init__(
        self,
        processor: BatchProcessor,
        cache_get: Callable[[List[str]], dict],
        cache_set: Callable[[str, List[float]], None]
    ):
        """Initialize cached batch processor

        Args:
            processor: Underlying batch processor
            cache_get: Function to get cached embeddings by content hash
            cache_set: Function to set embedding in cache
        """
        self.processor = processor
        self.cache_get = cache_get
        self.cache_set = cache_set

    async def process(
        self,
        texts: List[str],
        content_hashes: List[str],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> EmbeddingResult:
        """Process texts with cache lookup

        Args:
            texts: List of texts to embed
            content_hashes: Content hashes for each text (for caching)
            progress_callback: Optional progress callback

        Returns:
            EmbeddingResult with embeddings (from cache or API)
        """
        if len(texts) != len(content_hashes):
            raise ValueError("texts and content_hashes must have same length")

        if not texts:
            return EmbeddingResult(
                embeddings=[],
                model=self.processor.client.model_name,
                usage=EmbeddingUsage()
            )

        # Check cache
        cached = self.cache_get(content_hashes)

        # Identify uncached texts
        uncached_indices = []
        uncached_texts = []
        uncached_hashes = []

        for i, (text, hash_) in enumerate(zip(texts, content_hashes)):
            if hash_ not in cached:
                uncached_indices.append(i)
                uncached_texts.append(text)
                uncached_hashes.append(hash_)

        # Process uncached texts
        total_usage = EmbeddingUsage()
        if uncached_texts:
            result = await self.processor.process(
                uncached_texts,
                progress_callback=progress_callback
            )
            total_usage = result.usage

            # Store in cache
            for hash_, embedding in zip(uncached_hashes, result.embeddings):
                self.cache_set(hash_, embedding)
                cached[hash_] = embedding

        # Reconstruct result in original order
        embeddings = [cached[hash_] for hash_ in content_hashes]

        return EmbeddingResult(
            embeddings=embeddings,
            model=self.processor.client.model_name,
            usage=total_usage
        )


def estimate_optimal_batch_size(
    avg_text_length: int,
    max_tokens: int = 8191,
    safety_factor: float = 0.8
) -> int:
    """Estimate optimal batch size based on text length

    Args:
        avg_text_length: Average length of texts in characters
        max_tokens: Maximum tokens per API request
        safety_factor: Safety factor to avoid hitting limits (0-1)

    Returns:
        Recommended batch size
    """
    # Rough estimate: 4 characters per token for code
    avg_tokens_per_text = avg_text_length / 4

    if avg_tokens_per_text <= 0:
        return 100  # Default for empty/short texts

    # Calculate batch size with safety margin
    estimated_batch = int((max_tokens * safety_factor) / avg_tokens_per_text)

    # Clamp to reasonable range
    return max(5, min(200, estimated_batch))
