# Batch processor for embedding operations with dynamic size adjustment
# Based on ACI (augmented-codebase-indexer) and ContextWeaver best practices
#
# Features:
# - Dynamic batch size adjustment based on API responses
# - Rate limit handling with global concurrency control
# - Progress tracking with ETA estimation
# - Automatic size reduction on token limit errors (HTTP 413)
# - Gradual recovery after successful batches

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional, Callable, TypeVar, Generic, Tuple, Dict, Any
from abc import ABC, abstractmethod

from .interface import (
    EmbeddingClientInterface,
    EmbeddingResult,
    EmbeddingUsage,
    BatchSizeError,
    RetryableError,
)
from .retry import RetryConfig, RetryExecutor, EMBEDDING_RETRY_CONFIG
from .rate_limiter import RateLimitController, RateLimiterConfig, get_rate_limiter

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
        enable_rate_limiting: Whether to use global rate limiting
    """
    initial_batch_size: int = 150  # Increased from 50 for better throughput
    min_batch_size: int = 10
    max_batch_size: int = 300
    recovery_factor: float = 0.1  # Recover 10% per success
    reduction_factor: float = 0.5  # Halve on token limit error
    success_threshold: int = 3    # Successes before recovery attempt
    max_tokens_estimate: int = 512  # Conservative estimate per text
    max_concurrent_batches: int = 3  # Concurrent API requests
    enable_rate_limiting: bool = True  # Use global rate limiter


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
    rate_limit_pauses: int = 0  # Number of 429 pauses


class ProgressTracker:
    """Progress tracker with ETA estimation (based on ContextWeaver)

    Provides periodic progress logging to avoid flooding logs while
    still giving visibility into long-running operations.
    """

    def __init__(
        self,
        total: int,
        on_progress: Optional[Callable[[int, int], None]] = None,
        log_interval_ms: int = 2000,
        skip_logs: bool = False
    ):
        """Initialize progress tracker

        Args:
            total: Total number of items to process
            on_progress: Optional callback(completed, total)
            log_interval_ms: Minimum time between log outputs
            skip_logs: Whether to skip logging (for single batches)
        """
        self.total = total
        self.on_progress = on_progress
        self.log_interval_ms = log_interval_ms
        self.skip_logs = skip_logs or total <= 1

        self.completed = 0
        self.total_tokens = 0
        self.start_time = time.time()
        self.last_log_time = 0.0

    def record_batch(self, count: int, tokens: int = 0) -> None:
        """Record completion of a batch

        Args:
            count: Number of items completed in this batch
            tokens: Tokens used in this batch
        """
        self.completed += count
        self.total_tokens += tokens

        # Call external callback
        if self.on_progress:
            self.on_progress(self.completed, self.total)

        # Periodic logging
        now = time.time()
        if (now - self.last_log_time) * 1000 >= self.log_interval_ms:
            self._log_progress()
            self.last_log_time = now

    def _log_progress(self) -> None:
        """Output progress log"""
        if self.skip_logs:
            return

        elapsed = time.time() - self.start_time
        percent = round((self.completed / max(1, self.total)) * 100)
        rate = self.completed / max(0.1, elapsed)
        eta = int((self.total - self.completed) / max(0.1, rate))

        logger.info(
            f"Embedding progress: {self.completed}/{self.total} ({percent}%) "
            f"tokens={self.total_tokens} elapsed={elapsed:.1f}s eta={eta}s"
        )

    def complete(self) -> Dict[str, Any]:
        """Finalize and log completion statistics

        Returns:
            Summary statistics dict
        """
        elapsed = time.time() - self.start_time

        if not self.skip_logs:
            logger.info(
                f"Embedding complete: {self.completed} items, "
                f"{self.total_tokens} tokens in {elapsed:.1f}s "
                f"({self.completed / max(0.1, elapsed):.1f} items/s)"
            )

        return {
            "total_items": self.completed,
            "total_tokens": self.total_tokens,
            "elapsed_seconds": round(elapsed, 2),
            "items_per_second": round(self.completed / max(0.1, elapsed), 2),
        }


class BatchProcessor:
    """Batch processor with dynamic size adjustment and rate limiting

    Features:
    - Dynamic batch size adjustment based on API responses
    - Global rate limiting with 429 handling (ContextWeaver style)
    - Automatic size reduction on token limit errors (HTTP 413)
    - Gradual recovery after successful batches
    - Progress tracking with ETA estimation
    - Comprehensive statistics tracking
    """

    def __init__(
        self,
        client: EmbeddingClientInterface,
        config: Optional[BatchConfig] = None,
        retry_config: Optional[RetryConfig] = None,
        rate_limiter: Optional[RateLimitController] = None
    ):
        """Initialize batch processor

        Args:
            client: Embedding client to use
            config: Batch processing configuration
            retry_config: Retry configuration for individual batches
            rate_limiter: Rate limit controller (uses global if None)
        """
        self.client = client
        self.config = config or BatchConfig()
        self.retry_config = retry_config or EMBEDDING_RETRY_CONFIG
        self.retry_executor = RetryExecutor(self.retry_config)

        # Rate limiter (global or custom)
        if self.config.enable_rate_limiting:
            self._rate_limiter = rate_limiter or get_rate_limiter(
                RateLimiterConfig(max_concurrency=self.config.max_concurrent_batches)
            )
        else:
            self._rate_limiter = None

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
        """Process texts in batches with dynamic sizing, rate limiting and progress tracking

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

        # Create progress tracker
        progress = ProgressTracker(
            total=len(texts),
            on_progress=progress_callback,
            skip_logs=len(texts) <= self._current_batch_size  # Skip for single batch
        )

        # Use concurrent processing if enabled
        if self.config.max_concurrent_batches > 1:
            result = await self._process_concurrent(texts, progress)
        else:
            result = await self._process_sequential(texts, progress)

        # Log completion
        progress.complete()

        return result

    async def _process_concurrent(
        self,
        texts: List[str],
        progress: ProgressTracker
    ) -> EmbeddingResult:
        """Process batches concurrently with rate limiting

        Uses rate limiter for global concurrency control and 429 handling.
        """
        total = len(texts)

        # Split into batches upfront
        batches: List[Tuple[int, List[str]]] = []
        i = 0
        while i < total:
            batch = texts[i:i + self._current_batch_size]
            batches.append((i, batch))
            i += len(batch)

        # Results storage with order preservation
        results: List[Optional[EmbeddingResult]] = [None] * len(batches)
        lock = asyncio.Lock()

        async def process_batch(batch_idx: int, start_idx: int, batch: List[str]):
            """Process single batch with rate limiting"""
            # Acquire rate limit slot if enabled
            if self._rate_limiter:
                await self._rate_limiter.acquire()

            try:
                result = await self._process_batch_with_retry(batch)

                async with lock:
                    results[batch_idx] = result
                    self._stats.processed_texts += len(batch)
                    self._stats.successful_batches += 1
                    self._stats.total_batches += 1
                    self._consecutive_successes += 1
                    self._maybe_increase_batch_size()

                    # Update progress tracker
                    tokens = result.usage.total_tokens if result.usage else 0
                    progress.record_batch(len(batch), tokens)

                # Release rate limit slot on success
                if self._rate_limiter:
                    self._rate_limiter.release_success()

            except BatchSizeError as e:
                if self._rate_limiter:
                    self._rate_limiter.release_failure()
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
                error_msg = str(e).lower()
                # Check for rate limit error
                if '429' in error_msg or 'rate' in error_msg:
                    if self._rate_limiter:
                        self._rate_limiter.release_for_retry()
                        await self._rate_limiter.trigger_rate_limit()
                        self._stats.rate_limit_pauses += 1
                    raise  # Will be retried
                else:
                    if self._rate_limiter:
                        self._rate_limiter.release_failure()
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
                # Create tasks for unprocessed batches
                tasks = [
                    process_batch(idx, start_idx, batch)
                    for idx, (start_idx, batch) in enumerate(batches)
                    if results[idx] is None
                ]

                if not tasks:
                    break

                # Use semaphore if rate limiter is disabled
                if not self._rate_limiter:
                    semaphore = asyncio.Semaphore(self.config.max_concurrent_batches)

                    async def with_semaphore(task):
                        async with semaphore:
                            return await task

                    tasks = [with_semaphore(t) for t in tasks]

                await asyncio.gather(*tasks, return_exceptions=False)
                break

            except BatchSizeError:
                retry_count += 1
                # Rebuild batches with new size
                new_batches = []
                i = 0
                while i < total:
                    batch = texts[i:i + self._current_batch_size]
                    new_batches.append((i, batch))
                    i += len(batch)
                batches = new_batches
                results = [None] * len(batches)
                continue

            except Exception as e:
                # Handle rate limit retry at batch level
                if '429' in str(e).lower():
                    retry_count += 1
                    continue
                raise

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
        progress: ProgressTracker
    ) -> EmbeddingResult:
        """Process texts sequentially with rate limiting"""
        all_embeddings: List[List[float]] = []
        total_usage = EmbeddingUsage()
        i = 0

        while i < len(texts):
            batch = texts[i:i + self._current_batch_size]
            batch_size = len(batch)

            # Acquire rate limit slot if enabled
            if self._rate_limiter:
                await self._rate_limiter.acquire()

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

                # Update progress tracker
                progress.record_batch(batch_size, result.usage.total_tokens)

                # Try to recover batch size
                self._maybe_increase_batch_size()

                # Release rate limit slot on success
                if self._rate_limiter:
                    self._rate_limiter.release_success()

            except BatchSizeError as e:
                if self._rate_limiter:
                    self._rate_limiter.release_failure()
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
                error_msg = str(e).lower()
                # Check for rate limit error
                if '429' in error_msg or 'rate' in error_msg:
                    if self._rate_limiter:
                        self._rate_limiter.release_for_retry()
                        await self._rate_limiter.trigger_rate_limit()
                        self._stats.rate_limit_pauses += 1
                    # Don't increment i - retry after pause
                else:
                    if self._rate_limiter:
                        self._rate_limiter.release_failure()
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
