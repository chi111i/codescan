# Embedding client interface and data models
# Based on ACI (augmented-codebase-indexer) best practices

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict, Any
from enum import Enum


class EmbeddingError(Exception):
    """Base exception for embedding errors"""
    pass


class RetryableError(EmbeddingError):
    """Error that can be retried (network issues, rate limits)"""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class NonRetryableError(EmbeddingError):
    """Error that should not be retried (invalid input, auth failure)"""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class BatchSizeError(EmbeddingError):
    """Error indicating batch size is too large (token limit exceeded)"""
    def __init__(self, message: str, suggested_batch_size: Optional[int] = None):
        super().__init__(message)
        self.suggested_batch_size = suggested_batch_size


@dataclass
class EmbeddingUsage:
    """Token usage statistics for embedding request"""
    prompt_tokens: int = 0
    total_tokens: int = 0


@dataclass
class EmbeddingResult:
    """Result of embedding generation"""
    embeddings: List[List[float]]
    model: str
    usage: EmbeddingUsage = field(default_factory=EmbeddingUsage)

    @property
    def dimension(self) -> int:
        """Get embedding dimension from first embedding"""
        if self.embeddings and len(self.embeddings) > 0:
            return len(self.embeddings[0])
        return 0

    def __len__(self) -> int:
        return len(self.embeddings)


class EmbeddingClientInterface(ABC):
    """Abstract interface for embedding clients

    Implementations should handle:
    - Connection pooling
    - Retry logic with exponential backoff
    - Batch processing with dynamic size adjustment
    - Error classification (retryable vs non-retryable)
    """

    @abstractmethod
    async def embed_batch(
        self,
        texts: List[str],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> EmbeddingResult:
        """Generate embeddings for a batch of texts

        Args:
            texts: List of texts to embed
            progress_callback: Optional callback(processed_count, total_count)

        Returns:
            EmbeddingResult with embeddings and usage stats

        Raises:
            RetryableError: For transient errors
            NonRetryableError: For permanent errors
            BatchSizeError: When batch size needs reduction
        """
        pass

    @abstractmethod
    async def embed_single(self, text: str) -> List[float]:
        """Generate embedding for a single text

        Args:
            text: Text to embed

        Returns:
            Embedding vector as list of floats
        """
        pass

    def embed_batch_sync(
        self,
        texts: List[str],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> EmbeddingResult:
        """Synchronous wrapper for embed_batch

        For use in sync contexts like indexer.py
        """
        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If in async context, create new loop in thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        asyncio.run,
                        self.embed_batch(texts, progress_callback)
                    )
                    return future.result()
            else:
                return loop.run_until_complete(
                    self.embed_batch(texts, progress_callback)
                )
        except RuntimeError:
            # No event loop, create one
            return asyncio.run(self.embed_batch(texts, progress_callback))

    def embed_single_sync(self, text: str) -> List[float]:
        """Synchronous wrapper for embed_single"""
        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, self.embed_single(text))
                    return future.result()
            else:
                return loop.run_until_complete(self.embed_single(text))
        except RuntimeError:
            return asyncio.run(self.embed_single(text))

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Get the embedding dimension for this client"""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Get the model name used for embeddings"""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close the client and release resources"""
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


class LocalEmbeddingClient(EmbeddingClientInterface):
    """Local fallback embedding client using feature hashing

    Uses simple hash-based embeddings for offline/fallback scenarios.
    Does NOT provide semantic similarity - only ensures tool availability.
    """

    def __init__(self, dimension: int = 1536):
        self._dimension = dimension
        self._model = "local-hash-embedding"

    async def embed_batch(
        self,
        texts: List[str],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> EmbeddingResult:
        embeddings = []
        for i, text in enumerate(texts):
            embedding = self._hash_embed(text)
            embeddings.append(embedding)
            if progress_callback:
                progress_callback(i + 1, len(texts))

        return EmbeddingResult(
            embeddings=embeddings,
            model=self._model,
            usage=EmbeddingUsage(
                prompt_tokens=sum(len(t.split()) for t in texts),
                total_tokens=sum(len(t.split()) for t in texts)
            )
        )

    async def embed_single(self, text: str) -> List[float]:
        return self._hash_embed(text)

    def _hash_embed(self, text: str) -> List[float]:
        """Generate hash-based embedding"""
        import hashlib
        import math

        # Simple feature hashing with unigrams and bigrams
        vector = [0.0] * self._dimension
        tokens = text.lower().split()

        # Unigrams
        for token in tokens:
            h = int(hashlib.md5(token.encode()).hexdigest(), 16)
            idx = h % self._dimension
            sign = 1 if (h // self._dimension) % 2 == 0 else -1
            vector[idx] += sign

        # Bigrams
        for i in range(len(tokens) - 1):
            bigram = f"{tokens[i]} {tokens[i+1]}"
            h = int(hashlib.md5(bigram.encode()).hexdigest(), 16)
            idx = h % self._dimension
            sign = 1 if (h // self._dimension) % 2 == 0 else -1
            vector[idx] += sign * 0.5

        # L2 normalize
        norm = math.sqrt(sum(v * v for v in vector))
        if norm > 0:
            vector = [v / norm for v in vector]

        return vector

    @property
    def dimension(self) -> int:
        return self._dimension

    @property
    def model_name(self) -> str:
        return self._model

    async def close(self) -> None:
        pass  # No resources to release
