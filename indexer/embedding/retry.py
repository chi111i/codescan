# Retry configuration and strategy for embedding operations
# Based on ACI (augmented-codebase-indexer) best practices

import asyncio
import random
import logging
from dataclasses import dataclass, field
from typing import Optional, Callable, TypeVar, Awaitable
from enum import Enum

from .interface import RetryableError, NonRetryableError, BatchSizeError

logger = logging.getLogger(__name__)

T = TypeVar('T')


class RetryStrategy(Enum):
    """Retry strategy types"""
    EXPONENTIAL = "exponential"  # Exponential backoff with jitter
    LINEAR = "linear"            # Linear backoff
    CONSTANT = "constant"        # Fixed delay


@dataclass
class RetryConfig:
    """Configuration for retry behavior

    Attributes:
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay in seconds before first retry
        max_delay: Maximum delay in seconds between retries
        exponential_base: Base for exponential backoff (default 2)
        jitter: Whether to add random jitter to delays
        jitter_factor: Maximum jitter as fraction of delay (0.0-1.0)
        strategy: Retry strategy to use
        retry_on_timeout: Whether to retry on timeout errors
        retry_on_rate_limit: Whether to retry on rate limit errors
    """
    max_retries: int = 3
    initial_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    jitter_factor: float = 0.25
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    retry_on_timeout: bool = True
    retry_on_rate_limit: bool = True

    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for given attempt number (0-indexed)

        Args:
            attempt: Current attempt number (0 = first retry)

        Returns:
            Delay in seconds before next attempt
        """
        if self.strategy == RetryStrategy.CONSTANT:
            delay = self.initial_delay
        elif self.strategy == RetryStrategy.LINEAR:
            delay = self.initial_delay * (attempt + 1)
        else:  # EXPONENTIAL
            delay = self.initial_delay * (self.exponential_base ** attempt)

        # Cap at max delay
        delay = min(delay, self.max_delay)

        # Add jitter if enabled
        if self.jitter:
            jitter_range = delay * self.jitter_factor
            delay = delay + random.uniform(-jitter_range, jitter_range)
            delay = max(0.1, delay)  # Ensure positive delay

        return delay

    def should_retry(self, error: Exception, attempt: int) -> bool:
        """Determine if operation should be retried

        Args:
            error: The exception that occurred
            attempt: Current attempt number (0-indexed)

        Returns:
            True if should retry, False otherwise
        """
        # Check max retries
        if attempt >= self.max_retries:
            return False

        # Non-retryable errors should not be retried
        if isinstance(error, NonRetryableError):
            return False

        # BatchSizeError should not be retried (caller should reduce batch)
        if isinstance(error, BatchSizeError):
            return False

        # Retryable errors should be retried
        if isinstance(error, RetryableError):
            # Check specific status codes
            if hasattr(error, 'status_code'):
                status_code = error.status_code
                # Rate limit (429)
                if status_code == 429 and not self.retry_on_rate_limit:
                    return False
                # Timeout (408)
                if status_code == 408 and not self.retry_on_timeout:
                    return False
            return True

        # Check for common transient error types
        error_name = type(error).__name__.lower()
        if any(t in error_name for t in ['timeout', 'connection', 'network', 'ssl']):
            return self.retry_on_timeout

        # Default: don't retry unknown errors
        return False


class RetryExecutor:
    """Executes async operations with retry logic"""

    def __init__(self, config: Optional[RetryConfig] = None):
        """Initialize retry executor

        Args:
            config: Retry configuration (uses defaults if not provided)
        """
        self.config = config or RetryConfig()

    async def execute(
        self,
        operation: Callable[[], Awaitable[T]],
        on_retry: Optional[Callable[[Exception, int, float], None]] = None
    ) -> T:
        """Execute async operation with retry logic

        Args:
            operation: Async function to execute
            on_retry: Optional callback(error, attempt, delay) called before each retry

        Returns:
            Result of the operation

        Raises:
            The last exception if all retries are exhausted
        """
        last_error: Optional[Exception] = None

        for attempt in range(self.config.max_retries + 1):
            try:
                return await operation()
            except Exception as e:
                last_error = e

                if not self.config.should_retry(e, attempt):
                    raise

                delay = self.config.calculate_delay(attempt)

                logger.warning(
                    f"Retry attempt {attempt + 1}/{self.config.max_retries} "
                    f"after {delay:.2f}s due to: {type(e).__name__}: {str(e)[:100]}"
                )

                if on_retry:
                    on_retry(e, attempt, delay)

                await asyncio.sleep(delay)

        # Should not reach here, but just in case
        if last_error:
            raise last_error
        raise RuntimeError("Retry executor reached unexpected state")

    def execute_sync(
        self,
        operation: Callable[[], T],
        on_retry: Optional[Callable[[Exception, int, float], None]] = None
    ) -> T:
        """Execute sync operation with retry logic

        Args:
            operation: Sync function to execute
            on_retry: Optional callback(error, attempt, delay) called before each retry

        Returns:
            Result of the operation

        Raises:
            The last exception if all retries are exhausted
        """
        import time
        last_error: Optional[Exception] = None

        for attempt in range(self.config.max_retries + 1):
            try:
                return operation()
            except Exception as e:
                last_error = e

                if not self.config.should_retry(e, attempt):
                    raise

                delay = self.config.calculate_delay(attempt)

                logger.warning(
                    f"Retry attempt {attempt + 1}/{self.config.max_retries} "
                    f"after {delay:.2f}s due to: {type(e).__name__}: {str(e)[:100]}"
                )

                if on_retry:
                    on_retry(e, attempt, delay)

                time.sleep(delay)

        if last_error:
            raise last_error
        raise RuntimeError("Retry executor reached unexpected state")


def classify_http_error(status_code: int, message: str = "") -> Exception:
    """Classify HTTP error into appropriate exception type

    Args:
        status_code: HTTP status code
        message: Error message

    Returns:
        Appropriate exception instance
    """
    if status_code == 413:
        # Payload too large - batch size issue
        return BatchSizeError(
            f"Request too large (HTTP 413): {message}",
            suggested_batch_size=None
        )

    if status_code in (400, 401, 403, 404, 422):
        # Client errors - non-retryable
        return NonRetryableError(
            f"Client error (HTTP {status_code}): {message}",
            status_code=status_code
        )

    if status_code in (429, 500, 502, 503, 504):
        # Rate limit or server errors - retryable
        return RetryableError(
            f"Server error (HTTP {status_code}): {message}",
            status_code=status_code
        )

    # Default to retryable for unknown status codes >= 500
    if status_code >= 500:
        return RetryableError(
            f"Server error (HTTP {status_code}): {message}",
            status_code=status_code
        )

    # Unknown client error
    return NonRetryableError(
        f"HTTP error (HTTP {status_code}): {message}",
        status_code=status_code
    )


# Preset configurations for common use cases
EMBEDDING_RETRY_CONFIG = RetryConfig(
    max_retries=3,
    initial_delay=1.0,
    max_delay=30.0,
    exponential_base=2.0,
    jitter=True,
    jitter_factor=0.25,
    strategy=RetryStrategy.EXPONENTIAL,
    retry_on_timeout=True,
    retry_on_rate_limit=True,
)

FAST_RETRY_CONFIG = RetryConfig(
    max_retries=2,
    initial_delay=0.5,
    max_delay=5.0,
    exponential_base=2.0,
    jitter=True,
    jitter_factor=0.1,
    strategy=RetryStrategy.EXPONENTIAL,
    retry_on_timeout=True,
    retry_on_rate_limit=True,
)

AGGRESSIVE_RETRY_CONFIG = RetryConfig(
    max_retries=5,
    initial_delay=2.0,
    max_delay=120.0,
    exponential_base=2.0,
    jitter=True,
    jitter_factor=0.3,
    strategy=RetryStrategy.EXPONENTIAL,
    retry_on_timeout=True,
    retry_on_rate_limit=True,
)
