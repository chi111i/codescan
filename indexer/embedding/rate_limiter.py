# Rate Limit Controller for Embedding Operations
# Based on ContextWeaver's RateLimitController design
#
# Features:
# - Global concurrency control with adaptive throttling
# - 429 rate limit handling with exponential backoff
# - Gradual recovery after rate limits
# - Thread-safe implementation for sync/async usage

import asyncio
import threading
import time
import logging
from dataclasses import dataclass, field
from typing import Optional, Callable, TypeVar, Awaitable, Dict, Any

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class RateLimiterConfig:
    """Configuration for rate limiter behavior

    Attributes:
        max_concurrency: Maximum concurrent requests allowed
        initial_backoff_ms: Initial backoff time in milliseconds after 429
        max_backoff_ms: Maximum backoff time in milliseconds
        min_backoff_ms: Minimum backoff time in milliseconds
        successes_per_increase: Consecutive successes needed to increase concurrency
        recovery_factor: Factor to reduce backoff after successful recovery (0.5 = halve)
        recovery_successes: Consecutive successes needed to reduce backoff time
    """
    max_concurrency: int = 5
    initial_backoff_ms: int = 5000
    max_backoff_ms: int = 60000
    min_backoff_ms: int = 5000
    successes_per_increase: int = 3
    recovery_factor: float = 0.5
    recovery_successes: int = 10


@dataclass
class RateLimiterStatus:
    """Current status of the rate limiter"""
    is_paused: bool
    current_concurrency: int
    max_concurrency: int
    active_requests: int
    backoff_ms: int
    consecutive_successes: int
    total_rate_limits: int
    total_requests: int


class RateLimitController:
    """Global rate limit controller for embedding API requests

    Implements adaptive concurrency control:
    - When 429 is encountered, pauses ALL requests globally
    - Uses exponential backoff for wait time
    - After recovery, starts from concurrency=1 and gradually increases
    - Tracks consecutive successes to restore concurrency

    Thread-safe for use in both sync and async contexts.

    Example usage:
        controller = RateLimitController(RateLimiterConfig(max_concurrency=5))

        # Async usage
        async def make_request():
            await controller.acquire()
            try:
                result = await api_call()
                controller.release_success()
                return result
            except RateLimitError:
                controller.release_for_retry()
                await controller.trigger_rate_limit()
                raise
            except Exception:
                controller.release_failure()
                raise

        # Sync usage
        def make_request_sync():
            controller.acquire_sync()
            try:
                result = api_call_sync()
                controller.release_success()
                return result
            except RateLimitError:
                controller.release_for_retry()
                controller.trigger_rate_limit_sync()
                raise
    """

    def __init__(self, config: Optional[RateLimiterConfig] = None):
        """Initialize rate limit controller

        Args:
            config: Rate limiter configuration
        """
        self.config = config or RateLimiterConfig()

        # Thread safety
        self._lock = threading.RLock()
        self._async_lock: Optional[asyncio.Lock] = None

        # State
        self._is_paused = False
        self._pause_event = threading.Event()
        self._pause_event.set()  # Initially not paused
        self._async_pause_event: Optional[asyncio.Event] = None

        # Concurrency control
        self._current_concurrency = self.config.max_concurrency
        self._active_requests = 0
        self._semaphore = threading.Semaphore(self.config.max_concurrency)
        self._async_semaphore: Optional[asyncio.Semaphore] = None

        # Backoff state
        self._backoff_ms = self.config.initial_backoff_ms
        self._consecutive_successes = 0

        # Statistics
        self._total_rate_limits = 0
        self._total_requests = 0

    def _get_async_lock(self) -> asyncio.Lock:
        """Get or create async lock (lazy initialization)"""
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        return self._async_lock

    def _get_async_pause_event(self) -> asyncio.Event:
        """Get or create async pause event (lazy initialization)"""
        if self._async_pause_event is None:
            self._async_pause_event = asyncio.Event()
            if not self._is_paused:
                self._async_pause_event.set()
        return self._async_pause_event

    def _get_async_semaphore(self) -> asyncio.Semaphore:
        """Get or create async semaphore (lazy initialization)"""
        if self._async_semaphore is None:
            self._async_semaphore = asyncio.Semaphore(self._current_concurrency)
        return self._async_semaphore

    async def acquire(self) -> None:
        """Acquire execution slot (async version)

        Blocks if:
        - Rate limit pause is active (waits for recovery)
        - Concurrency limit is reached (waits for slot)
        """
        # Wait if paused
        pause_event = self._get_async_pause_event()
        if not pause_event.is_set():
            logger.debug("Rate limiter: waiting for pause to end...")
            await pause_event.wait()

        # Wait for concurrency slot
        semaphore = self._get_async_semaphore()
        await semaphore.acquire()

        with self._lock:
            self._active_requests += 1
            self._total_requests += 1

    def acquire_sync(self, timeout: Optional[float] = None) -> bool:
        """Acquire execution slot (sync version)

        Args:
            timeout: Maximum time to wait in seconds (None = wait forever)

        Returns:
            True if slot acquired, False if timeout
        """
        # Wait if paused
        if not self._pause_event.wait(timeout=timeout):
            return False

        # Wait for concurrency slot
        if not self._semaphore.acquire(timeout=timeout):
            return False

        with self._lock:
            self._active_requests += 1
            self._total_requests += 1

        return True

    def release_success(self) -> None:
        """Release execution slot after successful request

        Tracks consecutive successes for:
        - Gradually increasing concurrency back to max
        - Reducing backoff time for future rate limits
        """
        with self._lock:
            self._active_requests = max(0, self._active_requests - 1)
            self._consecutive_successes += 1

            # Gradually increase concurrency
            if (self._current_concurrency < self.config.max_concurrency and
                self._consecutive_successes >= self.config.successes_per_increase):
                self._current_concurrency += 1
                self._consecutive_successes = 0
                logger.debug(
                    f"Rate limiter: increased concurrency to {self._current_concurrency}"
                )

            # Gradually reduce backoff time
            if (self._consecutive_successes > 0 and
                self._consecutive_successes % self.config.recovery_successes == 0):
                new_backoff = int(self._backoff_ms * self.config.recovery_factor)
                self._backoff_ms = max(self.config.min_backoff_ms, new_backoff)
                logger.debug(f"Rate limiter: reduced backoff to {self._backoff_ms}ms")

        # Release semaphore
        self._semaphore.release()
        if self._async_semaphore is not None:
            try:
                self._async_semaphore.release()
            except ValueError:
                pass  # Already released

    def release_failure(self) -> None:
        """Release execution slot after non-rate-limit failure

        Does not reset success counter (transient failures are expected).
        """
        with self._lock:
            self._active_requests = max(0, self._active_requests - 1)

        self._semaphore.release()
        if self._async_semaphore is not None:
            try:
                self._async_semaphore.release()
            except ValueError:
                pass

    def release_for_retry(self) -> None:
        """Release execution slot before retrying (e.g., after 429)

        Resets consecutive success counter since rate limit was hit.
        """
        with self._lock:
            self._active_requests = max(0, self._active_requests - 1)
            self._consecutive_successes = 0

        self._semaphore.release()
        if self._async_semaphore is not None:
            try:
                self._async_semaphore.release()
            except ValueError:
                pass

    async def trigger_rate_limit(self) -> None:
        """Handle 429 rate limit - pause all requests (async version)

        Called when any request receives a 429 response.
        Pauses ALL concurrent requests until backoff period ends.
        """
        async_lock = self._get_async_lock()

        async with async_lock:
            # If already paused, just wait for existing pause to end
            if self._is_paused:
                pause_event = self._get_async_pause_event()
                logger.debug("Rate limiter: already paused, waiting...")
                await pause_event.wait()
                return

            self._is_paused = True
            self._pause_event.clear()
            pause_event = self._get_async_pause_event()
            pause_event.clear()

            # Track statistics
            with self._lock:
                self._total_rate_limits += 1
                previous_concurrency = self._current_concurrency
                self._current_concurrency = 1  # Reset to minimum
                self._consecutive_successes = 0

            logger.warning(
                f"Rate limiter: 429 triggered, pausing for {self._backoff_ms}ms "
                f"(concurrency: {previous_concurrency} -> 1, "
                f"active: {self._active_requests})"
            )

            # Wait for backoff period
            await asyncio.sleep(self._backoff_ms / 1000.0)

            # Increase backoff for next time (exponential)
            with self._lock:
                self._backoff_ms = min(
                    self.config.max_backoff_ms,
                    self._backoff_ms * 2
                )

            # Resume
            self._is_paused = False
            self._pause_event.set()
            pause_event.set()

            logger.info(
                f"Rate limiter: resuming (next backoff: {self._backoff_ms}ms)"
            )

    def trigger_rate_limit_sync(self) -> None:
        """Handle 429 rate limit - pause all requests (sync version)"""
        with self._lock:
            # If already paused, just wait for existing pause to end
            if self._is_paused:
                # Release lock to allow other threads to proceed
                pass

        if self._is_paused:
            logger.debug("Rate limiter: already paused, waiting...")
            self._pause_event.wait()
            return

        with self._lock:
            self._is_paused = True
            self._pause_event.clear()

            self._total_rate_limits += 1
            previous_concurrency = self._current_concurrency
            self._current_concurrency = 1
            self._consecutive_successes = 0

        logger.warning(
            f"Rate limiter: 429 triggered, pausing for {self._backoff_ms}ms "
            f"(concurrency: {previous_concurrency} -> 1)"
        )

        # Wait for backoff period
        time.sleep(self._backoff_ms / 1000.0)

        # Increase backoff for next time (exponential)
        with self._lock:
            self._backoff_ms = min(
                self.config.max_backoff_ms,
                self._backoff_ms * 2
            )

        # Resume
        with self._lock:
            self._is_paused = False
        self._pause_event.set()

        logger.info(f"Rate limiter: resuming (next backoff: {self._backoff_ms}ms)")

    def get_status(self) -> RateLimiterStatus:
        """Get current rate limiter status for monitoring"""
        with self._lock:
            return RateLimiterStatus(
                is_paused=self._is_paused,
                current_concurrency=self._current_concurrency,
                max_concurrency=self.config.max_concurrency,
                active_requests=self._active_requests,
                backoff_ms=self._backoff_ms,
                consecutive_successes=self._consecutive_successes,
                total_rate_limits=self._total_rate_limits,
                total_requests=self._total_requests,
            )

    def reset(self) -> None:
        """Reset rate limiter to initial state"""
        with self._lock:
            self._is_paused = False
            self._pause_event.set()
            if self._async_pause_event is not None:
                self._async_pause_event.set()

            self._current_concurrency = self.config.max_concurrency
            self._active_requests = 0
            self._backoff_ms = self.config.initial_backoff_ms
            self._consecutive_successes = 0

            # Reset semaphores
            self._semaphore = threading.Semaphore(self.config.max_concurrency)
            self._async_semaphore = None

        logger.info("Rate limiter: reset to initial state")


# Global rate limiter instance
_global_rate_limiter: Optional[RateLimitController] = None
_global_limiter_lock = threading.Lock()


def get_rate_limiter(config: Optional[RateLimiterConfig] = None) -> RateLimitController:
    """Get or create the global rate limiter instance

    Args:
        config: Optional configuration (only used on first call)

    Returns:
        Global RateLimitController instance
    """
    global _global_rate_limiter

    with _global_limiter_lock:
        if _global_rate_limiter is None:
            _global_rate_limiter = RateLimitController(config)
            logger.info(
                f"Created global rate limiter "
                f"(max_concurrency={_global_rate_limiter.config.max_concurrency})"
            )
        return _global_rate_limiter


def reset_global_rate_limiter() -> None:
    """Reset the global rate limiter instance"""
    global _global_rate_limiter

    with _global_limiter_lock:
        if _global_rate_limiter is not None:
            _global_rate_limiter.reset()


async def with_rate_limit(
    operation: Callable[[], Awaitable[T]],
    controller: Optional[RateLimitController] = None,
    on_rate_limit: Optional[Callable[[], Awaitable[None]]] = None,
) -> T:
    """Execute async operation with rate limit handling

    Args:
        operation: Async function to execute
        controller: Rate limit controller (uses global if None)
        on_rate_limit: Optional callback when rate limit is triggered

    Returns:
        Result of the operation

    Raises:
        Exception: If operation fails after rate limit handling
    """
    ctrl = controller or get_rate_limiter()

    while True:
        await ctrl.acquire()
        try:
            result = await operation()
            ctrl.release_success()
            return result
        except Exception as e:
            error_msg = str(e).lower()

            # Check if it's a rate limit error
            if '429' in error_msg or 'rate' in error_msg:
                ctrl.release_for_retry()
                if on_rate_limit:
                    await on_rate_limit()
                await ctrl.trigger_rate_limit()
                # Loop continues - retry after rate limit pause
            else:
                ctrl.release_failure()
                raise


def with_rate_limit_sync(
    operation: Callable[[], T],
    controller: Optional[RateLimitController] = None,
    on_rate_limit: Optional[Callable[[], None]] = None,
) -> T:
    """Execute sync operation with rate limit handling

    Args:
        operation: Sync function to execute
        controller: Rate limit controller (uses global if None)
        on_rate_limit: Optional callback when rate limit is triggered

    Returns:
        Result of the operation

    Raises:
        Exception: If operation fails after rate limit handling
    """
    ctrl = controller or get_rate_limiter()

    while True:
        ctrl.acquire_sync()
        try:
            result = operation()
            ctrl.release_success()
            return result
        except Exception as e:
            error_msg = str(e).lower()

            # Check if it's a rate limit error
            if '429' in error_msg or 'rate' in error_msg:
                ctrl.release_for_retry()
                if on_rate_limit:
                    on_rate_limit()
                ctrl.trigger_rate_limit_sync()
                # Loop continues - retry after rate limit pause
            else:
                ctrl.release_failure()
                raise
