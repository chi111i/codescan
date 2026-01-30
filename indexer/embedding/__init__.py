# Embedding module for CodeScan
# Provides embedding generation, caching, and batch processing

from .interface import (
    EmbeddingClientInterface,
    EmbeddingResult,
    EmbeddingUsage,
    EmbeddingError,
    RetryableError,
    NonRetryableError,
    BatchSizeError,
    LocalEmbeddingClient,
)
from .retry import (
    RetryConfig,
    RetryStrategy,
    RetryExecutor,
    classify_http_error,
    EMBEDDING_RETRY_CONFIG,
    FAST_RETRY_CONFIG,
    AGGRESSIVE_RETRY_CONFIG,
)
from .batch_processor import (
    BatchProcessor,
    BatchConfig,
    BatchStats,
    CachedBatchProcessor,
    estimate_optimal_batch_size,
)
from .openai_client import (
    OpenAIEmbeddingClient,
    OpenAIClientConfig,
    create_embedding_client,
    create_client_from_settings,
)
from .rate_limiter import (
    RateLimitController,
    RateLimiterConfig,
    RateLimiterStatus,
    get_rate_limiter,
    reset_global_rate_limiter,
    with_rate_limit,
    with_rate_limit_sync,
)

__all__ = [
    # Interface
    "EmbeddingClientInterface",
    "EmbeddingResult",
    "EmbeddingUsage",
    "EmbeddingError",
    "RetryableError",
    "NonRetryableError",
    "BatchSizeError",
    "LocalEmbeddingClient",
    # Retry
    "RetryConfig",
    "RetryStrategy",
    "RetryExecutor",
    "classify_http_error",
    "EMBEDDING_RETRY_CONFIG",
    "FAST_RETRY_CONFIG",
    "AGGRESSIVE_RETRY_CONFIG",
    # Batch processing
    "BatchProcessor",
    "BatchConfig",
    "BatchStats",
    "CachedBatchProcessor",
    "estimate_optimal_batch_size",
    # OpenAI client
    "OpenAIEmbeddingClient",
    "OpenAIClientConfig",
    "create_embedding_client",
    "create_client_from_settings",
    # Rate limiting (based on ContextWeaver)
    "RateLimitController",
    "RateLimiterConfig",
    "RateLimiterStatus",
    "get_rate_limiter",
    "reset_global_rate_limiter",
    "with_rate_limit",
    "with_rate_limit_sync",
]
