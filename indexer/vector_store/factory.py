# Unified Vector Store Factory
# Replaces the legacy create_vector_store from vector_store_legacy.py

import logging
from dataclasses import dataclass, field
from typing import Optional, Any

from .interface import VectorStoreInterface
from .memory_store import EnhancedInMemoryStore, MemoryStoreConfig
from .qdrant_store import EnhancedQdrantStore, QdrantConfig

logger = logging.getLogger(__name__)


@dataclass
class VectorStoreConfig:
    """Unified configuration for vector store creation

    Compatible with both legacy VectorStoreConfig and new enhanced stores.
    """
    # Provider: "memory", "inmemory", "qdrant"
    provider: str = "memory"

    # Embedding dimension
    embedding_dim: int = 1536

    # Qdrant settings
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: Optional[str] = None
    collection_name: str = "codescan_code_units"

    # Memory store settings
    use_numpy: bool = True
    use_faiss: bool = False

    # Cache settings (for compatibility)
    enable_cache: bool = True
    cache_dir: str = ".audit_cache"
    cache_ttl_days: int = 30

    # Legacy compatibility fields
    host: Optional[str] = None  # Deprecated, use qdrant_url
    port: Optional[int] = None  # Deprecated, use qdrant_url


def create_vector_store(
    config: Any,
    embedding_dim: Optional[int] = None,
) -> VectorStoreInterface:
    """Unified factory function for creating vector stores

    This function replaces the legacy create_vector_store from vector_store_legacy.py.
    It supports both the legacy VectorStoreConfig format and the new VectorStoreConfig.

    Args:
        config: VectorStoreConfig or legacy config object with 'provider' attribute
        embedding_dim: Override embedding dimension (optional)

    Returns:
        VectorStoreInterface implementation (EnhancedQdrantStore or EnhancedInMemoryStore)

    Examples:
        # Using new config
        store = create_vector_store(VectorStoreConfig(provider="memory", embedding_dim=1536))

        # Using legacy config (backwards compatible)
        store = create_vector_store(legacy_config)
    """
    # Extract provider from config
    if isinstance(config, VectorStoreConfig):
        provider = config.provider.lower()
        dim = embedding_dim or config.embedding_dim
    elif hasattr(config, 'provider'):
        provider = config.provider.lower()
        dim = embedding_dim or getattr(config, 'embedding_dim', None) or 1536
    else:
        # Fallback to memory store
        provider = "memory"
        dim = embedding_dim or 1536

    # Normalize provider name
    if provider in ("memory", "inmemory", "in-memory"):
        return _create_memory_store(config, dim)
    elif provider == "qdrant":
        return _create_qdrant_store(config, dim)
    else:
        logger.warning(f"Unknown provider '{provider}', falling back to memory store")
        return _create_memory_store(config, dim)


def _create_memory_store(config: Any, embedding_dim: int) -> EnhancedInMemoryStore:
    """Create an enhanced in-memory vector store

    Args:
        config: Configuration object
        embedding_dim: Embedding vector dimension

    Returns:
        EnhancedInMemoryStore instance
    """
    use_numpy = getattr(config, 'use_numpy', True)
    use_faiss = getattr(config, 'use_faiss', False)

    mem_config = MemoryStoreConfig(
        use_numpy=use_numpy,
        use_faiss=use_faiss,
        embedding_dim=embedding_dim,
    )

    store = EnhancedInMemoryStore(config=mem_config, embedding_dim=embedding_dim)
    logger.info(f"Created EnhancedInMemoryStore (dim={embedding_dim}, numpy={use_numpy})")

    return store


def _create_qdrant_store(config: Any, embedding_dim: int) -> VectorStoreInterface:
    """Create an enhanced Qdrant vector store

    Falls back to memory store if qdrant-client is not installed.

    Args:
        config: Configuration object
        embedding_dim: Embedding vector dimension

    Returns:
        EnhancedQdrantStore or EnhancedInMemoryStore (fallback)
    """
    # Check if qdrant-client is available
    try:
        from qdrant_client import QdrantClient  # noqa: F401
    except ImportError:
        logger.warning(
            "qdrant-client not installed, falling back to EnhancedInMemoryStore. "
            "Install with: pip install qdrant-client"
        )
        return _create_memory_store(config, embedding_dim)

    # Extract Qdrant settings
    if isinstance(config, VectorStoreConfig):
        url = config.qdrant_url
        api_key = config.qdrant_api_key
        collection_name = config.collection_name
    else:
        # Legacy config support
        host = getattr(config, 'host', None) or getattr(config, 'qdrant_host', 'localhost')
        port = getattr(config, 'port', None) or getattr(config, 'qdrant_port', 6333)
        url = getattr(config, 'qdrant_url', None) or f"http://{host}:{port}"
        api_key = getattr(config, 'qdrant_api_key', None) or getattr(config, 'api_key', None)
        collection_name = getattr(config, 'collection_name', 'codescan_code_units')

    qdrant_config = QdrantConfig(
        url=url,
        api_key=api_key,
        collection_name=collection_name,
        embedding_dim=embedding_dim,
    )

    try:
        store = EnhancedQdrantStore(config=qdrant_config)
        logger.info(f"Created EnhancedQdrantStore (url={url}, collection={collection_name})")
        return store
    except Exception as e:
        logger.warning(f"Failed to create Qdrant store: {e}. Falling back to memory store.")
        return _create_memory_store(config, embedding_dim)
