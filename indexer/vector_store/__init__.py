# Vector store module for CodeScan
# Provides vector storage backends and hybrid search

from .interface import (
    # Data classes
    SearchResult,
    UpsertResult,
    DeleteResult,
    RerankerConfig,
    HybridSearchConfig,
    ArtifactType,
    # Exceptions (new names, avoid shadowing Python built-ins)
    VectorStoreError,
    VectorConnectionError,
    VectorIndexError,
    # Deprecated aliases (will be removed in future)
    ConnectionError,
    IndexError,
    # Abstract interface
    VectorStoreInterface,
    # Reranker
    CodeReranker,
)

from .metadata_store import (
    # Data classes
    FileInfo,
    PendingBatch,
    BatchStatus,
    # Store
    IndexMetadataStore,
    # Utilities
    compute_file_hash,
)

from .qdrant_store import (
    EnhancedQdrantStore,
    QdrantConfig,
    create_enhanced_qdrant_store,
)

from .memory_store import (
    EnhancedInMemoryStore,
    MemoryStoreConfig,
    create_enhanced_memory_store,
)

__all__ = [
    # Data classes
    "SearchResult",
    "UpsertResult",
    "DeleteResult",
    "RerankerConfig",
    "HybridSearchConfig",
    "ArtifactType",
    # Metadata store
    "FileInfo",
    "PendingBatch",
    "BatchStatus",
    "IndexMetadataStore",
    "compute_file_hash",
    # Enhanced Qdrant
    "EnhancedQdrantStore",
    "QdrantConfig",
    "create_enhanced_qdrant_store",
    # Enhanced Memory Store
    "EnhancedInMemoryStore",
    "MemoryStoreConfig",
    "create_enhanced_memory_store",
    # Exceptions (new names)
    "VectorStoreError",
    "VectorConnectionError",
    "VectorIndexError",
    # Deprecated aliases (shadowed Python built-ins)
    "ConnectionError",
    "IndexError",
    # Interfaces
    "VectorStoreInterface",
    # Reranker
    "CodeReranker",
]
