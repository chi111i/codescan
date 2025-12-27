# Chunker module for CodeScan
# Provides AST-aware code chunking and multi-granularity indexing

from .models import (
    # Enums
    ChunkType,
    ArtifactType,
    # Data classes
    ChunkMetadata,
    CodeChunk,
    SummaryArtifact,
    ChunkingResult,
    ChunkerConfig,
)

from .smart_splitter import (
    SplitContext,
    SmartChunkSplitter,
    create_smart_splitter,
)

from .ast_chunker import (
    ASTNodeInfo,
    ASTChunker,
    create_ast_chunker,
)

__all__ = [
    # Enums
    "ChunkType",
    "ArtifactType",
    # Data classes
    "ChunkMetadata",
    "CodeChunk",
    "SummaryArtifact",
    "ChunkingResult",
    "ChunkerConfig",
    # Smart splitter
    "SplitContext",
    "SmartChunkSplitter",
    "create_smart_splitter",
    # AST chunker
    "ASTNodeInfo",
    "ASTChunker",
    "create_ast_chunker",
]
