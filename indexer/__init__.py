"""索引器模块"""

from .models import CodeUnit, CodeUnitType, CodeSpan
from .parser import (
    BaseLanguageParser,
    PythonParser,
    JavaScriptParser,
    PHPParser,
    get_parser,
    get_parser_for_file,
    register_parser,
)
from .vector_store import (
    BaseVectorStore,
    QdrantVectorStore,
    InMemoryVectorStore,
    SearchResult,
    HybridSearchConfig,
    RerankerConfig,
    CodeReranker,
    create_vector_store,
)
from .indexer import CodeIndexer, FileTracker, GitIgnoreParser
from .code_reader import CodeReader
from .storage import (
    StorageManager,
    ProjectIndex,
    StoredCodeUnit,
)
from .embedding_cache import (
    EmbeddingCache,
    CachedEmbeddingGenerator,
    CacheEntry,
)
from .incremental import (
    IncrementalIndexManager,
    FileIndexEntry,
    ChunkDeduplicationEntry,
    IncrementalIndexStats,
    ShardInfo,
)
from .code_graph import (
    CodePropertyGraph,
    CodeGraphBuilder,
    CodeGraphManager,
    GraphNode,
    GraphEdge,
    NodeType as GraphNodeType,
    EdgeType as GraphEdgeType,
)
from .file_filter import (
    FileFilter,
    FilterStats,
    create_default_auditignore,
)

__all__ = [
    # 代码单元
    "CodeUnit",
    "CodeUnitType",
    "CodeSpan",
    # 解析器
    "BaseLanguageParser",
    "PythonParser",
    "JavaScriptParser",
    "PHPParser",
    "get_parser",
    "get_parser_for_file",
    "register_parser",
    # 向量存储
    "BaseVectorStore",
    "QdrantVectorStore",
    "InMemoryVectorStore",
    "SearchResult",
    "HybridSearchConfig",
    "RerankerConfig",
    "CodeReranker",
    "create_vector_store",
    # 索引器
    "CodeIndexer",
    "FileTracker",
    "GitIgnoreParser",
    # 代码读取器
    "CodeReader",
    # 存储管理器
    "StorageManager",
    "ProjectIndex",
    "StoredCodeUnit",
    # 嵌入缓存
    "EmbeddingCache",
    "CachedEmbeddingGenerator",
    "CacheEntry",
    # 增量索引
    "IncrementalIndexManager",
    "FileIndexEntry",
    "ChunkDeduplicationEntry",
    "IncrementalIndexStats",
    "ShardInfo",
    # 代码属性图
    "CodePropertyGraph",
    "CodeGraphBuilder",
    "CodeGraphManager",
    "GraphNode",
    "GraphEdge",
    "GraphNodeType",
    "GraphEdgeType",
    # 文件过滤
    "FileFilter",
    "FilterStats",
    "create_default_auditignore",
]
