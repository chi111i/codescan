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

# 使用统一的向量存储接口（替代旧的 vector_store_legacy）
from .vector_store import (
    VectorStoreInterface,
    SearchResult,
    HybridSearchConfig,
    RerankerConfig,
    CodeReranker,
    create_vector_store,
    VectorStoreConfig,
    EnhancedQdrantStore,
    EnhancedInMemoryStore,
)

# 向后兼容别名（已弃用，将在未来版本移除）
# 从 vector_store_legacy 导入用于兼容旧代码
try:
    from .vector_store_legacy import (
        BaseVectorStore,
        QdrantVectorStore,
        InMemoryVectorStore,
    )
except ImportError:
    # 如果旧模块被删除，使用新接口作为别名
    BaseVectorStore = VectorStoreInterface
    QdrantVectorStore = EnhancedQdrantStore
    InMemoryVectorStore = EnhancedInMemoryStore

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
from .parallel_worker import (
    ParallelFileProcessor,
    parse_file_worker,
    reconstruct_code_unit,
    init_worker,
    process_files_async,
)
from .indexing_pipeline import (
    IndexingPipeline,
    PipelineConfig,
    PipelineStats,
    StageProgress,
)
from .file_change_detector import (
    FileChangeDetector,
    FileChangeResult,
    IndexedFileInfo,
    PendingBatch,
    compute_file_hash,
    get_file_change_detector,
    reset_global_detector,
)
from .incremental_pipeline import (
    IncrementalPipeline,
    IncrementalConfig,
    IncrementalStats,
    create_incremental_pipeline,
)
from .search_service import (
    SearchService,
    SearchConfig,
    SearchMode,
    HybridSearchResult,
    ParsedQuery,
    RerankerInterface,
    create_search_service,
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
    # 向量存储（新接口）
    "VectorStoreInterface",
    "SearchResult",
    "HybridSearchConfig",
    "RerankerConfig",
    "CodeReranker",
    "create_vector_store",
    "VectorStoreConfig",
    "EnhancedQdrantStore",
    "EnhancedInMemoryStore",
    # 向量存储（兼容别名，已弃用）
    "BaseVectorStore",
    "QdrantVectorStore",
    "InMemoryVectorStore",
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
    # 并行处理 (基于 ACI)
    "ParallelFileProcessor",
    "parse_file_worker",
    "reconstruct_code_unit",
    "init_worker",
    "process_files_async",
    # 索引流水线 (基于 ACI)
    "IndexingPipeline",
    "PipelineConfig",
    "PipelineStats",
    "StageProgress",
    # 文件变更检测 (基于 ACI)
    "FileChangeDetector",
    "FileChangeResult",
    "IndexedFileInfo",
    "PendingBatch",
    "compute_file_hash",
    "get_file_change_detector",
    "reset_global_detector",
    # 增量索引流水线 (基于 ACI)
    "IncrementalPipeline",
    "IncrementalConfig",
    "IncrementalStats",
    "create_incremental_pipeline",
    # 混合搜索服务 (基于 ACI + ContextWeaver)
    "SearchService",
    "SearchConfig",
    "SearchMode",
    "HybridSearchResult",
    "ParsedQuery",
    "RerankerInterface",
    "create_search_service",
]
