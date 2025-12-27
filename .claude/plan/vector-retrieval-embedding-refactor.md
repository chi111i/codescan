# 向量检索与嵌入重构规划

> 基于参考项目 `augmented-codebase-indexer` (ACI) 的最佳实践，重构 CodeScan 的向量检索和嵌入系统

## 一、项目背景

### 1.1 参考项目核心优势 (ACI)

| 特性 | ACI 实现 | 价值 |
|------|----------|------|
| **AST 感知分块** | SmartChunkSplitter + 语义边界 | 更精准的代码语义单元 |
| **多粒度索引** | chunk + function/class/file summary | 多层次检索能力 |
| **混合搜索** | 向量 + grep + 重排序 | 更高召回率 |
| **批量优化** | 动态 batch_size + Token 限制降级 | 稳定性和效率 |
| **事务一致性** | PendingBatch 机制 | Qdrant/SQLite 数据一致 |
| **依赖注入** | ServicesContainer | 模块解耦、易测试 |

### 1.2 CodeScan 当前问题

| 问题 | 位置 | 影响 |
|------|------|------|
| `get_batch()` 逐个查询 | `embedding_cache.py:405-417` | 大批量缓存查询慢 |
| 嵌入客户端禁用 HTTP/2 | `client.py:265-270` | 并发性能降低 |
| 固定 batch_size=50 | `indexer.py:519-529` | 无法动态调优 |
| 内存存储余弦相似度纯 Python | `vector_store.py:852-859` | 大规模数据搜索慢 |
| 缺少多粒度索引 | - | 仅 chunk 级别检索 |

---

## 二、重构目标

### 2.1 核心目标

1. **提升嵌入生成效率** - 批量优化、动态降级、异步调用
2. **增强检索精度** - 多粒度索引、混合搜索、智能重排序
3. **提高系统稳定性** - 事务一致性、故障恢复、优雅降级
4. **改善代码架构** - 依赖注入、接口抽象、模块解耦

### 2.2 量化指标

| 指标 | 当前基线 | 目标 | 提升幅度 |
|------|----------|------|----------|
| 批量缓存查询 | O(n) 次 SQL | O(1) 次 SQL | 10-50x |
| 嵌入生成吞吐 | ~50 texts/batch | 动态调优 | 2-3x |
| 搜索召回率 | 向量单一 | 混合+重排序 | 20-30% |
| 索引一致性 | 无事务保证 | PendingBatch | 100% |

---

## 三、重构方案

### 3.1 模块划分

```
indexer/
├── embedding/                    # 嵌入模块 (新增)
│   ├── __init__.py
│   ├── interface.py              # EmbeddingClientInterface 抽象
│   ├── openai_client.py          # OpenAI 兼容客户端 (重构)
│   ├── retry.py                  # RetryConfig + 指数退避
│   └── batch_processor.py        # 批量处理 + 动态降级
│
├── vector_store/                 # 向量存储模块 (重构)
│   ├── __init__.py
│   ├── interface.py              # VectorStoreInterface 抽象
│   ├── qdrant_store.py           # Qdrant 实现 (重构)
│   ├── memory_store.py           # 内存存储 (NumPy 加速)
│   └── metadata_store.py         # 元数据存储 (新增)
│
├── chunker/                      # 分块模块 (新增)
│   ├── __init__.py
│   ├── interface.py              # ChunkerInterface 抽象
│   ├── ast_chunker.py            # AST 感知分块
│   ├── smart_splitter.py         # 智能分割器 (参考 ACI)
│   └── models.py                 # CodeChunk, SummaryArtifact
│
├── search/                       # 搜索模块 (新增)
│   ├── __init__.py
│   ├── hybrid_searcher.py        # 混合搜索编排
│   ├── reranker.py               # 重排序器 (重构)
│   └── query_parser.py           # 查询修饰符解析
│
├── embedding_cache.py            # 优化批量查询
├── indexer.py                    # 精简为编排层
└── file_tracker.py               # 增量索引追踪
```

### 3.2 阶段规划

#### Phase 1: 嵌入客户端重构 (P0) ✅ 已完成

**目标**: 提升嵌入生成效率和稳定性

**任务清单**:

1. [x] **创建 `indexer/embedding/interface.py`**
   - 定义 `EmbeddingClientInterface` 抽象基类
   - 定义 `EmbeddingResult` 数据类
   - 支持同步和异步接口

2. [x] **创建 `indexer/embedding/retry.py`**
   - 实现 `RetryConfig` 配置类
   - 实现指数退避 + 抖动
   - 区分可重试/不可重试错误

3. [x] **创建 `indexer/embedding/batch_processor.py`**
   - 实现动态 batch_size 调整
   - Token 限制自动降级 (遇到 413 减半)
   - 批量嵌入进度回调

4. [x] **重构 `indexer/embedding/openai_client.py`**
   - 从 `llm_client/client.py` 分离嵌入逻辑
   - 使用 `httpx.AsyncClient` 连接池
   - 集成 RetryConfig 和 BatchProcessor

5. [x] **优化 `indexer/embedding_cache.py`**
   - `get_batch()` 使用 SQL `IN` 查询
   - `set_batch()` 使用事务批量插入
   - 添加缓存命中率统计

---

#### Phase 2: 向量存储重构 (P0) ✅ 已完成

**目标**: 提升存储效率和检索性能

**任务清单**:

1. [x] **创建 `indexer/vector_store/interface.py`**
   - 定义 `VectorStoreInterface` 抽象基类
   - 定义 `SearchResult`, `UpsertResult` 数据类
   - 支持过滤条件和批量操作

2. [x] **创建 `indexer/vector_store/metadata_store.py`**
   - 实现 `IndexMetadataStore` (参考 ACI)
   - 文件 hash 追踪 (增量索引)
   - PendingBatch 事务机制

3. [x] **创建 `indexer/vector_store/qdrant_store.py`**
   - 添加 Payload 索引 (file_path, artifact_type)
   - 支持 artifact_types 过滤
   - 批量 upsert 优化
   - 异步 API 支持

4. [x] **重构 `indexer/vector_store/memory_store.py`**
   - 使用 NumPy 加速余弦相似度
   - 添加 faiss-cpu 可选支持
   - 支持过滤条件

---

#### Phase 3: 多粒度分块 (P1) ✅ 已完成

**目标**: 实现 AST 感知分块和多粒度索引

**任务清单**:

1. [x] **创建 `indexer/chunker/models.py`**
   - 定义 `CodeChunk` 数据类 (参考 ACI)
   - 定义 `SummaryArtifact` 数据类
   - 定义 `ArtifactType` 枚举

2. [x] **创建 `indexer/chunker/smart_splitter.py`**
   - 实现超大节点智能分割
   - 优先空行/语句边界分割
   - 添加上下文前缀保持语义

3. [x] **创建 `indexer/chunker/ast_chunker.py`**
   - AST 感知分块 (函数/类/方法边界)
   - Token 限制控制 (tiktoken)
   - 生成多粒度 Summary

4. [x] **创建 `indexer/chunker/__init__.py`**
   - 模块导出定义
   - 解决 vector_store 命名冲突

**额外完成**:
- [x] 修复 `vector_store.py` 与 `vector_store/` 包命名冲突
  - 重命名 `vector_store.py` → `vector_store_legacy.py`
  - 更新所有导入路径

---

#### Phase 4: 混合搜索 (P1) ✅ 已完成

**目标**: 实现向量+关键词混合搜索

**任务清单**:

1. [x] **创建 `indexer/search/query_parser.py`**
   - 解析查询修饰符 (`path:*.py`, `-path:tests`)
   - 提取关键词和过滤条件
   - 支持 path/lang/type/severity/keyword/file/symbol 修饰符

2. [x] **创建 `indexer/search/hybrid_searcher.py`**
   - 向量搜索 + grep 并行执行 (支持 ripgrep)
   - 分数归一化和合并
   - 去重 (基于 file_path + line_range)
   - 可配置的搜索权重和限制

3. [x] **重构 `indexer/vector_store.py:CodeReranker`**
   - 提取到 `indexer/search/reranker.py`
   - 添加可选 API 重排序支持 (APIReranker 占位)
   - 优化安全相关性评分
   - 保持 vector_store/interface.py 向后兼容

---

#### Phase 5: 前后端优化 (P2) ✅ 已完成

**目标**: 优化前后端连接性能和用户体验

**任务清单**:

1. [x] **后端优化**
   - `llm_client/client.py`: httpx 连接池 + HTTP/2 支持 (第 260-282 行)
   - `api/agent_router.py`: orjson 序列化集成 (第 22 行)
   - 嵌入请求专用短超时 (15s) + 禁用 HTTP/2 提高网络稳定性

2. [x] **前端优化**
   - `frontend/src/api/index.js`: 自动重试策略 (超时/5xx 错误)
   - `frontend/src/stores/auditStore.js`: WebSocket 消息缓冲 (50ms 批量刷新)
   - `frontend/src/views/UnifiedAudit.vue`: scrollToBottom 使用 requestAnimationFrame

---

#### Phase 6: 服务容器 (P3 - 待实施)

**目标**: 实现依赖注入和模块解耦

**任务清单**:

1. [ ] **创建 `indexer/container.py`**
   - 实现 `IndexerContainer` 依赖注入容器
   - 统一组件初始化和配置
   - 支持组件替换 (测试 Mock)

2. [ ] **重构 `indexer/indexer.py`**
   - 精简为编排层
   - 使用 Container 获取依赖
   - 添加索引进度回调

---

## 四、详细设计

### 4.1 嵌入客户端接口

```python
# indexer/embedding/interface.py

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Callable

@dataclass
class EmbeddingResult:
    embeddings: List[List[float]]
    model: str
    usage: dict  # {"prompt_tokens": int, "total_tokens": int}

class EmbeddingClientInterface(ABC):
    @abstractmethod
    async def embed_batch(
        self,
        texts: List[str],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> EmbeddingResult:
        """批量生成嵌入向量"""
        pass

    @abstractmethod
    async def embed_single(self, text: str) -> List[float]:
        """单个文本嵌入"""
        pass

    @property
    @abstractmethod
    def dimension(self) -> int:
        """嵌入维度"""
        pass
```

### 4.2 向量存储接口

```python
# indexer/vector_store/interface.py

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

@dataclass
class SearchResult:
    chunk_id: str
    file_path: str
    start_line: int
    end_line: int
    content: str
    score: float
    artifact_type: str
    metadata: Dict[str, Any]

class VectorStoreInterface(ABC):
    @abstractmethod
    async def upsert_batch(
        self,
        ids: List[str],
        vectors: List[List[float]],
        payloads: List[Dict[str, Any]]
    ) -> int:
        """批量插入/更新向量"""
        pass

    @abstractmethod
    async def search(
        self,
        query_vector: List[float],
        limit: int = 10,
        file_filter: Optional[str] = None,
        artifact_types: Optional[List[str]] = None
    ) -> List[SearchResult]:
        """向量相似度搜索"""
        pass

    @abstractmethod
    async def delete_by_file(self, file_path: str) -> int:
        """删除指定文件的所有向量"""
        pass
```

### 4.3 批量缓存查询优化

```python
# indexer/embedding_cache.py (优化)

def get_batch(self, content_hashes: List[str]) -> Dict[str, List[float]]:
    """批量获取缓存 - 使用 SQL IN 查询"""
    if not content_hashes:
        return {}

    placeholders = ",".join("?" * len(content_hashes))
    query = f"""
        SELECT content_hash, embedding, accessed_at
        FROM embeddings
        WHERE content_hash IN ({placeholders})
    """

    results = {}
    now = time.time()
    rows = self._conn.execute(query, content_hashes).fetchall()

    for row in rows:
        content_hash, embedding_blob, _ = row
        embedding = self._decompress_embedding(embedding_blob)
        results[content_hash] = embedding

    # 批量更新 accessed_at (LRU)
    if results:
        update_query = f"""
            UPDATE embeddings
            SET accessed_at = ?
            WHERE content_hash IN ({placeholders})
        """
        self._conn.execute(update_query, [now] + list(results.keys()))
        self._conn.commit()

    self._stats["batch_hits"] += len(results)
    self._stats["batch_misses"] += len(content_hashes) - len(results)

    return results
```

### 4.4 动态 Batch 降级

```python
# indexer/embedding/batch_processor.py

class BatchProcessor:
    def __init__(
        self,
        client: EmbeddingClientInterface,
        initial_batch_size: int = 50,
        min_batch_size: int = 5,
        max_batch_size: int = 200
    ):
        self.client = client
        self.current_batch_size = initial_batch_size
        self.min_batch_size = min_batch_size
        self.max_batch_size = max_batch_size

    async def process(
        self,
        texts: List[str],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[List[float]]:
        """处理批量嵌入，支持动态降级"""
        results = []
        i = 0

        while i < len(texts):
            batch = texts[i:i + self.current_batch_size]
            try:
                embeddings = await self._process_batch(batch)
                results.extend(embeddings)
                i += len(batch)

                if progress_callback:
                    progress_callback(i, len(texts))

                # 成功后逐步恢复 batch_size
                self._maybe_increase_batch_size()

            except BatchSizeError:
                # Token 限制，减半 batch_size
                self.current_batch_size = max(
                    self.min_batch_size,
                    self.current_batch_size // 2
                )
                logger.warning(f"Reducing batch size to {self.current_batch_size}")

        return results
```

---

## 五、验收标准

### 5.1 功能验收

| 功能 | 验收条件 |
|------|----------|
| 批量缓存查询 | 100 个 hash 查询 < 10ms |
| 动态 batch 降级 | 遇到 413 自动减半并恢复 |
| 多粒度索引 | 支持 chunk/function/class/file summary |
| 混合搜索 | 向量 + grep 结果合并去重 |
| 事务一致性 | 索引中断后可恢复 |

### 5.2 性能验收

| 指标 | 基线 | 目标 |
|------|------|------|
| 1000 文件索引时间 | - | < 5 分钟 |
| 搜索响应时间 (p99) | - | < 500ms |
| 嵌入缓存命中率 | - | > 80% |

### 5.3 代码质量

- [ ] 所有新模块有单元测试
- [ ] 接口抽象清晰，无循环依赖
- [ ] 配置可通过环境变量覆盖
- [ ] 错误处理完善，有降级策略

---

## 六、风险与缓解

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| 接口变更导致兼容性问题 | 中 | 高 | 保持现有 API 兼容，逐步迁移 |
| 性能回归 | 低 | 高 | 基准测试 + 渐进式发布 |
| 第三方依赖问题 | 低 | 中 | 可选依赖 (faiss-cpu) |

---

## 七、时间估算

| 阶段 | 任务数 | 预计工时 |
|------|--------|----------|
| Phase 1: 嵌入客户端 | 5 | 8h |
| Phase 2: 向量存储 | 4 | 6h |
| Phase 3: 多粒度分块 | 4 | 6h |
| Phase 4: 混合搜索 | 3 | 4h |
| Phase 5: 服务容器 | 2 | 3h |
| **总计** | **18** | **27h** |

---

## 八、参考资料

- 参考项目: `E:\1ceshi\codescan\参考项目\augmented-codebase-indexer`
- 当前实现: `E:\1ceshi\codescan\indexer\`
- ACI 关键文件:
  - `src/aci/infrastructure/embedding/client.py` - 嵌入客户端
  - `src/aci/infrastructure/vector_store/qdrant.py` - 向量存储
  - `src/aci/core/chunker/chunker.py` - 代码分块
  - `src/aci/services/search_service.py` - 搜索服务
