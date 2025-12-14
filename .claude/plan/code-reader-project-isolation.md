# 功能规划：LLM 智能代码读取与项目隔离存储

## 1. 功能目标定义

### 1.1 核心需求

用户希望实现以下功能：

1. **LLM 智能代码读取**：LLM 能够像在代码编辑器中一样，利用向量存储快速读取代码
2. **精确代码定位**：支持根据行号范围读取代码片段
3. **文件级别读取**：支持按文件路径读取整个文件或特定部分
4. **项目隔离存储**：不同扫描项目的向量数据完全隔离，互不影响

### 1.2 功能价值

- **提升分析效率**：LLM 可以快速定位和读取相关代码，减少无关上下文
- **精确上下文构建**：按需获取代码，避免一次性加载过多内容导致 token 浪费
- **多项目支持**：支持同时管理多个扫描项目，各项目数据独立
- **更好的用户体验**：类似 IDE 的代码导航体验

---

## 2. 现有架构分析

### 2.1 当前向量存储结构

```
VectorStoreConfig:
├── provider: "qdrant"
├── host / port
├── collection_name: "code_audit"  # 单一集合名
├── api_key
└── cache_dir: ".audit_cache"
```

**问题**：当前使用固定的 `collection_name`，所有项目共享同一集合，无法隔离。

### 2.2 当前代码读取能力

```python
# indexer.py 现有方法
- search(query, top_k, language, file_pattern)  # 向量搜索
- get_unit(unit_id)                              # 按 ID 获取
- get_units_by_file(file_path)                   # 按文件获取（全量遍历，效率低）
- get_units_by_language(language)                # 按语言获取
```

**问题**：
1. 缺少按行号精确读取的能力
2. `get_units_by_file` 实现是全量遍历后过滤，效率低
3. 缺少原始文件读取能力（只能读取已索引的代码片段）

### 2.3 CodeUnit 数据模型

```python
CodeUnit:
├── id, language, file_path
├── symbol, unit_type, signature
├── span: CodeSpan(start_line, end_line, start_col, end_col)
├── code: str  # 代码片段
├── calls, called_by
└── metadata
```

**优势**：已有 `span` 字段记录行号信息，可以利用。

---

## 3. 技术方案设计

### 3.1 项目隔离方案

#### 方案 A：动态集合名（推荐）

```python
# 基于项目路径生成唯一集合名
def generate_collection_name(project_path: str) -> str:
    import hashlib
    # 使用路径 hash 生成唯一标识
    path_hash = hashlib.md5(project_path.encode()).hexdigest()[:8]
    project_name = Path(project_path).name
    # 格式: code_audit_{项目名}_{hash}
    return f"code_audit_{project_name}_{path_hash}"
```

**优点**：
- 简单直接，每个项目自动获得独立集合
- 支持同一项目不同路径的区分
- 集合名可读性好

**缺点**：
- 需要维护项目-集合映射关系

#### 方案 B：元数据隔离

在同一集合中使用 `project_id` 字段过滤：

```python
# 添加项目 ID 到每个向量
payload = {
    "project_id": "project_xxx",
    ...
}
# 查询时过滤
filters = {"project_id": current_project_id}
```

**优点**：
- 单一集合，管理简单

**缺点**：
- 数据量大时性能下降
- 删除项目数据麻烦

#### 推荐方案：方案 A（动态集合名）

### 3.2 代码读取服务设计

新建 `code_reader.py` 模块，提供以下能力：

```python
class CodeReader:
    """代码读取服务 - 为 LLM 提供代码访问能力"""

    def __init__(self, project_path: str, indexer: CodeIndexer):
        self.project_path = Path(project_path)
        self.indexer = indexer

    # 1. 向量搜索读取（语义搜索）
    def search_code(
        self,
        query: str,
        top_k: int = 10,
        language: Optional[str] = None,
        file_pattern: Optional[str] = None,
    ) -> List[CodeSnippet]:
        """通过语义搜索获取相关代码"""
        pass

    # 2. 精确行号读取
    def read_lines(
        self,
        file_path: str,
        start_line: int,
        end_line: int,
        context_lines: int = 0,  # 上下文行数
    ) -> CodeSnippet:
        """读取指定文件的指定行范围"""
        pass

    # 3. 文件读取
    def read_file(
        self,
        file_path: str,
        max_lines: Optional[int] = None,
    ) -> FileContent:
        """读取整个文件内容"""
        pass

    # 4. 符号定位读取
    def read_symbol(
        self,
        symbol_name: str,
        file_path: Optional[str] = None,
    ) -> List[CodeSnippet]:
        """读取指定符号（函数/类/方法）的代码"""
        pass

    # 5. 调用链读取
    def read_call_chain(
        self,
        symbol_name: str,
        direction: str = "both",  # "callers", "callees", "both"
        depth: int = 2,
    ) -> CallChainResult:
        """读取符号的调用链相关代码"""
        pass
```

### 3.3 数据结构设计

```python
@dataclass
class CodeSnippet:
    """代码片段"""
    file_path: str
    start_line: int
    end_line: int
    code: str
    language: str
    symbol: Optional[str] = None  # 所属符号
    context: Optional[str] = None  # 上下文说明

@dataclass
class FileContent:
    """文件内容"""
    file_path: str
    content: str
    total_lines: int
    language: str
    truncated: bool = False

@dataclass
class CallChainResult:
    """调用链结果"""
    target_symbol: str
    callers: List[CodeSnippet]
    callees: List[CodeSnippet]
```

### 3.4 项目管理器设计

```python
class ProjectManager:
    """项目管理器 - 管理多个扫描项目"""

    def __init__(self, base_config: AuditConfig):
        self.base_config = base_config
        self.projects: Dict[str, Project] = {}

    def create_project(
        self,
        project_path: str,
        project_name: Optional[str] = None,
    ) -> Project:
        """创建新项目"""
        pass

    def get_project(self, project_id: str) -> Optional[Project]:
        """获取项目"""
        pass

    def delete_project(self, project_id: str) -> bool:
        """删除项目（包括向量数据）"""
        pass

    def list_projects(self) -> List[ProjectInfo]:
        """列出所有项目"""
        pass

@dataclass
class Project:
    """项目实例"""
    id: str
    name: str
    path: str
    collection_name: str
    created_at: datetime
    last_indexed_at: Optional[datetime]

    indexer: CodeIndexer
    code_reader: CodeReader
```

### 3.5 配置扩展

```python
@dataclass
class VectorStoreConfig:
    # 现有字段...

    # 新增：项目隔离配置
    enable_project_isolation: bool = True
    collection_prefix: str = "code_audit"

    # 新增：项目元数据存储
    projects_metadata_file: str = ".audit_projects.json"
```

---

## 4. 模块分解与接口设计

### 4.1 新增模块结构

```
codescan/
├── indexer/
│   ├── code_reader.py      # 新增：代码读取服务
│   └── ...
├── project/                 # 新增：项目管理模块
│   ├── __init__.py
│   ├── manager.py          # 项目管理器
│   ├── models.py           # 项目数据模型
│   └── storage.py          # 项目元数据存储
└── config/
    └── settings.py         # 扩展配置
```

### 4.2 核心接口定义

#### CodeReader 接口

```python
class CodeReaderInterface(ABC):
    """代码读取接口"""

    @abstractmethod
    def search_code(self, query: str, **kwargs) -> List[CodeSnippet]:
        """语义搜索代码"""
        pass

    @abstractmethod
    def read_lines(self, file_path: str, start: int, end: int) -> CodeSnippet:
        """按行号读取"""
        pass

    @abstractmethod
    def read_file(self, file_path: str) -> FileContent:
        """读取文件"""
        pass

    @abstractmethod
    def read_symbol(self, symbol: str) -> List[CodeSnippet]:
        """读取符号"""
        pass
```

#### ProjectManager 接口

```python
class ProjectManagerInterface(ABC):
    """项目管理接口"""

    @abstractmethod
    def create_project(self, path: str, name: str = None) -> Project:
        pass

    @abstractmethod
    def get_project(self, project_id: str) -> Optional[Project]:
        pass

    @abstractmethod
    def delete_project(self, project_id: str) -> bool:
        pass

    @abstractmethod
    def list_projects(self) -> List[ProjectInfo]:
        pass
```

### 4.3 向量存储扩展

```python
class BaseVectorStore(ABC):
    # 现有方法...

    # 新增：按文件路径精确查询（利用索引）
    @abstractmethod
    def get_by_file_path(self, file_path: str) -> List[CodeUnit]:
        """按文件路径获取所有代码单元（使用索引）"""
        pass

    # 新增：按行号范围查询
    @abstractmethod
    def get_by_line_range(
        self,
        file_path: str,
        start_line: int,
        end_line: int,
    ) -> List[CodeUnit]:
        """获取指定行范围内的代码单元"""
        pass
```

---

## 5. 实施步骤与优先级

### 阶段一：项目隔离（优先级：高）

**目标**：实现不同项目的向量数据隔离

| 步骤 | 任务 | 文件 |
|------|------|------|
| 1.1 | 扩展 VectorStoreConfig，添加项目隔离配置 | `config/settings.py` |
| 1.2 | 实现动态集合名生成 | `indexer/vector_store.py` |
| 1.3 | 创建项目管理模块 | `project/` 目录 |
| 1.4 | 实现项目元数据持久化 | `project/storage.py` |
| 1.5 | 更新 CodeIndexer 支持项目隔离 | `indexer/indexer.py` |

### 阶段二：代码读取服务（优先级：高）

**目标**：为 LLM 提供灵活的代码读取能力

| 步骤 | 任务 | 文件 |
|------|------|------|
| 2.1 | 定义代码读取数据模型 | `indexer/models.py` |
| 2.2 | 实现 CodeReader 基础类 | `indexer/code_reader.py` |
| 2.3 | 实现语义搜索读取 | `indexer/code_reader.py` |
| 2.4 | 实现行号精确读取 | `indexer/code_reader.py` |
| 2.5 | 实现文件读取 | `indexer/code_reader.py` |
| 2.6 | 实现符号读取 | `indexer/code_reader.py` |

### 阶段三：向量存储优化（优先级：中）

**目标**：优化查询性能

| 步骤 | 任务 | 文件 |
|------|------|------|
| 3.1 | 为 file_path 添加 Qdrant 索引 | `indexer/vector_store.py` |
| 3.2 | 实现 get_by_file_path 方法 | `indexer/vector_store.py` |
| 3.3 | 实现 get_by_line_range 方法 | `indexer/vector_store.py` |
| 3.4 | 优化 InMemoryVectorStore | `indexer/vector_store.py` |

### 阶段四：集成与测试（优先级：中）

**目标**：集成到分析引擎，完善测试

| 步骤 | 任务 | 文件 |
|------|------|------|
| 4.1 | 更新 SecurityAnalyzer 使用 CodeReader | `analyzer/engine.py` |
| 4.2 | 更新 CLI 支持项目管理命令 | `cli/` |
| 4.3 | 添加单元测试 | `tests/` |
| 4.4 | 更新文档 | `README.md` |

---

## 6. 验收标准

### 6.1 项目隔离

- [ ] 创建项目时自动生成独立的向量集合
- [ ] 不同项目的索引数据完全隔离
- [ ] 支持删除项目并清理其向量数据
- [ ] 支持列出所有项目及其状态

### 6.2 代码读取

- [ ] `search_code()`: 语义搜索返回相关代码片段
- [ ] `read_lines()`: 精确读取指定文件的指定行范围
- [ ] `read_file()`: 读取整个文件，支持行数限制
- [ ] `read_symbol()`: 按符号名查找并读取代码
- [ ] 所有读取方法返回结构化的 CodeSnippet

### 6.3 性能要求

- [ ] 按文件路径查询：< 100ms（已索引文件）
- [ ] 语义搜索：< 500ms（top_k=10）
- [ ] 项目切换：< 200ms

### 6.4 兼容性

- [ ] 向后兼容现有配置
- [ ] 支持从旧版本迁移

---

## 7. 风险与注意事项

### 7.1 技术风险

1. **Qdrant 集合数量限制**：大量项目可能导致集合过多
   - 缓解：定期清理长期未使用的项目

2. **原始文件变更**：索引后文件被修改，行号不匹配
   - 缓解：read_lines 时检查文件修改时间，提示可能不一致

3. **大文件处理**：超大文件读取可能 OOM
   - 缓解：强制行数限制，分页读取

### 7.2 安全考虑

1. **路径遍历**：`read_file` 需要验证路径在项目范围内
2. **敏感文件**：避免读取 `.env`、密钥文件等

---

## 8. 后续扩展

- 支持代码差异对比（Git diff 集成）
- 支持代码引用跳转
- 支持多文件关联阅读
- 前端可视化代码导航
