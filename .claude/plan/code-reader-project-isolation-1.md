# 功能规划：LLM 函数调用实现智能代码读取与项目隔离

## 1. 核心架构：LLM Function Calling

### 1.1 设计理念

利用 **OpenAI Function Calling（Tool Use）** 机制，让 LLM 能够主动调用代码读取工具：

```
用户问题 → LLM 分析 → 调用 Tool (read_code/search_code) → 获取代码 → LLM 继续分析 → 最终结果
```

**核心优势**：
- LLM 自主决定何时需要读取代码
- 支持多轮工具调用，逐步深入分析
- 类似 IDE 的"跳转到定义"体验
- 减少无关代码的上下文污染

### 1.2 工具定义（Tools Schema）

```python
CODE_READER_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "通过语义搜索查找相关代码。用于查找与某个概念、功能或漏洞模式相关的代码片段。",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "搜索查询，描述要查找的代码功能或模式"
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "返回结果数量，默认 5",
                        "default": 5
                    },
                    "language": {
                        "type": "string",
                        "description": "限定编程语言 (python/javascript/php 等)"
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "文件路径模式，如 '**/auth/*.py'"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "读取指定文件的内容。可以读取整个文件或指定行范围。",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "文件路径（相对于项目根目录）"
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "起始行号（从 1 开始），不指定则从头开始"
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "结束行号，不指定则读取到文件末尾"
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "额外读取的上下文行数",
                        "default": 0
                    }
                },
                "required": ["file_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_symbol",
            "description": "读取指定符号（函数、类、方法）的完整定义代码。",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "符号名称，如函数名、类名、方法名"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定在特定文件中查找"
                    },
                    "include_callers": {
                        "type": "boolean",
                        "description": "是否包含调用此符号的代码",
                        "default": False
                    },
                    "include_callees": {
                        "type": "boolean",
                        "description": "是否包含此符号调用的其他函数",
                        "default": False
                    }
                },
                "required": ["symbol_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "列出项目中的文件，支持按模式过滤。",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "文件匹配模式，如 '**/*.py' 或 'src/auth/*'",
                        "default": "**/*"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "最大返回数量",
                        "default": 50
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_file_outline",
            "description": "获取文件的结构大纲（类、函数、方法列表）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "文件路径"
                    }
                },
                "required": ["file_path"]
            }
        }
    }
]
```

---

## 2. 系统架构设计

### 2.1 整体流程

```
┌─────────────────────────────────────────────────────────────────┐
│                        用户请求                                   │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    LLM Agent 控制器                              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  1. 接收用户请求                                          │   │
│  │  2. 发送给 LLM (带 Tools 定义)                            │   │
│  │  3. 如果 LLM 返回 tool_calls → 执行工具 → 返回结果给 LLM   │   │
│  │  4. 循环直到 LLM 返回最终答案                              │   │
│  └─────────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Tool 执行层                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ search_code  │  │  read_file   │  │ read_symbol  │   ...    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
└─────────┼─────────────────┼─────────────────┼───────────────────┘
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CodeReader 服务                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  - 向量搜索 (通过 Indexer)                                │   │
│  │  - 原始文件读取                                           │   │
│  │  - 符号定位                                               │   │
│  └─────────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│              项目隔离的向量存储 (Qdrant)                          │
│  ┌──────────────────┐  ┌──────────────────┐                    │
│  │ project_A_xxx    │  │ project_B_yyy    │    ...             │
│  │ (Collection)     │  │ (Collection)     │                    │
│  └──────────────────┘  └──────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 LLM Client 扩展

需要扩展现有 `llm_client/client.py` 支持 Function Calling：

```python
@dataclass
class ToolCall:
    """工具调用"""
    id: str
    name: str
    arguments: Dict[str, Any]

@dataclass
class ChatResponse:
    content: Optional[str]
    model: str
    usage: Dict[str, int]
    finish_reason: str
    tool_calls: Optional[List[ToolCall]] = None  # 新增
    raw_response: Dict[str, Any] = None

class OpenAICompatibleClient:
    def chat_completion(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[Dict]] = None,      # 新增
        tool_choice: Optional[str] = None,        # 新增: "auto", "none", "required"
        **kwargs
    ) -> ChatResponse:
        """支持 Function Calling 的聊天请求"""
        pass
```

### 2.3 Agent 控制器

```python
class CodeAnalysisAgent:
    """代码分析 Agent - 使用 Function Calling 实现智能代码读取"""

    def __init__(
        self,
        llm_client: BaseLLMClient,
        code_reader: CodeReader,
        project: Project,
        max_tool_calls: int = 10,
    ):
        self.llm_client = llm_client
        self.code_reader = code_reader
        self.project = project
        self.max_tool_calls = max_tool_calls
        self.tools = CODE_READER_TOOLS

    def analyze(
        self,
        task: str,
        system_prompt: Optional[str] = None,
    ) -> AgentResult:
        """执行分析任务

        Args:
            task: 分析任务描述
            system_prompt: 系统提示词

        Returns:
            AgentResult 包含分析结果和工具调用历史
        """
        messages = []

        if system_prompt:
            messages.append(ChatMessage(role="system", content=system_prompt))

        messages.append(ChatMessage(role="user", content=task))

        tool_call_count = 0

        while tool_call_count < self.max_tool_calls:
            # 调用 LLM
            response = self.llm_client.chat_completion(
                messages=messages,
                tools=self.tools,
                tool_choice="auto",
            )

            # 检查是否有工具调用
            if response.tool_calls:
                # 添加 assistant 消息
                messages.append(ChatMessage(
                    role="assistant",
                    content=response.content,
                    tool_calls=response.tool_calls,
                ))

                # 执行每个工具调用
                for tool_call in response.tool_calls:
                    result = self._execute_tool(tool_call)

                    # 添加工具结果消息
                    messages.append(ChatMessage(
                        role="tool",
                        tool_call_id=tool_call.id,
                        content=json.dumps(result, ensure_ascii=False),
                    ))

                    tool_call_count += 1

            else:
                # LLM 返回最终答案
                return AgentResult(
                    content=response.content,
                    tool_calls_history=self._extract_tool_history(messages),
                    total_tool_calls=tool_call_count,
                )

        # 达到最大工具调用次数
        return AgentResult(
            content=response.content,
            tool_calls_history=self._extract_tool_history(messages),
            total_tool_calls=tool_call_count,
            truncated=True,
        )

    def _execute_tool(self, tool_call: ToolCall) -> Dict[str, Any]:
        """执行工具调用"""
        name = tool_call.name
        args = tool_call.arguments

        if name == "search_code":
            return self.code_reader.search_code(**args)
        elif name == "read_file":
            return self.code_reader.read_file(**args)
        elif name == "read_symbol":
            return self.code_reader.read_symbol(**args)
        elif name == "list_files":
            return self.code_reader.list_files(**args)
        elif name == "get_file_outline":
            return self.code_reader.get_file_outline(**args)
        else:
            return {"error": f"Unknown tool: {name}"}
```

---

## 3. 项目隔离存储方案

### 3.1 动态集合名生成

```python
def generate_project_id(project_path: str) -> str:
    """生成项目唯一 ID"""
    import hashlib
    abs_path = str(Path(project_path).resolve())
    return hashlib.md5(abs_path.encode()).hexdigest()[:12]

def generate_collection_name(project_path: str, prefix: str = "code_audit") -> str:
    """生成项目专属集合名"""
    project_id = generate_project_id(project_path)
    project_name = Path(project_path).name
    # 清理项目名（只保留字母数字）
    safe_name = re.sub(r'[^a-zA-Z0-9]', '_', project_name)[:20]
    return f"{prefix}_{safe_name}_{project_id}"
```

### 3.2 项目管理器

```python
@dataclass
class ProjectInfo:
    """项目信息"""
    id: str
    name: str
    path: str
    collection_name: str
    created_at: str
    last_indexed_at: Optional[str]
    total_units: int

class ProjectManager:
    """项目管理器"""

    def __init__(self, config: AuditConfig):
        self.config = config
        self.projects_file = Path(config.vector_store.cache_dir) / "projects.json"
        self._projects: Dict[str, ProjectInfo] = {}
        self._load_projects()

    def create_project(self, project_path: str, name: Optional[str] = None) -> ProjectInfo:
        """创建新项目"""
        abs_path = str(Path(project_path).resolve())
        project_id = generate_project_id(abs_path)

        if project_id in self._projects:
            return self._projects[project_id]

        collection_name = generate_collection_name(abs_path)

        project = ProjectInfo(
            id=project_id,
            name=name or Path(abs_path).name,
            path=abs_path,
            collection_name=collection_name,
            created_at=datetime.now().isoformat(),
            last_indexed_at=None,
            total_units=0,
        )

        self._projects[project_id] = project
        self._save_projects()

        return project

    def get_project(self, project_id: str) -> Optional[ProjectInfo]:
        """获取项目"""
        return self._projects.get(project_id)

    def get_project_by_path(self, project_path: str) -> Optional[ProjectInfo]:
        """根据路径获取项目"""
        project_id = generate_project_id(project_path)
        return self._projects.get(project_id)

    def delete_project(self, project_id: str, delete_vectors: bool = True) -> bool:
        """删除项目"""
        if project_id not in self._projects:
            return False

        project = self._projects[project_id]

        # 删除向量数据
        if delete_vectors:
            vector_store = self._create_vector_store(project.collection_name)
            vector_store.clear()

        del self._projects[project_id]
        self._save_projects()
        return True

    def list_projects(self) -> List[ProjectInfo]:
        """列出所有项目"""
        return list(self._projects.values())
```

---

## 4. CodeReader 实现

```python
class CodeReader:
    """代码读取服务 - 为 LLM Tools 提供代码访问能力"""

    def __init__(
        self,
        project_path: str,
        indexer: CodeIndexer,
    ):
        self.project_path = Path(project_path).resolve()
        self.indexer = indexer

    def search_code(
        self,
        query: str,
        top_k: int = 5,
        language: Optional[str] = None,
        file_pattern: Optional[str] = None,
    ) -> Dict[str, Any]:
        """语义搜索代码"""
        results = self.indexer.search(
            query=query,
            top_k=top_k,
            language=language,
            file_pattern=file_pattern,
        )

        return {
            "results": [
                {
                    "file_path": unit.file_path,
                    "symbol": unit.symbol,
                    "type": unit.unit_type.value,
                    "start_line": unit.span.start_line,
                    "end_line": unit.span.end_line,
                    "code": unit.code,
                    "signature": unit.signature,
                }
                for unit in results
            ],
            "total": len(results),
        }

    def read_file(
        self,
        file_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
        context_lines: int = 0,
    ) -> Dict[str, Any]:
        """读取文件内容"""
        # 安全检查：确保路径在项目范围内
        full_path = self.project_path / file_path
        try:
            full_path = full_path.resolve()
            if not str(full_path).startswith(str(self.project_path)):
                return {"error": "路径超出项目范围"}
        except Exception:
            return {"error": "无效路径"}

        if not full_path.exists():
            return {"error": f"文件不存在: {file_path}"}

        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")
            total_lines = len(lines)

            # 处理行号范围
            if start_line is not None:
                start_idx = max(0, start_line - 1 - context_lines)
            else:
                start_idx = 0

            if end_line is not None:
                end_idx = min(total_lines, end_line + context_lines)
            else:
                end_idx = total_lines

            selected_lines = lines[start_idx:end_idx]

            # 添加行号
            numbered_lines = [
                f"{i + start_idx + 1:4d} | {line}"
                for i, line in enumerate(selected_lines)
            ]

            return {
                "file_path": file_path,
                "content": "\n".join(numbered_lines),
                "start_line": start_idx + 1,
                "end_line": end_idx,
                "total_lines": total_lines,
                "language": self._detect_language(file_path),
            }
        except Exception as e:
            return {"error": f"读取文件失败: {str(e)}"}

    def read_symbol(
        self,
        symbol_name: str,
        file_path: Optional[str] = None,
        include_callers: bool = False,
        include_callees: bool = False,
    ) -> Dict[str, Any]:
        """读取符号定义"""
        # 从向量库搜索符号
        results = self.indexer.search(
            query=symbol_name,
            top_k=10,
        )

        # 精确匹配符号名
        matched = [
            unit for unit in results
            if unit.symbol == symbol_name or unit.symbol.endswith(f".{symbol_name}")
        ]

        if file_path:
            matched = [u for u in matched if file_path in u.file_path]

        if not matched:
            return {"error": f"未找到符号: {symbol_name}"}

        result = {
            "symbol": symbol_name,
            "definitions": [
                {
                    "file_path": unit.file_path,
                    "type": unit.unit_type.value,
                    "start_line": unit.span.start_line,
                    "end_line": unit.span.end_line,
                    "code": unit.code,
                    "signature": unit.signature,
                    "parent_class": unit.parent_class,
                }
                for unit in matched[:3]
            ],
        }

        # 获取调用者
        if include_callers and matched:
            callers = self._find_callers(matched[0])
            result["callers"] = callers[:5]

        # 获取被调用者
        if include_callees and matched:
            result["callees"] = matched[0].calls[:10]

        return result

    def list_files(
        self,
        pattern: str = "**/*",
        max_results: int = 50,
    ) -> Dict[str, Any]:
        """列出项目文件"""
        import fnmatch

        files = []
        for path in self.project_path.rglob("*"):
            if path.is_file():
                rel_path = str(path.relative_to(self.project_path))
                if fnmatch.fnmatch(rel_path, pattern):
                    files.append(rel_path)
                    if len(files) >= max_results:
                        break

        return {
            "files": files,
            "total": len(files),
            "truncated": len(files) >= max_results,
        }

    def get_file_outline(self, file_path: str) -> Dict[str, Any]:
        """获取文件结构大纲"""
        units = self.indexer.get_units_by_file(file_path)

        outline = []
        for unit in units:
            outline.append({
                "symbol": unit.symbol,
                "type": unit.unit_type.value,
                "start_line": unit.span.start_line,
                "end_line": unit.span.end_line,
                "signature": unit.signature,
                "parent": unit.parent_class,
            })

        # 按行号排序
        outline.sort(key=lambda x: x["start_line"])

        return {
            "file_path": file_path,
            "outline": outline,
            "total_symbols": len(outline),
        }

    def _detect_language(self, file_path: str) -> str:
        """检测文件语言"""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".php": "php",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
        }
        suffix = Path(file_path).suffix.lower()
        return ext_map.get(suffix, "unknown")

    def _find_callers(self, unit: CodeUnit) -> List[Dict]:
        """查找调用者"""
        # 搜索调用此符号的代码
        results = self.indexer.search(
            query=f"calls {unit.symbol}",
            top_k=10,
        )

        callers = []
        for r in results:
            if unit.symbol in r.calls or unit.symbol in r.code:
                callers.append({
                    "file_path": r.file_path,
                    "symbol": r.symbol,
                    "line": r.span.start_line,
                })

        return callers
```

---

## 5. 实施步骤（更新）

### 阶段一：LLM Client 扩展（优先级：最高）

| 步骤 | 任务 | 文件 |
|------|------|------|
| 1.1 | 扩展 ChatMessage 支持 tool_calls | `llm_client/models.py` |
| 1.2 | 扩展 ChatResponse 支持 tool_calls | `llm_client/models.py` |
| 1.3 | 修改 chat_completion 支持 tools 参数 | `llm_client/client.py` |
| 1.4 | 处理 tool_calls 响应解析 | `llm_client/client.py` |
| 1.5 | 添加单元测试 | `tests/test_llm_client.py` |

### 阶段二：项目隔离（优先级：高）

| 步骤 | 任务 | 文件 |
|------|------|------|
| 2.1 | 创建 project 模块 | `project/__init__.py` |
| 2.2 | 实现 ProjectManager | `project/manager.py` |
| 2.3 | 实现项目持久化存储 | `project/storage.py` |
| 2.4 | 更新向量存储支持动态集合名 | `indexer/vector_store.py` |
| 2.5 | 更新 CodeIndexer | `indexer/indexer.py` |

### 阶段三：CodeReader 服务（优先级：高）

| 步骤 | 任务 | 文件 |
|------|------|------|
| 3.1 | 定义 Tools Schema | `agent/tools.py` |
| 3.2 | 实现 CodeReader | `indexer/code_reader.py` |
| 3.3 | 实现 search_code | `indexer/code_reader.py` |
| 3.4 | 实现 read_file | `indexer/code_reader.py` |
| 3.5 | 实现 read_symbol | `indexer/code_reader.py` |
| 3.6 | 实现 list_files 和 get_file_outline | `indexer/code_reader.py` |

### 阶段四：Agent 控制器（优先级：高）

| 步骤 | 任务 | 文件 |
|------|------|------|
| 4.1 | 创建 agent 模块 | `agent/__init__.py` |
| 4.2 | 实现 CodeAnalysisAgent | `agent/code_agent.py` |
| 4.3 | 实现工具调用循环 | `agent/code_agent.py` |
| 4.4 | 集成到 SecurityAnalyzer | `analyzer/engine.py` |

### 阶段五：测试与集成（优先级：中）

| 步骤 | 任务 | 文件 |
|------|------|------|
| 5.1 | 添加 Agent 测试 | `tests/test_agent.py` |
| 5.2 | 添加 CodeReader 测试 | `tests/test_code_reader.py` |
| 5.3 | 更新 CLI | `cli/` |
| 5.4 | 更新文档 | `README.md` |

---

## 6. 新增模块结构

```
codescan/
├── llm_client/
│   ├── client.py           # 扩展支持 tools
│   └── models.py           # 新增 ToolCall 等模型
├── agent/                   # 新增
│   ├── __init__.py
│   ├── tools.py            # Tools Schema 定义
│   └── code_agent.py       # Agent 控制器
├── indexer/
│   ├── code_reader.py      # 新增：代码读取服务
│   └── ...
├── project/                 # 新增
│   ├── __init__.py
│   ├── manager.py
│   └── storage.py
└── analyzer/
    └── engine.py           # 集成 Agent
```

---

## 7. 验收标准（更新）

### 7.1 Function Calling

- [ ] LLM Client 支持 tools 参数
- [ ] 正确解析 tool_calls 响应
- [ ] 支持多轮工具调用

### 7.2 Tools 实现

- [ ] `search_code`: 语义搜索返回相关代码
- [ ] `read_file`: 精确读取文件/行范围
- [ ] `read_symbol`: 按符号名读取定义
- [ ] `list_files`: 列出项目文件
- [ ] `get_file_outline`: 获取文件大纲

### 7.3 Agent 控制器

- [ ] 自动执行工具调用循环
- [ ] 最大调用次数限制
- [ ] 返回完整调用历史

### 7.4 项目隔离

- [ ] 每个项目独立集合
- [ ] 支持项目 CRUD
- [ ] 项目数据持久化

---

## 8. 使用示例

```python
# 创建项目
project_manager = ProjectManager(config)
project = project_manager.create_project("/path/to/my-app")

# 创建索引器（使用项目专属集合）
indexer = CodeIndexer(
    config=config,
    llm_client=llm_client,
    collection_name=project.collection_name,
)
indexer.index_directory(project.path)

# 创建代码读取器
code_reader = CodeReader(project.path, indexer)

# 创建 Agent
agent = CodeAnalysisAgent(
    llm_client=llm_client,
    code_reader=code_reader,
    project=project,
)

# 执行分析
result = agent.analyze(
    task="分析 login 函数是否存在认证绕过漏洞",
    system_prompt=SECURITY_ANALYSIS_PROMPT,
)

print(result.content)
print(f"工具调用次数: {result.total_tool_calls}")
```

---

## 9. 下一步

请确认此方案是否符合预期，确认后我将开始实施：

1. 先实现 LLM Client 的 Function Calling 支持
2. 然后实现 CodeReader 和 Tools
3. 最后实现 Agent 控制器和项目隔离
