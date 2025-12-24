"""
统一审计智能体 - 整合所有代码分析工具

核心特性：
1. 支持 LLM Function Calling 自主调用工具
2. 整合代码导航、调用链分析、变体分析等所有功能
3. 提供统一的对话式审计接口
4. 支持流式响应和工具执行可视化
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any, Callable, Union

from llm_client import BaseLLMClient, ChatMessage, ToolCall
from indexer import CodeUnit, CodeIndexer

from .tools.manager import AgentToolManager, ToolResult
from .tools.registry import CODE_NAVIGATION_TOOLS, SECURITY_ANALYSIS_TOOLS
from .tools.callchain_tools import (
    get_callchain_tool_definitions,
    create_callchain_executor,
)
from .tools.variant_tools import (
    get_variant_tool_definitions,
    create_variant_executor,
)

logger = logging.getLogger(__name__)


class ToolCallStatus(Enum):
    """工具调用状态"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


@dataclass
class ToolCallEvent:
    """工具调用事件（用于 UI 展示）"""
    id: str
    tool_name: str
    arguments: Dict[str, Any]
    status: ToolCallStatus
    result: Optional[Any] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_ms": self.duration_ms,
        }


@dataclass
class AgentMessage:
    """智能体消息"""
    role: str  # "user", "assistant", "tool"
    content: str
    tool_calls: List[ToolCallEvent] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "tool_calls": [tc.to_dict() for tc in self.tool_calls],
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class UnifiedAgentConfig:
    """统一智能体配置"""
    # LLM 配置
    max_tool_calls_per_turn: int = 10  # 每轮最大工具调用次数
    max_conversation_turns: int = 50  # 最大对话轮数
    temperature: float = 0.1
    max_tokens: int = 4000

    # 工具配置
    enable_code_navigation: bool = True
    enable_call_chain: bool = True
    enable_variant_analysis: bool = True
    enable_security_tools: bool = True

    # 上下文配置
    max_context_tokens: int = 100000  # 最大上下文 token 数
    context_window_messages: int = 20  # 保留的最近消息数

    # 回调
    on_tool_call: Optional[Callable[[ToolCallEvent], None]] = None
    on_stream: Optional[Callable[[str], None]] = None


class UnifiedAuditAgent:
    """统一审计智能体

    整合所有代码分析工具，提供统一的对话式审计接口。
    支持 LLM Function Calling 自主选择和调用工具。

    核心能力：
    1. 代码导航：搜索、读取、浏览代码
    2. 调用链分析：追踪调用关系、污点传播
    3. 变体分析：相似代码检测、模式匹配
    4. 安全分析：漏洞检测、规则匹配

    Usage:
        agent = UnifiedAuditAgent(
            session_id="xxx",
            llm_client=llm_client,
            indexer=indexer,
            config=UnifiedAgentConfig(),
        )

        # 初始化工具
        await agent.initialize()

        # 对话交互
        response = await agent.chat("分析这个项目的认证逻辑")

        # 处理流式响应和工具调用事件
    """

    def __init__(
        self,
        session_id: str,
        llm_client: BaseLLMClient,
        indexer: CodeIndexer,
        config: Optional[UnifiedAgentConfig] = None,
        # 可选的分析器实例
        call_chain_analyzer=None,
        variant_analyzer=None,
        vector_store=None,
    ):
        """初始化统一审计智能体

        Args:
            session_id: 会话 ID
            llm_client: LLM 客户端
            indexer: 代码索引器
            config: 配置
            call_chain_analyzer: 调用链分析器（可选）
            variant_analyzer: 变体分析器（可选）
            vector_store: 向量存储（可选）
        """
        self.session_id = session_id
        self.llm_client = llm_client
        self.indexer = indexer
        self.config = config or UnifiedAgentConfig()

        # 分析器
        self.call_chain_analyzer = call_chain_analyzer
        self.variant_analyzer = variant_analyzer
        self.vector_store = vector_store

        # 工具管理器
        self.tool_manager = AgentToolManager()

        # 对话历史
        self.messages: List[AgentMessage] = []
        self.conversation_history: List[ChatMessage] = []

        # 工具调用历史
        self.tool_call_history: List[ToolCallEvent] = []

        # 状态
        self._initialized = False
        self._is_processing = False

        # 统计
        self.total_llm_calls = 0
        self.total_tool_calls = 0
        self.total_tokens_used = 0

        logger.info(f"[UnifiedAgent] 创建会话: {session_id}")

    async def initialize(self):
        """初始化智能体

        注册所有工具并设置执行器。
        """
        if self._initialized:
            return

        logger.info("[UnifiedAgent] 开始初始化...")

        # 获取代码单元 - 使用正确的方法从 indexer 获取
        try:
            all_units = self.indexer.get_all_units()
            code_units = all_units if all_units else []
        except Exception as e:
            logger.warning(f"[UnifiedAgent] 获取代码单元失败: {e}, 使用空列表")
            code_units = []

        # 缓存代码单元用于后续查询
        self._code_units_cache: Dict[str, CodeUnit] = {u.id: u for u in code_units}

        # 注册代码导航工具
        if self.config.enable_code_navigation:
            self._register_code_navigation_tools()

        # 注册调用链分析工具
        if self.config.enable_call_chain and self.call_chain_analyzer:
            self._register_call_chain_tools(code_units)

        # 注册变体分析工具
        if self.config.enable_variant_analysis:
            self._register_variant_tools(code_units)

        # 注册安全分析工具
        if self.config.enable_security_tools:
            self._register_security_tools()

        self._initialized = True

        logger.info(
            f"[UnifiedAgent] 初始化完成，注册了 {self.tool_manager.count()} 个工具"
        )

    def _register_code_navigation_tools(self):
        """注册代码导航工具"""
        # search_code
        self.tool_manager.register_tool(
            name="search_code",
            description="通过语义搜索查找相关代码。适用于：查找与某个概念、功能或漏洞模式相关的代码片段。",
            parameters={
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
                        "description": "限定编程语言"
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "文件路径模式"
                    }
                },
                "required": ["query"]
            },
            executor=self._execute_search_code,
            category="code_navigation",
        )

        # read_file
        self.tool_manager.register_tool(
            name="read_file",
            description="读取指定文件的内容。可以读取整个文件或指定行范围。",
            parameters={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "文件路径（相对于项目根目录）"
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "起始行号（从 1 开始）"
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "结束行号"
                    }
                },
                "required": ["file_path"]
            },
            executor=self._execute_read_file,
            category="code_navigation",
        )

        # read_symbol
        self.tool_manager.register_tool(
            name="read_symbol",
            description="读取指定函数、类或方法的完整定义。",
            parameters={
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "符号名称（函数名、类名、方法名）"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定在特定文件中查找"
                    }
                },
                "required": ["symbol_name"]
            },
            executor=self._execute_read_symbol,
            category="code_navigation",
        )

        # list_files
        self.tool_manager.register_tool(
            name="list_files",
            description="列出项目中的文件和目录结构。",
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "文件匹配模式，如 '**/*.py'",
                        "default": "**/*"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "最大返回数量",
                        "default": 50
                    }
                }
            },
            executor=self._execute_list_files,
            category="code_navigation",
        )

        # get_file_outline
        self.tool_manager.register_tool(
            name="get_file_outline",
            description="获取文件的结构大纲，列出所有类、函数、方法的定义。",
            parameters={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "文件路径"
                    }
                },
                "required": ["file_path"]
            },
            executor=self._execute_get_file_outline,
            category="code_navigation",
        )

        logger.debug("[UnifiedAgent] 代码导航工具已注册")

    def _register_call_chain_tools(self, code_units: List[CodeUnit]):
        """注册调用链分析工具"""
        if not self.call_chain_analyzer:
            logger.warning("[UnifiedAgent] 调用链分析器未配置，跳过工具注册")
            return

        # 创建执行器
        executor = create_callchain_executor(
            call_chain_analyzer=self.call_chain_analyzer,
            code_units=code_units,
            indexer=self.indexer,
        )

        # 获取工具定义并注册
        tool_defs = get_callchain_tool_definitions()
        executors = executor.get_executors()

        self.tool_manager.register_many(
            tools=tool_defs,
            executors=executors,
            category="call_chain",
        )

        logger.debug(f"[UnifiedAgent] 调用链工具已注册: {len(tool_defs)} 个")

    def _register_variant_tools(self, code_units: List[CodeUnit]):
        """注册变体分析工具"""
        # 创建执行器
        executor = create_variant_executor(
            variant_analyzer=self.variant_analyzer,
            vector_store=self.vector_store,
            embedding_client=self.llm_client,  # 使用 LLM 客户端的嵌入功能
            code_units=code_units,
        )

        # 获取工具定义并注册
        tool_defs = get_variant_tool_definitions()
        executors = executor.get_executors()

        self.tool_manager.register_many(
            tools=tool_defs,
            executors=executors,
            category="variant_analysis",
        )

        logger.debug(f"[UnifiedAgent] 变体分析工具已注册: {len(tool_defs)} 个")

    def _register_security_tools(self):
        """注册安全分析工具"""
        # 确认发现
        self.tool_manager.register_tool(
            name="confirm_finding",
            description="确认一个安全发现为真实漏洞。",
            parameters={
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "发现 ID"
                    },
                    "notes": {
                        "type": "string",
                        "description": "确认备注"
                    }
                },
                "required": ["finding_id"]
            },
            executor=self._execute_confirm_finding,
            category="finding_management",
        )

        # 拒绝发现
        self.tool_manager.register_tool(
            name="reject_finding",
            description="拒绝一个安全发现（标记为误报）。",
            parameters={
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "发现 ID"
                    },
                    "reason": {
                        "type": "string",
                        "description": "拒绝原因"
                    }
                },
                "required": ["finding_id"]
            },
            executor=self._execute_reject_finding,
            category="finding_management",
        )

        # 索引项目
        self.tool_manager.register_tool(
            name="index_project",
            description="索引或重新索引项目代码。在分析新项目或代码有更新时使用。",
            parameters={
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "目标路径（相对或绝对）"
                    },
                    "languages": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "要索引的编程语言列表"
                    },
                    "force_reindex": {
                        "type": "boolean",
                        "description": "是否强制重新索引",
                        "default": False
                    }
                }
            },
            executor=self._execute_index_project,
            category="project",
        )

        logger.debug("[UnifiedAgent] 安全分析工具已注册")

    # ============ 核心对话接口 ============

    async def chat(self, user_message: str) -> AgentMessage:
        """与智能体对话

        支持 LLM 自主选择和调用工具。

        Args:
            user_message: 用户消息

        Returns:
            AgentMessage: 智能体响应（包含工具调用记录）
        """
        if not self._initialized:
            await self.initialize()

        if self._is_processing:
            return AgentMessage(
                role="assistant",
                content="正在处理上一个请求，请稍候...",
                metadata={"error": "busy"},
            )

        self._is_processing = True
        logger.info(f"[UnifiedAgent] 收到消息: {user_message[:50]}...")

        try:
            # 添加用户消息
            user_msg = AgentMessage(role="user", content=user_message)
            self.messages.append(user_msg)

            # 构建 LLM 消息
            messages = self._build_llm_messages(user_message)

            # 获取工具定义
            tools = self.tool_manager.get_tools_for_llm()

            # 多轮工具调用循环
            tool_calls_this_turn: List[ToolCallEvent] = []
            final_response = ""

            for turn in range(self.config.max_tool_calls_per_turn):
                # 调用 LLM
                response = await self._call_llm_with_tools(messages, tools)
                self.total_llm_calls += 1

                # 检查是否有工具调用
                if response.tool_calls:
                    # 执行工具调用
                    tool_results = await self._execute_tool_calls(response.tool_calls)
                    tool_calls_this_turn.extend(tool_results)

                    # 将工具结果添加到消息
                    messages.append(ChatMessage(
                        role="assistant",
                        content=response.content or "",
                        tool_calls=response.tool_calls,
                    ))

                    for tc, result in zip(response.tool_calls, tool_results):
                        messages.append(ChatMessage(
                            role="tool",
                            content=json.dumps(result.result or {"error": result.error}, ensure_ascii=False),
                            tool_call_id=tc.id,  # ToolCall 对象直接访问 id 属性
                        ))
                else:
                    # 没有工具调用，获取最终响应
                    final_response = response.content or ""
                    break

            # 如果循环结束仍有工具调用，再获取一次最终响应
            if not final_response and tool_calls_this_turn:
                final_resp = await self._call_llm_with_tools(messages, tools)
                final_response = final_resp.content or ""

            # 构建响应消息
            assistant_msg = AgentMessage(
                role="assistant",
                content=final_response,
                tool_calls=tool_calls_this_turn,
                metadata={
                    "llm_calls": self.total_llm_calls,
                    "tool_calls_count": len(tool_calls_this_turn),
                },
            )

            self.messages.append(assistant_msg)

            # 更新对话历史
            self.conversation_history.append(ChatMessage(role="user", content=user_message))
            self.conversation_history.append(ChatMessage(role="assistant", content=final_response))

            # 裁剪历史
            self._trim_conversation_history()

            return assistant_msg

        except Exception as e:
            logger.error(f"[UnifiedAgent] 对话失败: {e}")
            return AgentMessage(
                role="assistant",
                content=f"处理请求时发生错误: {str(e)}",
                metadata={"error": str(e)},
            )

        finally:
            self._is_processing = False

    async def chat_stream(self, user_message: str):
        """流式对话（生成器）

        Args:
            user_message: 用户消息

        Yields:
            Dict: 事件对象 {"type": "...", "data": ...}
        """
        # TODO: 实现流式响应
        # 目前先返回完整响应
        response = await self.chat(user_message)

        yield {"type": "message", "data": response.to_dict()}

    def _build_llm_messages(self, user_message: str) -> List[ChatMessage]:
        """构建 LLM 消息列表"""
        messages = []

        # 系统提示
        system_prompt = self._build_system_prompt()
        messages.append(ChatMessage(role="system", content=system_prompt))

        # 最近的对话历史
        recent_history = self.conversation_history[-self.config.context_window_messages:]
        messages.extend(recent_history)

        # 当前用户消息
        messages.append(ChatMessage(role="user", content=user_message))

        return messages

    def _build_system_prompt(self) -> str:
        """构建系统提示"""
        # 获取工具摘要
        tool_summary = self.tool_manager.get_tool_summary()

        return f"""你是一名资深安全工程师和代码审计专家。你正在使用一个智能代码审计系统，可以通过各种工具来分析代码。

## 你的能力

你可以使用以下工具来完成代码审计任务：

{tool_summary}

## 工作流程

1. **理解需求**：首先理解用户想要分析什么
2. **选择工具**：根据需求选择合适的工具
3. **执行分析**：调用工具获取信息
4. **综合判断**：基于工具返回的信息进行安全分析
5. **输出结果**：清晰地向用户报告发现

## 重要原则

1. **工具优先**：遇到需要查看代码、追踪调用链、查找相似代码等任务时，优先使用工具
2. **循序渐进**：可以多次调用工具，逐步深入分析
3. **证据导向**：所有安全判断都应基于工具返回的代码证据
4. **谨慎判断**：对于不确定的问题，明确说明需要进一步验证

## 安全分析重点

- 认证与授权是否正确、完整
- 访问控制是否可被绕过
- 业务流程是否可被跳过或篡改
- 用户输入是否经过适当验证
- 危险函数调用是否安全

## 会话信息

- 会话 ID: {self.session_id}
- 已索引代码单元: {len(self.indexer.code_units) if self.indexer.code_units else 0}
- 可用工具数: {self.tool_manager.count()}

使用中文回复。
"""

    async def _call_llm_with_tools(
        self,
        messages: List[ChatMessage],
        tools: List[Dict[str, Any]],
    ):
        """调用 LLM（支持工具调用）"""
        logger.debug(f"[UnifiedAgent] 调用 LLM，消息数: {len(messages)}, 工具数: {len(tools)}")

        # 使用 asyncio.to_thread 包装同步调用
        response = await asyncio.to_thread(
            self.llm_client.chat_completion,
            messages=messages,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            tools=tools if tools else None,
        )

        # 更新统计
        if response.usage:
            self.total_tokens_used += response.usage.get("total_tokens", 0)

        return response

    async def _execute_tool_calls(self, tool_calls: List[ToolCall]) -> List[ToolCallEvent]:
        """执行工具调用"""
        results = []

        for tc in tool_calls:
            # ToolCall 是 dataclass，直接访问属性
            tool_name = tc.name
            arguments = tc.arguments if isinstance(tc.arguments, dict) else {}

            # 创建事件
            event = ToolCallEvent(
                id=tc.id,
                tool_name=tool_name,
                arguments=arguments,
                status=ToolCallStatus.RUNNING,
                started_at=datetime.now(),
            )

            # 通知回调
            if self.config.on_tool_call:
                self.config.on_tool_call(event)

            logger.info(f"[UnifiedAgent] 执行工具: {tool_name}")

            try:
                # 执行工具
                result = await self.tool_manager.execute(tool_name, arguments)

                event.status = ToolCallStatus.SUCCESS if result.success else ToolCallStatus.FAILED
                event.result = result.data
                event.error = result.error
                event.finished_at = datetime.now()
                event.duration_ms = result.duration_ms

                self.total_tool_calls += 1

            except Exception as e:
                logger.error(f"[UnifiedAgent] 工具执行失败 {tool_name}: {e}")
                event.status = ToolCallStatus.FAILED
                event.error = str(e)
                event.finished_at = datetime.now()

            # 通知回调（完成状态）
            if self.config.on_tool_call:
                self.config.on_tool_call(event)

            results.append(event)
            self.tool_call_history.append(event)

        return results

    def _trim_conversation_history(self):
        """裁剪对话历史"""
        max_messages = self.config.context_window_messages * 2
        if len(self.conversation_history) > max_messages:
            self.conversation_history = self.conversation_history[-max_messages:]

    # ============ 工具执行器 ============

    def _execute_search_code(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行代码搜索"""
        query = args.get("query", "")
        top_k = args.get("top_k", 5)
        language = args.get("language")
        file_pattern = args.get("file_pattern")

        if not query:
            return {"success": False, "error": "query 是必需参数"}

        if not self.vector_store:
            return {"success": False, "error": "向量存储未配置"}

        try:
            # 生成查询向量
            embeddings = self.llm_client.embed([query])
            if not embeddings or not embeddings[0]:
                return {"success": False, "error": "无法生成嵌入向量"}

            # 搜索
            results = self.vector_store.search(
                query_vector=embeddings[0],
                top_k=top_k * 2,  # 预留过滤空间
            )

            # 过滤和格式化
            code_results = []
            for r in results:
                metadata = r.metadata or {}

                # 语言过滤
                if language and metadata.get("language") != language:
                    continue

                # 文件模式过滤
                if file_pattern:
                    import fnmatch
                    if not fnmatch.fnmatch(metadata.get("file_path", ""), file_pattern):
                        continue

                code_results.append({
                    "file_path": metadata.get("file_path", ""),
                    "symbol": metadata.get("symbol", ""),
                    "language": metadata.get("language", ""),
                    "line_start": metadata.get("line_start", 0),
                    "line_end": metadata.get("line_end", 0),
                    "score": round(r.score, 3),
                    "code_preview": metadata.get("code", "")[:500],
                })

                if len(code_results) >= top_k:
                    break

            return {
                "success": True,
                "results": code_results,
                "total": len(code_results),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_read_file(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行文件读取"""
        file_path = args.get("file_path", "")
        start_line = args.get("start_line")
        end_line = args.get("end_line")

        if not file_path:
            return {"success": False, "error": "file_path 是必需参数"}

        try:
            content = self.indexer.read_file(
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
            )

            if content is None:
                return {"success": False, "error": f"文件不存在: {file_path}"}

            return {
                "success": True,
                "file_path": file_path,
                "content": content,
                "start_line": start_line or 1,
                "end_line": end_line,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_read_symbol(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行符号读取"""
        symbol_name = args.get("symbol_name", "")
        file_path = args.get("file_path")

        if not symbol_name:
            return {"success": False, "error": "symbol_name 是必需参数"}

        try:
            # 在代码单元中查找
            matching_units = []
            for unit in (self.indexer.code_units or {}).values():
                if unit.symbol == symbol_name or symbol_name in unit.symbol:
                    if file_path and file_path not in unit.file_path:
                        continue
                    matching_units.append(unit)

            if not matching_units:
                return {"success": False, "error": f"未找到符号: {symbol_name}"}

            # 返回第一个匹配
            unit = matching_units[0]
            return {
                "success": True,
                "symbol": unit.symbol,
                "file_path": unit.file_path,
                "language": unit.language,
                "line_start": unit.span.start_line,
                "line_end": unit.span.end_line,
                "code": unit.code,
                "calls": unit.calls,
                "total_matches": len(matching_units),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_list_files(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行文件列表"""
        pattern = args.get("pattern", "**/*")
        max_results = args.get("max_results", 50)

        try:
            files = self.indexer.list_files(pattern=pattern, max_results=max_results)

            return {
                "success": True,
                "files": files,
                "total": len(files),
                "pattern": pattern,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_get_file_outline(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行获取文件大纲"""
        file_path = args.get("file_path", "")

        if not file_path:
            return {"success": False, "error": "file_path 是必需参数"}

        try:
            # 从代码单元中提取该文件的符号
            symbols = []
            for unit in (self.indexer.code_units or {}).values():
                if unit.file_path == file_path or file_path in unit.file_path:
                    symbols.append({
                        "name": unit.symbol,
                        "type": unit.unit_type.value,
                        "line_start": unit.span.start_line,
                        "line_end": unit.span.end_line,
                    })

            # 按行号排序
            symbols.sort(key=lambda x: x["line_start"])

            return {
                "success": True,
                "file_path": file_path,
                "symbols": symbols,
                "total": len(symbols),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_confirm_finding(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行确认发现"""
        finding_id = args.get("finding_id", "")
        notes = args.get("notes", "")

        # TODO: 实现发现确认逻辑
        return {
            "success": True,
            "finding_id": finding_id,
            "status": "confirmed",
            "notes": notes,
        }

    def _execute_reject_finding(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行拒绝发现"""
        finding_id = args.get("finding_id", "")
        reason = args.get("reason", "")

        # TODO: 实现发现拒绝逻辑
        return {
            "success": True,
            "finding_id": finding_id,
            "status": "rejected",
            "reason": reason,
        }

    def _execute_index_project(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行项目索引"""
        target_path = args.get("target_path")
        languages = args.get("languages")
        force_reindex = args.get("force_reindex", False)

        try:
            # 执行索引
            self.indexer.index_directory(
                target_path=target_path,
            )

            return {
                "success": True,
                "target_path": target_path,
                "code_units_count": len(self.indexer.code_units) if self.indexer.code_units else 0,
                "languages": languages,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    # ============ 状态查询 ============

    def get_session_state(self) -> Dict[str, Any]:
        """获取会话状态"""
        return {
            "session_id": self.session_id,
            "initialized": self._initialized,
            "is_processing": self._is_processing,
            "messages_count": len(self.messages),
            "tool_calls_count": len(self.tool_call_history),
            "total_llm_calls": self.total_llm_calls,
            "total_tool_calls": self.total_tool_calls,
            "total_tokens_used": self.total_tokens_used,
            "available_tools": self.tool_manager.get_all_names(),
        }

    def get_messages(self) -> List[Dict[str, Any]]:
        """获取所有消息"""
        return [m.to_dict() for m in self.messages]

    def get_tool_call_history(self) -> List[Dict[str, Any]]:
        """获取工具调用历史"""
        return [tc.to_dict() for tc in self.tool_call_history]

    def clear_history(self):
        """清空对话历史"""
        self.messages.clear()
        self.conversation_history.clear()
        self.tool_call_history.clear()
        logger.info(f"[UnifiedAgent] 已清空会话 {self.session_id} 的历史")


def create_unified_agent(
    session_id: str,
    llm_client: BaseLLMClient,
    indexer: CodeIndexer,
    config: Optional[UnifiedAgentConfig] = None,
    **kwargs,
) -> UnifiedAuditAgent:
    """创建统一审计智能体（工厂函数）

    Args:
        session_id: 会话 ID
        llm_client: LLM 客户端
        indexer: 代码索引器
        config: 配置
        **kwargs: 传递给 UnifiedAuditAgent 的其他参数

    Returns:
        UnifiedAuditAgent 实例
    """
    return UnifiedAuditAgent(
        session_id=session_id,
        llm_client=llm_client,
        indexer=indexer,
        config=config,
        **kwargs,
    )
