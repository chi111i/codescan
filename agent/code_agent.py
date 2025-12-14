"""
代码分析 Agent - 使用 LLM Function Calling 实现智能代码读取和分析

Agent 工作流程：
1. 接收用户任务/问题
2. 发送给 LLM（带工具定义）
3. 如果 LLM 返回 tool_calls → 执行工具 → 返回结果给 LLM
4. 循环直到 LLM 返回最终答案
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable

from llm_client import BaseLLMClient, ChatMessage, ChatResponse, ToolCall
from indexer import CodeReader
from .tools import CODE_READER_TOOLS

logger = logging.getLogger(__name__)


@dataclass
class ToolCallRecord:
    """工具调用记录"""
    call_id: str
    tool_name: str
    arguments: Dict[str, Any]
    result: Dict[str, Any]
    success: bool


@dataclass
class AgentResult:
    """Agent 执行结果"""
    content: str  # LLM 最终回答
    tool_calls_history: List[ToolCallRecord] = field(default_factory=list)
    total_tool_calls: int = 0
    total_tokens: int = 0
    truncated: bool = False  # 是否因达到最大调用次数而截断
    error: Optional[str] = None


class CodeAnalysisAgent:
    """代码分析 Agent

    使用 LLM Function Calling 实现智能代码读取和分析。
    LLM 可以自主决定需要读取哪些代码，实现类似 IDE 的代码导航体验。
    """

    def __init__(
        self,
        llm_client: BaseLLMClient,
        code_reader: CodeReader,
        tools: Optional[List[Dict[str, Any]]] = None,
        max_tool_calls: int = 15,
        max_iterations: int = 10,
    ):
        """初始化 Agent

        Args:
            llm_client: LLM 客户端
            code_reader: 代码读取器
            tools: 工具定义列表，默认使用 CODE_READER_TOOLS
            max_tool_calls: 最大工具调用次数
            max_iterations: 最大迭代次数
        """
        self.llm_client = llm_client
        self.code_reader = code_reader
        self.tools = tools or CODE_READER_TOOLS
        self.max_tool_calls = max_tool_calls
        self.max_iterations = max_iterations

        # 工具执行器映射
        self._tool_executors: Dict[str, Callable] = {
            "search_code": self._execute_search_code,
            "read_file": self._execute_read_file,
            "read_symbol": self._execute_read_symbol,
            "list_files": self._execute_list_files,
            "get_file_outline": self._execute_get_file_outline,
        }

    def analyze(
        self,
        task: str,
        system_prompt: Optional[str] = None,
        context: Optional[str] = None,
    ) -> AgentResult:
        """执行分析任务

        Args:
            task: 分析任务描述
            system_prompt: 系统提示词（可选）
            context: 额外上下文信息（可选）

        Returns:
            AgentResult 包含分析结果和工具调用历史
        """
        messages: List[ChatMessage] = []

        # 构建系统提示词
        default_system = self._get_default_system_prompt()
        if system_prompt:
            messages.append(ChatMessage(role="system", content=f"{default_system}\n\n{system_prompt}"))
        else:
            messages.append(ChatMessage(role="system", content=default_system))

        # 构建用户消息
        user_content = task
        if context:
            user_content = f"{task}\n\n【上下文信息】\n{context}"
        messages.append(ChatMessage(role="user", content=user_content))

        tool_calls_history: List[ToolCallRecord] = []
        total_tool_calls = 0
        total_tokens = 0
        iteration = 0

        while iteration < self.max_iterations and total_tool_calls < self.max_tool_calls:
            iteration += 1

            try:
                # 调用 LLM
                response = self.llm_client.chat_completion(
                    messages=messages,
                    tools=self.tools,
                    tool_choice="auto",
                    temperature=0.0,
                )

                total_tokens += response.usage.get("total_tokens", 0)

                # 检查是否有工具调用
                if response.tool_calls:
                    # 添加 assistant 消息（包含 tool_calls）
                    messages.append(ChatMessage(
                        role="assistant",
                        content=response.content,
                        tool_calls=response.tool_calls,
                    ))

                    # 执行每个工具调用
                    for tool_call in response.tool_calls:
                        if total_tool_calls >= self.max_tool_calls:
                            logger.warning("Max tool calls reached")
                            break

                        result, success = self._execute_tool(tool_call)

                        # 记录工具调用
                        tool_calls_history.append(ToolCallRecord(
                            call_id=tool_call.id,
                            tool_name=tool_call.name,
                            arguments=tool_call.arguments,
                            result=result,
                            success=success,
                        ))

                        # 添加工具结果消息
                        messages.append(ChatMessage(
                            role="tool",
                            content=json.dumps(result, ensure_ascii=False),
                            tool_call_id=tool_call.id,
                            name=tool_call.name,
                        ))

                        total_tool_calls += 1

                        logger.debug(
                            f"Tool call [{total_tool_calls}]: {tool_call.name} "
                            f"-> {'success' if success else 'failed'}"
                        )

                else:
                    # LLM 返回最终答案
                    return AgentResult(
                        content=response.content or "",
                        tool_calls_history=tool_calls_history,
                        total_tool_calls=total_tool_calls,
                        total_tokens=total_tokens,
                        truncated=False,
                    )

            except Exception as e:
                logger.error(f"Agent iteration failed: {e}")
                return AgentResult(
                    content="",
                    tool_calls_history=tool_calls_history,
                    total_tool_calls=total_tool_calls,
                    total_tokens=total_tokens,
                    error=str(e),
                )

        # 达到最大迭代/工具调用次数，尝试获取最终答案
        logger.warning(f"Max iterations ({iteration}) or tool calls ({total_tool_calls}) reached")

        # 添加一个提示让 LLM 总结
        messages.append(ChatMessage(
            role="user",
            content="请根据已获取的信息，总结你的分析结果。"
        ))

        try:
            response = self.llm_client.chat_completion(
                messages=messages,
                tools=None,  # 不再允许工具调用
                temperature=0.0,
            )
            total_tokens += response.usage.get("total_tokens", 0)

            return AgentResult(
                content=response.content or "",
                tool_calls_history=tool_calls_history,
                total_tool_calls=total_tool_calls,
                total_tokens=total_tokens,
                truncated=True,
            )
        except Exception as e:
            return AgentResult(
                content="分析未完成，已达到最大迭代次数。",
                tool_calls_history=tool_calls_history,
                total_tool_calls=total_tool_calls,
                total_tokens=total_tokens,
                truncated=True,
                error=str(e),
            )

    def _execute_tool(self, tool_call: ToolCall) -> tuple:
        """执行工具调用

        Args:
            tool_call: 工具调用对象

        Returns:
            (result_dict, success_bool)
        """
        executor = self._tool_executors.get(tool_call.name)
        if not executor:
            return {"error": f"Unknown tool: {tool_call.name}"}, False

        try:
            result = executor(tool_call.arguments)
            success = result.get("success", True) if isinstance(result, dict) else True
            return result, success
        except Exception as e:
            logger.error(f"Tool execution failed: {tool_call.name} - {e}")
            return {"error": str(e)}, False

    def _execute_search_code(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行代码搜索"""
        return self.code_reader.search_code(
            query=args.get("query", ""),
            top_k=args.get("top_k", 5),
            language=args.get("language"),
            file_pattern=args.get("file_pattern"),
        )

    def _execute_read_file(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行文件读取"""
        return self.code_reader.read_file(
            file_path=args.get("file_path", ""),
            start_line=args.get("start_line"),
            end_line=args.get("end_line"),
            context_lines=args.get("context_lines", 0),
        )

    def _execute_read_symbol(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行符号读取"""
        return self.code_reader.read_symbol(
            symbol_name=args.get("symbol_name", ""),
            file_path=args.get("file_path"),
            include_callers=args.get("include_callers", False),
            include_callees=args.get("include_callees", False),
        )

    def _execute_list_files(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行文件列表"""
        return self.code_reader.list_files(
            pattern=args.get("pattern", "**/*"),
            max_results=args.get("max_results", 50),
        )

    def _execute_get_file_outline(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行获取文件大纲"""
        return self.code_reader.get_file_outline(
            file_path=args.get("file_path", ""),
        )

    def _get_default_system_prompt(self) -> str:
        """获取默认系统提示词"""
        return """你是一个专业的代码分析助手。你可以使用以下工具来读取和分析代码：

1. **search_code**: 通过语义搜索查找相关代码。输入你想查找的功能描述，返回相关的函数、类或方法。

2. **read_file**: 读取指定文件的内容。可以读取整个文件或指定行范围。

3. **read_symbol**: 读取指定符号（函数、类、方法）的完整定义。可以同时获取调用关系。

4. **list_files**: 列出项目中的文件。用于了解项目结构。

5. **get_file_outline**: 获取文件的结构大纲，包含所有类、函数、方法的列表。

使用这些工具时：
- 先使用 search_code 或 list_files 了解相关代码的位置
- 然后使用 read_file 或 read_symbol 获取详细代码
- 如需了解代码调用关系，使用 read_symbol 并设置 include_callers/include_callees

请根据用户的问题，合理使用这些工具来获取所需信息，然后给出准确的分析结果。"""

    def register_tool(
        self,
        name: str,
        executor: Callable[[Dict[str, Any]], Dict[str, Any]],
        schema: Dict[str, Any],
    ):
        """注册自定义工具

        Args:
            name: 工具名称
            executor: 工具执行函数
            schema: 工具定义（OpenAI 格式）
        """
        self._tool_executors[name] = executor
        self.tools.append(schema)
        logger.info(f"Registered custom tool: {name}")


class SecurityAnalysisAgent(CodeAnalysisAgent):
    """安全分析专用 Agent

    在 CodeAnalysisAgent 基础上，添加安全分析专用提示词和工具。
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def analyze_security(
        self,
        target: str,
        focus_areas: Optional[List[str]] = None,
    ) -> AgentResult:
        """执行安全分析

        Args:
            target: 分析目标（文件路径、函数名或描述）
            focus_areas: 重点关注的安全领域

        Returns:
            AgentResult
        """
        focus_text = ""
        if focus_areas:
            focus_text = f"\n\n重点关注以下安全领域：\n" + "\n".join(f"- {area}" for area in focus_areas)

        task = f"""请对以下目标进行安全分析：

**分析目标**: {target}
{focus_text}

请从以下角度进行分析：
1. 身份认证和授权是否正确实现
2. 是否存在输入验证缺陷
3. 是否存在越权访问风险（水平/垂直越权）
4. 业务逻辑是否可被绕过
5. 是否存在敏感信息泄露风险

请使用工具获取相关代码，然后给出详细的分析结果。如果发现潜在问题，请说明：
- 问题类型和风险等级
- 问题位置（文件和行号）
- 攻击场景（高层次描述）
- 修复建议"""

        system_prompt = """你是一位资深的安全工程师，专注于代码审计和漏洞挖掘。

在分析代码时，请特别关注：
1. **认证与授权**：登录状态检查、权限验证、会话管理
2. **输入验证**：用户输入是否经过验证和过滤
3. **业务逻辑**：流程是否可被跳过、参数是否可被篡改
4. **数据访问**：是否存在未授权的数据访问（IDOR）
5. **敏感操作**：关键操作是否有适当保护

发现问题时，请给出具体的代码位置和修复建议。如果不确定是否构成漏洞，请明确说明需要人工确认的原因。"""

        return self.analyze(task=task, system_prompt=system_prompt)
