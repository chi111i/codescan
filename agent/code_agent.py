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
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable

from llm_client import BaseLLMClient, ChatMessage, ChatResponse, ToolCall
from indexer import CodeReader
from .tools.registry import CODE_NAVIGATION_TOOLS

# 向后兼容别名
CODE_READER_TOOLS = CODE_NAVIGATION_TOOLS

logger = logging.getLogger(__name__)


@dataclass
class ToolCallRecord:
    """工具调用记录"""
    call_id: str
    tool_name: str
    arguments: Dict[str, Any]
    result: Dict[str, Any]
    success: bool
    duration_ms: Optional[int] = None  # 执行耗时（毫秒）


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
        on_tool_call: Optional[Callable[[ToolCallRecord], None]] = None,
        on_thinking: Optional[Callable[[str], None]] = None,
    ):
        """初始化 Agent

        Args:
            llm_client: LLM 客户端
            code_reader: 代码读取器
            tools: 工具定义列表，默认使用 CODE_READER_TOOLS
            max_tool_calls: 最大工具调用次数
            max_iterations: 最大迭代次数
            on_tool_call: 工具调用回调，每次工具执行后触发
            on_thinking: LLM 思考回调，当 LLM 返回非工具调用内容时触发
        """
        self.llm_client = llm_client
        self.code_reader = code_reader
        self.tools = tools or CODE_READER_TOOLS
        self.max_tool_calls = max_tool_calls
        self.max_iterations = max_iterations
        self.on_tool_call = on_tool_call
        self.on_thinking = on_thinking

        # 工具执行器映射
        self._tool_executors: Dict[str, Callable] = {
            "search_code": self._execute_search_code,
            "read_file": self._execute_read_file,
            "read_symbol": self._execute_read_symbol,
            "list_files": self._execute_list_files,
            "get_file_outline": self._execute_get_file_outline,
            "get_callers": self._execute_get_callers,
            "get_callees": self._execute_get_callees,
        }

    def analyze(
        self,
        task: str,
        system_prompt: Optional[str] = None,
        context: Optional[str] = None,
        on_tool_call: Optional[Callable[[ToolCallRecord], None]] = None,
        on_thinking: Optional[Callable[[str], None]] = None,
    ) -> AgentResult:
        """执行分析任务

        Args:
            task: 分析任务描述
            system_prompt: 系统提示词（可选）
            context: 额外上下文信息（可选）
            on_tool_call: 工具调用回调，覆盖构造函数设置
            on_thinking: LLM 思考回调，覆盖构造函数设置

        Returns:
            AgentResult 包含分析结果和工具调用历史
        """
        # 使用传入的回调或默认回调
        tool_callback = on_tool_call or self.on_tool_call
        thinking_callback = on_thinking or self.on_thinking

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
                    # LLM 返回的 content 可能包含思考过程
                    if response.content and thinking_callback:
                        thinking_callback(response.content)

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

                        # 记录开始时间
                        start_time = time.time()
                        result, success = self._execute_tool(tool_call)
                        duration_ms = int((time.time() - start_time) * 1000)

                        # 记录工具调用
                        record = ToolCallRecord(
                            call_id=tool_call.id,
                            tool_name=tool_call.name,
                            arguments=tool_call.arguments,
                            result=result,
                            success=success,
                            duration_ms=duration_ms,
                        )
                        tool_calls_history.append(record)

                        # 触发工具调用回调
                        if tool_callback:
                            try:
                                tool_callback(record)
                            except Exception as e:
                                logger.warning(f"Tool call callback error: {e}")

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
                            f"-> {'success' if success else 'failed'} ({duration_ms}ms)"
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

    def _execute_get_callers(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行查找调用者（向上追溯调用链）"""
        return self.code_reader.get_callers(
            symbol_name=args.get("symbol_name", ""),
            file_path=args.get("file_path"),
            max_results=args.get("max_results", 10),
        )

    def _execute_get_callees(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行查找被调用函数（向下追溯调用链）"""
        return self.code_reader.get_callees(
            symbol_name=args.get("symbol_name", ""),
            file_path=args.get("file_path"),
            max_depth=args.get("max_depth", 1),
        )

    def _get_default_system_prompt(self) -> str:
        """获取默认系统提示词"""
        return """# 角色定位

你是一位资深的代码安全审计专家，具备十年以上的代码审计和漏洞挖掘经验。你将使用一套类似 IDE 的代码导航工具，像人类安全专家一样系统化地阅读、理解和分析代码。

# 可用工具

你可以使用以下工具来导航和分析代码：

## 搜索与发现
- **search_code**: 语义搜索，根据功能描述查找相关代码（如"用户登录验证"、"文件上传处理"）
- **list_files**: 列出项目文件结构，了解项目布局

## 代码阅读
- **read_file**: 读取文件内容，可指定行范围（start_line, end_line）
- **read_symbol**: 读取函数/类/方法的完整定义
- **get_file_outline**: 获取文件结构大纲（所有函数、类、方法）

## 调用链追踪
- **get_callers**: 查找谁调用了这个函数（向上追溯调用链）
- **get_callees**: 查找这个函数调用了谁（向下追溯调用链）

# 工作方法论

## 第一步：建立全局视图
1. 使用 `list_files` 了解项目结构和目录布局
2. 使用 `search_code` 定位与任务相关的核心代码
3. 识别关键入口点（路由处理器、API 端点、命令处理函数等）

## 第二步：深入阅读代码
1. 使用 `get_file_outline` 了解文件结构
2. 使用 `read_file` 或 `read_symbol` 读取具体代码
3. 关注：函数签名、参数来源、数据处理逻辑、返回值

## 第三步：追踪数据流和调用链
1. 使用 `get_callers` 追溯"谁调用了这个函数"
2. 使用 `get_callees` 追溯"这个函数调用了谁"
3. 识别：数据输入源 → 处理过程 → 危险操作（如数据库查询、命令执行、文件操作）

## 第四步：形成分析结论
1. 基于收集的代码证据形成判断
2. 明确指出问题位置（文件名:行号）
3. 如信息不足，继续使用工具收集更多上下文

# 分析原则

1. **眼见为实**：所有结论必须基于实际读取到的代码，不要臆测或假设代码逻辑
2. **追本溯源**：遇到不确定的函数调用，使用工具追溯其定义和实现
3. **层层深入**：从入口点开始，沿着数据流逐步深入分析
4. **实时汇报**：每完成一步分析，简要说明发现了什么，下一步计划做什么

# 输出格式

分析过程中，请遵循以下格式：

```
【当前步骤】正在执行的操作
【发现】通过工具调用发现的关键信息
【推理】基于发现的逻辑推理
【下一步】计划执行的下一个操作
```

最终结论请包含：
- 是否存在安全问题
- 问题类型和风险等级
- 具体代码位置（文件:行号）
- 问题成因分析
- 修复建议"""

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
            focus_text = f"\n\n**重点关注领域**：\n" + "\n".join(f"- {area}" for area in focus_areas)

        task = f"""# 安全审计任务

## 分析目标
{target}
{focus_text}

## 审计要求

请像资深安全工程师一样，系统化地对目标代码进行安全审计。你需要：

### 阶段一：信息收集
1. 定位目标代码的位置和入口点
2. 阅读相关的路由配置、权限配置
3. 理解业务场景和数据流向

### 阶段二：深度分析
逐一检查以下安全维度：

**1. 认证检查 (Authentication)**
- 是否验证用户登录状态
- Session/Token 验证是否完整
- 是否存在认证绕过风险

**2. 授权检查 (Authorization)**
- 是否检查用户权限/角色
- 对象级权限是否正确（用户只能访问自己的资源）
- 是否存在 IDOR（不安全的直接对象引用）

**3. 输入验证 (Input Validation)**
- 用户输入是否经过验证和过滤
- 是否存在注入风险（SQL、命令、模板等）
- 文件上传是否安全

**4. 业务逻辑 (Business Logic)**
- 关键流程是否可被跳过或重复
- 价格/数量等敏感参数是否可被篡改
- 状态机转换是否安全

**5. 敏感操作保护**
- 关键操作是否有二次确认
- 是否有适当的日志审计
- 是否存在敏感信息泄露

### 阶段三：输出结论

对于发现的每个问题，请提供：
1. **问题标题**：简洁描述问题
2. **风险等级**：Critical / High / Medium / Low
3. **置信度**：确定 / 疑似 / 需人工确认
4. **代码位置**：文件名:行号
5. **问题描述**：具体说明问题成因
6. **攻击场景**：描述攻击者如何利用（不要给出具体 payload）
7. **修复建议**：具体的修复方案

如果未发现明确问题，请说明已检查的范围和结论。"""

        system_prompt = """# 安全审计专家角色设定

你是一位拥有十年经验的安全审计专家，曾在多家顶级安全公司担任首席安全研究员。你的专长是：

- 代码审计与漏洞挖掘
- 业务逻辑漏洞分析
- 权限控制缺陷检测
- 安全架构评估

## 审计方法论

### 思维模式
1. **攻击者视角**：始终站在攻击者角度思考"如何绕过这个检查"
2. **防御者视角**：评估现有防护措施是否充分
3. **数据流追踪**：追踪用户输入从入口到最终使用的完整路径

### 分析步骤
1. **宏观理解**：先了解整体架构和业务流程
2. **边界识别**：找出信任边界和数据入口点
3. **逐点深入**：针对每个入口点进行深度分析
4. **交叉验证**：验证多个代码路径的一致性

### 常见漏洞模式识别

**认证绕过**：
- 仅在前端检查登录状态
- Token/Session 验证不完整
- 忘记在某些 API 添加认证中间件

**越权访问（IDOR）**：
- 使用用户可控的 ID 直接查询数据库
- 未验证资源是否属于当前用户
- 批量操作缺少权限检查

**业务逻辑缺陷**：
- 订单状态可被任意修改
- 优惠/积分/余额计算可被操控
- 关键步骤可被跳过或重放

## 输出要求

1. **实事求是**：只报告有代码证据支持的问题
2. **风险明确**：每个问题都要给出风险等级
3. **位置精确**：提供具体的文件名和行号
4. **建议可行**：修复建议要具体、可执行

## 重要提醒

- 不要臆测或假设代码逻辑，必须通过工具读取实际代码
- 不确定的问题标记为"需人工确认"
- 不要给出可直接利用的攻击 payload
- 每一步分析都要简要说明正在做什么，让用户了解进度"""

        return self.analyze(task=task, system_prompt=system_prompt)
