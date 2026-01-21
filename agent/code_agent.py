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

from serialization import safe_json_dumps

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
            "grep_code": self._execute_grep_code,
            # P0-3.1: 安全分析专用工具执行器
            "analyze_call_chain": self._execute_analyze_call_chain,
            "trace_taint_path": self._execute_trace_taint_path,
            "get_code_context": self._execute_get_code_context,
            "check_vulnerability_pattern": self._execute_check_vulnerability_pattern,
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
                    # temperature 使用 LLM 客户端配置的默认值
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
                            # 工具结果可能包含 datetime/path 等对象，直接 json.dumps 会导致序列化失败
                            content=safe_json_dumps(result, ensure_ascii=False),
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
                logger.exception(f"Agent iteration failed: {e}")
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
                # temperature 使用 LLM 客户端配置的默认值
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
            logger.exception(f"Tool execution failed: {tool_call.name} - {e}")
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

    def _execute_grep_code(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行精确代码搜索（基于正则/关键词）"""
        return self.code_reader.grep_code(
            pattern=args.get("pattern", ""),
            file_glob=args.get("file_glob"),
            max_results=args.get("max_results", 50),
            context_lines=args.get("context_lines", 2),
            use_regex=args.get("use_regex", False),
            case_sensitive=args.get("case_sensitive", True),
        )

    # P0-3.1: 安全分析专用工具执行器实现

    def _execute_analyze_call_chain(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """分析函数的调用关系链

        基于 get_callers/get_callees 组合实现调用链分析。
        """
        symbol_name = args.get("symbol_name", "")
        direction = args.get("direction", "both")
        max_depth = min(args.get("max_depth", 3), 5)  # 限制最大深度
        include_sources = args.get("include_sources", True)
        include_sinks = args.get("include_sinks", True)

        try:
            result = {
                "success": True,
                "symbol": symbol_name,
                "direction": direction,
                "max_depth": max_depth,
            }

            # 获取符号定义
            symbol_result = self.code_reader.read_symbol(symbol_name)
            if not symbol_result.get("success"):
                return {
                    "success": False,
                    "error": f"未找到符号: {symbol_name}",
                    "hint": "使用 search_code 或 grep_code 搜索符号位置",
                }

            definitions = symbol_result.get("definitions", [])
            if definitions:
                result["symbol_definition"] = {
                    "file_path": definitions[0].get("file_path"),
                    "start_line": definitions[0].get("start_line"),
                    "end_line": definitions[0].get("end_line"),
                    "type": definitions[0].get("type"),
                }

            # 获取调用者（向上追溯）
            if direction in ("both", "callers"):
                callers_result = self.code_reader.get_callers(symbol_name)
                result["callers"] = callers_result.get("callers", [])[:10]
                result["callers_count"] = len(callers_result.get("callers", []))

            # 获取被调用者（向下追溯）
            if direction in ("both", "callees"):
                callees_result = self.code_reader.get_callees(symbol_name)
                result["callees"] = callees_result.get("callees", [])[:10]
                result["callees_count"] = len(callees_result.get("callees", []))

            # 标记 Source 和 Sink 节点
            if include_sources or include_sinks:
                result["security_markers"] = self._identify_security_markers(
                    result.get("callers", []),
                    result.get("callees", []),
                    include_sources,
                    include_sinks,
                )

            return result

        except Exception as e:
            logger.error(f"Analyze call chain failed: {e}")
            return {
                "success": False,
                "error": f"调用链分析失败: {str(e)}",
            }

    def _execute_trace_taint_path(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """追踪污点传播路径

        基于调用链分析实现简化版污点追踪。
        """
        source_symbol = args.get("source_symbol")
        sink_symbol = args.get("sink_symbol")
        max_depth = min(args.get("max_depth", 10), 15)
        show_sanitizers = args.get("show_sanitizers", True)
        only_unsanitized = args.get("only_unsanitized", False)

        try:
            result = {
                "success": True,
                "max_depth": max_depth,
                "paths": [],
            }

            # 如果指定了 source，追踪从 source 出发的调用
            if source_symbol:
                source_callees = self.code_reader.get_callees(source_symbol)
                result["source"] = source_symbol
                result["source_callees"] = source_callees.get("callees", [])[:5]

            # 如果指定了 sink，追踪调用 sink 的位置
            if sink_symbol:
                sink_callers = self.code_reader.get_callers(sink_symbol)
                result["sink"] = sink_symbol
                result["sink_callers"] = sink_callers.get("callers", [])[:5]

            # 识别潜在的 source 和 sink
            if not source_symbol and not sink_symbol:
                # 搜索常见的 source 和 sink 模式
                result["hint"] = (
                    "未指定 source 或 sink。建议：\n"
                    "- 使用 grep_code 搜索危险函数如 'os.system', 'eval', 'exec'\n"
                    "- 使用 grep_code 搜索输入源如 'request.', 'input('"
                )

            # 标记 sanitizer
            if show_sanitizers:
                result["common_sanitizers"] = [
                    "escape", "quote", "sanitize", "validate",
                    "encode", "filter", "clean", "safe",
                ]

            return result

        except Exception as e:
            logger.error(f"Trace taint path failed: {e}")
            return {
                "success": False,
                "error": f"污点追踪失败: {str(e)}",
            }

    def _execute_get_code_context(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """获取代码的完整上下文信息

        组合 read_symbol、get_callers、get_callees 实现。
        """
        symbol_name = args.get("symbol_name", "")
        file_path = args.get("file_path")
        include_callers = args.get("include_callers", True)
        include_callees = args.get("include_callees", True)
        include_class = args.get("include_class", True)
        include_imports = args.get("include_imports", False)

        try:
            result = {
                "success": True,
                "symbol": symbol_name,
            }

            # 读取符号定义
            symbol_result = self.code_reader.read_symbol(
                symbol_name,
                file_path=file_path,
                include_callers=include_callers,
                include_callees=include_callees,
            )

            if not symbol_result.get("success"):
                return symbol_result

            result["definition"] = symbol_result.get("definitions", [])
            result["total_definitions"] = symbol_result.get("total_found", 0)

            # 添加调用关系
            if include_callers:
                result["callers"] = symbol_result.get("callers", [])

            if include_callees:
                result["callees"] = symbol_result.get("callees", [])

            # 如果是方法，获取类的其他方法
            if include_class and result["definition"]:
                parent_class = result["definition"][0].get("parent_class")
                if parent_class:
                    class_result = self.code_reader.read_symbol(parent_class)
                    if class_result.get("success"):
                        result["parent_class"] = {
                            "name": parent_class,
                            "file_path": class_result.get("definitions", [{}])[0].get("file_path"),
                        }

            # 获取导入信息
            if include_imports and result["definition"]:
                file_path = result["definition"][0].get("file_path")
                if file_path:
                    # 读取文件头部获取导入语句
                    file_result = self.code_reader.read_file(file_path, start_line=1, end_line=50)
                    if file_result.get("success"):
                        content = file_result.get("content", "")
                        imports = [
                            line for line in content.split("\n")
                            if line.strip().startswith(("import ", "from "))
                        ]
                        result["imports"] = imports[:20]

            return result

        except Exception as e:
            logger.error(f"Get code context failed: {e}")
            return {
                "success": False,
                "error": f"获取代码上下文失败: {str(e)}",
            }

    def _execute_check_vulnerability_pattern(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """检查代码中是否存在特定的漏洞模式

        使用 grep_code 搜索常见漏洞模式。
        """
        pattern_type = args.get("pattern_type", "")
        file_path = args.get("file_path")
        symbol_name = args.get("symbol_name")

        # 漏洞模式对应的搜索 patterns
        vuln_patterns = {
            "sql_injection": [
                r"execute\s*\(.*%.*\)",
                r"execute\s*\(.*\.format\(",
                r"execute\s*\(.*\+",
                r"raw\s*\(",
                r"cursor\.execute\s*\(.*f['\"]",
            ],
            "command_injection": [
                r"os\.system\s*\(",
                r"subprocess\.call\s*\(.*shell\s*=\s*True",
                r"subprocess\.Popen\s*\(.*shell\s*=\s*True",
                r"eval\s*\(",
                r"exec\s*\(",
            ],
            "xss": [
                r"innerHTML\s*=",
                r"document\.write\s*\(",
                r"\|safe",
                r"mark_safe\s*\(",
                r"dangerouslySetInnerHTML",
            ],
            "path_traversal": [
                r"open\s*\(.*\+",
                r"Path\s*\(.*\+",
                r"os\.path\.join\s*\(.*request",
                r"send_file\s*\(",
                r"\.\.\/",
            ],
            "insecure_deserialization": [
                r"pickle\.loads?\s*\(",
                r"yaml\.load\s*\(",
                r"marshal\.loads?\s*\(",
                r"unserialize\s*\(",
            ],
            "authentication_bypass": [
                r"@login_not_required",
                r"authentication_classes\s*=\s*\[\]",
                r"IsAuthenticated.*False",
                r"AllowAny",
            ],
            "authorization_bypass": [
                r"permission_classes\s*=\s*\[\]",
                r"@permission_exempt",
                r"check_permission\s*=\s*False",
            ],
            "idor": [
                r"\.get\s*\(\s*['\"]id['\"]\s*\)",
                r"\.objects\.get\s*\(.*id\s*=",
                r"filter\s*\(.*user_id\s*=.*request",
            ],
            "ssrf": [
                r"requests\.get\s*\(.*request\.",
                r"urllib\.request\.urlopen\s*\(",
                r"http\.client\.",
                r"curl_exec\s*\(",
            ],
            "open_redirect": [
                r"redirect\s*\(.*request\.",
                r"HttpResponseRedirect\s*\(",
                r"Location:\s*.*\$",
            ],
        }

        patterns = vuln_patterns.get(pattern_type, [])
        if not patterns:
            return {
                "success": False,
                "error": f"未知的漏洞模式类型: {pattern_type}",
                "available_types": list(vuln_patterns.keys()),
            }

        try:
            result = {
                "success": True,
                "pattern_type": pattern_type,
                "matches": [],
            }

            # 对每个 pattern 执行搜索
            for pattern in patterns[:5]:  # 限制搜索次数
                grep_result = self.code_reader.grep_code(
                    pattern=pattern,
                    file_glob=file_path,
                    max_results=10,
                    use_regex=True,
                    context_lines=2,
                )

                if grep_result.get("success") and grep_result.get("matches"):
                    for match in grep_result["matches"]:
                        match["pattern"] = pattern
                        result["matches"].append(match)

            result["total_matches"] = len(result["matches"])

            if result["matches"]:
                result["warning"] = (
                    f"发现 {len(result['matches'])} 个可能的 {pattern_type} 模式匹配。"
                    "请人工验证这些匹配是否为真正的漏洞。"
                )
            else:
                result["message"] = f"未发现 {pattern_type} 相关的漏洞模式。"

            return result

        except Exception as e:
            logger.error(f"Check vulnerability pattern failed: {e}")
            return {
                "success": False,
                "error": f"漏洞模式检查失败: {str(e)}",
            }

    def _identify_security_markers(
        self,
        callers: List[Dict[str, Any]],
        callees: List[Dict[str, Any]],
        include_sources: bool,
        include_sinks: bool,
    ) -> Dict[str, List[str]]:
        """识别调用链中的安全相关标记

        Args:
            callers: 调用者列表
            callees: 被调用者列表
            include_sources: 是否标记 source
            include_sinks: 是否标记 sink

        Returns:
            安全标记字典
        """
        markers = {"sources": [], "sinks": [], "sanitizers": []}

        source_patterns = [
            "request", "input", "argv", "environ", "stdin",
            "get", "post", "query", "param", "body",
        ]
        sink_patterns = [
            "exec", "eval", "system", "popen", "execute",
            "write", "open", "send", "query", "render",
        ]
        sanitizer_patterns = [
            "escape", "quote", "sanitize", "validate", "encode",
            "filter", "clean", "safe", "check",
        ]

        # 检查调用者是否包含 source
        if include_sources:
            for caller in callers:
                caller_name = caller.get("caller", "").lower()
                for pattern in source_patterns:
                    if pattern in caller_name:
                        markers["sources"].append(caller.get("caller"))
                        break

        # 检查被调用者是否包含 sink
        if include_sinks:
            for callee in callees:
                callee_name = str(callee).lower()
                for pattern in sink_patterns:
                    if pattern in callee_name:
                        markers["sinks"].append(str(callee))
                        break

        # 检查是否有 sanitizer
        all_symbols = [c.get("caller", "") for c in callers] + [str(c) for c in callees]
        for symbol in all_symbols:
            symbol_lower = symbol.lower()
            for pattern in sanitizer_patterns:
                if pattern in symbol_lower:
                    markers["sanitizers"].append(symbol)
                    break

        return markers

    def _get_default_system_prompt(self) -> str:
        """获取默认系统提示词"""
        return """# 角色定位

你是一位资深的代码安全审计专家，具备十年以上的代码审计和漏洞挖掘经验。你将使用一套类似 IDE 的代码导航工具，像人类安全专家一样系统化地阅读、理解和分析代码。

# 可用工具

你可以使用以下工具来导航和分析代码：

## 搜索与发现
- **search_code**: 语义搜索，根据功能描述查找相关代码（如"用户登录验证"、"文件上传处理"）
- **grep_code**: 精确搜索，基于正则/关键词查找代码（如"os.system"、"eval("），适合查找特定函数调用
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
