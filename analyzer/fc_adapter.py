"""
Function Calling 适配器 - 统一 LLM 分析接口

为 SecurityAnalyzer 提供 Function Calling 模式支持，
使快速扫描和交互审计使用统一的 LLM 交互模式。

核心功能：
1. 封装 LLM Function Calling 调用逻辑
2. 管理工具注册和执行
3. 支持多轮工具调用循环
4. 提供回调接口用于实时展示
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any, Callable, Union

from llm_client import BaseLLMClient, ChatMessage, ToolCall

logger = logging.getLogger(__name__)


class FCToolStatus(Enum):
    """工具调用状态"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


@dataclass
class FCToolCall:
    """Function Calling 工具调用记录"""
    id: str
    tool_name: str
    arguments: Dict[str, Any]
    status: FCToolStatus = FCToolStatus.PENDING
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
class FCAnalysisResult:
    """Function Calling 分析结果"""
    content: str  # 最终分析内容
    tool_calls: List[FCToolCall] = field(default_factory=list)
    total_llm_calls: int = 0
    total_tokens: int = 0
    duration_ms: int = 0
    has_issue: bool = False
    parsed_result: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "tool_calls": [tc.to_dict() for tc in self.tool_calls],
            "total_llm_calls": self.total_llm_calls,
            "total_tokens": self.total_tokens,
            "duration_ms": self.duration_ms,
            "has_issue": self.has_issue,
            "parsed_result": self.parsed_result,
        }


@dataclass
class FCAdapterConfig:
    """Function Calling 适配器配置"""
    # LLM 配置
    max_tool_calls_per_turn: int = 5  # 每轮最大工具调用次数
    max_turns: int = 10  # 最大轮数
    temperature: float = 0.1
    max_tokens: int = 3000

    # 回调配置
    on_tool_call_start: Optional[Callable[[FCToolCall], None]] = None
    on_tool_call_end: Optional[Callable[[FCToolCall], None]] = None
    on_llm_thinking: Optional[Callable[[str], None]] = None
    on_llm_response: Optional[Callable[[str], None]] = None

    # 日志
    enable_debug_logging: bool = False


class FCSecurityTools:
    """安全分析专用工具集

    提供给 Function Calling 使用的安全分析工具。
    这些工具专注于代码分析场景。
    """

    def __init__(
        self,
        indexer=None,
        code_units: List = None,
        call_chain_analyzer=None,
        rule_manager=None,
    ):
        self.indexer = indexer
        self.code_units = code_units or []
        self.call_chain_analyzer = call_chain_analyzer
        self.rule_manager = rule_manager

        # 构建符号到代码单元的映射
        self._symbol_map: Dict[str, Any] = {}
        self._file_map: Dict[str, List[Any]] = {}
        self._build_maps()

    def _build_maps(self):
        """构建查找映射"""
        for unit in self.code_units:
            # 符号映射
            self._symbol_map[unit.symbol] = unit
            if hasattr(unit, 'parent_class') and unit.parent_class:
                full_name = f"{unit.parent_class}.{unit.symbol}"
                self._symbol_map[full_name] = unit

            # 文件映射
            if unit.file_path not in self._file_map:
                self._file_map[unit.file_path] = []
            self._file_map[unit.file_path].append(unit)

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """获取工具定义（OpenAI Function Calling 格式）"""
        return [
            {
                "type": "function",
                "function": {
                    "name": "read_function_code",
                    "description": "读取指定函数或方法的完整代码。用于查看函数实现细节。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "symbol": {
                                "type": "string",
                                "description": "函数或方法名称，例如 'process_upload' 或 'UserController.login'"
                            }
                        },
                        "required": ["symbol"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "find_callers",
                    "description": "查找调用指定函数的所有位置。用于追踪函数的调用来源。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "symbol": {
                                "type": "string",
                                "description": "要查找调用者的函数名称"
                            },
                            "max_results": {
                                "type": "integer",
                                "description": "最大返回数量，默认 10",
                                "default": 10
                            }
                        },
                        "required": ["symbol"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "find_callees",
                    "description": "查找指定函数调用的所有函数。用于追踪函数的调用链。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "symbol": {
                                "type": "string",
                                "description": "要查找被调用函数的函数名称"
                            }
                        },
                        "required": ["symbol"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "search_code",
                    "description": "在代码库中搜索包含指定关键词的代码。用于查找相关代码片段。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "搜索关键词或模式"
                            },
                            "max_results": {
                                "type": "integer",
                                "description": "最大返回数量，默认 5",
                                "default": 5
                            }
                        },
                        "required": ["query"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "list_file_functions",
                    "description": "列出指定文件中的所有函数和类。用于了解文件结构。",
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
            },
            {
                "type": "function",
                "function": {
                    "name": "get_call_chain",
                    "description": "获取从入口点到目标函数的调用链路径。用于分析攻击路径。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target_symbol": {
                                "type": "string",
                                "description": "目标函数名称（通常是 sink 函数）"
                            },
                            "max_depth": {
                                "type": "integer",
                                "description": "最大搜索深度，默认 5",
                                "default": 5
                            }
                        },
                        "required": ["target_symbol"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "check_sanitization",
                    "description": "检查指定代码路径上是否有输入验证或过滤。用于判断漏洞是否可利用。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "symbols": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "要检查的函数符号列表（调用链上的函数）"
                            }
                        },
                        "required": ["symbols"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "report_finding",
                    "description": "报告发现的安全问题。当确认存在漏洞时调用此工具。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "has_issue": {
                                "type": "boolean",
                                "description": "是否存在安全问题"
                            },
                            "issue_type": {
                                "type": "string",
                                "description": "问题类型，如 command_injection, sql_injection"
                            },
                            "severity": {
                                "type": "string",
                                "enum": ["low", "medium", "high", "critical"],
                                "description": "严重程度"
                            },
                            "confidence": {
                                "type": "number",
                                "description": "置信度 0-1"
                            },
                            "summary": {
                                "type": "string",
                                "description": "问题摘要"
                            },
                            "details": {
                                "type": "string",
                                "description": "详细分析"
                            },
                            "attack_scenario": {
                                "type": "string",
                                "description": "攻击场景描述"
                            },
                            "fix_suggestion": {
                                "type": "string",
                                "description": "修复建议"
                            }
                        },
                        "required": ["has_issue"]
                    }
                }
            }
        ]

    def execute(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """执行工具"""
        tool_map = {
            "read_function_code": self._read_function_code,
            "find_callers": self._find_callers,
            "find_callees": self._find_callees,
            "search_code": self._search_code,
            "list_file_functions": self._list_file_functions,
            "get_call_chain": self._get_call_chain,
            "check_sanitization": self._check_sanitization,
            "report_finding": self._report_finding,
        }

        if tool_name not in tool_map:
            return {"success": False, "error": f"未知工具: {tool_name}"}

        try:
            return tool_map[tool_name](arguments)
        except Exception as e:
            logger.error(f"工具执行失败 {tool_name}: {e}")
            return {"success": False, "error": str(e)}

    def _read_function_code(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """读取函数代码"""
        symbol = args.get("symbol", "")

        unit = self._symbol_map.get(symbol)
        if not unit:
            # 尝试模糊匹配
            for key, u in self._symbol_map.items():
                if symbol in key or key in symbol:
                    unit = u
                    break

        if not unit:
            return {
                "success": False,
                "error": f"未找到函数: {symbol}",
                "available_symbols": list(self._symbol_map.keys())[:20]
            }

        return {
            "success": True,
            "symbol": unit.symbol,
            "file_path": unit.file_path,
            "line_start": unit.span.start_line,
            "line_end": unit.span.end_line,
            "code": unit.code,
            "calls": unit.calls if hasattr(unit, 'calls') else [],
        }

    def _find_callers(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """查找调用者"""
        symbol = args.get("symbol", "")
        max_results = args.get("max_results", 10)

        callers = []
        for unit in self.code_units:
            if hasattr(unit, 'calls') and symbol in unit.calls:
                callers.append({
                    "symbol": unit.symbol,
                    "file_path": unit.file_path,
                    "line": unit.span.start_line,
                })
                if len(callers) >= max_results:
                    break

        return {
            "success": True,
            "target": symbol,
            "callers": callers,
            "total": len(callers),
        }

    def _find_callees(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """查找被调用函数"""
        symbol = args.get("symbol", "")

        unit = self._symbol_map.get(symbol)
        if not unit:
            return {"success": False, "error": f"未找到函数: {symbol}"}

        callees = []
        if hasattr(unit, 'calls'):
            for call in unit.calls:
                callee_unit = self._symbol_map.get(call)
                if callee_unit:
                    callees.append({
                        "symbol": call,
                        "file_path": callee_unit.file_path,
                        "defined": True,
                    })
                else:
                    callees.append({
                        "symbol": call,
                        "defined": False,
                    })

        return {
            "success": True,
            "source": symbol,
            "callees": callees,
        }

    def _search_code(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """搜索代码"""
        query = args.get("query", "")
        max_results = args.get("max_results", 5)

        results = []
        query_lower = query.lower()

        for unit in self.code_units:
            if query_lower in unit.code.lower() or query_lower in unit.symbol.lower():
                results.append({
                    "symbol": unit.symbol,
                    "file_path": unit.file_path,
                    "line_start": unit.span.start_line,
                    "snippet": unit.code[:200] + "..." if len(unit.code) > 200 else unit.code,
                })
                if len(results) >= max_results:
                    break

        return {
            "success": True,
            "query": query,
            "results": results,
            "total": len(results),
        }

    def _list_file_functions(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """列出文件中的函数"""
        file_path = args.get("file_path", "")

        # 规范化路径
        file_path = file_path.replace("\\", "/")

        units = []
        for path, file_units in self._file_map.items():
            if file_path in path.replace("\\", "/"):
                for unit in file_units:
                    units.append({
                        "symbol": unit.symbol,
                        "type": unit.unit_type.value if hasattr(unit.unit_type, 'value') else str(unit.unit_type),
                        "line_start": unit.span.start_line,
                        "line_end": unit.span.end_line,
                    })
                break

        return {
            "success": True,
            "file_path": file_path,
            "functions": units,
            "total": len(units),
        }

    def _get_call_chain(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """获取调用链"""
        target_symbol = args.get("target_symbol", "")
        max_depth = args.get("max_depth", 5)

        if not self.call_chain_analyzer:
            return {"success": False, "error": "调用链分析器未初始化"}

        try:
            paths = self.call_chain_analyzer.find_paths_to_sink(
                target_symbol,
                max_depth=max_depth,
                max_paths=5,
            )

            chains = []
            for path in paths:
                chains.append({
                    "path": path,
                    "depth": len(path),
                })

            return {
                "success": True,
                "target": target_symbol,
                "chains": chains,
                "total": len(chains),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _check_sanitization(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """检查净化措施"""
        symbols = args.get("symbols", [])

        sanitization_patterns = [
            "escape", "sanitize", "validate", "filter", "clean",
            "htmlspecialchars", "addslashes", "mysql_real_escape",
            "prepared_statement", "parameterized", "bind_param",
            "strip_tags", "preg_replace", "intval", "floatval",
        ]

        results = []
        has_sanitization = False

        for symbol in symbols:
            unit = self._symbol_map.get(symbol)
            if not unit:
                continue

            code_lower = unit.code.lower()
            found_patterns = []

            for pattern in sanitization_patterns:
                if pattern in code_lower:
                    found_patterns.append(pattern)
                    has_sanitization = True

            results.append({
                "symbol": symbol,
                "has_sanitization": len(found_patterns) > 0,
                "patterns_found": found_patterns,
            })

        return {
            "success": True,
            "results": results,
            "overall_has_sanitization": has_sanitization,
        }

    def _report_finding(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """报告发现"""
        return {
            "success": True,
            "finding_reported": True,
            "data": args,
        }


class FunctionCallingAdapter:
    """Function Calling 适配器

    封装 LLM Function Calling 逻辑，提供统一的分析接口。

    Usage:
        adapter = FunctionCallingAdapter(
            llm_client=llm_client,
            tools=security_tools,
            config=FCAdapterConfig(),
        )

        result = adapter.analyze(
            system_prompt="你是安全分析专家...",
            user_prompt="请分析以下代码...",
        )
    """

    def __init__(
        self,
        llm_client: BaseLLMClient,
        tools: FCSecurityTools,
        config: Optional[FCAdapterConfig] = None,
    ):
        self.llm_client = llm_client
        self.tools = tools
        self.config = config or FCAdapterConfig()

        # 获取工具定义
        self.tool_definitions = tools.get_tool_definitions()

        # 统计
        self.total_llm_calls = 0
        self.total_tokens = 0

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        context: Optional[str] = None,
    ) -> FCAnalysisResult:
        """执行 Function Calling 分析

        Args:
            system_prompt: 系统提示词
            user_prompt: 用户提示词
            context: 额外上下文（会追加到用户提示）

        Returns:
            FCAnalysisResult 分析结果
        """
        start_time = time.time()

        # 构建消息
        messages = [
            ChatMessage(role="system", content=system_prompt),
        ]

        if context:
            user_prompt = f"{user_prompt}\n\n【额外上下文】\n{context}"

        messages.append(ChatMessage(role="user", content=user_prompt))

        # 记录工具调用
        all_tool_calls: List[FCToolCall] = []
        final_content = ""
        parsed_result = None

        # 多轮对话循环
        for turn in range(self.config.max_turns):
            logger.debug(f"[FCAdapter] Turn {turn + 1}/{self.config.max_turns}")

            # 通知 LLM 开始思考
            if self.config.on_llm_thinking:
                self.config.on_llm_thinking(f"第 {turn + 1} 轮分析中...")

            # 调用 LLM
            try:
                response = self.llm_client.chat_completion(
                    messages=messages,
                    tools=self.tool_definitions,
                    tool_choice="auto",
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                )
                self.total_llm_calls += 1
                if response.usage:
                    self.total_tokens += response.usage.get("total_tokens", 0)

            except Exception as e:
                logger.error(f"[FCAdapter] LLM 调用失败: {e}")
                return FCAnalysisResult(
                    content=f"LLM 调用失败: {e}",
                    tool_calls=all_tool_calls,
                    total_llm_calls=self.total_llm_calls,
                    total_tokens=self.total_tokens,
                    duration_ms=int((time.time() - start_time) * 1000),
                )

            # 如果有中间思考内容，通知回调
            if response.content and self.config.on_llm_thinking:
                # 仅在有工具调用时推送中间思考
                if response.tool_calls:
                    self.config.on_llm_thinking(response.content[:500])

            # 检查是否有工具调用
            if response.tool_calls:
                # 执行工具调用
                tool_results = self._execute_tool_calls(response.tool_calls, all_tool_calls)

                # 将工具调用和结果添加到消息历史
                messages.append(ChatMessage(
                    role="assistant",
                    content=response.content or "",
                    tool_calls=response.tool_calls,
                ))

                for tool_call, result in zip(response.tool_calls, tool_results):
                    messages.append(ChatMessage(
                        role="tool",
                        content=json.dumps(result, ensure_ascii=False, default=str),
                        tool_call_id=tool_call.id,
                    ))

                # 检查是否调用了 report_finding
                for tc in response.tool_calls:
                    if tc.function_name == "report_finding":
                        try:
                            parsed_result = json.loads(tc.function_arguments)
                        except:
                            pass

            else:
                # 没有工具调用，返回最终结果
                final_content = response.content or ""

                # 尝试从内容中解析 JSON
                if not parsed_result:
                    parsed_result = self._parse_json_response(final_content)

                # 通知回调
                if self.config.on_llm_response:
                    self.config.on_llm_response(final_content)

                break

        # 确定是否有问题
        has_issue = False
        if parsed_result:
            has_issue = parsed_result.get("has_issue", False)

        return FCAnalysisResult(
            content=final_content,
            tool_calls=all_tool_calls,
            total_llm_calls=self.total_llm_calls,
            total_tokens=self.total_tokens,
            duration_ms=int((time.time() - start_time) * 1000),
            has_issue=has_issue,
            parsed_result=parsed_result,
        )

    def _execute_tool_calls(
        self,
        tool_calls: List[ToolCall],
        all_tool_calls: List[FCToolCall],
    ) -> List[Dict[str, Any]]:
        """执行工具调用"""
        results = []

        for tc in tool_calls[:self.config.max_tool_calls_per_turn]:
            # 创建记录
            fc_call = FCToolCall(
                id=tc.id,
                tool_name=tc.function_name,
                arguments=self._safe_parse_json(tc.function_arguments),
                status=FCToolStatus.RUNNING,
                started_at=datetime.now(),
            )
            all_tool_calls.append(fc_call)

            # 回调
            if self.config.on_tool_call_start:
                self.config.on_tool_call_start(fc_call)

            # 执行
            try:
                result = self.tools.execute(tc.function_name, fc_call.arguments)
                fc_call.result = result
                fc_call.status = FCToolStatus.SUCCESS if result.get("success", True) else FCToolStatus.FAILED
            except Exception as e:
                result = {"success": False, "error": str(e)}
                fc_call.error = str(e)
                fc_call.status = FCToolStatus.FAILED

            fc_call.finished_at = datetime.now()
            fc_call.duration_ms = int((fc_call.finished_at - fc_call.started_at).total_seconds() * 1000)

            # 回调
            if self.config.on_tool_call_end:
                self.config.on_tool_call_end(fc_call)

            results.append(result)

            logger.debug(
                f"[FCAdapter] Tool {tc.function_name}: "
                f"{'SUCCESS' if fc_call.status == FCToolStatus.SUCCESS else 'FAILED'} "
                f"({fc_call.duration_ms}ms)"
            )

        return results

    def _safe_parse_json(self, json_str: str) -> Dict[str, Any]:
        """安全解析 JSON"""
        try:
            return json.loads(json_str) if json_str else {}
        except:
            return {}

    def _parse_json_response(self, content: str) -> Optional[Dict[str, Any]]:
        """从响应内容中解析 JSON"""
        import re

        # 尝试直接解析
        try:
            return json.loads(content)
        except:
            pass

        # 尝试提取 JSON 块
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', content)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except:
                pass

        # 尝试找到 { } 块
        brace_match = re.search(r'\{[\s\S]*\}', content)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except:
                pass

        return None
