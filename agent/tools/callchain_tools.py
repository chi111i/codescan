"""
调用链分析工具 - 封装为 LLM Function Calling 格式

提供：
1. analyze_call_chain - 分析完整调用链
2. trace_taint_path - 追踪污点传播路径
3. analyze_callers - 查找调用者（高级版，与 registry.py 中的 get_callers 区分）
4. analyze_callees - 查找被调用者（高级版，与 registry.py 中的 get_callees 区分）
5. list_entry_points - 列出入口点
6. list_sink_sites - 列出危险函数调用点
"""

import fnmatch
import logging
from typing import Dict, Any, List, Optional, Callable

logger = logging.getLogger(__name__)


# ============ 工具定义（OpenAI Function Calling 格式）============

CALLCHAIN_TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "analyze_call_chain",
            "description": """分析函数的完整调用关系链。

功能：
- 查找函数的所有调用者和被调用者
- 识别调用链中的 Source（输入源）、Sink（危险函数）、Sanitizer（过滤函数）
- 计算调用深度和风险等级

使用场景：
- 理解某个函数在系统中的角色
- 追踪用户输入如何传递到危险函数
- 评估修改某函数的影响范围""",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "要分析的函数/方法名。支持类方法格式如 'ClassName.method_name'"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定在特定文件中查找（用于同名函数区分）"
                    },
                    "direction": {
                        "type": "string",
                        "description": "分析方向：both（双向）、callers（仅调用者）、callees（仅被调用者）",
                        "enum": ["both", "callers", "callees"],
                        "default": "both"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "最大追溯深度（默认 3，最大 10）",
                        "default": 3,
                        "minimum": 1,
                        "maximum": 10
                    },
                    "include_code": {
                        "type": "boolean",
                        "description": "是否包含各节点的代码片段（会增加输出长度）",
                        "default": False
                    },
                    "highlight_security": {
                        "type": "boolean",
                        "description": "是否高亮标记 Source/Sink/Sanitizer 节点",
                        "default": True
                    }
                },
                "required": ["symbol_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "trace_taint_path",
            "description": """追踪污点数据传播路径（从 Source 到 Sink）。

功能：
- 从指定的输入源追踪数据如何流向危险函数
- 识别路径上是否存在安全过滤（Sanitizer）
- 评估路径的风险等级和置信度

使用场景：
- 验证用户输入是否能够到达 SQL 执行、命令执行等危险函数
- 检查数据流路径上是否有适当的过滤/验证
- 评估漏洞的可利用性""",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_symbol": {
                        "type": "string",
                        "description": "污点源函数名（如 'request.get_json'）。不指定则查找所有 Source"
                    },
                    "sink_symbol": {
                        "type": "string",
                        "description": "危险函数名（如 'cursor.execute'）。不指定则查找所有 Sink"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定在特定文件或目录中查找"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "最大路径深度（默认 10）",
                        "default": 10
                    },
                    "only_unsanitized": {
                        "type": "boolean",
                        "description": "是否只返回未经安全过滤的高风险路径",
                        "default": False
                    },
                    "max_paths": {
                        "type": "integer",
                        "description": "最大返回路径数量（默认 20）",
                        "default": 20
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_callers",
            "description": """查找谁调用了指定函数（向上追溯调用链）- 高级版本。

与基础版 get_callers 的区别：
- 支持更深层次的调用链追溯
- 可识别安全相关节点（Source/Sink/Sanitizer）
- 提供风险等级标注

使用场景：
- 找到函数的所有使用位置
- 分析修改函数的影响范围
- 追踪数据来源""",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "要查找调用者的函数名"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定在特定文件中查找"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "向上追溯深度（1=直接调用者，2=间接调用者）",
                        "default": 1
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "最大返回数量",
                        "default": 20
                    }
                },
                "required": ["symbol_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_callees",
            "description": """查找指定函数调用了哪些其他函数（向下追溯调用链）- 高级版本。

与基础版 get_callees 的区别：
- 支持更深层次的调用链追溯
- 可识别安全相关节点（Source/Sink/Sanitizer）
- 提供风险等级标注

使用场景：
- 分析函数的依赖关系
- 追踪数据流向危险函数
- 理解函数的内部行为""",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "要分析的函数名"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定在特定文件中查找"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "向下追溯深度（1=直接调用，2=间接调用）",
                        "default": 1
                    },
                    "include_external": {
                        "type": "boolean",
                        "description": "是否包含外部库函数",
                        "default": True
                    }
                },
                "required": ["symbol_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_entry_points",
            "description": """列出项目的入口点（HTTP 路由、API 端点、命令行入口等）。

入口点是用户输入进入系统的起始位置，是安全分析的关键起点。

使用场景：
- 发现所有对外暴露的接口
- 作为污点分析的起点
- 识别需要重点审计的代码路径""",
            "parameters": {
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "description": "限定框架类型",
                        "enum": ["flask", "django", "fastapi", "express", "spring", "laravel", "auto"],
                        "default": "auto"
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "文件路径模式过滤，如 '**/api/*.py'"
                    },
                    "include_internal": {
                        "type": "boolean",
                        "description": "是否包含内部 API（非 public）",
                        "default": False
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
            "name": "list_sink_sites",
            "description": """列出代码中的危险函数调用点（Sink Sites）。

Sink 是数据流向的危险终点，如 SQL 执行、命令执行、文件操作等。

使用场景：
- 快速定位所有可能存在漏洞的位置
- 作为代码审计的切入点
- 统计项目中的风险分布""",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "危险函数类别过滤",
                        "enum": [
                            "all",
                            "sql_injection",
                            "command_injection",
                            "code_execution",
                            "file_operation",
                            "deserialization",
                            "ssrf",
                            "xxe"
                        ],
                        "default": "all"
                    },
                    "risk_level": {
                        "type": "string",
                        "description": "风险等级过滤",
                        "enum": ["all", "critical", "high", "medium", "low"],
                        "default": "all"
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "文件路径模式过滤"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "最大返回数量",
                        "default": 50
                    }
                }
            }
        }
    }
]


# ============ 工具执行器类 ============

class CallChainToolExecutor:
    """调用链工具执行器

    封装 CallChainAnalyzer，提供工具执行接口。
    """

    def __init__(
        self,
        call_chain_analyzer,
        code_units: List = None,
        indexer = None,
    ):
        """初始化执行器

        Args:
            call_chain_analyzer: CallChainAnalyzer 实例
            code_units: 代码单元列表（用于查找代码）
            indexer: CodeIndexer 实例（用于读取代码）
        """
        self.analyzer = call_chain_analyzer
        self.code_units = code_units or []
        self.indexer = indexer

        # 建立符号到代码单元的映射
        self._unit_by_symbol: Dict[str, List] = {}
        for unit in self.code_units:
            if unit.symbol not in self._unit_by_symbol:
                self._unit_by_symbol[unit.symbol] = []
            self._unit_by_symbol[unit.symbol].append(unit)

    def analyze_call_chain(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行 analyze_call_chain 工具"""
        symbol_name = args.get("symbol_name")
        file_path = args.get("file_path")
        direction = args.get("direction", "both")
        max_depth = min(args.get("max_depth", 3), 10)
        include_code = args.get("include_code", False)
        highlight_security = args.get("highlight_security", True)

        if not symbol_name:
            return {"success": False, "error": "symbol_name 是必需参数"}

        # 在调用图中查找节点
        nodes = self.analyzer.call_graph.get_nodes_by_name(symbol_name)

        if file_path:
            nodes = [n for n in nodes if file_path in n.file_path]

        if not nodes:
            return {
                "success": False,
                "error": f"未找到符号: {symbol_name}",
                "suggestion": "请检查符号名称是否正确，或使用 search_code 工具查找"
            }

        # 取第一个匹配的节点
        target_node = nodes[0]
        result = {
            "success": True,
            "symbol": target_node.qualified_name,
            "file_path": target_node.file_path,
            "line": f"{target_node.line_start}-{target_node.line_end}",
            "node_type": target_node.node_type.value,
        }

        # 收集调用者
        if direction in ("both", "callers"):
            callers = self._collect_chain(
                target_node.id,
                direction="callers",
                max_depth=max_depth,
                include_code=include_code,
                highlight_security=highlight_security,
            )
            result["callers"] = callers

        # 收集被调用者
        if direction in ("both", "callees"):
            callees = self._collect_chain(
                target_node.id,
                direction="callees",
                max_depth=max_depth,
                include_code=include_code,
                highlight_security=highlight_security,
            )
            result["callees"] = callees

        # 统计
        result["statistics"] = {
            "callers_count": len(result.get("callers", [])),
            "callees_count": len(result.get("callees", [])),
            "max_depth_used": max_depth,
        }

        return result

    def _collect_chain(
        self,
        node_id: str,
        direction: str,
        max_depth: int,
        include_code: bool,
        highlight_security: bool,
    ) -> List[Dict[str, Any]]:
        """收集调用链"""
        collected = []
        visited = {node_id}
        queue = [(node_id, 0)]

        while queue:
            current_id, depth = queue.pop(0)

            if depth >= max_depth:
                continue

            # 获取下一级节点
            if direction == "callers":
                next_nodes = self.analyzer.call_graph.get_callers(current_id)
            else:
                next_nodes = self.analyzer.call_graph.get_callees(current_id)

            for node in next_nodes:
                if node.id in visited:
                    continue

                visited.add(node.id)
                queue.append((node.id, depth + 1))

                node_info = {
                    "name": node.qualified_name,
                    "file_path": node.file_path,
                    "line": node.line_start,
                    "depth": depth + 1,
                }

                if highlight_security:
                    node_info["node_type"] = node.node_type.value
                    if node.risk_level:
                        node_info["risk_level"] = node.risk_level

                if include_code:
                    code = self._get_node_code(node)
                    if code:
                        node_info["code"] = code[:500]  # 限制长度

                collected.append(node_info)

        return collected

    def _get_node_code(self, node) -> Optional[str]:
        """获取节点的代码"""
        # 从 code_units 查找
        units = self._unit_by_symbol.get(node.name, [])
        for unit in units:
            if unit.file_path == node.file_path:
                return unit.code
        return None

    def trace_taint_path(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行 trace_taint_path 工具"""
        source_symbol = args.get("source_symbol")
        sink_symbol = args.get("sink_symbol")
        max_depth = args.get("max_depth", 10)
        only_unsanitized = args.get("only_unsanitized", False)
        max_paths = args.get("max_paths", 20)

        # 查找污点路径
        taint_paths = self.analyzer.find_taint_paths(
            max_depth=max_depth,
            max_paths=max_paths * 2,  # 预留过滤空间
        )

        # 过滤
        filtered_paths = []
        for path in taint_paths:
            # 按 source 过滤
            if source_symbol:
                source_node = self.analyzer.call_graph.get_node(path.source_node)
                if source_node and source_symbol.lower() not in source_node.name.lower():
                    continue

            # 按 sink 过滤
            if sink_symbol:
                sink_node = self.analyzer.call_graph.get_node(path.sink_node)
                if sink_node and sink_symbol.lower() not in sink_node.name.lower():
                    continue

            # 按是否过滤过滤
            if only_unsanitized and path.is_sanitized:
                continue

            filtered_paths.append(path)

            if len(filtered_paths) >= max_paths:
                break

        # 转换结果
        results = []
        for path in filtered_paths:
            source_node = self.analyzer.call_graph.get_node(path.source_node)
            sink_node = self.analyzer.call_graph.get_node(path.sink_node)

            path_info = {
                "id": path.id,
                "source": {
                    "name": source_node.qualified_name if source_node else path.source_node,
                    "file_path": source_node.file_path if source_node else "",
                    "line": source_node.line_start if source_node else 0,
                },
                "sink": {
                    "name": sink_node.qualified_name if sink_node else path.sink_node,
                    "file_path": sink_node.file_path if sink_node else "",
                    "line": sink_node.line_start if sink_node else 0,
                },
                "path_length": len(path.path),
                "is_sanitized": path.is_sanitized,
                "sanitizers": path.sanitizers,
                "risk_level": path.risk_level,
                "confidence": path.confidence,
                "description": path.description,
            }

            # 展开路径节点
            path_nodes = []
            for node_id in path.path:
                node = self.analyzer.call_graph.get_node(node_id)
                if node:
                    path_nodes.append({
                        "name": node.qualified_name,
                        "type": node.node_type.value,
                    })
            path_info["path_nodes"] = path_nodes

            results.append(path_info)

        return {
            "success": True,
            "total_found": len(results),
            "paths": results,
            "summary": f"找到 {len(results)} 条{'未过滤的' if only_unsanitized else ''}污点传播路径"
        }

    def analyze_callers(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行 analyze_callers 工具（调用链高级版）"""
        symbol_name = args.get("symbol_name")
        file_path = args.get("file_path")
        max_depth = args.get("max_depth", 1)
        max_results = args.get("max_results", 20)

        if not symbol_name:
            return {"success": False, "error": "symbol_name 是必需参数"}

        nodes = self.analyzer.call_graph.get_nodes_by_name(symbol_name)
        if file_path:
            nodes = [n for n in nodes if file_path in n.file_path]

        if not nodes:
            return {"success": False, "error": f"未找到符号: {symbol_name}"}

        target_node = nodes[0]
        callers = self._collect_chain(
            target_node.id,
            direction="callers",
            max_depth=max_depth,
            include_code=False,
            highlight_security=True,
        )

        return {
            "success": True,
            "symbol": target_node.qualified_name,
            "callers": callers[:max_results],
            "total": len(callers),
        }

    def analyze_callees(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行 analyze_callees 工具（调用链高级版）"""
        symbol_name = args.get("symbol_name")
        file_path = args.get("file_path")
        max_depth = args.get("max_depth", 1)
        include_external = args.get("include_external", True)

        if not symbol_name:
            return {"success": False, "error": "symbol_name 是必需参数"}

        nodes = self.analyzer.call_graph.get_nodes_by_name(symbol_name)
        if file_path:
            nodes = [n for n in nodes if file_path in n.file_path]

        if not nodes:
            return {"success": False, "error": f"未找到符号: {symbol_name}"}

        target_node = nodes[0]
        callees = self._collect_chain(
            target_node.id,
            direction="callees",
            max_depth=max_depth,
            include_code=False,
            highlight_security=True,
        )

        # 过滤外部函数
        if not include_external:
            callees = [c for c in callees if not c.get("file_path", "").startswith("<external>")]

        return {
            "success": True,
            "symbol": target_node.qualified_name,
            "callees": callees,
            "total": len(callees),
        }

    def list_entry_points(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行 list_entry_points 工具"""
        file_pattern = args.get("file_pattern")
        max_results = args.get("max_results", 50)
        framework = args.get("framework", "auto")
        include_internal = args.get("include_internal", False)

        entry_points = self.analyzer.call_graph.get_entry_points()

        # 文件模式过滤
        if file_pattern:
            entry_points = [
                ep for ep in entry_points
                if fnmatch.fnmatch(ep.file_path, file_pattern)
            ]

        # 框架过滤：根据 decorators 匹配框架特征
        if framework and framework != "auto":
            framework_decorator_patterns = {
                "flask": ["route", "blueprint"],
                "django": ["url", "path"],
                "fastapi": ["get", "post", "put", "delete", "patch", "router", "app"],
                "express": ["get", "post", "put", "delete", "patch", "use"],
                "spring": ["mapping", "getmapping", "postmapping", "putmapping", "deletemapping", "requestmapping"],
                "laravel": ["route", "middleware"],
            }
            fw_keywords = framework_decorator_patterns.get(framework, [])
            if fw_keywords:
                filtered_eps = []
                for ep in entry_points:
                    decorators = ep.metadata.get("decorators", [])
                    decorator_str = " ".join(str(d).lower() for d in decorators)
                    if any(kw in decorator_str for kw in fw_keywords):
                        filtered_eps.append(ep)
                entry_points = filtered_eps

        # 内部 API 过滤
        if not include_internal:
            entry_points = [
                ep for ep in entry_points
                if not ep.name.startswith("_") and not ep.metadata.get("internal", False)
            ]

        results = []
        for ep in entry_points[:max_results]:
            results.append({
                "name": ep.qualified_name,
                "file_path": ep.file_path,
                "line": ep.line_start,
                "decorators": ep.metadata.get("decorators", []),
            })

        return {
            "success": True,
            "entry_points": results,
            "total": len(entry_points),
        }

    def list_sink_sites(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行 list_sink_sites 工具"""
        category = args.get("category", "all")
        risk_level = args.get("risk_level", "all")
        file_pattern = args.get("file_pattern")
        max_results = args.get("max_results", 50)

        sinks = self.analyzer.call_graph.get_sinks()

        # 过滤
        filtered = []
        for sink in sinks:
            # 风险等级过滤
            if risk_level != "all" and sink.risk_level != risk_level:
                continue

            # 类别过滤：从 matched_rules 规则 ID 和 metadata 推断 category
            if category != "all":
                # 定义 category 关键词映射
                category_keywords = {
                    "sql_injection": ["sql", "sqli", "query", "injection"],
                    "command_injection": ["command", "cmd", "rce", "os_system", "exec", "shell"],
                    "code_execution": ["eval", "code_exec", "code_execution", "dynamic"],
                    "file_operation": ["file", "path", "read", "write", "upload", "download"],
                    "deserialization": ["deserial", "pickle", "yaml_load", "unserialize", "marshal"],
                    "ssrf": ["ssrf", "url", "request", "fetch", "curl"],
                    "xxe": ["xxe", "xml", "entity"],
                }
                keywords = category_keywords.get(category, [])
                if keywords:
                    rules_str = " ".join(str(r).lower() for r in (sink.matched_rules or []))
                    meta_category = str(sink.metadata.get("category", "")).lower() if hasattr(sink, 'metadata') and sink.metadata else ""
                    combined = f"{rules_str} {meta_category}"
                    if not any(kw in combined for kw in keywords):
                        continue

            # 文件过滤
            if file_pattern:
                if not fnmatch.fnmatch(sink.file_path, file_pattern):
                    continue

            filtered.append(sink)

        results = []
        for sink in filtered[:max_results]:
            results.append({
                "name": sink.qualified_name,
                "file_path": sink.file_path,
                "line": sink.line_start,
                "risk_level": sink.risk_level,
                "matched_rules": sink.matched_rules,
            })

        return {
            "success": True,
            "sink_sites": results,
            "total": len(filtered),
        }

    def get_executors(self) -> Dict[str, Callable]:
        """返回所有执行器映射"""
        return {
            "analyze_call_chain": self.analyze_call_chain,
            "trace_taint_path": self.trace_taint_path,
            "analyze_callers": self.analyze_callers,
            "analyze_callees": self.analyze_callees,
            "list_entry_points": self.list_entry_points,
            "list_sink_sites": self.list_sink_sites,
        }


def get_callchain_tool_definitions() -> List[Dict[str, Any]]:
    """获取调用链工具定义列表"""
    return CALLCHAIN_TOOL_DEFINITIONS.copy()


def create_callchain_executor(
    call_chain_analyzer,
    code_units: List = None,
    indexer = None,
) -> CallChainToolExecutor:
    """创建调用链工具执行器"""
    return CallChainToolExecutor(
        call_chain_analyzer=call_chain_analyzer,
        code_units=code_units,
        indexer=indexer,
    )
