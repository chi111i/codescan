"""
增强的安全分析 Agent - 支持调用链和污点分析
"""

import json
import logging
from typing import Optional, List, Dict, Any

from llm_client import BaseLLMClient, ChatMessage
from indexer import CodeReader, CodeIndexer
from agent.code_agent import CodeAnalysisAgent, AgentResult, ToolCallRecord
from agent.tools import SECURITY_ANALYSIS_TOOLS

logger = logging.getLogger(__name__)


class EnhancedSecurityAgent(CodeAnalysisAgent):
    """增强的安全分析 Agent

    在 CodeAnalysisAgent 基础上，增加对调用链和污点分析的支持。
    """

    def __init__(
        self,
        llm_client: BaseLLMClient,
        code_reader: CodeReader,
        indexer: CodeIndexer,
        call_chain_analyzer: Optional[Any] = None,
        taint_analyzer: Optional[Any] = None,
        **kwargs
    ):
        """初始化增强 Agent

        Args:
            llm_client: LLM 客户端
            code_reader: 代码读取器
            indexer: 代码索引器
            call_chain_analyzer: 调用链分析器（可选）
            taint_analyzer: 污点分析器（可选）
        """
        super().__init__(
            llm_client=llm_client,
            code_reader=code_reader,
            tools=SECURITY_ANALYSIS_TOOLS,
            **kwargs
        )

        self.indexer = indexer
        self.call_chain_analyzer = call_chain_analyzer
        self.taint_analyzer = taint_analyzer
        self._call_graph = None
        self._taint_flows = None

        # 注册增强工具
        self._register_enhanced_tools()

    def _register_enhanced_tools(self):
        """注册增强的安全分析工具"""
        self._tool_executors["analyze_call_chain"] = self._execute_analyze_call_chain
        self._tool_executors["trace_taint_path"] = self._execute_trace_taint_path
        self._tool_executors["get_code_context"] = self._execute_get_code_context
        self._tool_executors["check_vulnerability_pattern"] = self._execute_check_pattern

    def prepare_analysis(self, force_rebuild: bool = False):
        """准备分析环境

        构建调用图和污点分析（如果尚未构建）

        Args:
            force_rebuild: 是否强制重建
        """
        if self._call_graph is None or force_rebuild:
            if self.call_chain_analyzer:
                logger.info("构建调用图...")
                code_units = self.indexer.get_all_units()
                self._call_graph = self.call_chain_analyzer.build_call_graph(code_units)
                logger.info(f"调用图已构建: {len(self._call_graph.nodes)} 节点")

        if self._taint_flows is None or force_rebuild:
            if self.taint_analyzer and self._call_graph:
                logger.info("执行污点分析...")
                code_units = self.indexer.get_all_units()
                self._taint_flows = self.taint_analyzer.analyze_interprocedural(
                    code_units,
                    max_depth=10,
                )
                logger.info(f"污点分析完成: {len(self._taint_flows)} 条污点流")

    def _execute_analyze_call_chain(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行调用链分析"""
        if not self.call_chain_analyzer or not self._call_graph:
            return {
                "success": False,
                "error": "调用链分析器未初始化，请先运行 prepare_analysis()"
            }

        symbol_name = args.get("symbol_name", "")
        direction = args.get("direction", "both")
        max_depth = args.get("max_depth", 3)
        include_sources = args.get("include_sources", True)
        include_sinks = args.get("include_sinks", True)

        # 查找目标节点
        nodes = self._call_graph.get_nodes_by_name(symbol_name)
        if not nodes:
            return {
                "success": False,
                "error": f"未找到符号: {symbol_name}",
                "hint": "尝试使用 search_code 查找"
            }

        # 使用第一个匹配的节点
        target_node = nodes[0]

        # 获取调用链
        result = {
            "success": True,
            "symbol": symbol_name,
            "node_type": target_node.node_type.value,
            "file_path": target_node.file_path,
            "line": target_node.line_start,
        }

        # 获取调用者
        if direction in ("both", "callers"):
            callers_data = self._get_call_chain_data(
                target_node.id,
                direction="callers",
                max_depth=max_depth,
                include_sources=include_sources,
                include_sinks=include_sinks,
            )
            result["callers"] = callers_data

        # 获取被调用者
        if direction in ("both", "callees"):
            callees_data = self._get_call_chain_data(
                target_node.id,
                direction="callees",
                max_depth=max_depth,
                include_sources=include_sources,
                include_sinks=include_sinks,
            )
            result["callees"] = callees_data

        return result

    def _get_call_chain_data(
        self,
        node_id: str,
        direction: str,
        max_depth: int,
        include_sources: bool,
        include_sinks: bool,
    ) -> List[Dict[str, Any]]:
        """获取调用链数据"""
        chain_data = []
        visited = set()

        # BFS 遍历
        queue = [(node_id, 0)]

        while queue:
            current_id, depth = queue.pop(0)

            if current_id in visited or depth >= max_depth:
                continue

            visited.add(current_id)
            node = self._call_graph.get_node(current_id)
            if not node or current_id == node_id:
                continue

            # 构建节点数据
            node_data = {
                "name": node.qualified_name,
                "file": node.file_path,
                "line": node.line_start,
                "type": node.node_type.value,
                "depth": depth,
            }

            # 标记特殊节点
            if include_sources and node.node_type.value == "source":
                node_data["is_source"] = True
                node_data["matched_rules"] = node.matched_rules

            if include_sinks and node.node_type.value == "sink":
                node_data["is_sink"] = True
                node_data["risk_level"] = node.risk_level
                node_data["matched_rules"] = node.matched_rules

            if node.node_type.value == "sanitizer":
                node_data["is_sanitizer"] = True

            chain_data.append(node_data)

            # 扩展邻居
            if direction == "callers":
                neighbors = self._call_graph._callers.get(current_id, set())
            else:  # callees
                neighbors = self._call_graph._callees.get(current_id, set())

            for neighbor_id in neighbors:
                if neighbor_id not in visited:
                    queue.append((neighbor_id, depth + 1))

        return chain_data

    def _execute_trace_taint_path(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行污点路径追踪"""
        if not self.taint_analyzer:
            return {
                "success": False,
                "error": "污点分析器未初始化"
            }

        source_symbol = args.get("source_symbol")
        sink_symbol = args.get("sink_symbol")
        max_depth = args.get("max_depth", 10)
        show_sanitizers = args.get("show_sanitizers", True)
        only_unsanitized = args.get("only_unsanitized", False)

        # 使用已计算的污点流或重新计算
        if self._taint_flows is None:
            if not self._call_graph:
                return {"success": False, "error": "请先运行 prepare_analysis()"}

            code_units = self.indexer.get_all_units()
            self._taint_flows = self.taint_analyzer.analyze_interprocedural(
                code_units,
                max_depth=max_depth,
            )

        # 过滤污点流
        filtered_flows = self._taint_flows

        if source_symbol:
            filtered_flows = [
                f for f in filtered_flows
                if source_symbol in f.source_function or source_symbol in f.source_var
            ]

        if sink_symbol:
            filtered_flows = [
                f for f in filtered_flows
                if sink_symbol in (f.sink_function or "") or sink_symbol in (f.sink_call or "")
            ]

        if only_unsanitized:
            filtered_flows = [f for f in filtered_flows if not f.is_sanitized]

        # 转换为返回格式
        paths_data = []
        for flow in filtered_flows[:20]:  # 限制返回数量
            path_info = {
                "source": {
                    "function": flow.source_function,
                    "variable": flow.source_var,
                    "type": flow.source_type.value,
                    "location": flow.source_location,
                },
                "sink": {
                    "function": flow.sink_function,
                    "call": flow.sink_call,
                    "category": flow.sink_category.value if flow.sink_category else None,
                    "location": flow.target_location,
                },
                "call_chain": flow.call_chain,
                "chain_length": len(flow.call_chain),
                "is_sanitized": flow.is_sanitized,
                "risk_level": flow.risk_level.value,
                "confidence": flow.confidence,
                "description": flow.description,
            }

            if show_sanitizers and flow.sanitizers:
                path_info["sanitizers"] = flow.sanitizers

            paths_data.append(path_info)

        return {
            "success": True,
            "total_paths": len(paths_data),
            "paths": paths_data,
            "summary": self.taint_analyzer.get_cross_function_summary() if hasattr(self.taint_analyzer, 'get_cross_function_summary') else {},
        }

    def _execute_get_code_context(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行获取代码上下文"""
        symbol_name = args.get("symbol_name", "")
        file_path = args.get("file_path")
        include_callers = args.get("include_callers", True)
        include_callees = args.get("include_callees", True)
        include_class = args.get("include_class", True)
        include_imports = args.get("include_imports", False)

        # 使用 CodeReader 读取符号
        symbol_data = self.code_reader.read_symbol(
            symbol_name=symbol_name,
            file_path=file_path,
            include_callers=include_callers,
            include_callees=include_callees,
        )

        if not symbol_data.get("success"):
            return symbol_data

        # 扩展上下文信息
        if symbol_data.get("definitions"):
            for definition in symbol_data["definitions"]:
                # 如果是方法，获取类的其他方法
                if include_class and definition.get("parent_class"):
                    parent_class = definition["parent_class"]
                    class_members = self.indexer.search(
                        query=parent_class,
                        top_k=10,
                    )
                    definition["class_members"] = [
                        {
                            "symbol": u.symbol,
                            "type": u.unit_type.value,
                            "line": u.span.start_line,
                            "signature": u.signature,
                        }
                        for u in class_members
                        if u.parent_class == parent_class
                    ]

                # 获取导入语句
                if include_imports:
                    unit_id = definition.get("unit_id")
                    if unit_id:
                        unit = self.indexer.get_unit(unit_id)
                        if unit and unit.imports:
                            definition["imports"] = unit.imports

        return symbol_data

    def _execute_check_pattern(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行漏洞模式检查"""
        pattern_type = args.get("pattern_type")
        file_path = args.get("file_path")
        symbol_name = args.get("symbol_name")

        # 构建搜索查询
        pattern_queries = {
            "sql_injection": "SQL 注入 execute query cursor",
            "command_injection": "命令执行 system popen subprocess exec",
            "xss": "XSS 跨站脚本 render template innerHTML",
            "path_traversal": "路径遍历 open read write file",
            "insecure_deserialization": "反序列化 pickle yaml loads",
            "authentication_bypass": "认证绕过 login auth token session",
            "authorization_bypass": "授权绕过 permission role admin access",
            "idor": "越权访问 user_id get delete update",
            "ssrf": "SSRF 请求伪造 requests fetch http",
            "open_redirect": "开放重定向 redirect location",
        }

        query = pattern_queries.get(pattern_type, pattern_type)

        # 搜索相关代码
        matches = self.code_reader.search_code(
            query=query,
            top_k=10,
            file_pattern=file_pattern,
        )

        if not matches.get("success"):
            return matches

        # 过滤符号
        if symbol_name:
            results = matches.get("results", [])
            matches["results"] = [
                r for r in results
                if symbol_name in r.get("symbol", "")
            ]
            matches["total"] = len(matches["results"])

        matches["pattern_type"] = pattern_type
        return matches
