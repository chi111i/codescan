"""
调用链上下文收集器

根据目标文档 P0-3/P0-4 的要求：
- 为每个 SinkCallSite 枚举调用链
- 收集整条链路的代码上下文
- 输出结构化的 ChainContext 供 LLM 分析
"""

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set

from indexer.models import CodeUnit
from .sink_scanner import SinkCallSite, SinkCategory
from .call_chain import CallChainAnalyzer, CallGraph, CallNode, NodeType

logger = logging.getLogger(__name__)


@dataclass
class ChainNode:
    """调用链节点（包含代码上下文）"""
    symbol: str                  # 函数/方法名
    qualified_name: str          # 完整限定名
    file_path: str               # 文件路径
    line_start: int              # 起始行
    line_end: int                # 结束行
    node_type: str               # 节点类型: entry_point, normal, sink
    code: str                    # 代码片段
    calls: List[str] = field(default_factory=list)  # 调用的函数
    is_sink: bool = False        # 是否是 sink 节点
    risk_info: Optional[str] = None  # 风险信息

    def to_dict(self) -> Dict[str, Any]:
        return {
            "symbol": self.symbol,
            "qualified_name": self.qualified_name,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "node_type": self.node_type,
            "code": self.code,
            "calls": self.calls,
            "is_sink": self.is_sink,
            "risk_info": self.risk_info,
        }


@dataclass
class ChainContext:
    """调用链上下文（用于 LLM 分析）"""
    sink_site: SinkCallSite          # 原始的 sink 调用点
    chain_nodes: List[ChainNode]     # 调用链节点列表（从入口到 sink）
    entry_point: Optional[ChainNode] = None  # 入口点
    chain_length: int = 0            # 调用链长度
    has_user_input: bool = False     # 是否有用户输入
    sanitizers_on_path: List[str] = field(default_factory=list)  # 路径上的过滤器
    risk_level: str = "medium"       # 风险等级
    confidence: float = 0.0          # 置信度

    def to_prompt_text(self, include_intermediate_code: bool = True, max_code_length: int = 800) -> str:
        """生成用于 LLM 分析的提示文本

        P0-5: 支持包含中间函数代码片段

        Args:
            include_intermediate_code: 是否包含中间函数代码
            max_code_length: 每个函数代码的最大长度

        Returns:
            格式化的提示文本
        """
        lines = []

        # 1. 概述
        lines.append("【调用链分析】")
        lines.append(f"Sink 类型: {self.sink_site.sink_category.value}")
        lines.append(f"风险等级: {self.risk_level}")
        lines.append(f"调用链长度: {self.chain_length}")
        if self.has_user_input:
            lines.append("⚠️ 存在用户输入")
        if self.sanitizers_on_path:
            lines.append(f"路径上的过滤器: {', '.join(self.sanitizers_on_path)}")
        lines.append("")

        # 2. 入口点
        if self.entry_point:
            lines.append("【入口点】")
            lines.append(f"函数: {self.entry_point.qualified_name}")
            lines.append(f"位置: {self.entry_point.file_path}:{self.entry_point.line_start}")
            lines.append("```")
            lines.append(self._truncate_code(self.entry_point.code, max_code_length))
            lines.append("```")
            lines.append("")

        # 3. 调用链（P0-5: 包含中间函数代码）
        lines.append("【调用链路】")

        # 分离中间节点（排除入口点和 sink）
        intermediate_nodes = [
            node for node in self.chain_nodes
            if not node.is_sink and node != self.entry_point
        ]

        for i, node in enumerate(self.chain_nodes):
            prefix = "└─>" if i == len(self.chain_nodes) - 1 else "├─>"
            sink_mark = " [SINK]" if node.is_sink else ""
            entry_mark = " [ENTRY]" if node.node_type == "entry_point" else ""
            sanitizer_mark = " [SANITIZER]" if node.node_type == "sanitizer" else ""

            lines.append(f"{prefix} {node.qualified_name}{entry_mark}{sanitizer_mark}{sink_mark}")
            lines.append(f"    位置: {node.file_path}:{node.line_start}")

        lines.append("")

        # P0-5: 中间函数代码片段
        if include_intermediate_code and intermediate_nodes:
            lines.append("【中间函数代码】")
            for node in intermediate_nodes:
                if node.code:
                    lines.append(f"--- {node.qualified_name} ({node.file_path}:{node.line_start}) ---")
                    lines.append("```")
                    lines.append(self._truncate_code(node.code, max_code_length))
                    lines.append("```")
                    lines.append("")

        # 4. Sink 代码
        lines.append("【危险函数调用】")
        lines.append(f"文件: {self.sink_site.file_path}:{self.sink_site.line_start}")
        lines.append(f"函数: {self.sink_site.symbol}")
        lines.append(f"匹配规则: {', '.join(self.sink_site.matched_rule_ids)}")
        lines.append("```")
        lines.append(self.sink_site.call_snippet)
        lines.append("```")

        return "\n".join(lines)

    def _truncate_code(self, code: str, max_length: int) -> str:
        """截断代码到指定长度"""
        if not code:
            return ""
        # 边界检查：max_length 必须为正数
        if max_length <= 0:
            return ""
        if len(code) <= max_length:
            return code
        # 预留截断标记长度
        truncate_suffix = "\n... (truncated)"
        suffix_len = len(truncate_suffix)
        # 确保有足够空间放截断标记
        if max_length <= suffix_len:
            return code[:max_length]
        effective_max = max_length - suffix_len
        # 尝试在行边界截断
        truncated = code[:effective_max]
        last_newline = truncated.rfind("\n")
        if last_newline > effective_max * 0.5:
            truncated = truncated[:last_newline]
        return truncated + truncate_suffix

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sink_site": self.sink_site.to_dict(),
            "chain_nodes": [n.to_dict() for n in self.chain_nodes],
            "entry_point": self.entry_point.to_dict() if self.entry_point else None,
            "chain_length": self.chain_length,
            "has_user_input": self.has_user_input,
            "sanitizers_on_path": self.sanitizers_on_path,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
        }


class ChainContextCollector:
    """调用链上下文收集器

    功能：
    1. 为每个 SinkCallSite 构建调用链
    2. 收集链路上的代码上下文
    3. 识别入口点、用户输入、过滤器

    P0-4: 支持收集 top-k 条路径而非仅第一个调用者
    """

    # 用户输入标识符
    USER_INPUT_PATTERNS = {
        "python": ["request.args", "request.form", "request.json", "request.data",
                   "request.get_json", "input(", "sys.argv", "os.environ"],
        "php": ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES",
                "$_SERVER", "file_get_contents('php://input"],
        "javascript": ["req.body", "req.query", "req.params", "request.body",
                       "ctx.request.body", "process.argv"],
    }

    def __init__(
        self,
        call_chain_analyzer: Optional[CallChainAnalyzer] = None,
        code_units: Optional[List[CodeUnit]] = None,
    ):
        self.call_chain_analyzer = call_chain_analyzer
        self.code_units = code_units or []
        self._unit_map: Dict[str, CodeUnit] = {}

        # 构建 unit 索引
        for unit in self.code_units:
            self._unit_map[unit.id] = unit
            # 同时按 symbol 索引
            if unit.symbol not in self._unit_map:
                self._unit_map[unit.symbol] = unit

    def collect_context(
        self,
        sink_site: SinkCallSite,
        max_depth: int = 5,
    ) -> ChainContext:
        """为 SinkCallSite 收集调用链上下文（单条路径）

        Args:
            sink_site: 危险函数触发点
            max_depth: 最大追溯深度

        Returns:
            ChainContext 对象
        """
        # 使用 top-k 方法，但只返回第一条（保持兼容性）
        contexts = self.collect_topk_contexts(sink_site, top_k=1, max_depth=max_depth)
        if contexts:
            return contexts[0]

        # 降级：返回空上下文
        return self._create_empty_context(sink_site)

    def collect_topk_contexts(
        self,
        sink_site: SinkCallSite,
        top_k: int = 5,
        max_depth: int = 10,
    ) -> List[ChainContext]:
        """P0-4: 为 SinkCallSite 收集 top-k 条调用链上下文

        Args:
            sink_site: 危险函数触发点
            top_k: 最多返回的路径数量
            max_depth: 最大追溯深度

        Returns:
            ChainContext 列表（按置信度排序）
        """
        contexts: List[ChainContext] = []

        # 1. 获取 sink 所在的 CodeUnit
        sink_unit = self._unit_map.get(sink_site.unit_id)
        language = sink_unit.language if sink_unit else "unknown"

        # 2. 获取调用图
        call_graph = self._get_call_graph()

        if call_graph and sink_unit:
            # P0-4: 使用 BFS 收集多条路径
            all_paths = self._collect_all_paths_bfs(
                sink_id=sink_site.unit_id,
                call_graph=call_graph,
                max_depth=max_depth,
                max_paths=top_k * 2,  # 多找一些，后面过滤
            )

            # 转换为 ChainContext
            for path in all_paths[:top_k]:
                ctx = self._path_to_context(
                    path=path,
                    sink_site=sink_site,
                    sink_unit=sink_unit,
                    call_graph=call_graph,
                    language=language,
                )
                if ctx:
                    contexts.append(ctx)
        else:
            # 无调用图时，尝试简单路径收集
            ctx = self._collect_context_without_graph(
                sink_site=sink_site,
                sink_unit=sink_unit,
                max_depth=max_depth,
                language=language,
            )
            if ctx:
                contexts.append(ctx)

        # 按置信度排序
        contexts.sort(key=lambda c: c.confidence, reverse=True)

        return contexts[:top_k]

    def _collect_all_paths_bfs(
        self,
        sink_id: str,
        call_graph: CallGraph,
        max_depth: int,
        max_paths: int,
    ) -> List[List[str]]:
        """P0-4: 使用 BFS 收集从入口点到 sink 的所有路径

        向上追溯，收集多条可能的调用链。

        Args:
            sink_id: Sink 节点 ID
            call_graph: 调用图
            max_depth: 最大深度
            max_paths: 最大路径数量

        Returns:
            路径列表（每条路径是节点 ID 列表，从入口到 sink）
        """
        paths: List[List[str]] = []
        # (当前节点ID, 当前路径) - 使用 deque 优化 O(1) 出队
        queue: deque = deque([(sink_id, [sink_id])])
        visited_paths: Set[tuple] = set()

        while queue and len(paths) < max_paths:
            current_id, current_path = queue.popleft()  # O(1) 出队

            if len(current_path) > max_depth:
                continue

            # 获取调用者
            callers = call_graph.get_callers(current_id)

            if not callers:
                # 没有调用者，记录当前路径（反转为从入口到 sink）
                reversed_path = list(reversed(current_path))
                path_tuple = tuple(reversed_path)
                if path_tuple not in visited_paths:
                    visited_paths.add(path_tuple)
                    paths.append(reversed_path)
                continue

            # 检查是否到达入口点
            current_node = call_graph.get_node(current_id)
            if current_node and current_node.node_type == NodeType.ENTRY_POINT and len(current_path) > 1:
                reversed_path = list(reversed(current_path))
                path_tuple = tuple(reversed_path)
                if path_tuple not in visited_paths:
                    visited_paths.add(path_tuple)
                    paths.append(reversed_path)
                # 入口点不再继续向上扩展（修复 Codex 发现的问题）
                continue

            # P0-4: 遍历所有调用者，而非只取第一个
            for caller in callers:
                if caller.id not in current_path:  # 避免循环
                    new_path = current_path + [caller.id]
                    queue.append((caller.id, new_path))

        return paths

    def _path_to_context(
        self,
        path: List[str],
        sink_site: SinkCallSite,
        sink_unit: Optional[CodeUnit],
        call_graph: CallGraph,
        language: str,
    ) -> Optional[ChainContext]:
        """将路径转换为 ChainContext

        Args:
            path: 节点 ID 路径（从入口到 sink）
            sink_site: Sink 调用点
            sink_unit: Sink 代码单元
            call_graph: 调用图
            language: 语言

        Returns:
            ChainContext 或 None
        """
        if not path:
            return None

        chain_nodes: List[ChainNode] = []
        entry_point: Optional[ChainNode] = None
        has_user_input = False
        sanitizers_on_path: List[str] = []

        # 遍历路径上的每个节点
        for i, node_id in enumerate(path):
            call_node = call_graph.get_node(node_id)
            if not call_node:
                continue

            unit = self._unit_map.get(node_id)
            is_sink = (i == len(path) - 1)  # 最后一个是 sink

            # 确定节点类型
            if call_node.node_type == NodeType.ENTRY_POINT:
                node_type = "entry_point"
            elif is_sink:
                node_type = "sink"
            elif call_node.node_type == NodeType.SANITIZER:
                node_type = "sanitizer"
                sanitizers_on_path.append(call_node.name)
            else:
                node_type = "normal"

            # 创建 ChainNode
            chain_node = ChainNode(
                symbol=call_node.name,
                qualified_name=call_node.qualified_name,
                file_path=call_node.file_path,
                line_start=call_node.line_start,
                line_end=call_node.line_end,
                node_type=node_type,
                code=unit.code[:1000] if unit else "",
                calls=unit.calls if unit else [],
                is_sink=is_sink,
                risk_info=f"{sink_site.sink_category.value}: {sink_site.risk_level.value}" if is_sink else None,
            )
            chain_nodes.append(chain_node)

            # 记录入口点
            if call_node.node_type == NodeType.ENTRY_POINT:
                entry_point = chain_node

            # 检查用户输入
            if unit and self._has_user_input(unit.code, language):
                has_user_input = True

        # 检查 sink 代码中是否有用户输入
        if self._has_user_input(sink_site.call_snippet, language):
            has_user_input = True

        # 计算置信度
        confidence = self._calculate_confidence(
            chain_nodes=chain_nodes,
            has_user_input=has_user_input,
            has_sanitizers=len(sanitizers_on_path) > 0,
        )

        return ChainContext(
            sink_site=sink_site,
            chain_nodes=chain_nodes,
            entry_point=entry_point,
            chain_length=len(chain_nodes),
            has_user_input=has_user_input,
            sanitizers_on_path=sanitizers_on_path,
            risk_level=sink_site.risk_level.value,
            confidence=confidence,
        )

    def _collect_context_without_graph(
        self,
        sink_site: SinkCallSite,
        sink_unit: Optional[CodeUnit],
        max_depth: int,
        language: str,
    ) -> Optional[ChainContext]:
        """无调用图时收集上下文

        Args:
            sink_site: Sink 调用点
            sink_unit: Sink 代码单元
            max_depth: 最大深度
            language: 语言

        Returns:
            ChainContext 或 None
        """
        chain_nodes: List[ChainNode] = []
        has_user_input = False
        sanitizers_on_path: List[str] = []

        # 创建 sink 节点
        sink_node = self._create_chain_node(
            unit=sink_unit,
            site=sink_site,
            node_type="sink",
            is_sink=True,
        )

        # 检查 sink 代码中是否有用户输入
        if self._has_user_input(sink_site.call_snippet, language):
            has_user_input = True

        # 尝试从 code_units 中找到调用者
        self._find_callers_without_graph(
            sink_site, sink_unit, chain_nodes, max_depth
        )

        # 检查找到的节点是否有用户输入
        for node in chain_nodes:
            unit = self._unit_map.get(node.symbol)
            if unit and self._has_user_input(unit.code, unit.language):
                has_user_input = True
                break

        # 添加 sink 节点
        chain_nodes.append(sink_node)

        # 计算置信度
        confidence = self._calculate_confidence(
            chain_nodes=chain_nodes,
            has_user_input=has_user_input,
            has_sanitizers=len(sanitizers_on_path) > 0,
        )

        return ChainContext(
            sink_site=sink_site,
            chain_nodes=chain_nodes,
            entry_point=None,
            chain_length=len(chain_nodes),
            has_user_input=has_user_input,
            sanitizers_on_path=sanitizers_on_path,
            risk_level=sink_site.risk_level.value,
            confidence=confidence,
        )

    def _create_empty_context(self, sink_site: SinkCallSite) -> ChainContext:
        """创建空上下文（降级处理）"""
        sink_node = ChainNode(
            symbol=sink_site.symbol,
            qualified_name=sink_site.symbol,
            file_path=sink_site.file_path,
            line_start=sink_site.line_start,
            line_end=sink_site.line_end,
            node_type="sink",
            code=sink_site.call_snippet,
            calls=[],
            is_sink=True,
            risk_info=f"{sink_site.sink_category.value}: {sink_site.risk_level.value}",
        )

        return ChainContext(
            sink_site=sink_site,
            chain_nodes=[sink_node],
            entry_point=None,
            chain_length=1,
            has_user_input=False,
            sanitizers_on_path=[],
            risk_level=sink_site.risk_level.value,
            confidence=0.3,
        )

    def _get_call_graph(self) -> Optional[CallGraph]:
        """安全地获取调用图"""
        if self.call_chain_analyzer is None:
            return None
        # 检查 call_chain_analyzer 是否有 call_graph 属性且不为 None
        call_graph = getattr(self.call_chain_analyzer, 'call_graph', None)
        if call_graph is None:
            # 尝试获取 _call_graph 属性（可能是私有属性）
            call_graph = getattr(self.call_chain_analyzer, '_call_graph', None)
        return call_graph

    def _find_callers_without_graph(
        self,
        sink_site: SinkCallSite,
        sink_unit: Optional[CodeUnit],
        chain_nodes: List[ChainNode],
        max_depth: int = 3,
    ) -> None:
        """在没有调用图时，尝试从 code_units 中找到调用者

        通过简单的文本搜索找到可能调用 sink 函数的其他函数

        Args:
            sink_site: Sink 调用点
            sink_unit: Sink 所在的代码单元
            chain_nodes: 调用链节点列表（会被修改）
            max_depth: 最大搜索深度
        """
        if not sink_unit:
            return

        sink_symbol = sink_unit.symbol
        visited: Set[str] = {sink_unit.id}
        current_symbols = [sink_symbol]
        depth = 0

        while depth < max_depth and current_symbols:
            next_symbols = []
            for symbol in current_symbols:
                # 在其他代码单元中搜索调用当前 symbol 的函数
                for unit in self.code_units:
                    if unit.id in visited:
                        continue
                    # 检查该单元是否调用了当前 symbol
                    if unit.calls and symbol in unit.calls:
                        visited.add(unit.id)
                        # 创建调用链节点
                        node = ChainNode(
                            symbol=unit.symbol,
                            qualified_name=f"{unit.parent_class}.{unit.symbol}" if unit.parent_class else unit.symbol,
                            file_path=unit.file_path,
                            line_start=unit.span.start_line,
                            line_end=unit.span.end_line,
                            node_type="normal",
                            code=unit.code[:1000] if unit.code else "",
                            calls=unit.calls or [],
                            is_sink=False,
                        )
                        chain_nodes.insert(0, node)
                        next_symbols.append(unit.symbol)
            current_symbols = next_symbols
            depth += 1

    def collect_contexts_batch(
        self,
        sink_sites: List[SinkCallSite],
        max_depth: int = 5,
    ) -> List[ChainContext]:
        """批量收集调用链上下文

        Args:
            sink_sites: 危险函数触发点列表
            max_depth: 最大追溯深度

        Returns:
            ChainContext 列表
        """
        contexts = []
        for site in sink_sites:
            try:
                ctx = self.collect_context(site, max_depth)
                contexts.append(ctx)
            except Exception as e:
                logger.warning(f"收集上下文失败 {site.id}: {e}")

        return contexts

    def collect_topk_contexts_batch(
        self,
        sink_sites: List[SinkCallSite],
        top_k: int = 5,
        max_depth: int = 10,
    ) -> Dict[str, List[ChainContext]]:
        """P0-4: 批量收集 top-k 调用链上下文

        Args:
            sink_sites: 危险函数触发点列表
            top_k: 每个 sink 最多返回的路径数量
            max_depth: 最大追溯深度

        Returns:
            字典，key 为 sink_site.id，value 为 ChainContext 列表
        """
        result: Dict[str, List[ChainContext]] = {}

        for site in sink_sites:
            try:
                contexts = self.collect_topk_contexts(site, top_k, max_depth)
                if contexts:
                    result[site.id] = contexts
            except Exception as e:
                logger.warning(f"收集 top-k 上下文失败 {site.id}: {e}")

        logger.info(
            f"[P0-4] 批量收集完成: {len(sink_sites)} sinks -> "
            f"{sum(len(v) for v in result.values())} 条路径"
        )

        return result

    def _create_chain_node(
        self,
        unit: Optional[CodeUnit],
        site: SinkCallSite,
        node_type: str,
        is_sink: bool = False,
    ) -> ChainNode:
        """创建调用链节点"""
        if unit:
            return ChainNode(
                symbol=unit.symbol,
                qualified_name=f"{unit.parent_class}.{unit.symbol}" if unit.parent_class else unit.symbol,
                file_path=unit.file_path,
                line_start=unit.span.start_line,
                line_end=unit.span.end_line,
                node_type=node_type,
                code=unit.code[:1000] if unit.code else "",
                calls=unit.calls or [],
                is_sink=is_sink,
                risk_info=f"{site.sink_category.value}: {site.risk_level.value}" if is_sink else None,
            )
        else:
            return ChainNode(
                symbol=site.symbol,
                qualified_name=site.symbol,
                file_path=site.file_path,
                line_start=site.line_start,
                line_end=site.line_end,
                node_type=node_type,
                code=site.call_snippet,
                calls=[],
                is_sink=is_sink,
                risk_info=f"{site.sink_category.value}: {site.risk_level.value}" if is_sink else None,
            )

    def _create_chain_node_from_call_node(
        self,
        call_node: CallNode,
        unit: Optional[CodeUnit],
    ) -> ChainNode:
        """从 CallNode 创建调用链节点"""
        node_type_map = {
            NodeType.ENTRY_POINT: "entry_point",
            NodeType.SOURCE: "source",
            NodeType.SINK: "sink",
            NodeType.SANITIZER: "sanitizer",
            NodeType.NORMAL: "normal",
        }

        return ChainNode(
            symbol=call_node.name,
            qualified_name=call_node.qualified_name,
            file_path=call_node.file_path,
            line_start=call_node.line_start,
            line_end=call_node.line_end,
            node_type=node_type_map.get(call_node.node_type, "normal"),
            code=unit.code[:1000] if unit else "",
            calls=unit.calls if unit else [],
            is_sink=call_node.node_type == NodeType.SINK,
            risk_info=call_node.risk_level,
        )

    def _has_user_input(self, code: str, language: str) -> bool:
        """检查代码中是否有用户输入"""
        patterns = self.USER_INPUT_PATTERNS.get(language, [])
        code_lower = code.lower()

        for pattern in patterns:
            if pattern.lower() in code_lower:
                return True

        return False

    def _calculate_confidence(
        self,
        chain_nodes: List[ChainNode],
        has_user_input: bool,
        has_sanitizers: bool,
    ) -> float:
        """计算置信度"""
        confidence = 0.5  # 基础置信度

        # 有用户输入增加置信度
        if has_user_input:
            confidence += 0.3

        # 有过滤器降低置信度
        if has_sanitizers:
            confidence -= 0.2

        # 调用链越短，置信度越高
        if len(chain_nodes) <= 2:
            confidence += 0.1
        elif len(chain_nodes) >= 5:
            confidence -= 0.1

        # 有入口点增加置信度
        if any(n.node_type == "entry_point" for n in chain_nodes):
            confidence += 0.1

        return max(0.0, min(1.0, confidence))
