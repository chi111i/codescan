"""
调用链分析模块 - 构建和分析函数调用关系图

功能：
1. 构建完整的调用图（Call Graph）
2. 识别危险函数调用链（Source -> ... -> Sink）
3. 检测调用链中的安全过滤（Sanitizer）
4. 存储调用图和分析结果到 JSON
"""

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Optional, Any, Tuple
from enum import Enum

from indexer import CodeUnit, CodeUnitType
from rules import RuleManager, SecurityRule, RuleType, RiskLevel

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """节点类型"""
    NORMAL = "normal"          # 普通函数
    SOURCE = "source"          # 输入源（用户输入等）
    SINK = "sink"              # 危险函数（SQL执行等）
    SANITIZER = "sanitizer"    # 安全过滤函数
    ENTRY_POINT = "entry_point"  # 入口点（如 Web 处理器）


@dataclass
class CallNode:
    """调用图节点"""
    id: str                     # 节点 ID（通常是 CodeUnit.id）
    name: str                   # 函数/方法名
    qualified_name: str         # 完整名称（包含类名）
    file_path: str
    line_start: int
    line_end: int
    language: str
    node_type: NodeType = NodeType.NORMAL
    matched_rules: List[str] = field(default_factory=list)  # 匹配的规则 ID
    risk_level: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "qualified_name": self.qualified_name,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "language": self.language,
            "node_type": self.node_type.value,
            "matched_rules": self.matched_rules,
            "risk_level": self.risk_level,
            "metadata": self.metadata,
        }


@dataclass
class CallEdge:
    """调用图边"""
    caller_id: str              # 调用者节点 ID
    callee_id: str              # 被调用者节点 ID
    call_site: str              # 调用位置（file:line）
    call_type: str = "direct"   # 调用类型：direct, indirect, callback
    arguments: List[str] = field(default_factory=list)  # 传递的参数

    def to_dict(self) -> Dict[str, Any]:
        return {
            "caller_id": self.caller_id,
            "callee_id": self.callee_id,
            "call_site": self.call_site,
            "call_type": self.call_type,
            "arguments": self.arguments,
        }


@dataclass
class TaintPath:
    """污点传播路径（Source -> Sink）"""
    id: str
    source_node: str            # 源节点 ID
    sink_node: str              # 汇节点 ID
    path: List[str]             # 路径上的节点 ID 列表
    sanitizers: List[str]       # 路径上的过滤器节点 ID
    is_sanitized: bool          # 是否被安全过滤
    risk_level: str
    confidence: float
    description: str
    source_rule: Optional[str] = None
    sink_rule: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_node": self.source_node,
            "sink_node": self.sink_node,
            "path": self.path,
            "path_length": len(self.path),
            "sanitizers": self.sanitizers,
            "is_sanitized": self.is_sanitized,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "description": self.description,
            "source_rule": self.source_rule,
            "sink_rule": self.sink_rule,
        }


@dataclass
class CallGraph:
    """调用图"""
    nodes: Dict[str, CallNode] = field(default_factory=dict)
    edges: List[CallEdge] = field(default_factory=list)

    # 索引结构
    _callers: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    _callees: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    _by_name: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))

    def add_node(self, node: CallNode) -> None:
        """添加节点"""
        self.nodes[node.id] = node
        self._by_name[node.name].append(node.id)
        if node.qualified_name != node.name:
            self._by_name[node.qualified_name].append(node.id)

    def add_edge(self, edge: CallEdge) -> None:
        """添加边"""
        self.edges.append(edge)
        self._callers[edge.callee_id].add(edge.caller_id)
        self._callees[edge.caller_id].add(edge.callee_id)

    def get_node(self, node_id: str) -> Optional[CallNode]:
        """获取节点"""
        return self.nodes.get(node_id)

    def get_nodes_by_name(self, name: str) -> List[CallNode]:
        """按名称获取节点"""
        node_ids = self._by_name.get(name, [])
        return [self.nodes[nid] for nid in node_ids if nid in self.nodes]

    def get_callers(self, node_id: str) -> List[CallNode]:
        """获取调用者"""
        caller_ids = self._callers.get(node_id, set())
        return [self.nodes[cid] for cid in caller_ids if cid in self.nodes]

    def get_callees(self, node_id: str) -> List[CallNode]:
        """获取被调用者"""
        callee_ids = self._callees.get(node_id, set())
        return [self.nodes[cid] for cid in callee_ids if cid in self.nodes]

    def get_nodes_by_type(self, node_type: NodeType) -> List[CallNode]:
        """按类型获取节点"""
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def get_entry_points(self) -> List[CallNode]:
        """获取入口点"""
        return self.get_nodes_by_type(NodeType.ENTRY_POINT)

    def get_sources(self) -> List[CallNode]:
        """获取输入源"""
        return self.get_nodes_by_type(NodeType.SOURCE)

    def get_sinks(self) -> List[CallNode]:
        """获取危险函数"""
        return self.get_nodes_by_type(NodeType.SINK)

    def get_sanitizers(self) -> List[CallNode]:
        """获取过滤函数"""
        return self.get_nodes_by_type(NodeType.SANITIZER)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "nodes": {nid: node.to_dict() for nid, node in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
            "statistics": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "entry_points": len(self.get_entry_points()),
                "sources": len(self.get_sources()),
                "sinks": len(self.get_sinks()),
                "sanitizers": len(self.get_sanitizers()),
            }
        }


class CallChainAnalyzer:
    """调用链分析器"""

    def __init__(self, rule_manager: RuleManager):
        self.rule_manager = rule_manager
        self.call_graph = CallGraph()
        self.taint_paths: List[TaintPath] = []

        # 新增：路径缓存
        self._path_cache: Dict[Tuple[str, frozenset], List[List[str]]] = {}
        # 可达性缓存
        self._reachability: Dict[Tuple[str, str, int], bool] = {}
        # 优化算法实例（延迟初始化）
        self._optimizer = None

    def _get_optimizer(self):
        """获取优化算法实例（懒加载）"""
        if self._optimizer is None:
            from .optimized_algorithms import OptimizedPathFinder
            self._optimizer = OptimizedPathFinder(self.call_graph)
        return self._optimizer

    def build_call_graph(self, code_units: List[CodeUnit]) -> CallGraph:
        """从代码单元构建调用图

        Args:
            code_units: 代码单元列表

        Returns:
            构建的调用图
        """
        logger.info(f"Building call graph from {len(code_units)} code units...")

        # 1. 创建所有节点
        for unit in code_units:
            node = self._create_node_from_unit(unit)
            self.call_graph.add_node(node)

        # 2. 创建调用边
        for unit in code_units:
            self._create_edges_for_unit(unit)

        # 3. 标记节点类型（source/sink/sanitizer）
        self._classify_nodes()

        logger.info(
            f"Call graph built: {len(self.call_graph.nodes)} nodes, "
            f"{len(self.call_graph.edges)} edges"
        )

        return self.call_graph

    def _create_node_from_unit(self, unit: CodeUnit) -> CallNode:
        """从 CodeUnit 创建节点"""
        qualified_name = unit.symbol
        if unit.parent_class:
            qualified_name = f"{unit.parent_class}.{unit.symbol}"

        # 初步确定节点类型
        node_type = NodeType.NORMAL
        if unit.unit_type == CodeUnitType.HANDLER:
            node_type = NodeType.ENTRY_POINT

        return CallNode(
            id=unit.id,
            name=unit.symbol,
            qualified_name=qualified_name,
            file_path=unit.file_path,
            line_start=unit.span.start_line,
            line_end=unit.span.end_line,
            language=unit.language,
            node_type=node_type,
            metadata={
                "decorators": unit.decorators,
                "parent_class": unit.parent_class,
                "unit_type": unit.unit_type.value,
            }
        )

    def _create_edges_for_unit(self, unit: CodeUnit) -> None:
        """为代码单元创建调用边"""
        caller_id = unit.id

        for called_name in unit.calls:
            # 尝试找到被调用的节点
            callee_nodes = self.call_graph.get_nodes_by_name(called_name)

            if callee_nodes:
                # 优先选择同文件、同语言的节点
                best_match = None
                for node in callee_nodes:
                    if node.language == unit.language:
                        if node.file_path == unit.file_path:
                            best_match = node
                            break
                        elif best_match is None:
                            best_match = node

                if best_match:
                    edge = CallEdge(
                        caller_id=caller_id,
                        callee_id=best_match.id,
                        call_site=f"{unit.file_path}:{unit.span.start_line}",
                        call_type="direct",
                    )
                    self.call_graph.add_edge(edge)
            else:
                # 创建外部函数节点（库函数等）
                external_id = f"external:{called_name}"
                if external_id not in self.call_graph.nodes:
                    external_node = CallNode(
                        id=external_id,
                        name=called_name,
                        qualified_name=called_name,
                        file_path="<external>",
                        line_start=0,
                        line_end=0,
                        language=unit.language,
                        node_type=NodeType.NORMAL,
                        metadata={"is_external": True}
                    )
                    self.call_graph.add_node(external_node)

                edge = CallEdge(
                    caller_id=caller_id,
                    callee_id=external_id,
                    call_site=f"{unit.file_path}:{unit.span.start_line}",
                    call_type="external",
                )
                self.call_graph.add_edge(edge)

    def _classify_nodes(self) -> None:
        """使用规则库分类节点"""
        for node in self.call_graph.nodes.values():
            # 跳过已分类为入口点的节点
            if node.node_type == NodeType.ENTRY_POINT:
                continue

            language = node.language
            name = node.name

            # 检查是否是 Source
            source_rules = self.rule_manager.match_function(name, language, RuleType.SOURCE)
            if source_rules:
                node.node_type = NodeType.SOURCE
                node.matched_rules = [r.id for r in source_rules]
                continue

            # 检查是否是 Sink
            sink_rules = self.rule_manager.match_function(name, language, RuleType.SINK)
            if sink_rules:
                node.node_type = NodeType.SINK
                node.matched_rules = [r.id for r in sink_rules]
                # 设置风险等级
                max_risk = max(r.risk_level for r in sink_rules)
                node.risk_level = max_risk.value
                continue

            # 检查是否是 Sanitizer
            sanitizer_rules = self.rule_manager.match_function(name, language, RuleType.SANITIZER)
            if sanitizer_rules:
                node.node_type = NodeType.SANITIZER
                node.matched_rules = [r.id for r in sanitizer_rules]

    def find_taint_paths(
        self,
        max_depth: int = 10,
        max_paths: int = 100,
        use_optimized: bool = True,
    ) -> List[TaintPath]:
        """查找污点传播路径（Source -> Sink）

        使用 DFS 或优化的双向 BFS 从每个 Source 节点出发，查找到 Sink 节点的路径

        Args:
            max_depth: 最大搜索深度
            max_paths: 最大路径数量
            use_optimized: 是否使用优化算法（双向 BFS）

        Returns:
            污点路径列表
        """
        logger.info("Finding taint paths...")

        sources = self.call_graph.get_sources()
        sinks = self.call_graph.get_sinks()
        entry_points = self.call_graph.get_entry_points()

        # 同时从入口点开始搜索（入口点通常接收用户输入）
        start_nodes = sources + entry_points

        sink_ids = {s.id for s in sinks}
        paths_found = []

        for source in start_nodes:
            if len(paths_found) >= max_paths:
                break

            # 使用优化算法或原始 DFS
            if use_optimized:
                optimizer = self._get_optimizer()
                paths = optimizer.find_paths_bidirectional_bfs(
                    source.id,
                    sink_ids,
                    max_depth,
                    max_paths - len(paths_found)
                )
            else:
                # 原始 DFS（fallback）
                paths = self._dfs_find_paths(
                    source.id,
                    sink_ids,
                    max_depth,
                    max_paths - len(paths_found)
                )

            for path in paths:
                taint_path = self._create_taint_path(source, path)
                if taint_path:
                    paths_found.append(taint_path)

        self.taint_paths = paths_found
        logger.info(f"Found {len(paths_found)} taint paths (optimized={use_optimized})")

        return paths_found

    def _dfs_find_paths(
        self,
        start_id: str,
        target_ids: Set[str],
        max_depth: int,
        max_paths: int,
    ) -> List[List[str]]:
        """DFS 查找从起点到目标集合的所有路径"""
        paths = []
        stack = [(start_id, [start_id])]
        visited_paths: Set[tuple] = set()

        while stack and len(paths) < max_paths:
            node_id, current_path = stack.pop()

            if len(current_path) > max_depth:
                continue

            if node_id in target_ids:
                path_tuple = tuple(current_path)
                if path_tuple not in visited_paths:
                    visited_paths.add(path_tuple)
                    paths.append(current_path.copy())
                continue

            # 获取被调用者
            for callee_id in self.call_graph._callees.get(node_id, set()):
                if callee_id not in current_path:  # 避免循环
                    stack.append((callee_id, current_path + [callee_id]))

        return paths

    def _create_taint_path(
        self,
        source_node: CallNode,
        path: List[str]
    ) -> Optional[TaintPath]:
        """创建污点路径对象"""
        if len(path) < 2:
            return None

        sink_id = path[-1]
        sink_node = self.call_graph.get_node(sink_id)
        if not sink_node:
            return None

        # 检查路径上的 sanitizer
        sanitizers = []
        for node_id in path[1:-1]:  # 排除首尾
            node = self.call_graph.get_node(node_id)
            if node and node.node_type == NodeType.SANITIZER:
                sanitizers.append(node_id)

        is_sanitized = len(sanitizers) > 0

        # 计算风险等级
        risk_level = sink_node.risk_level or "medium"
        if is_sanitized:
            # 如果有过滤，降低风险
            risk_map = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}
            risk_level = risk_map.get(risk_level, risk_level)

        # 计算置信度
        confidence = 0.8
        if is_sanitized:
            confidence = 0.4
        if len(path) > 5:
            confidence *= 0.8  # 路径越长，置信度越低

        # 生成描述
        source_name = source_node.qualified_name
        sink_name = sink_node.qualified_name
        description = f"数据从 {source_name} 流向危险函数 {sink_name}"
        if is_sanitized:
            sanitizer_names = [
                self.call_graph.get_node(sid).name
                for sid in sanitizers
                if self.call_graph.get_node(sid)
            ]
            description += f"，经过安全过滤 ({', '.join(sanitizer_names)})"

        return TaintPath(
            id=f"path-{len(self.taint_paths) + 1}",
            source_node=source_node.id,
            sink_node=sink_id,
            path=path,
            sanitizers=sanitizers,
            is_sanitized=is_sanitized,
            risk_level=risk_level,
            confidence=confidence,
            description=description,
            source_rule=source_node.matched_rules[0] if source_node.matched_rules else None,
            sink_rule=sink_node.matched_rules[0] if sink_node.matched_rules else None,
        )

    def find_dangerous_chains(self) -> List[Dict[str, Any]]:
        """查找危险调用链

        返回从入口点到危险函数的完整调用链
        """
        dangerous_chains = []
        sinks = self.call_graph.get_sinks()

        for sink in sinks:
            # 向上追溯找到所有到达该 sink 的路径
            chains = self._trace_back_to_entry(sink.id)

            for chain in chains:
                chain_info = self._analyze_chain(chain, sink)
                if chain_info:
                    dangerous_chains.append(chain_info)

        # 按风险排序
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        dangerous_chains.sort(key=lambda x: risk_order.get(x.get("risk_level", "low"), 4))

        return dangerous_chains

    def _trace_back_to_entry(
        self,
        sink_id: str,
        max_depth: int = 15
    ) -> List[List[str]]:
        """向上追溯调用链到入口点"""
        paths = []
        stack = [(sink_id, [sink_id])]

        while stack:
            node_id, current_path = stack.pop()

            if len(current_path) > max_depth:
                continue

            node = self.call_graph.get_node(node_id)
            if node and node.node_type == NodeType.ENTRY_POINT:
                # 找到入口点，反转路径
                paths.append(list(reversed(current_path)))
                continue

            # 获取调用者
            callers = self.call_graph._callers.get(node_id, set())

            if not callers:
                # 没有调用者，可能是顶层函数
                if len(current_path) > 1:
                    paths.append(list(reversed(current_path)))
            else:
                for caller_id in callers:
                    if caller_id not in current_path:
                        stack.append((caller_id, current_path + [caller_id]))

        return paths

    def _analyze_chain(
        self,
        chain: List[str],
        sink_node: CallNode
    ) -> Optional[Dict[str, Any]]:
        """分析单个调用链"""
        if len(chain) < 2:
            return None

        # 收集链上的节点信息
        chain_nodes = []
        sanitizers_in_chain = []
        sources_in_chain = []

        for node_id in chain:
            node = self.call_graph.get_node(node_id)
            if not node:
                continue

            node_info = {
                "id": node.id,
                "name": node.qualified_name,
                "file": node.file_path,
                "line": node.line_start,
                "type": node.node_type.value,
            }
            chain_nodes.append(node_info)

            if node.node_type == NodeType.SANITIZER:
                sanitizers_in_chain.append(node.name)
            if node.node_type == NodeType.SOURCE:
                sources_in_chain.append(node.name)

        # 获取 sink 规则信息
        sink_rules = self.rule_manager.match_function(
            sink_node.name,
            sink_node.language,
            RuleType.SINK
        )

        risk_level = sink_node.risk_level or "medium"
        is_sanitized = len(sanitizers_in_chain) > 0

        # 如果被过滤，调整风险
        if is_sanitized:
            risk_map = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}
            effective_risk = risk_map.get(risk_level, risk_level)
        else:
            effective_risk = risk_level

        return {
            "chain_id": f"chain-{hash(tuple(chain)) % 10000:04d}",
            "sink": {
                "name": sink_node.qualified_name,
                "file": sink_node.file_path,
                "line": sink_node.line_start,
                "rules": [r.id for r in sink_rules],
                "risk_level": risk_level,
            },
            "entry_point": chain_nodes[0] if chain_nodes else None,
            "chain_length": len(chain),
            "chain_nodes": chain_nodes,
            "has_sanitizer": is_sanitized,
            "sanitizers": sanitizers_in_chain,
            "has_source": len(sources_in_chain) > 0,
            "sources": sources_in_chain,
            "effective_risk": effective_risk,
            "confidence": 0.9 if not is_sanitized else 0.5,
        }

    def export_to_json(
        self,
        output_path: str,
        include_call_graph: bool = True,
        include_taint_paths: bool = True,
        include_dangerous_chains: bool = True,
    ) -> str:
        """导出分析结果到 JSON 文件

        Args:
            output_path: 输出路径
            include_call_graph: 是否包含调用图
            include_taint_paths: 是否包含污点路径
            include_dangerous_chains: 是否包含危险调用链

        Returns:
            输出文件路径
        """
        result = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "LLM Code Auditor - Call Chain Analyzer",
                "version": "0.1.0",
            },
            "statistics": {
                "total_nodes": len(self.call_graph.nodes),
                "total_edges": len(self.call_graph.edges),
                "entry_points": len(self.call_graph.get_entry_points()),
                "sources": len(self.call_graph.get_sources()),
                "sinks": len(self.call_graph.get_sinks()),
                "sanitizers": len(self.call_graph.get_sanitizers()),
                "taint_paths": len(self.taint_paths),
            }
        }

        if include_call_graph:
            result["call_graph"] = self.call_graph.to_dict()

        if include_taint_paths:
            result["taint_paths"] = [p.to_dict() for p in self.taint_paths]

            # 统计
            unsafe_paths = [p for p in self.taint_paths if not p.is_sanitized]
            result["statistics"]["unsafe_taint_paths"] = len(unsafe_paths)

        if include_dangerous_chains:
            dangerous_chains = self.find_dangerous_chains()
            result["dangerous_chains"] = dangerous_chains
            result["statistics"]["dangerous_chains"] = len(dangerous_chains)

            # 按风险分组统计
            risk_counts = defaultdict(int)
            for chain in dangerous_chains:
                risk_counts[chain.get("effective_risk", "unknown")] += 1
            result["statistics"]["chains_by_risk"] = dict(risk_counts)

        # 写入文件
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        logger.info(f"Analysis result exported to: {path}")
        return str(path)

    def get_node_neighbors(
        self,
        node_id: str,
        depth: int = 2
    ) -> Dict[str, Any]:
        """获取节点的邻居信息（用于 LLM 上下文）"""
        node = self.call_graph.get_node(node_id)
        if not node:
            return {}

        result = {
            "target": node.to_dict(),
            "callers": [],
            "callees": [],
        }

        # 获取调用者
        visited_callers = set()
        to_visit = [(node_id, 0)]
        while to_visit:
            current_id, current_depth = to_visit.pop(0)
            if current_depth >= depth:
                continue
            for caller in self.call_graph.get_callers(current_id):
                if caller.id not in visited_callers:
                    visited_callers.add(caller.id)
                    result["callers"].append({
                        **caller.to_dict(),
                        "depth": current_depth + 1
                    })
                    to_visit.append((caller.id, current_depth + 1))

        # 获取被调用者
        visited_callees = set()
        to_visit = [(node_id, 0)]
        while to_visit:
            current_id, current_depth = to_visit.pop(0)
            if current_depth >= depth:
                continue
            for callee in self.call_graph.get_callees(current_id):
                if callee.id not in visited_callees:
                    visited_callees.add(callee.id)
                    result["callees"].append({
                        **callee.to_dict(),
                        "depth": current_depth + 1
                    })
                    to_visit.append((callee.id, current_depth + 1))

        return result
