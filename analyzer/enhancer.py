"""
DeepAnalysisEnhancer - 深度分析增强器

对预扫描发现的危险函数触发点进行深度分析增强：
1. 调用链分析 - 找出每个 sink 的调用入口和上下文
2. 污点分析 - 分析数据流是否从用户输入传播到 sink
3. 置信度评分 - 综合评估漏洞可利用性

核心理念：
- 预扫描只发现"可能危险"的点
- 深度增强确定"确实可利用"的漏洞
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Set

from indexer.models import CodeUnit
from rules import RuleManager
from .call_chain import CallChainAnalyzer, CallGraph, CallNode, TaintPath, NodeType
from .taint_analysis import TaintAnalyzer, TaintFlow
from .sink_scanner import SinkCallSite
from .prescan import PreScanResult

logger = logging.getLogger(__name__)


@dataclass
class CallChainInfo:
    """调用链信息"""
    site_id: str
    entry_points: List[str]
    callers: List[Dict[str, Any]]
    depth_to_entry: int
    call_path: List[str]
    has_auth_check: bool = False
    has_sanitizer: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "site_id": self.site_id,
            "entry_points": self.entry_points,
            "callers": self.callers,
            "depth_to_entry": self.depth_to_entry,
            "call_path": self.call_path,
            "has_auth_check": self.has_auth_check,
            "has_sanitizer": self.has_sanitizer,
        }


@dataclass
class TaintInfo:
    """污点分析信息"""
    site_id: str
    has_taint_path: bool
    taint_sources: List[Dict[str, Any]]
    is_sanitized: bool
    sanitizers: List[str]
    taint_confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "site_id": self.site_id,
            "has_taint_path": self.has_taint_path,
            "taint_sources": self.taint_sources,
            "is_sanitized": self.is_sanitized,
            "sanitizers": self.sanitizers,
            "taint_confidence": self.taint_confidence,
        }


@dataclass
class EnhancedSite:
    """深度增强后的触发点"""
    site: SinkCallSite
    call_chain_info: Optional[CallChainInfo] = None
    taint_info: Optional[TaintInfo] = None
    enhanced_score: float = 0.0
    priority_rank: int = 0
    analysis_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "site": self.site.to_dict(),
            "call_chain_info": self.call_chain_info.to_dict() if self.call_chain_info else None,
            "taint_info": self.taint_info.to_dict() if self.taint_info else None,
            "enhanced_score": self.enhanced_score,
            "priority_rank": self.priority_rank,
            "analysis_notes": self.analysis_notes,
        }


@dataclass
class EnhancementConfig:
    """深度增强配置"""
    enable_call_chain: bool = True
    enable_taint_analysis: bool = True
    max_call_depth: int = 10
    max_taint_paths: int = 50
    min_confidence_threshold: float = 0.3


@dataclass
class EnhancementResult:
    """深度增强结果"""
    enhanced_sites: List[EnhancedSite]
    call_graph_stats: Dict[str, int]
    taint_flow_count: int
    high_confidence_count: int
    processing_time_ms: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enhanced_sites_count": len(self.enhanced_sites),
            "call_graph_stats": self.call_graph_stats,
            "taint_flow_count": self.taint_flow_count,
            "high_confidence_count": self.high_confidence_count,
            "processing_time_ms": self.processing_time_ms,
        }

    def get_top_sites(self, limit: int = 20) -> List[EnhancedSite]:
        """获取置信度最高的触发点"""
        return sorted(
            self.enhanced_sites,
            key=lambda s: s.enhanced_score,
            reverse=True,
        )[:limit]


class DeepAnalysisEnhancer:
    """深度分析增强器

    整合调用链分析和污点分析，对预扫描发现的触发点进行深度增强。
    输出带有置信度评分的增强结果，供智能体深入分析。
    """

    def __init__(
        self,
        rule_manager: RuleManager,
        config: Optional[EnhancementConfig] = None,
    ):
        self.rule_manager = rule_manager
        self.config = config or EnhancementConfig()

        self.call_chain_analyzer = CallChainAnalyzer(rule_manager)
        self.taint_analyzer = TaintAnalyzer(rule_manager)
        self.call_graph: Optional[CallGraph] = None
        self._code_units_map: Dict[str, CodeUnit] = {}

    def enhance(
        self,
        prescan_result: PreScanResult,
        code_units: List[CodeUnit],
    ) -> EnhancementResult:
        """执行深度增强分析

        Args:
            prescan_result: 预扫描结果
            code_units: 代码单元列表

        Returns:
            EnhancementResult 包含增强后的触发点列表
        """
        import time
        start_time = time.time()

        self._code_units_map = {u.id: u for u in code_units}

        if self.config.enable_call_chain:
            self.call_graph = self.call_chain_analyzer.build_call_graph(code_units)
            self.taint_analyzer.call_graph = self.call_graph
        else:
            self.call_graph = CallGraph()

        enhanced_sites: List[EnhancedSite] = []

        for site in prescan_result.filtered_sites:
            enhanced = self._enhance_site(site)
            enhanced_sites.append(enhanced)

        enhanced_sites = self._compute_scores(enhanced_sites)
        enhanced_sites = self._assign_ranks(enhanced_sites)

        high_conf_count = sum(1 for s in enhanced_sites if s.enhanced_score >= 0.7)

        result = EnhancementResult(
            enhanced_sites=enhanced_sites,
            call_graph_stats={
                "nodes": len(self.call_graph.nodes),
                "edges": len(self.call_graph.edges),
                "entry_points": len(self.call_graph.get_entry_points()),
                "sinks": len(self.call_graph.get_sinks()),
            },
            taint_flow_count=len(getattr(self.taint_analyzer, 'flows', [])),
            high_confidence_count=high_conf_count,
            processing_time_ms=int((time.time() - start_time) * 1000),
        )

        logger.info(
            f"[DeepEnhance] 完成: 增强 {len(enhanced_sites)} 个触发点, "
            f"高置信度 {high_conf_count} 个, "
            f"调用图 {len(self.call_graph.nodes)} 节点"
        )

        return result

    def _enhance_site(self, site: SinkCallSite) -> EnhancedSite:
        """增强单个触发点"""
        enhanced = EnhancedSite(site=site)

        if self.config.enable_call_chain:
            enhanced.call_chain_info = self._analyze_call_chain(site)

        if self.config.enable_taint_analysis:
            enhanced.taint_info = self._analyze_taint(site)

        return enhanced

    def _analyze_call_chain(self, site: SinkCallSite) -> Optional[CallChainInfo]:
        """分析调用链"""
        if not self.call_graph:
            return None

        node = self.call_graph.get_node(site.unit_id)
        if not node:
            nodes = self.call_graph.get_nodes_by_name(site.symbol)
            node = nodes[0] if nodes else None

        if not node:
            return CallChainInfo(
                site_id=site.id,
                entry_points=[],
                callers=[],
                depth_to_entry=0,
                call_path=[],
            )

        callers = self._get_caller_chain(node.id, max_depth=self.config.max_call_depth)
        entry_points = self._find_entry_points(node.id)
        depth = self._get_depth_to_entry(node.id)
        has_auth = self._check_auth_in_chain(callers)
        has_sanitizer = self._check_sanitizer_in_chain(callers)

        return CallChainInfo(
            site_id=site.id,
            entry_points=[ep["name"] for ep in entry_points],
            callers=callers,
            depth_to_entry=depth,
            call_path=[c["name"] for c in callers],
            has_auth_check=has_auth,
            has_sanitizer=has_sanitizer,
        )

    def _analyze_taint(self, site: SinkCallSite) -> Optional[TaintInfo]:
        """分析污点传播"""
        unit = self._code_units_map.get(site.unit_id)
        if not unit:
            return TaintInfo(
                site_id=site.id,
                has_taint_path=False,
                taint_sources=[],
                is_sanitized=False,
                sanitizers=[],
                taint_confidence=0.0,
            )

        flows = self.taint_analyzer.analyze_code_unit(unit)

        relevant_flows = [
            f for f in flows
            if site.symbol in f.sink or any(p in f.sink for p in site.matched_patterns)
        ]

        if not relevant_flows:
            return TaintInfo(
                site_id=site.id,
                has_taint_path=False,
                taint_sources=[],
                is_sanitized=False,
                sanitizers=[],
                taint_confidence=0.2,
            )

        taint_sources = []
        all_sanitizers = []
        is_sanitized = False

        for flow in relevant_flows:
            taint_sources.append({
                "source": flow.source,
                "source_type": flow.source_type.value,
                "location": flow.source_location,
            })
            all_sanitizers.extend(flow.sanitizers)
            if flow.is_sanitized:
                is_sanitized = True

        confidence = 0.8 if not is_sanitized else 0.3

        return TaintInfo(
            site_id=site.id,
            has_taint_path=True,
            taint_sources=taint_sources,
            is_sanitized=is_sanitized,
            sanitizers=list(set(all_sanitizers)),
            taint_confidence=confidence,
        )

    def _compute_scores(
        self, sites: List[EnhancedSite]
    ) -> List[EnhancedSite]:
        """计算置信度评分"""
        for site in sites:
            score = self._calculate_score(site)
            site.enhanced_score = score
        return sites

    def _calculate_score(self, enhanced: EnhancedSite) -> float:
        """计算单个触发点的置信度评分

        评分因素（权重）:
        - 原始规则置信度 (0.2)
        - 风险等级 (0.2)
        - 有调用入口 (0.15)
        - 有污点路径 (0.25)
        - 无消毒函数 (0.1)
        - 无认证检查 (0.1)
        """
        site = enhanced.site
        score = 0.0

        score += site.confidence * 0.2

        risk_scores = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
        score += risk_scores.get(site.risk_level.value, 0.3) * 0.2

        if enhanced.call_chain_info:
            if enhanced.call_chain_info.entry_points:
                score += 0.15
                enhanced.analysis_notes.append(
                    f"有 {len(enhanced.call_chain_info.entry_points)} 个入口点可达"
                )

            if enhanced.call_chain_info.has_sanitizer:
                score -= 0.05
                enhanced.analysis_notes.append("调用链中存在消毒函数")

            if enhanced.call_chain_info.has_auth_check:
                score -= 0.05
                enhanced.analysis_notes.append("调用链中存在认证检查")

        if enhanced.taint_info:
            if enhanced.taint_info.has_taint_path:
                score += 0.25
                enhanced.analysis_notes.append(
                    f"存在 {len(enhanced.taint_info.taint_sources)} 条污点传播路径"
                )

            if enhanced.taint_info.is_sanitized:
                score -= 0.1
                enhanced.analysis_notes.append("污点数据经过消毒处理")
            else:
                score += 0.1
        else:
            score += 0.05

        return max(0.0, min(1.0, score))

    def _assign_ranks(
        self, sites: List[EnhancedSite]
    ) -> List[EnhancedSite]:
        """分配优先级排名"""
        sorted_sites = sorted(sites, key=lambda s: s.enhanced_score, reverse=True)
        for i, site in enumerate(sorted_sites, 1):
            site.priority_rank = i
        return sorted_sites

    def _get_caller_chain(
        self, node_id: str, max_depth: int = 10
    ) -> List[Dict[str, Any]]:
        """获取调用者链"""
        chain = []
        visited: Set[str] = set()
        queue = [(node_id, 0)]

        while queue and len(chain) < 20:
            current_id, depth = queue.pop(0)
            if current_id in visited or depth > max_depth:
                continue

            visited.add(current_id)

            if current_id != node_id:
                node = self.call_graph.get_node(current_id)
                if node:
                    chain.append({
                        "id": node.id,
                        "name": node.name,
                        "file": node.file_path,
                        "line": node.line_start,
                        "type": node.node_type.value,
                    })

            for caller in self.call_graph.get_callers(current_id):
                if caller.id not in visited:
                    queue.append((caller.id, depth + 1))

        return chain

    def _find_entry_points(self, node_id: str) -> List[Dict[str, Any]]:
        """找出可达的入口点"""
        entry_points = []
        visited: Set[str] = set()

        def dfs(current_id: str, depth: int):
            if current_id in visited or depth > self.config.max_call_depth:
                return
            visited.add(current_id)

            node = self.call_graph.get_node(current_id)
            if node and node.node_type == NodeType.ENTRY_POINT:
                entry_points.append({
                    "id": node.id,
                    "name": node.name,
                    "file": node.file_path,
                    "line": node.line_start,
                })

            for caller in self.call_graph.get_callers(current_id):
                dfs(caller.id, depth + 1)

        dfs(node_id, 0)
        return entry_points

    def _get_depth_to_entry(self, node_id: str) -> int:
        """计算到入口点的最短距离"""
        visited: Set[str] = set()
        queue = [(node_id, 0)]

        while queue:
            current_id, depth = queue.pop(0)
            if current_id in visited:
                continue
            visited.add(current_id)

            node = self.call_graph.get_node(current_id)
            if node and node.node_type == NodeType.ENTRY_POINT:
                return depth

            for caller in self.call_graph.get_callers(current_id):
                if caller.id not in visited:
                    queue.append((caller.id, depth + 1))

        return -1

    def _check_auth_in_chain(self, callers: List[Dict[str, Any]]) -> bool:
        """检查调用链中是否有认证检查"""
        auth_keywords = [
            "auth", "login", "permission", "check_user", "verify",
            "is_authenticated", "require_auth", "has_permission",
        ]
        for caller in callers:
            name = caller.get("name", "").lower()
            if any(kw in name for kw in auth_keywords):
                return True
        return False

    def _check_sanitizer_in_chain(self, callers: List[Dict[str, Any]]) -> bool:
        """检查调用链中是否有消毒函数"""
        for caller in callers:
            if caller.get("type") == NodeType.SANITIZER.value:
                return True
        return False

    def get_context_for_agent(
        self,
        result: EnhancementResult,
        max_sites: int = 20,
    ) -> str:
        """生成供智能体使用的增强上下文

        Args:
            result: 增强结果
            max_sites: 最大包含的触发点数量

        Returns:
            格式化的上下文字符串
        """
        lines = [
            "## 深度分析增强结果",
            "",
            f"- 调用图节点: {result.call_graph_stats.get('nodes', 0)}",
            f"- 调用图边: {result.call_graph_stats.get('edges', 0)}",
            f"- 入口点: {result.call_graph_stats.get('entry_points', 0)}",
            f"- 污点流: {result.taint_flow_count}",
            f"- 高置信度触发点: {result.high_confidence_count}",
            "",
            "### 优先分析目标（按置信度排序）",
            "",
        ]

        top_sites = result.get_top_sites(max_sites)
        for i, enhanced in enumerate(top_sites, 1):
            site = enhanced.site
            lines.append(
                f"{i}. **[{site.risk_level.value.upper()}] {site.symbol}** "
                f"(置信度: {enhanced.enhanced_score:.2f})"
            )
            lines.append(f"   文件: {site.file_path}:{site.line_start}")
            lines.append(f"   类别: {site.sink_category.value}")

            if enhanced.call_chain_info and enhanced.call_chain_info.entry_points:
                entries = ", ".join(enhanced.call_chain_info.entry_points[:3])
                lines.append(f"   入口点: {entries}")

            if enhanced.taint_info and enhanced.taint_info.has_taint_path:
                sources = [s["source_type"] for s in enhanced.taint_info.taint_sources[:3]]
                lines.append(f"   污点源: {', '.join(sources)}")
                if enhanced.taint_info.is_sanitized:
                    lines.append("   ⚠️ 已消毒")

            if enhanced.analysis_notes:
                lines.append(f"   备注: {'; '.join(enhanced.analysis_notes[:2])}")

            lines.append("")

        return "\n".join(lines)
