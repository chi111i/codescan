"""
RuleScanPreprocessor - 规则预扫描预处理器

在智能体深入分析前，先利用规则扫描代码发现危险函数触发点，
并根据风险等级过滤，为后续深度分析提供候选点。

核心职责：
1. 调用 SinkCallScanner 扫描危险函数触发点
2. 根据配置的风险等级过滤结果
3. 生成分类统计摘要
4. 提供结构化的预扫描结果供后续使用
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from enum import Enum

from indexer.models import CodeUnit
from rules import RuleManager
from rules.models import RiskLevel
from .sink_scanner import SinkCallScanner, SinkCallSite, SinkCategory

logger = logging.getLogger(__name__)


class PreScanStatus(Enum):
    """预扫描状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class PreScanConfig:
    """预扫描配置"""
    enabled_risk_levels: List[str] = field(
        default_factory=lambda: ["high", "critical"]
    )
    include_categories: Optional[List[str]] = None
    exclude_categories: Optional[List[str]] = None
    max_sites_per_category: int = 50
    min_confidence: float = 0.5

    def should_include_risk_level(self, level: RiskLevel) -> bool:
        """检查是否应包含该风险等级"""
        return level.value in self.enabled_risk_levels

    def should_include_category(self, category: SinkCategory) -> bool:
        """检查是否应包含该类别"""
        cat_value = category.value
        if self.exclude_categories and cat_value in self.exclude_categories:
            return False
        if self.include_categories:
            return cat_value in self.include_categories
        return True


@dataclass
class RiskSummary:
    """风险等级统计"""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low

    def to_dict(self) -> Dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "total": self.total(),
        }


@dataclass
class CategorySummary:
    """Sink 类别统计"""
    category: str
    count: int
    critical_count: int = 0
    high_count: int = 0
    files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "count": self.count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "files": self.files[:5],
            "file_count": len(self.files),
        }


@dataclass
class PreScanResult:
    """预扫描结果"""
    project_path: str
    language: Optional[str]
    status: PreScanStatus
    sink_sites: List[SinkCallSite] = field(default_factory=list)
    filtered_sites: List[SinkCallSite] = field(default_factory=list)
    risk_summary: RiskSummary = field(default_factory=RiskSummary)
    category_summaries: List[CategorySummary] = field(default_factory=list)
    total_units_scanned: int = 0
    error_message: Optional[str] = None
    scan_duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_path": self.project_path,
            "language": self.language,
            "status": self.status.value,
            "total_sites_found": len(self.sink_sites),
            "filtered_sites_count": len(self.filtered_sites),
            "risk_summary": self.risk_summary.to_dict(),
            "category_summaries": [cs.to_dict() for cs in self.category_summaries],
            "total_units_scanned": self.total_units_scanned,
            "error_message": self.error_message,
            "scan_duration_ms": self.scan_duration_ms,
        }

    def get_filtered_sites_dict(self) -> List[Dict[str, Any]]:
        """获取过滤后的触发点字典列表"""
        return [site.to_dict() for site in self.filtered_sites]

    def get_high_priority_sites(self, limit: int = 20) -> List[SinkCallSite]:
        """获取高优先级触发点（critical + high）"""
        high_priority = [
            s for s in self.filtered_sites
            if s.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        ]
        return sorted(
            high_priority,
            key=lambda s: (
                0 if s.risk_level == RiskLevel.CRITICAL else 1,
                -s.confidence,
            ),
        )[:limit]


class RuleScanPreprocessor:
    """规则预扫描预处理器

    在智能体深入分析前，先利用规则扫描代码发现危险函数触发点。
    支持按风险等级过滤，为后续深度分析提供候选点列表。
    """

    def __init__(
        self,
        rule_manager: RuleManager,
        config: Optional[PreScanConfig] = None,
    ):
        self.rule_manager = rule_manager
        self.config = config or PreScanConfig()
        self.scanner = SinkCallScanner(rule_manager)

    def scan(
        self,
        code_units: List[CodeUnit],
        project_path: str,
        language: Optional[str] = None,
    ) -> PreScanResult:
        """执行预扫描

        Args:
            code_units: 代码单元列表
            project_path: 项目路径
            language: 限定语言

        Returns:
            PreScanResult 包含扫描结果和统计信息
        """
        import time
        start_time = time.time()

        result = PreScanResult(
            project_path=project_path,
            language=language,
            status=PreScanStatus.RUNNING,
            total_units_scanned=len(code_units),
        )

        try:
            all_sites = self.scanner.scan(code_units, language)
            result.sink_sites = all_sites
            result.filtered_sites = self._filter_sites(all_sites)
            result.risk_summary = self._compute_risk_summary(result.filtered_sites)
            result.category_summaries = self._compute_category_summaries(result.filtered_sites)
            result.status = PreScanStatus.COMPLETED

            logger.info(
                f"[PreScan] 完成: 扫描 {len(code_units)} 个代码单元, "
                f"发现 {len(all_sites)} 个触发点, "
                f"过滤后保留 {len(result.filtered_sites)} 个"
            )

        except Exception as e:
            logger.error(f"[PreScan] 扫描失败: {e}")
            result.status = PreScanStatus.FAILED
            result.error_message = str(e)

        result.scan_duration_ms = int((time.time() - start_time) * 1000)
        return result

    def _filter_sites(self, sites: List[SinkCallSite]) -> List[SinkCallSite]:
        """根据配置过滤触发点"""
        filtered = []
        category_counts: Dict[str, int] = {}

        for site in sites:
            if not self.config.should_include_risk_level(site.risk_level):
                continue
            if not self.config.should_include_category(site.sink_category):
                continue
            if site.confidence < self.config.min_confidence:
                continue

            cat_key = site.sink_category.value
            current_count = category_counts.get(cat_key, 0)
            if current_count >= self.config.max_sites_per_category:
                continue

            category_counts[cat_key] = current_count + 1
            filtered.append(site)

        return filtered

    def _compute_risk_summary(self, sites: List[SinkCallSite]) -> RiskSummary:
        """计算风险等级统计"""
        summary = RiskSummary()
        for site in sites:
            if site.risk_level == RiskLevel.CRITICAL:
                summary.critical += 1
            elif site.risk_level == RiskLevel.HIGH:
                summary.high += 1
            elif site.risk_level == RiskLevel.MEDIUM:
                summary.medium += 1
            elif site.risk_level == RiskLevel.LOW:
                summary.low += 1
        return summary

    def _compute_category_summaries(
        self, sites: List[SinkCallSite]
    ) -> List[CategorySummary]:
        """计算类别统计"""
        cat_data: Dict[str, Dict[str, Any]] = {}

        for site in sites:
            cat = site.sink_category.value
            if cat not in cat_data:
                cat_data[cat] = {
                    "count": 0,
                    "critical": 0,
                    "high": 0,
                    "files": set(),
                }

            cat_data[cat]["count"] += 1
            cat_data[cat]["files"].add(site.file_path)
            if site.risk_level == RiskLevel.CRITICAL:
                cat_data[cat]["critical"] += 1
            elif site.risk_level == RiskLevel.HIGH:
                cat_data[cat]["high"] += 1

        summaries = []
        for cat, data in sorted(
            cat_data.items(), key=lambda x: x[1]["count"], reverse=True
        ):
            summaries.append(
                CategorySummary(
                    category=cat,
                    count=data["count"],
                    critical_count=data["critical"],
                    high_count=data["high"],
                    files=list(data["files"]),
                )
            )

        return summaries

    def get_context_for_agent(
        self,
        result: PreScanResult,
        max_sites: int = 30,
    ) -> str:
        """生成供智能体使用的上下文摘要

        Args:
            result: 预扫描结果
            max_sites: 最大包含的触发点数量

        Returns:
            格式化的上下文字符串
        """
        lines = [
            "## 规则预扫描结果摘要",
            "",
            f"- 扫描代码单元: {result.total_units_scanned}",
            f"- 发现危险函数触发点: {len(result.sink_sites)}",
            f"- 过滤后高危触发点: {len(result.filtered_sites)}",
            "",
            "### 风险等级分布",
            f"- Critical: {result.risk_summary.critical}",
            f"- High: {result.risk_summary.high}",
            f"- Medium: {result.risk_summary.medium}",
            f"- Low: {result.risk_summary.low}",
            "",
        ]

        if result.category_summaries:
            lines.append("### 类别分布")
            for cs in result.category_summaries[:8]:
                lines.append(
                    f"- {cs.category}: {cs.count} "
                    f"(Critical: {cs.critical_count}, High: {cs.high_count})"
                )
            lines.append("")

        high_priority = result.get_high_priority_sites(max_sites)
        if high_priority:
            lines.append("### 高优先级触发点")
            for i, site in enumerate(high_priority, 1):
                lines.append(
                    f"{i}. [{site.risk_level.value.upper()}] "
                    f"{site.file_path}:{site.line_start} - {site.symbol}"
                )
                lines.append(f"   类别: {site.sink_category.value}")
                lines.append(f"   匹配规则: {', '.join(site.matched_rule_ids)}")
                if site.call_snippet:
                    snippet = site.call_snippet.strip().replace('\n', ' ')[:100]
                    lines.append(f"   代码: {snippet}")
                lines.append("")

        return "\n".join(lines)
