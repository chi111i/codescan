"""
错误标记模块

为解析结果添加元数据标记，标识解析来源和置信度。
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ...models import CodeUnit
    from .strategy import ParseError

logger = logging.getLogger(__name__)


@dataclass
class ErrorMarkedUnit:
    """带错误标记的 CodeUnit

    包装 CodeUnit 并添加解析元数据，用于：
    - 标识解析来源（Tree-sitter 或正则回退）
    - 记录关联的解析错误
    - 提供置信度评分
    """
    unit: 'CodeUnit'
    parse_source: str  # "treesitter" | "regex_fallback" | "hybrid"
    errors: List['ParseError'] = field(default_factory=list)
    confidence: float = 1.0  # 解析置信度 (0-1)

    @property
    def has_errors(self) -> bool:
        """是否有关联的解析错误"""
        return len(self.errors) > 0

    @property
    def is_fallback(self) -> bool:
        """是否来自回退解析"""
        return self.parse_source == "regex_fallback"

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典，用于 API 响应"""
        # 获取 CodeUnit 的字典表示
        if hasattr(self.unit, 'to_dict'):
            result = self.unit.to_dict()
        elif hasattr(self.unit, '__dict__'):
            result = dict(self.unit.__dict__)
        else:
            result = {}

        # 添加解析元数据
        result['_parse_metadata'] = {
            'source': self.parse_source,
            'confidence': self.confidence,
            'has_errors': self.has_errors,
            'error_count': len(self.errors),
            'is_fallback': self.is_fallback,
        }

        return result

    def get_error_summary(self) -> str:
        """获取错误摘要"""
        if not self.errors:
            return ""
        return "; ".join([str(e) for e in self.errors[:3]])


def mark_units_with_errors(
    units: List['CodeUnit'],
    parse_source: str,
    errors: Optional[List['ParseError']] = None,
    confidence: float = 1.0,
) -> List[ErrorMarkedUnit]:
    """为代码单元列表添加错误标记

    Args:
        units: CodeUnit 列表
        parse_source: 解析来源
        errors: 关联的错误列表
        confidence: 置信度

    Returns:
        ErrorMarkedUnit 列表
    """
    return [
        ErrorMarkedUnit(
            unit=unit,
            parse_source=parse_source,
            errors=errors or [],
            confidence=confidence,
        )
        for unit in units
    ]


def merge_marked_units(
    ts_units: List[ErrorMarkedUnit],
    fallback_units: List[ErrorMarkedUnit],
) -> List[ErrorMarkedUnit]:
    """合并 Tree-sitter 和回退解析的结果

    去重策略：优先保留 Tree-sitter 结果

    Args:
        ts_units: Tree-sitter 解析结果
        fallback_units: 回退解析结果

    Returns:
        合并后的结果
    """
    seen_ids = {mu.unit.id for mu in ts_units}
    merged = list(ts_units)

    for mu in fallback_units:
        if mu.unit.id not in seen_ids:
            merged.append(mu)
            seen_ids.add(mu.unit.id)

    return merged


def calculate_overall_confidence(marked_units: List[ErrorMarkedUnit]) -> float:
    """计算整体置信度

    Args:
        marked_units: ErrorMarkedUnit 列表

    Returns:
        整体置信度 (0-1)
    """
    if not marked_units:
        return 0.0

    total_confidence = sum(mu.confidence for mu in marked_units)
    return total_confidence / len(marked_units)


def filter_by_confidence(
    marked_units: List[ErrorMarkedUnit],
    min_confidence: float = 0.5,
) -> List[ErrorMarkedUnit]:
    """按置信度过滤

    Args:
        marked_units: ErrorMarkedUnit 列表
        min_confidence: 最低置信度阈值

    Returns:
        过滤后的列表
    """
    return [mu for mu in marked_units if mu.confidence >= min_confidence]


def get_units_by_source(
    marked_units: List[ErrorMarkedUnit],
    source: str,
) -> List[ErrorMarkedUnit]:
    """按解析来源筛选

    Args:
        marked_units: ErrorMarkedUnit 列表
        source: 解析来源

    Returns:
        筛选后的列表
    """
    return [mu for mu in marked_units if mu.parse_source == source]


def summarize_parse_results(marked_units: List[ErrorMarkedUnit]) -> Dict[str, Any]:
    """汇总解析结果统计

    Args:
        marked_units: ErrorMarkedUnit 列表

    Returns:
        统计信息字典
    """
    if not marked_units:
        return {
            "total": 0,
            "treesitter_count": 0,
            "fallback_count": 0,
            "with_errors": 0,
            "average_confidence": 0.0,
        }

    ts_count = sum(1 for mu in marked_units if mu.parse_source == "treesitter")
    fallback_count = sum(1 for mu in marked_units if mu.parse_source == "regex_fallback")
    error_count = sum(1 for mu in marked_units if mu.has_errors)
    avg_confidence = calculate_overall_confidence(marked_units)

    return {
        "total": len(marked_units),
        "treesitter_count": ts_count,
        "fallback_count": fallback_count,
        "with_errors": error_count,
        "average_confidence": round(avg_confidence, 3),
    }
