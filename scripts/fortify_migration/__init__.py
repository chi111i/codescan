"""Fortify 规则转换模块

将 Fortify XML 格式的安全规则转换为 CodeScan YAML 格式。
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

__all__ = [
    'FortifyRule',
    'ConversionResult',
    'ConversionStats',
]


@dataclass
class FortifyRule:
    """Fortify 原始规则数据"""
    rule_id: str
    rule_type: str  # StructuralRule/SemanticRule/DataflowRule
    language: str
    vuln_kingdom: str
    vuln_category: str
    vuln_subcategory: Optional[str]
    default_severity: float
    predicate: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    # 从 MetaInfo 提取的字段
    impact: Optional[float] = None
    accuracy: Optional[float] = None
    probability: Optional[float] = None
    cwe_ids: List[str] = field(default_factory=list)
    owasp_ids: List[str] = field(default_factory=list)


@dataclass
class ConversionResult:
    """单条规则转换结果"""
    success: bool
    fortify_rule: FortifyRule
    patterns: Optional[List[str]] = None
    conversion_method: str = ""  # direct/heuristic/llm/failed
    confidence: float = 0.0
    error_message: Optional[str] = None
    codescan_rule: Optional[Dict[str, Any]] = None


@dataclass
class ConversionStats:
    """转换统计信息"""
    total_rules: int = 0
    successful: int = 0
    failed: int = 0
    by_method: Dict[str, int] = field(default_factory=dict)
    by_language: Dict[str, int] = field(default_factory=dict)
    by_category: Dict[str, int] = field(default_factory=dict)

    def add_result(self, result: ConversionResult):
        """添加转换结果"""
        self.total_rules += 1

        if result.success:
            self.successful += 1
            method = result.conversion_method
            self.by_method[method] = self.by_method.get(method, 0) + 1
        else:
            self.failed += 1

        lang = result.fortify_rule.language
        self.by_language[lang] = self.by_language.get(lang, 0) + 1

        cat = result.fortify_rule.vuln_category
        self.by_category[cat] = self.by_category.get(cat, 0) + 1

    def success_rate(self) -> float:
        """计算成功率"""
        if self.total_rules == 0:
            return 0.0
        return self.successful / self.total_rules

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'total_rules': self.total_rules,
            'successful': self.successful,
            'failed': self.failed,
            'success_rate': f"{self.success_rate():.2%}",
            'by_method': self.by_method,
            'by_language': self.by_language,
            'by_category': self.by_category,
        }
