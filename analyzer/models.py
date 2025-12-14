"""
分析结果数据模型
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid


class Severity(Enum):
    """严重性级别"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """从字符串创建 Severity"""
        value_lower = value.lower() if value else "medium"
        for member in cls:
            if member.value == value_lower:
                return member
        return cls.MEDIUM  # 默认返回 MEDIUM


@dataclass
class Evidence:
    """证据信息"""
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    description: str


@dataclass
class Finding:
    """分析发现"""
    id: str
    # 基本信息
    title: str
    category: str  # auth, access-control, business-logic, injection, etc.
    severity: Severity
    confidence: float  # 0.0 - 1.0

    # 位置
    file_path: str
    symbol: str
    line_start: int
    line_end: int

    # 描述
    summary: str
    details: str
    attack_scenario: str  # 高层次攻击思路

    # 证据
    evidence: List[Evidence] = field(default_factory=list)

    # 修复建议
    fix_suggestion: str = ""

    # 需要人工确认的点
    notes: str = ""

    # 关联信息
    cwe_ids: List[str] = field(default_factory=list)
    rule_ids: List[str] = field(default_factory=list)  # 触发的规则

    # 元数据
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def generate_id() -> str:
        return str(uuid.uuid4())[:8]

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "symbol": self.symbol,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "summary": self.summary,
            "details": self.details,
            "attack_scenario": self.attack_scenario,
            "evidence": [
                {
                    "file_path": e.file_path,
                    "line_start": e.line_start,
                    "line_end": e.line_end,
                    "code_snippet": e.code_snippet,
                    "description": e.description,
                }
                for e in self.evidence
            ],
            "fix_suggestion": self.fix_suggestion,
            "notes": self.notes,
            "cwe_ids": self.cwe_ids,
            "rule_ids": self.rule_ids,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """从字典创建"""
        evidence = [
            Evidence(
                file_path=e["file_path"],
                line_start=e["line_start"],
                line_end=e["line_end"],
                code_snippet=e["code_snippet"],
                description=e["description"],
            )
            for e in data.get("evidence", [])
        ]

        return cls(
            id=data["id"],
            title=data["title"],
            category=data["category"],
            severity=Severity(data["severity"]),
            confidence=data["confidence"],
            file_path=data["file_path"],
            symbol=data["symbol"],
            line_start=data["line_start"],
            line_end=data["line_end"],
            summary=data["summary"],
            details=data["details"],
            attack_scenario=data["attack_scenario"],
            evidence=evidence,
            fix_suggestion=data.get("fix_suggestion", ""),
            notes=data.get("notes", ""),
            cwe_ids=data.get("cwe_ids", []),
            rule_ids=data.get("rule_ids", []),
            created_at=data.get("created_at", ""),
            metadata=data.get("metadata", {}),
        )


@dataclass
class AnalysisContext:
    """分析上下文 - 传递给 LLM 的信息包"""
    # 主要代码
    target_code: str
    target_file: str
    target_symbol: str
    target_line_start: int

    # 相关代码
    related_code: List[Dict[str, str]] = field(default_factory=list)  # [{file, symbol, code}]

    # 规则摘要
    rules_summary: str = ""

    # 业务上下文
    business_context: str = ""

    # 触发的规则
    triggered_rules: List[str] = field(default_factory=list)

    def to_prompt(self) -> str:
        """生成用于 LLM 的提示内容"""
        parts = ["【待分析代码】", f"文件: {self.target_file}", f"符号: {self.target_symbol}", f"行号: {self.target_line_start}", "", "```", self.target_code, "```", ""]

        if self.related_code:
            parts.append("【相关代码】")
            for item in self.related_code[:5]:  # 最多5个相关代码
                parts.append(f"\n文件: {item['file']}, 符号: {item['symbol']}")
                parts.append("```")
                parts.append(item["code"][:1000])  # 限制长度
                parts.append("```")
            parts.append("")

        if self.rules_summary:
            parts.append("【安全规则摘要】")
            parts.append(self.rules_summary)
            parts.append("")

        if self.triggered_rules:
            parts.append("【触发的规则】")
            parts.append(", ".join(self.triggered_rules))
            parts.append("")

        if self.business_context:
            parts.append("【业务上下文】")
            parts.append(self.business_context)
            parts.append("")

        return "\n".join(parts)


@dataclass
class Candidate:
    """候选分析点"""
    code_unit_id: str
    file_path: str
    symbol: str
    line_start: int
    line_end: int
    code: str
    triggered_rules: List[str]
    priority: float  # 优先级分数
