"""
安全规则数据模型
"""

from dataclasses import dataclass, field
from enum import Enum
from functools import total_ordering
from typing import List, Optional, Dict, Any


@total_ordering
class RiskLevel(Enum):
    """风险等级（支持比较操作）"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def _get_order(self) -> int:
        """获取风险等级的排序值"""
        order_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return order_map.get(self.value, 0)

    def __lt__(self, other):
        if isinstance(other, RiskLevel):
            return self._get_order() < other._get_order()
        return NotImplemented

    def __eq__(self, other):
        if isinstance(other, RiskLevel):
            return self.value == other.value
        return NotImplemented

    def __hash__(self):
        return hash(self.value)


class RuleCategory(Enum):
    """规则类别"""
    AUTH = "auth"  # 认证
    ACCESS_CONTROL = "access-control"  # 授权/访问控制
    BUSINESS_LOGIC = "business-logic"  # 业务逻辑
    INJECTION = "injection"  # 注入
    DESERIALIZATION = "deserialization"  # 反序列化
    CRYPTO = "crypto"  # 加密相关
    SSRF = "ssrf"  # 服务端请求伪造
    FILE = "file"  # 文件操作（读/写/路径遍历）
    FILE_UPLOAD = "file-upload"  # 文件上传
    XSS = "xss"  # 跨站脚本
    XXE = "xxe"  # XML外部实体
    OTHER = "other"


class RuleType(Enum):
    """规则类型"""
    SINK = "sink"  # 危险函数
    SOURCE = "source"  # 输入源
    SANITIZER = "sanitizer"  # 消毒函数
    PATTERN = "pattern"  # 代码模式


@dataclass
class SecurityRule:
    """安全规则定义"""
    id: str  # 唯一标识
    name: str  # 规则名称
    rule_type: RuleType
    category: RuleCategory
    risk_level: RiskLevel

    # 匹配条件
    languages: List[str]  # 适用语言
    patterns: List[str]  # 匹配模式（函数名、正则等）
    frameworks: List[str] = field(default_factory=list)  # 适用框架

    # 描述信息
    description: str = ""
    example: str = ""  # 示例代码
    fix_suggestion: str = ""  # 修复建议

    # 关联信息
    cwe_ids: List[str] = field(default_factory=list)  # CWE ID
    owasp_ids: List[str] = field(default_factory=list)  # OWASP 分类

    # 附加标签
    tags: List[str] = field(default_factory=list)

    # 元数据
    metadata: Dict[str, Any] = field(default_factory=dict)

    def matches(self, function_name: str) -> bool:
        """检查函数名是否匹配该规则"""
        import re
        for pattern in self.patterns:
            if pattern.startswith("regex:"):
                if re.match(pattern[6:], function_name):
                    return True
            elif pattern.startswith("prefix:"):
                if function_name.startswith(pattern[7:]):
                    return True
            elif pattern.startswith("suffix:"):
                if function_name.endswith(pattern[7:]):
                    return True
            elif pattern.startswith("contains:"):
                if pattern[9:] in function_name:
                    return True
            else:
                # 精确匹配
                if function_name == pattern:
                    return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "name": self.name,
            "rule_type": self.rule_type.value,
            "category": self.category.value,
            "risk_level": self.risk_level.value,
            "languages": self.languages,
            "patterns": self.patterns,
            "frameworks": self.frameworks,
            "description": self.description,
            "example": self.example,
            "fix_suggestion": self.fix_suggestion,
            "cwe_ids": self.cwe_ids,
            "owasp_ids": self.owasp_ids,
            "tags": self.tags,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityRule":
        """从字典创建"""
        return cls(
            id=data["id"],
            name=data["name"],
            rule_type=RuleType(data["rule_type"]),
            category=RuleCategory(data["category"]),
            risk_level=RiskLevel(data["risk_level"]),
            languages=data.get("languages", []),
            patterns=data.get("patterns", []),
            frameworks=data.get("frameworks", []),
            description=data.get("description", ""),
            example=data.get("example", ""),
            fix_suggestion=data.get("fix_suggestion", ""),
            cwe_ids=data.get("cwe_ids", []),
            owasp_ids=data.get("owasp_ids", []),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )

    def to_prompt_text(self) -> str:
        """生成用于 LLM 提示词的描述文本"""
        lines = [
            f"[{self.rule_type.value.upper()}] {self.name}",
            f"  类别: {self.category.value}",
            f"  风险: {self.risk_level.value}",
            f"  模式: {', '.join(self.patterns[:5])}",
        ]
        if self.description:
            lines.append(f"  说明: {self.description[:200]}")
        if self.cwe_ids:
            lines.append(f"  CWE: {', '.join(self.cwe_ids[:3])}")
        return "\n".join(lines)


@dataclass
class RuleMatch:
    """规则匹配结果"""
    rule: SecurityRule
    matched_pattern: str
    location: str  # file:line
    code_snippet: str
    confidence: float = 1.0
