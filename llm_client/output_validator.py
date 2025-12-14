"""
LLM 输出验证与幻觉控制模块

功能:
- JSON Schema 校验
- 文件路径/行号有效性检查
- 置信度验证
- 自动重试和格式修正
- 幻觉检测 (虚假路径、API、包名等)
"""

import json
import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Callable, Union
from enum import Enum

logger = logging.getLogger(__name__)


class ValidationResult(Enum):
    """验证结果"""
    VALID = "valid"
    INVALID_JSON = "invalid_json"
    SCHEMA_ERROR = "schema_error"
    HALLUCINATION_DETECTED = "hallucination_detected"
    PATH_NOT_FOUND = "path_not_found"
    CONFIDENCE_TOO_LOW = "confidence_too_low"


@dataclass
class ValidationReport:
    """验证报告"""
    result: ValidationResult
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    corrected_data: Optional[Dict[str, Any]] = None
    raw_content: str = ""


@dataclass
class LLMOutputSchema:
    """LLM 输出 Schema 定义"""
    required_fields: List[str] = field(default_factory=list)
    optional_fields: List[str] = field(default_factory=list)
    field_types: Dict[str, type] = field(default_factory=dict)
    enum_values: Dict[str, List[str]] = field(default_factory=dict)
    range_constraints: Dict[str, tuple] = field(default_factory=dict)  # field: (min, max)


# 预定义的审计结果 Schema
AUDIT_RESULT_SCHEMA = LLMOutputSchema(
    required_fields=["has_issue"],
    optional_fields=[
        "issue_type", "severity", "confidence", "summary",
        "details", "evidence", "attack_scenario", "fix_suggestion", "notes"
    ],
    field_types={
        "has_issue": bool,
        "severity": str,
        "confidence": (int, float),
        "summary": str,
        "details": (str, list),
        "evidence": list,
        "notes": str,
    },
    enum_values={
        "severity": ["low", "medium", "high", "critical"],
    },
    range_constraints={
        "confidence": (0.0, 1.0),
    }
)


# 链级分析结果 Schema（根据目标文档 P0-5）
CHAIN_ANALYSIS_SCHEMA = LLMOutputSchema(
    required_fields=[
        "chain_id",
        "sink_category",
        "has_issue",
        "confidence",
    ],
    optional_fields=[
        "risk_level",
        "issue_type",
        "summary",
        "evidence",
        "data_flow",
        "security_controls",
        "exploitability_conditions",
        "fix_suggestion",
        "notes",
    ],
    field_types={
        "chain_id": str,
        "sink_category": str,
        "has_issue": (bool, str),  # 允许 "uncertain"
        "risk_level": str,
        "issue_type": str,
        "confidence": (int, float),
        "summary": str,
        "evidence": list,
        "data_flow": str,
        "security_controls": list,
        "exploitability_conditions": str,
        "fix_suggestion": str,
        "notes": str,
    },
    enum_values={
        "risk_level": ["low", "medium", "high", "critical"],
        "sink_category": [
            "command_exec", "code_exec", "sql_injection",
            "file_read", "file_write", "deserialization",
            "ssrf", "xss", "path_traversal", "other"
        ],
    },
    range_constraints={
        "confidence": (0.0, 1.0),
    }
)


class OutputValidator:
    """LLM 输出验证器"""

    def __init__(
        self,
        project_root: Optional[str] = None,
        known_files: Optional[Set[str]] = None,
        min_confidence: float = 0.0
    ):
        """初始化验证器

        Args:
            project_root: 项目根目录 (用于验证文件路径)
            known_files: 已知文件路径集合
            min_confidence: 最低置信度阈值
        """
        self.project_root = Path(project_root) if project_root else None
        self.known_files = known_files or set()
        self.min_confidence = min_confidence

    def validate(
        self,
        content: str,
        schema: Optional[LLMOutputSchema] = None,
        check_hallucinations: bool = True
    ) -> ValidationReport:
        """验证 LLM 输出

        Args:
            content: LLM 输出内容
            schema: 输出 Schema
            check_hallucinations: 是否检查幻觉

        Returns:
            ValidationReport
        """
        errors = []
        warnings = []

        # 1. JSON 解析
        data = self._parse_json(content)
        if data is None:
            return ValidationReport(
                result=ValidationResult.INVALID_JSON,
                is_valid=False,
                errors=["Failed to parse JSON from LLM output"],
                raw_content=content
            )

        # 2. Schema 校验
        if schema:
            schema_errors = self._validate_schema(data, schema)
            if schema_errors:
                errors.extend(schema_errors)

        # 3. 幻觉检测
        if check_hallucinations:
            hallucination_issues = self._detect_hallucinations(data)
            if hallucination_issues["errors"]:
                errors.extend(hallucination_issues["errors"])
            if hallucination_issues["warnings"]:
                warnings.extend(hallucination_issues["warnings"])

        # 4. 置信度检查
        confidence = data.get("confidence")
        if confidence is not None and confidence < self.min_confidence:
            warnings.append(
                f"Confidence {confidence} is below threshold {self.min_confidence}"
            )

        # 确定最终结果
        if errors:
            # 检查是否是幻觉相关错误
            if any("hallucination" in e.lower() or "not found" in e.lower() for e in errors):
                result = ValidationResult.HALLUCINATION_DETECTED
            elif any("schema" in e.lower() or "field" in e.lower() for e in errors):
                result = ValidationResult.SCHEMA_ERROR
            else:
                result = ValidationResult.INVALID_JSON
            is_valid = False
        else:
            result = ValidationResult.VALID
            is_valid = True

        return ValidationReport(
            result=result,
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            corrected_data=data,
            raw_content=content
        )

    def _parse_json(self, content: str) -> Optional[Dict[str, Any]]:
        """解析 JSON，支持从文本中提取"""
        # 直接尝试解析
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        # 尝试从 markdown 代码块中提取
        json_patterns = [
            r'```json\s*([\s\S]*?)\s*```',
            r'```\s*([\s\S]*?)\s*```',
            r'\{[\s\S]*\}',
        ]

        for pattern in json_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                try:
                    return json.loads(match)
                except json.JSONDecodeError:
                    continue

        return None

    def _validate_schema(
        self,
        data: Dict[str, Any],
        schema: LLMOutputSchema
    ) -> List[str]:
        """Schema 校验"""
        errors = []

        # 检查必需字段
        for field in schema.required_fields:
            if field not in data:
                errors.append(f"Missing required field: {field}")

        # 检查字段类型
        for field, expected_type in schema.field_types.items():
            if field in data and data[field] is not None:
                if isinstance(expected_type, tuple):
                    if not isinstance(data[field], expected_type):
                        errors.append(
                            f"Field '{field}' has wrong type: expected {expected_type}, got {type(data[field])}"
                        )
                else:
                    if not isinstance(data[field], expected_type):
                        errors.append(
                            f"Field '{field}' has wrong type: expected {expected_type.__name__}, got {type(data[field]).__name__}"
                        )

        # 检查枚举值
        for field, allowed_values in schema.enum_values.items():
            if field in data and data[field] is not None:
                if data[field] not in allowed_values:
                    errors.append(
                        f"Field '{field}' has invalid value: {data[field]}, allowed: {allowed_values}"
                    )

        # 检查范围约束
        for field, (min_val, max_val) in schema.range_constraints.items():
            if field in data and data[field] is not None:
                value = data[field]
                if not (min_val <= value <= max_val):
                    errors.append(
                        f"Field '{field}' value {value} is out of range [{min_val}, {max_val}]"
                    )

        return errors

    def _detect_hallucinations(self, data: Dict[str, Any]) -> Dict[str, List[str]]:
        """检测幻觉"""
        errors = []
        warnings = []

        # 检查 evidence 中的文件路径
        evidence = data.get("evidence", [])
        if isinstance(evidence, list):
            for item in evidence:
                if isinstance(item, dict):
                    file_path = item.get("file") or item.get("file_path")
                    if file_path:
                        path_issues = self._check_file_path(file_path)
                        errors.extend(path_issues["errors"])
                        warnings.extend(path_issues["warnings"])

                    line_num = item.get("line") or item.get("line_number")
                    if line_num and not isinstance(line_num, int):
                        warnings.append(f"Invalid line number: {line_num}")

        # 检查可能的虚假包名 (简单启发式)
        fix_suggestion = data.get("fix_suggestion", "")
        if isinstance(fix_suggestion, str):
            suspicious_packages = self._detect_suspicious_packages(fix_suggestion)
            if suspicious_packages:
                warnings.append(
                    f"Potentially fabricated packages detected: {suspicious_packages}. "
                    "Please verify these packages exist before using them."
                )

        return {"errors": errors, "warnings": warnings}

    def _check_file_path(self, file_path: str) -> Dict[str, List[str]]:
        """检查文件路径有效性"""
        errors = []
        warnings = []

        # 如果有已知文件列表，检查是否存在
        if self.known_files:
            # 标准化路径
            normalized = file_path.replace("\\", "/")
            if normalized not in self.known_files and not any(
                normalized.endswith(f) or f.endswith(normalized)
                for f in self.known_files
            ):
                warnings.append(f"File path not in known files: {file_path}")

        # 如果有项目根目录，检查文件是否存在
        if self.project_root:
            full_path = self.project_root / file_path
            if not full_path.exists():
                warnings.append(f"File does not exist: {file_path}")

        # 检查路径格式是否合理
        if not re.match(r'^[\w\-./\\]+$', file_path):
            warnings.append(f"File path contains unusual characters: {file_path}")

        return {"errors": errors, "warnings": warnings}

    def _detect_suspicious_packages(self, text: str) -> List[str]:
        """检测可能的虚假包名"""
        # 提取 import 语句中的包名
        import_patterns = [
            r'import\s+(\w+)',
            r'from\s+(\w+)\s+import',
            r'pip install\s+(\S+)',
            r'npm install\s+(\S+)',
            r'require\([\'"](\S+)[\'"]\)',
        ]

        packages = set()
        for pattern in import_patterns:
            packages.update(re.findall(pattern, text))

        # 简单的启发式检测
        suspicious = []
        for pkg in packages:
            # 检查是否是随机字符串
            if len(pkg) > 20:
                suspicious.append(pkg)
            # 检查是否包含奇怪的字符组合
            if re.search(r'[0-9]{5,}', pkg):
                suspicious.append(pkg)

        return suspicious


class OutputCorrector:
    """LLM 输出修正器

    当输出格式不正确时，尝试自动修正或请求 LLM 重新生成
    """

    def __init__(self, llm_client, max_retries: int = 2):
        """初始化

        Args:
            llm_client: LLM 客户端
            max_retries: 最大重试次数
        """
        self.llm_client = llm_client
        self.max_retries = max_retries

    def correct_output(
        self,
        original_content: str,
        validation_report: ValidationReport,
        original_messages: List[Any]
    ) -> Optional[Dict[str, Any]]:
        """尝试修正输出

        Args:
            original_content: 原始 LLM 输出
            validation_report: 验证报告
            original_messages: 原始消息列表

        Returns:
            修正后的数据，如果无法修正则返回 None
        """
        from llm_client import ChatMessage

        if validation_report.result == ValidationResult.INVALID_JSON:
            # 尝试请求 LLM 修正 JSON 格式
            correction_prompt = f"""The previous response was not valid JSON. Please fix the following output and return ONLY valid JSON:

Original output:
{original_content[:2000]}

Errors:
{chr(10).join(validation_report.errors)}

Please return the corrected JSON without any explanation or markdown formatting."""

            for attempt in range(self.max_retries):
                try:
                    response = self.llm_client.chat_completion(
                        messages=[
                            ChatMessage(role="user", content=correction_prompt)
                        ],
                        response_format={"type": "json_object"},
                        temperature=0
                    )

                    corrected = json.loads(response.content)
                    logger.info(f"Successfully corrected JSON on attempt {attempt + 1}")
                    return corrected

                except (json.JSONDecodeError, Exception) as e:
                    logger.warning(f"Correction attempt {attempt + 1} failed: {e}")
                    continue

        return None


class HallucinationGuard:
    """幻觉防护器

    在将 LLM 建议应用到项目之前进行安全检查
    """

    def __init__(
        self,
        project_root: str,
        known_packages: Optional[Set[str]] = None,
        strict_mode: bool = True
    ):
        """初始化

        Args:
            project_root: 项目根目录
            known_packages: 已知安全的包列表
            strict_mode: 严格模式 (阻止任何可疑内容)
        """
        self.project_root = Path(project_root)
        self.known_packages = known_packages or set()
        self.strict_mode = strict_mode

        # 加载项目文件列表
        self.project_files = self._scan_project_files()

    def _scan_project_files(self) -> Set[str]:
        """扫描项目文件"""
        files = set()
        try:
            for path in self.project_root.rglob("*"):
                if path.is_file():
                    rel_path = str(path.relative_to(self.project_root))
                    files.add(rel_path.replace("\\", "/"))
        except Exception as e:
            logger.warning(f"Failed to scan project files: {e}")
        return files

    def check_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """检查单个发现的有效性

        Args:
            finding: 审计发现

        Returns:
            检查结果，包含 is_valid 和 issues 字段
        """
        issues = []

        # 检查文件路径
        file_path = finding.get("file") or finding.get("file_path")
        if file_path:
            normalized = file_path.replace("\\", "/")
            if normalized not in self.project_files:
                issues.append({
                    "type": "file_not_found",
                    "message": f"Referenced file does not exist: {file_path}",
                    "severity": "high" if self.strict_mode else "medium"
                })

        # 检查行号
        line_num = finding.get("line") or finding.get("line_number")
        if line_num and file_path:
            if not self._validate_line_number(file_path, line_num):
                issues.append({
                    "type": "invalid_line",
                    "message": f"Line number {line_num} may be invalid for {file_path}",
                    "severity": "medium"
                })

        # 检查修复建议中的依赖
        fix = finding.get("fix_suggestion", "")
        suspicious_deps = self._check_dependencies(fix)
        if suspicious_deps:
            issues.append({
                "type": "suspicious_dependency",
                "message": f"Potentially fabricated dependencies: {suspicious_deps}",
                "severity": "high"
            })

        return {
            "is_valid": len([i for i in issues if i["severity"] == "high"]) == 0,
            "issues": issues,
            "needs_review": len(issues) > 0
        }

    def _validate_line_number(self, file_path: str, line_num: int) -> bool:
        """验证行号是否有效"""
        try:
            full_path = self.project_root / file_path
            if full_path.exists():
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    total_lines = sum(1 for _ in f)
                return 1 <= line_num <= total_lines
        except Exception:
            pass
        return True  # 无法验证时假设有效

    def _check_dependencies(self, text: str) -> List[str]:
        """检查文本中提到的依赖是否可疑"""
        # 提取 pip/npm 安装命令中的包名
        patterns = [
            r'pip install\s+([^\s]+)',
            r'npm install\s+([^\s]+)',
            r'yarn add\s+([^\s]+)',
        ]

        packages = []
        for pattern in patterns:
            packages.extend(re.findall(pattern, text))

        suspicious = []
        for pkg in packages:
            # 清理包名
            pkg = pkg.strip().split("[")[0].split(">=")[0].split("==")[0]
            if pkg and pkg not in self.known_packages:
                # 简单启发式：非常短或非常长的包名可能是虚构的
                if len(pkg) < 2 or len(pkg) > 50:
                    suspicious.append(pkg)
                # 检查是否是随机字符串
                elif re.match(r'^[a-z0-9]{10,}$', pkg):
                    suspicious.append(pkg)

        return suspicious


def create_validator(
    config,
    project_root: Optional[str] = None,
    known_files: Optional[Set[str]] = None
) -> OutputValidator:
    """创建输出验证器

    Args:
        config: AuditConfig
        project_root: 项目根目录
        known_files: 已知文件列表

    Returns:
        OutputValidator 实例
    """
    return OutputValidator(
        project_root=project_root or config.scan.target_path,
        known_files=known_files,
        min_confidence=config.rules.min_confidence
    )
