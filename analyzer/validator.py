"""确定性验证器模块

P2-2: 验证 LLM 输出的发现，防止幻觉
- 校验文件路径存在
- 校验行号范围内包含 sink 调用
- 校验调用链路径真实存在
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class ValidationStatus(Enum):
    """验证状态"""
    VALID = "valid"
    INVALID = "invalid"
    UNCERTAIN = "uncertain"
    NEEDS_REVIEW = "needs_review"


@dataclass
class ValidationIssue:
    """验证问题"""
    issue_type: str
    message: str
    severity: str = "warning"  # error, warning, info
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "issue_type": self.issue_type,
            "message": self.message,
            "severity": self.severity,
            "details": self.details,
        }


@dataclass
class ValidationResult:
    """验证结果"""
    status: ValidationStatus
    confidence: float
    issues: List[ValidationIssue] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        return self.status == ValidationStatus.VALID

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "confidence": self.confidence,
            "issues": [i.to_dict() for i in self.issues],
            "evidence": self.evidence,
        }


class DeterministicValidator:
    """确定性验证器

    P2-2: 验证 LLM 发现，防止幻觉

    验证内容：
    1. 文件路径存在性
    2. 行号有效性
    3. Sink 调用存在性
    4. 调用链路径有效性
    """

    def __init__(self, project_root: Optional[str] = None):
        self.project_root = Path(project_root) if project_root else None
        self._file_cache: Dict[str, List[str]] = {}
        self._existence_cache: Dict[str, bool] = {}

    def set_project_root(self, project_root: str):
        """设置项目根目录"""
        self.project_root = Path(project_root)
        self._file_cache.clear()
        self._existence_cache.clear()

    def validate_finding(self, finding: Dict[str, Any]) -> ValidationResult:
        """验证单个发现

        Args:
            finding: 发现结果字典，需包含：
                - file_path: 文件路径
                - line_start/line_end: 行号范围
                - sink_call/call_snippet: Sink 调用代码
                - call_chain: 调用链（可选）

        Returns:
            ValidationResult 验证结果
        """
        issues: List[ValidationIssue] = []
        evidence: Dict[str, Any] = {}
        confidence = 1.0

        # 1. 验证文件路径
        file_path = finding.get("file_path", "")
        file_valid, file_issue = self._validate_file_path(file_path)
        if file_issue:
            issues.append(file_issue)
            confidence -= 0.3

        # 2. 验证行号
        if file_valid:
            line_start = finding.get("line_start", 0)
            line_end = finding.get("line_end", line_start)
            line_valid, line_issue, line_content = self._validate_line_range(
                file_path, line_start, line_end
            )
            if line_issue:
                issues.append(line_issue)
                confidence -= 0.2
            if line_content:
                evidence["actual_code"] = line_content

        # 3. 验证 Sink 调用存在性
        if file_valid:
            sink_call = finding.get("sink_call") or finding.get("call_snippet", "")
            sink_valid, sink_issue = self._validate_sink_exists(
                file_path, line_start, line_end, sink_call
            )
            if sink_issue:
                issues.append(sink_issue)
                confidence -= 0.25

        # 4. 验证调用链（如果存在）
        call_chain = finding.get("call_chain") or finding.get("chain_nodes", [])
        if call_chain:
            chain_valid, chain_issues = self._validate_call_chain(call_chain)
            issues.extend(chain_issues)
            if not chain_valid:
                confidence -= 0.15

        # 5. 验证 evidence 中的每个引用
        evidence_items = finding.get("evidence", [])
        if evidence_items:
            evidence_issues = self._validate_evidence_items(evidence_items)
            issues.extend(evidence_issues)
            if evidence_issues:
                confidence -= 0.1 * len(evidence_issues)

        # 确定最终状态
        status = self._determine_status(issues, confidence)

        return ValidationResult(
            status=status,
            confidence=max(0.0, min(1.0, confidence)),
            issues=issues,
            evidence=evidence,
        )

    def validate_findings_batch(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Tuple[Dict[str, Any], ValidationResult]]:
        """批量验证发现

        Args:
            findings: 发现列表

        Returns:
            (finding, validation_result) 元组列表
        """
        results = []
        for finding in findings:
            try:
                result = self.validate_finding(finding)
                results.append((finding, result))
            except Exception as e:
                logger.warning(f"Validation failed for finding: {e}")
                results.append((finding, ValidationResult(
                    status=ValidationStatus.UNCERTAIN,
                    confidence=0.5,
                    issues=[ValidationIssue(
                        issue_type="validation_error",
                        message=f"Validation failed: {e}",
                        severity="error"
                    )]
                )))
        return results

    def filter_valid_findings(
        self,
        findings: List[Dict[str, Any]],
        min_confidence: float = 0.6
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """过滤并返回有效的发现

        Args:
            findings: 发现列表
            min_confidence: 最低置信度阈值

        Returns:
            (valid_findings, invalid_findings) 元组
        """
        valid = []
        invalid = []

        for finding in findings:
            result = self.validate_finding(finding)
            finding["_validation"] = result.to_dict()

            if result.is_valid() and result.confidence >= min_confidence:
                valid.append(finding)
            else:
                invalid.append(finding)

        logger.info(
            f"[Validator] Valid: {len(valid)}, Invalid/Uncertain: {len(invalid)}"
        )

        return valid, invalid

    def _validate_file_path(self, file_path: str) -> Tuple[bool, Optional[ValidationIssue]]:
        """验证文件路径是否存在"""
        if not file_path:
            return False, ValidationIssue(
                issue_type="missing_file_path",
                message="File path is empty",
                severity="error"
            )

        # 缓存检查
        if file_path in self._existence_cache:
            exists = self._existence_cache[file_path]
        else:
            # 尝试绝对路径
            path = Path(file_path)
            if not path.is_absolute() and self.project_root:
                path = self.project_root / file_path

            exists = path.exists()
            self._existence_cache[file_path] = exists

        if not exists:
            return False, ValidationIssue(
                issue_type="file_not_found",
                message=f"File does not exist: {file_path}",
                severity="error",
                details={"file_path": file_path}
            )

        return True, None

    def _validate_line_range(
        self,
        file_path: str,
        line_start: int,
        line_end: int
    ) -> Tuple[bool, Optional[ValidationIssue], Optional[str]]:
        """验证行号范围是否有效"""
        if line_start <= 0:
            return False, ValidationIssue(
                issue_type="invalid_line_number",
                message=f"Invalid line start: {line_start}",
                severity="error"
            ), None

        # 读取文件内容
        lines = self._get_file_lines(file_path)
        if not lines:
            return False, ValidationIssue(
                issue_type="file_read_error",
                message=f"Could not read file: {file_path}",
                severity="warning"
            ), None

        total_lines = len(lines)
        if line_start > total_lines:
            return False, ValidationIssue(
                issue_type="line_out_of_range",
                message=f"Line {line_start} exceeds file length ({total_lines})",
                severity="error",
                details={"line_start": line_start, "total_lines": total_lines}
            ), None

        if line_end > total_lines:
            line_end = total_lines

        # 获取代码内容
        code_lines = lines[line_start - 1:line_end]
        code_content = "\n".join(code_lines)

        return True, None, code_content

    def _validate_sink_exists(
        self,
        file_path: str,
        line_start: int,
        line_end: int,
        sink_call: str
    ) -> Tuple[bool, Optional[ValidationIssue]]:
        """验证 Sink 调用是否存在于指定行"""
        if not sink_call:
            return True, None  # 无 sink 信息，跳过验证

        lines = self._get_file_lines(file_path)
        if not lines:
            return False, ValidationIssue(
                issue_type="file_read_error",
                message=f"Could not read file to verify sink",
                severity="warning"
            )

        # 获取目标行范围
        if line_start <= 0 or line_start > len(lines):
            return False, None

        line_end = min(line_end, len(lines))
        target_code = "\n".join(lines[line_start - 1:line_end])

        # 提取 sink 函数名
        sink_pattern = self._extract_function_name(sink_call)
        if not sink_pattern:
            return True, None  # 无法提取函数名，跳过

        # 检查是否存在
        if sink_pattern.lower() not in target_code.lower():
            return False, ValidationIssue(
                issue_type="sink_not_found",
                message=f"Sink '{sink_pattern}' not found at lines {line_start}-{line_end}",
                severity="warning",
                details={
                    "expected_sink": sink_pattern,
                    "line_range": f"{line_start}-{line_end}",
                }
            )

        return True, None

    def _validate_call_chain(
        self,
        call_chain: List[Dict[str, Any]]
    ) -> Tuple[bool, List[ValidationIssue]]:
        """验证调用链路径"""
        issues = []
        all_valid = True

        for i, node in enumerate(call_chain):
            node_file = node.get("file_path", "")
            node_line = node.get("line_start", 0)

            # 验证节点文件存在
            if node_file:
                file_valid, file_issue = self._validate_file_path(node_file)
                if file_issue:
                    issues.append(ValidationIssue(
                        issue_type="chain_node_invalid",
                        message=f"Chain node {i}: {file_issue.message}",
                        severity="warning",
                        details={"node_index": i, "node": node}
                    ))
                    all_valid = False

        return all_valid, issues

    def _validate_evidence_items(
        self,
        evidence_items: List[Dict[str, Any]]
    ) -> List[ValidationIssue]:
        """验证 evidence 中的每个引用"""
        issues = []

        for i, item in enumerate(evidence_items):
            file_path = item.get("file_path", "")
            line_start = item.get("line_start", 0)
            line_end = item.get("line_end", line_start)

            if file_path:
                file_valid, file_issue = self._validate_file_path(file_path)
                if file_issue:
                    issues.append(ValidationIssue(
                        issue_type="evidence_invalid",
                        message=f"Evidence {i}: {file_issue.message}",
                        severity="warning",
                        details={"evidence_index": i}
                    ))
                elif line_start > 0:
                    line_valid, line_issue, _ = self._validate_line_range(
                        file_path, line_start, line_end
                    )
                    if line_issue:
                        issues.append(ValidationIssue(
                            issue_type="evidence_line_invalid",
                            message=f"Evidence {i}: {line_issue.message}",
                            severity="warning",
                            details={"evidence_index": i}
                        ))

        return issues

    def _get_file_lines(self, file_path: str) -> List[str]:
        """获取文件内容（带缓存）"""
        if file_path in self._file_cache:
            return self._file_cache[file_path]

        try:
            path = Path(file_path)
            if not path.is_absolute() and self.project_root:
                path = self.project_root / file_path

            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
                self._file_cache[file_path] = lines
                return lines
        except Exception as e:
            logger.debug(f"Failed to read file {file_path}: {e}")
            return []

    def _extract_function_name(self, code: str) -> Optional[str]:
        """从代码片段提取函数名"""
        # 常见模式
        patterns = [
            r"(\w+)\s*\(",  # function_name(
            r"\.(\w+)\s*\(",  # .method_name(
            r"(\w+)\s*=",  # assignment
        ]

        for pattern in patterns:
            match = re.search(pattern, code)
            if match:
                name = match.group(1)
                # 过滤掉太短或常见关键字
                if len(name) > 2 and name not in {"if", "for", "while", "def", "class", "return"}:
                    return name

        return None

    def _determine_status(
        self,
        issues: List[ValidationIssue],
        confidence: float
    ) -> ValidationStatus:
        """确定验证状态"""
        # 有严重错误
        error_count = sum(1 for i in issues if i.severity == "error")
        if error_count > 0:
            return ValidationStatus.INVALID

        # 多个警告
        warning_count = sum(1 for i in issues if i.severity == "warning")
        if warning_count >= 2:
            return ValidationStatus.NEEDS_REVIEW

        # 置信度低
        if confidence < 0.5:
            return ValidationStatus.UNCERTAIN

        if confidence < 0.7:
            return ValidationStatus.NEEDS_REVIEW

        return ValidationStatus.VALID

    def clear_cache(self):
        """清空缓存"""
        self._file_cache.clear()
        self._existence_cache.clear()
