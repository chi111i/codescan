"""SARIF 导入模块

P1-3: 使用 SARIF 作为统一中间表示
- 导入 Semgrep/CodeQL/其他工具的 SARIF 输出
- 转换为内部 SinkCallSite 格式
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from enum import Enum

logger = logging.getLogger(__name__)


class SarifSeverity(Enum):
    """SARIF 严重性级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SarifLocation:
    """SARIF 位置信息"""
    file_path: str
    line_start: int
    line_end: int
    col_start: int = 1
    col_end: int = 1
    snippet: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "col_start": self.col_start,
            "col_end": self.col_end,
            "snippet": self.snippet,
        }


@dataclass
class SarifDataflowStep:
    """SARIF 数据流步骤"""
    location: SarifLocation
    message: str = ""
    kind: str = ""  # source, sink, propagate

    def to_dict(self) -> Dict[str, Any]:
        return {
            "location": self.location.to_dict(),
            "message": self.message,
            "kind": self.kind,
        }


@dataclass
class SarifFinding:
    """SARIF 发现结果（统一格式）"""
    # 基本信息
    rule_id: str
    message: str
    severity: SarifSeverity
    tool: str  # 来源工具：semgrep, codeql, internal

    # 位置信息
    location: SarifLocation

    # 唯一标识
    fingerprint: str = ""

    # 分类信息
    cwe: List[str] = field(default_factory=list)
    owasp: List[str] = field(default_factory=list)
    category: str = ""

    # 数据流追踪
    dataflow: List[SarifDataflowStep] = field(default_factory=list)

    # 元数据
    metadata: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)

    # 内部追踪
    source_file: str = ""  # 原始 SARIF 文件

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value,
            "tool": self.tool,
            "location": self.location.to_dict(),
            "fingerprint": self.fingerprint,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "category": self.category,
            "dataflow": [s.to_dict() for s in self.dataflow],
            "metadata": self.metadata,
            "references": self.references,
        }

    def to_sink_call_site_dict(self) -> Dict[str, Any]:
        """转换为 SinkCallSite 兼容格式"""
        return {
            "id": f"{self.tool}:{self.rule_id}:{self.fingerprint}",
            "file_path": self.location.file_path,
            "line_start": self.location.line_start,
            "line_end": self.location.line_end,
            "symbol": self.rule_id,
            "call_snippet": self.location.snippet or self.message[:200],
            "sink_category": self._infer_sink_category(),
            "risk_level": self._map_severity_to_risk(),
            "matched_rule_ids": [self.rule_id],
            "metadata": {
                "tool": self.tool,
                "cwe": self.cwe,
                "owasp": self.owasp,
                "dataflow_length": len(self.dataflow),
            },
        }

    def _infer_sink_category(self) -> str:
        """从规则 ID 和 CWE 推断 sink 类别"""
        rule_lower = self.rule_id.lower()
        cwe_set = set(self.cwe)

        # 基于 CWE 映射
        cwe_mapping = {
            "CWE-78": "command_injection",
            "CWE-89": "sql_injection",
            "CWE-22": "path_traversal",
            "CWE-94": "code_injection",
            "CWE-502": "deserialization",
            "CWE-918": "ssrf",
            "CWE-79": "xss",
            "CWE-611": "xxe",
            "CWE-798": "hardcoded_credentials",
        }
        for cwe, category in cwe_mapping.items():
            if cwe in cwe_set:
                return category

        # 基于规则 ID 关键词
        keyword_mapping = {
            "injection": "injection",
            "sqli": "sql_injection",
            "xss": "xss",
            "ssrf": "ssrf",
            "path-traversal": "path_traversal",
            "deserialization": "deserialization",
            "command": "command_injection",
            "exec": "code_execution",
            "file-read": "file_read",
            "file-write": "file_write",
            "credential": "hardcoded_credentials",
            "secret": "hardcoded_credentials",
        }
        for keyword, category in keyword_mapping.items():
            if keyword in rule_lower:
                return category

        return "other"

    def _map_severity_to_risk(self) -> str:
        """映射严重性到风险等级"""
        mapping = {
            SarifSeverity.CRITICAL: "critical",
            SarifSeverity.HIGH: "high",
            SarifSeverity.MEDIUM: "medium",
            SarifSeverity.LOW: "low",
            SarifSeverity.INFO: "info",
        }
        return mapping.get(self.severity, "medium")


class SarifImporter:
    """SARIF 文件导入器

    P1-3: 统一导入各种工具的 SARIF 输出
    """

    # 已知工具映射
    TOOL_MAPPING = {
        "semgrep": "semgrep",
        "codeql": "codeql",
        "sonarqube": "sonarqube",
        "bandit": "bandit",
        "gosec": "gosec",
        "snyk": "snyk",
    }

    def __init__(self):
        self._findings: List[SarifFinding] = []

    def import_file(self, sarif_path: str) -> List[SarifFinding]:
        """导入单个 SARIF 文件

        Args:
            sarif_path: SARIF 文件路径

        Returns:
            SarifFinding 列表
        """
        path = Path(sarif_path)
        if not path.exists():
            logger.error(f"SARIF file not found: {sarif_path}")
            return []

        try:
            with open(path, "r", encoding="utf-8") as f:
                sarif_data = json.load(f)

            findings = self._parse_sarif(sarif_data, str(path))
            self._findings.extend(findings)

            logger.info(f"Imported {len(findings)} findings from {sarif_path}")
            return findings

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse SARIF JSON: {e}")
            return []
        except Exception as e:
            logger.exception(f"Failed to import SARIF: {e}")
            return []

    def import_directory(self, directory: str, pattern: str = "*.sarif") -> List[SarifFinding]:
        """导入目录下的所有 SARIF 文件

        Args:
            directory: 目录路径
            pattern: 文件匹配模式

        Returns:
            SarifFinding 列表
        """
        dir_path = Path(directory)
        if not dir_path.is_dir():
            logger.error(f"Not a directory: {directory}")
            return []

        findings = []
        for sarif_file in dir_path.glob(pattern):
            file_findings = self.import_file(str(sarif_file))
            findings.extend(file_findings)

        # 也尝试 .json 后缀（某些工具用这个）
        if pattern == "*.sarif":
            for json_file in dir_path.glob("*sarif*.json"):
                file_findings = self.import_file(str(json_file))
                findings.extend(file_findings)

        return findings

    def import_data(self, sarif_data: Dict[str, Any], source: str = "inline") -> List[SarifFinding]:
        """直接导入 SARIF 数据

        Args:
            sarif_data: SARIF JSON 数据
            source: 数据来源标识

        Returns:
            SarifFinding 列表
        """
        findings = self._parse_sarif(sarif_data, source)
        self._findings.extend(findings)
        return findings

    def get_all_findings(self) -> List[SarifFinding]:
        """获取所有已导入的发现"""
        return self._findings

    def get_findings_by_tool(self, tool: str) -> List[SarifFinding]:
        """按工具过滤发现"""
        return [f for f in self._findings if f.tool == tool]

    def get_findings_by_severity(
        self,
        min_severity: SarifSeverity = SarifSeverity.MEDIUM
    ) -> List[SarifFinding]:
        """按最低严重性过滤"""
        severity_order = [
            SarifSeverity.INFO,
            SarifSeverity.LOW,
            SarifSeverity.MEDIUM,
            SarifSeverity.HIGH,
            SarifSeverity.CRITICAL,
        ]
        min_index = severity_order.index(min_severity)
        return [
            f for f in self._findings
            if severity_order.index(f.severity) >= min_index
        ]

    def deduplicate(self) -> List[SarifFinding]:
        """去重（基于 fingerprint 或位置）

        Returns:
            去重后的发现列表
        """
        seen = set()
        unique = []

        for finding in self._findings:
            # 优先使用 fingerprint
            if finding.fingerprint:
                key = finding.fingerprint
            else:
                # 回退到位置
                key = f"{finding.location.file_path}:{finding.location.line_start}:{finding.rule_id}"

            if key not in seen:
                seen.add(key)
                unique.append(finding)

        self._findings = unique
        logger.info(f"Deduplicated to {len(unique)} unique findings")
        return unique

    def clear(self):
        """清空已导入的发现"""
        self._findings = []

    def _parse_sarif(self, sarif_data: Dict[str, Any], source_file: str) -> List[SarifFinding]:
        """解析 SARIF 数据"""
        findings = []

        # 验证 SARIF 版本
        version = sarif_data.get("version", "")
        if not version.startswith("2.1"):
            logger.warning(f"Unsupported SARIF version: {version}")

        runs = sarif_data.get("runs", [])
        for run in runs:
            tool_info = run.get("tool", {}).get("driver", {})
            tool_name = self._identify_tool(tool_info)

            results = run.get("results", [])
            for result in results:
                finding = self._parse_result(result, tool_name, tool_info, source_file)
                if finding:
                    findings.append(finding)

        return findings

    def _identify_tool(self, driver: Dict[str, Any]) -> str:
        """识别扫描工具"""
        name = driver.get("name", "").lower()
        for key, tool_name in self.TOOL_MAPPING.items():
            if key in name:
                return tool_name
        return name or "unknown"

    def _parse_result(
        self,
        result: Dict[str, Any],
        tool: str,
        driver: Dict[str, Any],
        source_file: str
    ) -> Optional[SarifFinding]:
        """解析单个 SARIF result"""
        try:
            rule_id = result.get("ruleId", "unknown")

            # 获取规则信息
            rule_info = self._get_rule_info(rule_id, driver)

            # 消息
            message = result.get("message", {}).get("text", "")
            if not message and rule_info:
                message = rule_info.get("shortDescription", {}).get("text", "")

            # 严重性
            level = result.get("level", "warning")
            severity = self._map_level_to_severity(level, rule_info)

            # 位置
            location = self._parse_location(result)
            if not location:
                return None

            # fingerprint
            fingerprints = result.get("partialFingerprints", {})
            fingerprint = (
                fingerprints.get("primaryLocationLineHash", "") or
                fingerprints.get("primaryLocationStartColumnFingerprint", "") or
                ""
            )

            # 分类信息
            properties = result.get("properties", {})
            tags = properties.get("tags", [])
            metadata = rule_info.get("properties", {}) if rule_info else {}

            cwe = self._extract_cwe(metadata, tags)
            owasp = self._extract_owasp(metadata, tags)

            # 数据流
            dataflow = self._parse_codeflows(result)

            return SarifFinding(
                rule_id=rule_id,
                message=message,
                severity=severity,
                tool=tool,
                location=location,
                fingerprint=fingerprint,
                cwe=cwe,
                owasp=owasp,
                category=metadata.get("category", ""),
                dataflow=dataflow,
                metadata=metadata,
                references=metadata.get("references", []),
                source_file=source_file,
            )

        except Exception as e:
            logger.warning(f"Failed to parse SARIF result: {e}")
            return None

    def _get_rule_info(self, rule_id: str, driver: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """获取规则详细信息"""
        rules = driver.get("rules", [])
        for rule in rules:
            if rule.get("id") == rule_id:
                return rule
        return None

    def _parse_location(self, result: Dict[str, Any]) -> Optional[SarifLocation]:
        """解析位置信息"""
        locations = result.get("locations", [])
        if not locations:
            return None

        location = locations[0]
        physical = location.get("physicalLocation", {})
        artifact = physical.get("artifactLocation", {})
        region = physical.get("region", {})

        file_path = artifact.get("uri", "")
        if not file_path:
            return None

        # 移除 file:// 前缀
        if file_path.startswith("file://"):
            file_path = file_path[7:]

        snippet = region.get("snippet", {}).get("text", "")

        return SarifLocation(
            file_path=file_path,
            line_start=region.get("startLine", 1),
            line_end=region.get("endLine", region.get("startLine", 1)),
            col_start=region.get("startColumn", 1),
            col_end=region.get("endColumn", 1),
            snippet=snippet,
        )

    def _parse_codeflows(self, result: Dict[str, Any]) -> List[SarifDataflowStep]:
        """解析数据流追踪"""
        steps = []

        codeflows = result.get("codeFlows", [])
        for codeflow in codeflows:
            thread_flows = codeflow.get("threadFlows", [])
            for thread_flow in thread_flows:
                locations = thread_flow.get("locations", [])
                for loc in locations:
                    step = self._parse_threadflow_location(loc)
                    if step:
                        steps.append(step)

        return steps

    def _parse_threadflow_location(self, loc: Dict[str, Any]) -> Optional[SarifDataflowStep]:
        """解析 threadFlow 位置"""
        try:
            location = loc.get("location", {})
            physical = location.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})

            file_path = artifact.get("uri", "")
            if file_path.startswith("file://"):
                file_path = file_path[7:]

            sarif_location = SarifLocation(
                file_path=file_path,
                line_start=region.get("startLine", 1),
                line_end=region.get("endLine", region.get("startLine", 1)),
                col_start=region.get("startColumn", 1),
                col_end=region.get("endColumn", 1),
                snippet=region.get("snippet", {}).get("text", ""),
            )

            kinds = loc.get("kinds", [])
            kind = kinds[0] if kinds else ""

            return SarifDataflowStep(
                location=sarif_location,
                message=location.get("message", {}).get("text", ""),
                kind=kind,
            )
        except Exception:
            return None

    def _map_level_to_severity(
        self,
        level: str,
        rule_info: Optional[Dict[str, Any]]
    ) -> SarifSeverity:
        """映射 SARIF level 到严重性"""
        # 优先使用规则定义的严重性
        if rule_info:
            props = rule_info.get("properties", {})
            if "security-severity" in props:
                score = float(props["security-severity"])
                if score >= 9.0:
                    return SarifSeverity.CRITICAL
                elif score >= 7.0:
                    return SarifSeverity.HIGH
                elif score >= 4.0:
                    return SarifSeverity.MEDIUM
                elif score >= 1.0:
                    return SarifSeverity.LOW
                return SarifSeverity.INFO

        # 回退到 level 映射
        mapping = {
            "error": SarifSeverity.HIGH,
            "warning": SarifSeverity.MEDIUM,
            "note": SarifSeverity.LOW,
            "none": SarifSeverity.INFO,
        }
        return mapping.get(level.lower(), SarifSeverity.MEDIUM)

    def _extract_cwe(
        self,
        metadata: Dict[str, Any],
        tags: List[str]
    ) -> List[str]:
        """提取 CWE 信息"""
        cwe_list = []

        # 从 metadata
        cwe = metadata.get("cwe", [])
        if isinstance(cwe, str):
            cwe_list.append(cwe)
        elif isinstance(cwe, list):
            cwe_list.extend(cwe)

        # 从 tags
        for tag in tags:
            if tag.upper().startswith("CWE-"):
                cwe_list.append(tag.upper())

        return list(set(cwe_list))

    def _extract_owasp(
        self,
        metadata: Dict[str, Any],
        tags: List[str]
    ) -> List[str]:
        """提取 OWASP 信息"""
        owasp_list = []

        # 从 metadata
        owasp = metadata.get("owasp", [])
        if isinstance(owasp, str):
            owasp_list.append(owasp)
        elif isinstance(owasp, list):
            owasp_list.extend(owasp)

        # 从 tags
        for tag in tags:
            if "owasp" in tag.lower() or tag.startswith("A"):
                owasp_list.append(tag)

        return list(set(owasp_list))
