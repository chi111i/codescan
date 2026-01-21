"""Semgrep 集成模块

P1-1: 使用 Semgrep 作为候选点生成器
- 执行 Semgrep 扫描
- 解析 SARIF/JSON 输出
- 转换为内部 SinkCallSite 格式
"""

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class SemgrepSeverity(Enum):
    """Semgrep 严重性级别"""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class SemgrepConfig:
    """Semgrep 运行配置"""
    # 规则配置
    rules_path: Optional[str] = None  # 自定义规则目录
    config: str = "auto"  # 默认使用 auto 配置
    include_patterns: List[str] = field(default_factory=list)  # 包含模式
    exclude_patterns: List[str] = field(default_factory=list)  # 排除模式

    # 性能配置
    timeout: int = 300  # 超时（秒）
    max_target_bytes: int = 10_000_000  # 最大文件大小
    jobs: int = 4  # 并发数

    # 输出配置
    output_format: str = "sarif"  # sarif 或 json
    severity_filter: List[str] = field(default_factory=lambda: ["error", "warning"])

    # 功能开关
    enable_taint_mode: bool = True  # 启用污点分析
    enable_secrets: bool = True  # 启用密钥检测


@dataclass
class SemgrepFinding:
    """Semgrep 发现结果"""
    rule_id: str
    message: str
    severity: SemgrepSeverity
    file_path: str
    line_start: int
    line_end: int
    col_start: int = 0
    col_end: int = 0
    code_snippet: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    # 额外信息
    cwe: List[str] = field(default_factory=list)
    owasp: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    # 污点分析信息
    dataflow_trace: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "col_start": self.col_start,
            "col_end": self.col_end,
            "code_snippet": self.code_snippet,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "references": self.references,
            "dataflow_trace": self.dataflow_trace,
        }


@dataclass
class SemgrepResult:
    """Semgrep 扫描结果"""
    findings: List[SemgrepFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    success: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "stats": self.stats,
        }


class SemgrepRunner:
    """Semgrep 扫描执行器

    P1-1: 执行 Semgrep 扫描并解析结果
    """

    def __init__(self, config: Optional[SemgrepConfig] = None):
        self.config = config or SemgrepConfig()
        self._semgrep_available: Optional[bool] = None

    def is_available(self) -> bool:
        """检查 Semgrep 是否可用"""
        if self._semgrep_available is not None:
            return self._semgrep_available

        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self._semgrep_available = result.returncode == 0
            if self._semgrep_available:
                logger.info(f"Semgrep available: {result.stdout.strip()}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._semgrep_available = False
            logger.warning("Semgrep not available")

        return self._semgrep_available

    def scan(self, target_path: str) -> SemgrepResult:
        """执行 Semgrep 扫描

        Args:
            target_path: 扫描目标路径

        Returns:
            SemgrepResult 扫描结果
        """
        if not self.is_available():
            return SemgrepResult(
                success=False,
                errors=["Semgrep not available. Install with: pip install semgrep"]
            )

        target = Path(target_path)
        if not target.exists():
            return SemgrepResult(
                success=False,
                errors=[f"Target path does not exist: {target_path}"]
            )

        try:
            # 创建临时输出文件
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json" if self.config.output_format == "json" else ".sarif",
                delete=False
            ) as output_file:
                output_path = output_file.name

            # 构建命令
            cmd = self._build_command(target_path, output_path)
            logger.info(f"Running Semgrep: {' '.join(cmd)}")

            # 执行扫描
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
            )

            # 解析结果
            if Path(output_path).exists():
                with open(output_path, "r", encoding="utf-8") as f:
                    output_data = json.load(f)

                if self.config.output_format == "sarif":
                    findings = self._parse_sarif(output_data)
                else:
                    findings = self._parse_json(output_data)

                # 按严重性过滤
                findings = self._filter_by_severity(findings)

                return SemgrepResult(
                    findings=findings,
                    success=True,
                    stats={
                        "total_findings": len(findings),
                        "files_scanned": output_data.get("stats", {}).get("totalFiles", 0),
                    }
                )
            else:
                return SemgrepResult(
                    success=False,
                    errors=[f"Semgrep output not found: {result.stderr}"]
                )

        except subprocess.TimeoutExpired:
            return SemgrepResult(
                success=False,
                errors=[f"Semgrep scan timed out after {self.config.timeout}s"]
            )
        except json.JSONDecodeError as e:
            return SemgrepResult(
                success=False,
                errors=[f"Failed to parse Semgrep output: {e}"]
            )
        except Exception as e:
            logger.exception("Semgrep scan failed")
            return SemgrepResult(
                success=False,
                errors=[f"Semgrep scan failed: {e}"]
            )
        finally:
            # 清理临时文件
            try:
                Path(output_path).unlink(missing_ok=True)
            except Exception:
                pass

    def _build_command(self, target_path: str, output_path: str) -> List[str]:
        """构建 Semgrep 命令"""
        cmd = ["semgrep"]

        # 配置规则
        if self.config.rules_path:
            cmd.extend(["--config", self.config.rules_path])
        else:
            cmd.extend(["--config", self.config.config])

        # 输出格式
        if self.config.output_format == "sarif":
            cmd.append("--sarif")
        else:
            cmd.append("--json")
        cmd.extend(["--output", output_path])

        # 性能参数
        cmd.extend(["--timeout", str(self.config.timeout)])
        cmd.extend(["--jobs", str(self.config.jobs)])
        cmd.extend(["--max-target-bytes", str(self.config.max_target_bytes)])

        # 包含/排除模式
        for pattern in self.config.include_patterns:
            cmd.extend(["--include", pattern])
        for pattern in self.config.exclude_patterns:
            cmd.extend(["--exclude", pattern])

        # 功能开关
        if self.config.enable_secrets:
            cmd.append("--secrets")

        # 目标路径
        cmd.append(target_path)

        return cmd

    def _parse_sarif(self, sarif_data: Dict[str, Any]) -> List[SemgrepFinding]:
        """解析 SARIF 格式输出"""
        findings = []

        runs = sarif_data.get("runs", [])
        for run in runs:
            results = run.get("results", [])
            for result in results:
                finding = self._sarif_result_to_finding(result, run)
                if finding:
                    findings.append(finding)

        return findings

    def _sarif_result_to_finding(
        self,
        result: Dict[str, Any],
        run: Dict[str, Any]
    ) -> Optional[SemgrepFinding]:
        """将 SARIF result 转换为 SemgrepFinding"""
        try:
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")

            # 获取位置信息
            locations = result.get("locations", [])
            if not locations:
                return None

            location = locations[0]
            physical_location = location.get("physicalLocation", {})
            artifact_location = physical_location.get("artifactLocation", {})
            region = physical_location.get("region", {})

            file_path = artifact_location.get("uri", "")
            line_start = region.get("startLine", 1)
            line_end = region.get("endLine", line_start)
            col_start = region.get("startColumn", 1)
            col_end = region.get("endColumn", col_start)

            # 代码片段
            snippet = region.get("snippet", {}).get("text", "")

            # 严重性
            level = result.get("level", "warning")
            severity = self._map_sarif_level(level)

            # 元数据
            properties = result.get("properties", {})
            metadata = properties.get("metadata", {})

            # CWE/OWASP
            cwe = metadata.get("cwe", [])
            if isinstance(cwe, str):
                cwe = [cwe]
            owasp = metadata.get("owasp", [])
            if isinstance(owasp, str):
                owasp = [owasp]

            # 数据流追踪
            dataflow_trace = None
            codeFlows = result.get("codeFlows", [])
            if codeFlows:
                dataflow_trace = self._parse_codeflow(codeFlows[0])

            return SemgrepFinding(
                rule_id=rule_id,
                message=message,
                severity=severity,
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                col_start=col_start,
                col_end=col_end,
                code_snippet=snippet,
                metadata=metadata,
                cwe=cwe,
                owasp=owasp,
                references=metadata.get("references", []),
                dataflow_trace=dataflow_trace,
            )
        except Exception as e:
            logger.warning(f"Failed to parse SARIF result: {e}")
            return None

    def _parse_codeflow(self, codeflow: Dict[str, Any]) -> Dict[str, Any]:
        """解析 SARIF codeFlow（污点追踪路径）"""
        trace = {"steps": []}

        thread_flows = codeflow.get("threadFlows", [])
        for thread_flow in thread_flows:
            locations = thread_flow.get("locations", [])
            for loc in locations:
                location = loc.get("location", {})
                physical = location.get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})

                step = {
                    "file": artifact.get("uri", ""),
                    "line": region.get("startLine", 0),
                    "message": location.get("message", {}).get("text", ""),
                }
                trace["steps"].append(step)

        return trace

    def _parse_json(self, json_data: Dict[str, Any]) -> List[SemgrepFinding]:
        """解析 Semgrep JSON 格式输出"""
        findings = []

        results = json_data.get("results", [])
        for result in results:
            try:
                finding = SemgrepFinding(
                    rule_id=result.get("check_id", "unknown"),
                    message=result.get("extra", {}).get("message", ""),
                    severity=self._map_json_severity(
                        result.get("extra", {}).get("severity", "WARNING")
                    ),
                    file_path=result.get("path", ""),
                    line_start=result.get("start", {}).get("line", 1),
                    line_end=result.get("end", {}).get("line", 1),
                    col_start=result.get("start", {}).get("col", 1),
                    col_end=result.get("end", {}).get("col", 1),
                    code_snippet=result.get("extra", {}).get("lines", ""),
                    metadata=result.get("extra", {}).get("metadata", {}),
                )
                findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to parse JSON result: {e}")

        return findings

    def _map_sarif_level(self, level: str) -> SemgrepSeverity:
        """映射 SARIF level 到 SemgrepSeverity"""
        mapping = {
            "error": SemgrepSeverity.ERROR,
            "warning": SemgrepSeverity.WARNING,
            "note": SemgrepSeverity.INFO,
            "none": SemgrepSeverity.INFO,
        }
        return mapping.get(level.lower(), SemgrepSeverity.WARNING)

    def _map_json_severity(self, severity: str) -> SemgrepSeverity:
        """映射 Semgrep JSON severity 到 SemgrepSeverity"""
        mapping = {
            "ERROR": SemgrepSeverity.ERROR,
            "WARNING": SemgrepSeverity.WARNING,
            "INFO": SemgrepSeverity.INFO,
        }
        return mapping.get(severity.upper(), SemgrepSeverity.WARNING)

    def _filter_by_severity(
        self,
        findings: List[SemgrepFinding]
    ) -> List[SemgrepFinding]:
        """按严重性过滤结果"""
        allowed = set(s.lower() for s in self.config.severity_filter)
        return [f for f in findings if f.severity.value in allowed]
