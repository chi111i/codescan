"""
报告生成模块 - 多格式输出
"""

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from config import ReportConfig
from analyzer import Finding, Severity
from serialization import safe_json_dumps

logger = logging.getLogger(__name__)


class BaseReporter(ABC):
    """报告生成器抽象基类"""

    @abstractmethod
    def generate(self, findings: List[Finding], metadata: Dict[str, Any]) -> str:
        """生成报告内容"""
        pass

    @abstractmethod
    def save(self, content: str, output_path: str) -> None:
        """保存报告"""
        pass


class JsonReporter(BaseReporter):
    """JSON 格式报告"""

    def __init__(self, config: ReportConfig):
        self.config = config

    def generate(self, findings: List[Finding], metadata: Dict[str, Any]) -> str:
        """生成 JSON 报告"""
        report = {
            "metadata": {
                "tool": "LLM Code Auditor",
                "version": "0.1.0",
                "generated_at": datetime.now().isoformat(),
                "target": metadata.get("target_path", "unknown"),
                "total_findings": len(findings),
                "summary": self._generate_summary(findings),
                **metadata,
            },
            "findings": [f.to_dict() for f in findings],
        }

        return safe_json_dumps(report, ensure_ascii=False, indent=2)

    def _generate_summary(self, findings: List[Finding]) -> Dict[str, int]:
        """生成摘要统计"""
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        for f in findings:
            summary[f.severity.value] += 1
        return summary

    def save(self, content: str, output_path: str) -> None:
        """保存 JSON 报告"""
        path = Path(output_path)
        if path.is_dir():
            path = path / f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        logger.info(f"Report saved to: {path}")


class ConsoleReporter(BaseReporter):
    """控制台输出报告"""

    # ANSI 颜色代码
    COLORS = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "green": "\033[92m",
        "blue": "\033[94m",
        "cyan": "\033[96m",
        "gray": "\033[90m",
    }

    SEVERITY_COLORS = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
    }

    def __init__(self, config: ReportConfig, use_color: bool = True):
        self.config = config
        self.use_color = use_color

    def _color(self, text: str, color: str) -> str:
        """应用颜色"""
        if not self.use_color:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"

    def generate(self, findings: List[Finding], metadata: Dict[str, Any]) -> str:
        """生成控制台报告"""
        lines = []

        # 标题
        lines.append("")
        lines.append(self._color("=" * 60, "cyan"))
        lines.append(self._color("  LLM 代码安全审计报告", "bold"))
        lines.append(self._color("=" * 60, "cyan"))
        lines.append("")

        # 元数据
        lines.append(f"  目标路径: {metadata.get('target_path', 'N/A')}")
        lines.append(f"  扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  发现问题: {len(findings)} 个")
        lines.append("")

        # 摘要
        summary = self._count_by_severity(findings)
        lines.append("  严重性分布:")
        lines.append(f"    {self._color('CRITICAL', 'red')}: {summary['critical']}")
        lines.append(f"    {self._color('HIGH', 'red')}: {summary['high']}")
        lines.append(f"    {self._color('MEDIUM', 'yellow')}: {summary['medium']}")
        lines.append(f"    {self._color('LOW', 'blue')}: {summary['low']}")
        lines.append("")
        lines.append(self._color("-" * 60, "gray"))

        # 详细发现
        for i, finding in enumerate(findings, 1):
            lines.append("")
            severity_color = self.SEVERITY_COLORS.get(finding.severity, "reset")

            lines.append(
                f"  [{i}] {self._color(f'[{finding.severity.value.upper()}]', severity_color)} "
                f"{self._color(finding.title, 'bold')}"
            )
            lines.append(f"      文件: {finding.file_path}:{finding.line_start}")
            lines.append(f"      函数: {finding.symbol}")
            lines.append(f"      置信度: {finding.confidence:.0%}")
            lines.append("")
            lines.append(f"      {self._color('摘要:', 'cyan')} {finding.summary}")

            if self.config.include_evidence and finding.details:
                lines.append(f"      {self._color('详情:', 'cyan')}")
                for line in finding.details.split("\n")[:5]:
                    lines.append(f"        {line}")

            if finding.attack_scenario:
                lines.append(f"      {self._color('攻击思路:', 'yellow')}")
                for line in finding.attack_scenario.split("\n")[:3]:
                    lines.append(f"        {line}")

            if self.config.include_fix_suggestions and finding.fix_suggestion:
                lines.append(f"      {self._color('修复建议:', 'green')}")
                for line in finding.fix_suggestion.split("\n")[:3]:
                    lines.append(f"        {line}")

            if finding.notes:
                lines.append(f"      {self._color('备注:', 'gray')} {finding.notes}")

            lines.append("")
            lines.append(self._color("  " + "-" * 58, "gray"))

        lines.append("")
        lines.append(self._color("=" * 60, "cyan"))
        lines.append("")

        return "\n".join(lines)

    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """按严重性统计"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f.severity.value] += 1
        return counts

    def save(self, content: str, output_path: str) -> None:
        """控制台输出不保存文件，直接打印"""
        print(content)


class SarifReporter(BaseReporter):
    """SARIF 格式报告 - 用于 CI 集成"""

    def __init__(self, config: ReportConfig):
        self.config = config

    def generate(self, findings: List[Finding], metadata: Dict[str, Any]) -> str:
        """生成 SARIF 报告"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "LLM Code Auditor",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/your-org/llm-code-auditor",
                        "rules": self._generate_rules(findings),
                    }
                },
                "results": self._generate_results(findings),
            }]
        }

        return safe_json_dumps(sarif, ensure_ascii=False, indent=2)

    def _generate_rules(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """生成规则定义"""
        rules = {}
        for f in findings:
            rule_id = f.category
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.summary[:100] if f.summary else f.title},
                    "defaultConfiguration": {
                        "level": self._severity_to_level(f.severity)
                    },
                }
        return list(rules.values())

    def _severity_to_level(self, severity: Severity) -> str:
        """转换严重性到 SARIF level"""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
        }
        return mapping.get(severity, "warning")

    def _generate_results(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """生成结果列表"""
        results = []
        for f in findings:
            result = {
                "ruleId": f.category,
                "level": self._severity_to_level(f.severity),
                "message": {"text": f.summary},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {
                            "startLine": f.line_start,
                            "endLine": f.line_end,
                        }
                    }
                }],
                "properties": {
                    "confidence": f.confidence,
                    "fix_suggestion": f.fix_suggestion,
                }
            }
            results.append(result)
        return results

    def save(self, content: str, output_path: str) -> None:
        """保存 SARIF 报告"""
        path = Path(output_path)
        if path.is_dir():
            path = path / f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sarif"

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        logger.info(f"SARIF report saved to: {path}")


class ReportGenerator:
    """报告生成器工厂"""

    def __init__(self, config: ReportConfig):
        self.config = config

    def generate_report(
        self,
        findings: List[Finding],
        output_format: Optional[str] = None,
        output_path: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """生成并保存报告

        Args:
            findings: 发现列表
            output_format: 输出格式 (json, console, sarif)
            output_path: 输出路径
            metadata: 额外元数据

        Returns:
            报告内容
        """
        format_type = output_format or self.config.output_format
        out_path = output_path or self.config.output_path
        meta = metadata or {}

        # 选择报告器
        if format_type == "json":
            reporter = JsonReporter(self.config)
        elif format_type == "sarif":
            reporter = SarifReporter(self.config)
        elif format_type == "console":
            reporter = ConsoleReporter(self.config)
        else:
            logger.warning(f"Unknown format {format_type}, using JSON")
            reporter = JsonReporter(self.config)

        # 生成报告
        content = reporter.generate(findings, meta)

        # 保存报告
        reporter.save(content, out_path)

        return content
