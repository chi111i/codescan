"""
业务逻辑漏洞分析模块 - 基于场景规则的检测

功能：
1. 加载业务场景规则
2. 匹配代码单元与场景
3. 执行checklist检查
4. 生成LLM分析提示词
5. 综合评估业务逻辑风险
"""

import re
import yaml
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from enum import Enum

from indexer import CodeUnit, CodeUnitType
from rules import RiskLevel
from llm_client import BaseLLMClient, ChatMessage

logger = logging.getLogger(__name__)


@dataclass
class ChecklistItem:
    """检查项"""
    id: str
    name: str
    description: str
    severity: RiskLevel
    check_patterns: List[str] = field(default_factory=list)
    anti_patterns: List[str] = field(default_factory=list)


@dataclass
class CheckResult:
    """检查结果"""
    checklist_id: str
    checklist_name: str
    passed: bool
    severity: RiskLevel
    evidence: List[str] = field(default_factory=list)
    missing_patterns: List[str] = field(default_factory=list)
    found_anti_patterns: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class BusinessScenario:
    """业务场景定义"""
    id: str
    name: str
    category: str
    risk_level: RiskLevel
    description: str

    # 识别规则
    keywords: List[str] = field(default_factory=list)
    function_patterns: List[str] = field(default_factory=list)
    parameter_patterns: List[str] = field(default_factory=list)
    decorator_patterns: List[str] = field(default_factory=list)

    # 检查清单
    checklist: List[ChecklistItem] = field(default_factory=list)

    # LLM提示词
    llm_prompt_template: str = ""


@dataclass
class ScenarioMatch:
    """场景匹配结果"""
    scenario: BusinessScenario
    code_unit: CodeUnit
    confidence: float
    matched_keywords: List[str] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)


@dataclass
class BusinessLogicFinding:
    """业务逻辑漏洞发现"""
    id: str
    scenario_id: str
    scenario_name: str
    category: str

    # 位置信息
    file_path: str
    function_name: str
    line_start: int
    line_end: int
    code_snippet: str

    # 分析结果
    risk_level: RiskLevel
    confidence: float
    check_results: List[CheckResult] = field(default_factory=list)
    failed_checks: List[str] = field(default_factory=list)

    # LLM分析
    llm_analysis: Optional[str] = None
    attack_scenario: str = ""
    fix_suggestion: str = ""

    # 元数据
    matched_keywords: List[str] = field(default_factory=list)
    needs_manual_review: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "category": self.category,
            "file_path": self.file_path,
            "function_name": self.function_name,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet[:1500],
            "risk_level": self.risk_level.value,
            "confidence": self.confidence,
            "check_results": [
                {
                    "id": r.checklist_id,
                    "name": r.checklist_name,
                    "passed": r.passed,
                    "severity": r.severity.value,
                    "evidence": r.evidence,
                    "notes": r.notes,
                }
                for r in self.check_results
            ],
            "failed_checks": self.failed_checks,
            "llm_analysis": self.llm_analysis,
            "attack_scenario": self.attack_scenario,
            "fix_suggestion": self.fix_suggestion,
            "matched_keywords": self.matched_keywords,
            "needs_manual_review": self.needs_manual_review,
        }


class BusinessLogicAnalyzer:
    """业务逻辑漏洞分析器"""

    def __init__(
        self,
        llm_client: Optional[BaseLLMClient] = None,
        scenarios_path: Optional[str] = None,
    ):
        self.llm_client = llm_client
        self.scenarios: List[BusinessScenario] = []
        self.common_checks: List[ChecklistItem] = []
        self.config: Dict[str, Any] = {}
        self.findings: List[BusinessLogicFinding] = []
        self._finding_counter = 0

        # 加载场景规则
        if scenarios_path:
            self.load_scenarios(scenarios_path)
        else:
            # 默认路径
            default_path = Path(__file__).parent.parent / "rules" / "data" / "business_scenarios.yaml"
            if default_path.exists():
                self.load_scenarios(str(default_path))

    def load_scenarios(self, path: str) -> None:
        """加载业务场景规则"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            # 解析场景
            for scenario_data in data.get("scenarios", []):
                scenario = self._parse_scenario(scenario_data)
                self.scenarios.append(scenario)

            # 解析通用检查
            for check_data in data.get("common_checks", []):
                check = self._parse_checklist_item(check_data)
                self.common_checks.append(check)

            # 解析配置
            self.config = {
                "severity_weights": data.get("severity_weights", {}),
                "matching_thresholds": data.get("matching_thresholds", {}),
            }

            logger.info(f"Loaded {len(self.scenarios)} business scenarios from {path}")

        except Exception as e:
            logger.error(f"Failed to load scenarios from {path}: {e}")

    def _parse_scenario(self, data: Dict[str, Any]) -> BusinessScenario:
        """解析场景定义"""
        identification = data.get("identification", {})

        # 解析checklist
        checklist = []
        for item_data in data.get("checklist", []):
            checklist.append(self._parse_checklist_item(item_data))

        return BusinessScenario(
            id=data.get("id", ""),
            name=data.get("name", ""),
            category=data.get("category", ""),
            risk_level=self._parse_risk_level(data.get("risk_level", "medium")),
            description=data.get("description", ""),
            keywords=identification.get("keywords", []),
            function_patterns=identification.get("function_patterns", []),
            parameter_patterns=identification.get("parameter_patterns", []),
            decorator_patterns=identification.get("decorator_patterns", []),
            checklist=checklist,
            llm_prompt_template=data.get("llm_prompt_template", ""),
        )

    def _parse_checklist_item(self, data: Dict[str, Any]) -> ChecklistItem:
        """解析检查项"""
        return ChecklistItem(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            severity=self._parse_risk_level(data.get("severity", "medium")),
            check_patterns=data.get("check_patterns", []),
            anti_patterns=data.get("anti_patterns", []),
        )

    def _parse_risk_level(self, level: str) -> RiskLevel:
        """解析风险等级"""
        level_map = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "low": RiskLevel.LOW,
        }
        return level_map.get(level.lower(), RiskLevel.MEDIUM)

    def analyze(
        self,
        code_units: List[CodeUnit],
        use_llm: bool = True,
        scenario_filter: Optional[List[str]] = None,
    ) -> List[BusinessLogicFinding]:
        """分析业务逻辑漏洞

        Args:
            code_units: 代码单元列表
            use_llm: 是否使用LLM深度分析
            scenario_filter: 仅检查指定场景ID列表

        Returns:
            业务逻辑漏洞发现列表
        """
        logger.info(f"Analyzing {len(code_units)} code units for business logic vulnerabilities...")

        self.findings = []
        self._finding_counter = 0

        # 过滤场景
        scenarios_to_check = self.scenarios
        if scenario_filter:
            scenarios_to_check = [s for s in self.scenarios if s.id in scenario_filter]

        # 第一阶段：场景匹配
        matches = self._match_scenarios(code_units, scenarios_to_check)
        logger.info(f"Found {len(matches)} scenario matches")

        # 第二阶段：Checklist检查
        for match in matches:
            finding = self._analyze_match(match)

            # 第三阶段：LLM深度分析（仅对有风险的发现）
            if use_llm and self.llm_client and finding.failed_checks:
                self._llm_analyze(finding, match)

            self.findings.append(finding)

        # 按风险排序
        self.findings.sort(key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.risk_level.value, 4),
            -f.confidence
        ))

        logger.info(f"Found {len(self.findings)} potential business logic vulnerabilities")
        return self.findings

    def _match_scenarios(
        self,
        code_units: List[CodeUnit],
        scenarios: List[BusinessScenario],
    ) -> List[ScenarioMatch]:
        """匹配代码单元与业务场景"""
        matches = []

        for unit in code_units:
            # 只分析函数/方法/handler
            if unit.unit_type not in (CodeUnitType.FUNCTION, CodeUnitType.METHOD, CodeUnitType.HANDLER):
                continue

            for scenario in scenarios:
                match = self._try_match(unit, scenario)
                if match:
                    matches.append(match)

        return matches

    def _try_match(
        self,
        unit: CodeUnit,
        scenario: BusinessScenario,
    ) -> Optional[ScenarioMatch]:
        """尝试匹配单个代码单元与场景"""
        code_lower = unit.code.lower()
        symbol_lower = unit.symbol.lower()

        matched_keywords = []
        matched_patterns = []

        # 关键词匹配
        for keyword in scenario.keywords:
            if keyword.lower() in code_lower or keyword.lower() in symbol_lower:
                matched_keywords.append(keyword)

        # 函数名模式匹配
        for pattern in scenario.function_patterns:
            if re.search(pattern, symbol_lower, re.IGNORECASE):
                matched_patterns.append(f"func:{pattern}")

        # 参数模式匹配
        if unit.signature:
            for pattern in scenario.parameter_patterns:
                if re.search(pattern, unit.signature, re.IGNORECASE):
                    matched_patterns.append(f"param:{pattern}")

        # 装饰器模式匹配
        if unit.decorators:
            decorators_str = " ".join(unit.decorators)
            for pattern in scenario.decorator_patterns:
                if re.search(pattern, decorators_str, re.IGNORECASE):
                    matched_patterns.append(f"deco:{pattern}")

        # 计算置信度
        thresholds = self.config.get("matching_thresholds", {})
        keyword_ratio = len(matched_keywords) / max(len(scenario.keywords), 1)
        pattern_count = len(matched_patterns)

        keyword_threshold = thresholds.get("keyword_match_ratio", 0.3)
        pattern_threshold = thresholds.get("pattern_match_count", 2)

        if keyword_ratio >= keyword_threshold or pattern_count >= pattern_threshold:
            confidence = min(0.4 + keyword_ratio * 0.3 + pattern_count * 0.1, 0.9)

            return ScenarioMatch(
                scenario=scenario,
                code_unit=unit,
                confidence=confidence,
                matched_keywords=matched_keywords,
                matched_patterns=matched_patterns,
            )

        return None

    def _analyze_match(self, match: ScenarioMatch) -> BusinessLogicFinding:
        """分析匹配的场景"""
        self._finding_counter += 1
        unit = match.code_unit
        scenario = match.scenario

        # 执行Checklist检查
        check_results = []
        failed_checks = []

        for checklist_item in scenario.checklist:
            result = self._execute_check(unit.code, checklist_item)
            check_results.append(result)
            if not result.passed:
                failed_checks.append(f"{checklist_item.id}: {checklist_item.name}")

        # 执行通用检查
        for common_check in self.common_checks:
            result = self._execute_check(unit.code, common_check)
            check_results.append(result)
            if not result.passed:
                failed_checks.append(f"{common_check.id}: {common_check.name}")

        # 计算最终风险等级
        risk_level = self._calculate_risk_level(scenario, check_results, match.confidence)

        return BusinessLogicFinding(
            id=f"LOGIC-{self._finding_counter:04d}",
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            category=scenario.category,
            file_path=unit.file_path,
            function_name=unit.symbol,
            line_start=unit.span.start_line,
            line_end=unit.span.end_line,
            code_snippet=unit.code,
            risk_level=risk_level,
            confidence=match.confidence,
            check_results=check_results,
            failed_checks=failed_checks,
            matched_keywords=match.matched_keywords,
            needs_manual_review=len(failed_checks) > 0,
        )

    def _execute_check(self, code: str, item: ChecklistItem) -> CheckResult:
        """执行单个检查项"""
        evidence = []
        missing_patterns = []
        found_anti_patterns = []

        # 检查正向模式（应该存在的安全措施）
        patterns_found = 0
        for pattern in item.check_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                patterns_found += 1
                evidence.append(f"找到安全模式: {pattern}")
            else:
                missing_patterns.append(pattern)

        # 检查反向模式（不应该存在的危险模式）
        for pattern in item.anti_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                found_anti_patterns.append(pattern)
                evidence.append(f"发现危险模式: {pattern}")

        # 判断是否通过
        # 如果有正向模式要求，至少应该找到一个
        # 如果发现反向模式，则不通过
        passed = True
        notes = ""

        if found_anti_patterns:
            passed = False
            notes = f"发现{len(found_anti_patterns)}个危险模式"
        elif item.check_patterns and patterns_found == 0:
            passed = False
            notes = f"未找到任何安全检查模式"
        elif item.check_patterns and patterns_found < len(item.check_patterns) / 2:
            passed = False
            notes = f"仅找到{patterns_found}/{len(item.check_patterns)}个安全模式"

        return CheckResult(
            checklist_id=item.id,
            checklist_name=item.name,
            passed=passed,
            severity=item.severity,
            evidence=evidence,
            missing_patterns=missing_patterns,
            found_anti_patterns=found_anti_patterns,
            notes=notes,
        )

    def _calculate_risk_level(
        self,
        scenario: BusinessScenario,
        check_results: List[CheckResult],
        confidence: float,
    ) -> RiskLevel:
        """计算综合风险等级"""
        # 基础风险来自场景
        base_risk = scenario.risk_level

        # 检查失败的严重性
        critical_failed = sum(1 for r in check_results if not r.passed and r.severity == RiskLevel.CRITICAL)
        high_failed = sum(1 for r in check_results if not r.passed and r.severity == RiskLevel.HIGH)

        if critical_failed > 0:
            return RiskLevel.CRITICAL
        elif high_failed >= 2:
            return RiskLevel.CRITICAL
        elif high_failed > 0:
            return RiskLevel.HIGH
        elif any(not r.passed for r in check_results):
            return max(base_risk, RiskLevel.MEDIUM)
        else:
            return RiskLevel.LOW

    def _llm_analyze(self, finding: BusinessLogicFinding, match: ScenarioMatch) -> None:
        """使用LLM进行深度分析"""
        scenario = match.scenario
        unit = match.code_unit

        # 构建系统提示词
        system_prompt = """你是一名资深安全工程师，专长于代码审计和业务逻辑漏洞挖掘。
你将收到一段代码和对应的业务场景描述。请基于场景特点进行深度安全分析。

输出要求（JSON格式）：
{
    "has_vulnerability": true/false,
    "vulnerability_type": "漏洞类型",
    "severity": "critical/high/medium/low",
    "confidence": 0.0-1.0,
    "analysis": "详细分析",
    "attack_scenario": "攻击场景描述（不含具体payload）",
    "impact": "影响说明",
    "fix_suggestion": "修复建议",
    "needs_manual_review": true/false,
    "review_notes": "需要人工确认的点"
}
"""

        # 构建用户提示词
        failed_checks_str = "\n".join(f"- {check}" for check in finding.failed_checks)

        user_prompt = f"""{scenario.llm_prompt_template}

【代码信息】
文件：{unit.file_path}
函数：{unit.symbol}
行号：{unit.span.start_line}-{unit.span.end_line}
装饰器：{', '.join(unit.decorators) if unit.decorators else '无'}

【代码】
```{unit.language}
{unit.code}
```

【自动检查结果】
以下检查项未通过：
{failed_checks_str if failed_checks_str else "所有检查项均已通过"}

请分析此代码是否存在业务逻辑漏洞。
"""

        try:
            response = self.llm_client.chat_completion(
                messages=[
                    ChatMessage(role="system", content=system_prompt),
                    ChatMessage(role="user", content=user_prompt),
                ],
                response_format={"type": "json_object"},
                # temperature 使用 LLM 客户端配置的默认值
            )

            # 解析响应
            import json
            try:
                result = json.loads(response.content)
            except json.JSONDecodeError:
                # 尝试提取JSON
                json_match = re.search(r'\{[\s\S]*\}', response.content)
                if json_match:
                    result = json.loads(json_match.group(0))
                else:
                    return

            # 更新finding
            finding.llm_analysis = result.get("analysis", "")
            finding.attack_scenario = result.get("attack_scenario", "")
            finding.fix_suggestion = result.get("fix_suggestion", "")
            finding.needs_manual_review = result.get("needs_manual_review", True)

            # 根据LLM结果调整置信度
            llm_confidence = result.get("confidence", 0.5)
            finding.confidence = (finding.confidence + llm_confidence) / 2

            # 如果LLM认为没有漏洞，降低置信度
            if not result.get("has_vulnerability", True):
                finding.confidence *= 0.4
                finding.risk_level = RiskLevel.LOW

        except Exception as e:
            logger.warning(f"LLM analysis failed for {finding.id}: {e}")

    def get_summary(self) -> Dict[str, Any]:
        """获取分析摘要"""
        summary = {
            "total_findings": len(self.findings),
            "by_category": {},
            "by_risk_level": {},
            "by_scenario": {},
            "needs_review_count": 0,
            "high_confidence_count": 0,
        }

        for finding in self.findings:
            # 按类别
            category = finding.category
            summary["by_category"][category] = summary["by_category"].get(category, 0) + 1

            # 按风险
            level = finding.risk_level.value
            summary["by_risk_level"][level] = summary["by_risk_level"].get(level, 0) + 1

            # 按场景
            scenario = finding.scenario_name
            summary["by_scenario"][scenario] = summary["by_scenario"].get(scenario, 0) + 1

            # 统计
            if finding.needs_manual_review:
                summary["needs_review_count"] += 1
            if finding.confidence >= 0.7:
                summary["high_confidence_count"] += 1

        return summary

    def export_findings(self, output_path: str) -> str:
        """导出发现到JSON"""
        import json
        from datetime import datetime

        result = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "Business Logic Analyzer",
                "total_findings": len(self.findings),
            },
            "summary": self.get_summary(),
            "findings": [f.to_dict() for f in self.findings],
        }

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        logger.info(f"Findings exported to: {path}")
        return str(path)
