"""分析器模块"""

from .models import (
    Finding,
    Candidate,
    AnalysisContext,
    Severity,
    Evidence,
)
from .prompts import build_analysis_prompt, SYSTEM_PROMPT
from .engine import SecurityAnalyzer
from .call_chain import (
    CallChainAnalyzer,
    CallGraph,
    CallNode,
    CallEdge,
    TaintPath,
    NodeType,
)
from .vuln_detector import (
    HighRiskVulnDetector,
    VulnFinding,
    VulnPattern,
    VulnType,
    VULN_PATTERNS,
    # 新增：可利用性评估
    Exploitability,
)
from .taint_analysis import (
    TaintAnalyzer,
    TaintFlow,
    TaintSource,
    TaintSink,
    Sanitizer,
    TaintType,
    SinkCategory,
    TaintedVariable,
    TAINT_SOURCES,
    TAINT_SINKS,
    SANITIZERS,
    # 新增：跨函数污点分析
    InterproceduralTaint,
    CrossFunctionFlow,
    FrameworkPropagationRule,
    FRAMEWORK_PROPAGATION_RULES,
)
from .business_logic import (
    BusinessLogicAnalyzer,
    BusinessScenario,
    BusinessLogicFinding,
    ChecklistItem,
    CheckResult,
    ScenarioMatch,
)
from .variant_analysis import (
    VariantAnalyzer,
    VulnPattern as VariantPattern,
    VariantMatch,
    GeneratedRule,
    PatternType,
)

__all__ = [
    # 基础模型
    "Finding",
    "Candidate",
    "AnalysisContext",
    "Severity",
    "Evidence",
    # 提示词
    "build_analysis_prompt",
    "SYSTEM_PROMPT",
    # 分析引擎
    "SecurityAnalyzer",
    # 调用链分析
    "CallChainAnalyzer",
    "CallGraph",
    "CallNode",
    "CallEdge",
    "TaintPath",
    "NodeType",
    # 高危漏洞检测
    "HighRiskVulnDetector",
    "VulnFinding",
    "VulnPattern",
    "VulnType",
    "VULN_PATTERNS",
    "Exploitability",
    # 污点分析
    "TaintAnalyzer",
    "TaintFlow",
    "TaintSource",
    "TaintSink",
    "Sanitizer",
    "TaintType",
    "SinkCategory",
    "TaintedVariable",
    "TAINT_SOURCES",
    "TAINT_SINKS",
    "SANITIZERS",
    # 跨函数污点分析
    "InterproceduralTaint",
    "CrossFunctionFlow",
    "FrameworkPropagationRule",
    "FRAMEWORK_PROPAGATION_RULES",
    # 业务逻辑分析
    "BusinessLogicAnalyzer",
    "BusinessScenario",
    "BusinessLogicFinding",
    "ChecklistItem",
    "CheckResult",
    "ScenarioMatch",
    # 变体分析
    "VariantAnalyzer",
    "VariantPattern",
    "VariantMatch",
    "GeneratedRule",
    "PatternType",
]
