"""分析器模块"""

from .models import (
    Finding,
    Candidate,
    AnalysisContext,
    Severity,
    Evidence,
)
from .prompts import (
    build_analysis_prompt,
    build_chain_analysis_prompt,
    get_chain_output_schema,
)

# 废弃常量 - 保留向后兼容但不再导入
# 使用 prompts.get_prompt_manager() 替代
SYSTEM_PROMPT = ""
CHAIN_SYSTEM_PROMPT = ""
SINK_CATEGORY_PROMPTS = {}
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
from .sink_scanner import (
    SinkCallScanner,
    SinkCallSite,
    SinkCategory as SinkScanCategory,
)
from .prescan import (
    RuleScanPreprocessor,
    PreScanConfig,
    PreScanResult,
    PreScanStatus,
    RiskSummary,
    CategorySummary,
)
from .enhancer import (
    DeepAnalysisEnhancer,
    EnhancementConfig,
    EnhancementResult,
    EnhancedSite,
    CallChainInfo,
    TaintInfo,
)
from .chain_context import (
    ChainContextCollector,
    ChainContext,
    ChainNode,
)
from .interactive_agent import (
    InteractiveAuditAgent,
    InteractiveFinding,
    AgentResponse,
    AgentResponseType,
    FindingStatus,
    AnalysisContext as InteractiveAnalysisContext,
)
from .session_manager import (
    InteractiveSessionManager,
    SessionInfo,
    SessionStatus,
)
from .fc_adapter import (
    FunctionCallingAdapter,
    FCAdapterConfig,
    FCAnalysisResult,
    FCSecurityTools,
    FCToolCall,
    FCToolStatus,
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
    "build_chain_analysis_prompt",
    "get_chain_output_schema",
    "SYSTEM_PROMPT",
    "CHAIN_SYSTEM_PROMPT",
    "SINK_CATEGORY_PROMPTS",
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
    # SinkCallScanner
    "SinkCallScanner",
    "SinkCallSite",
    "SinkScanCategory",
    # 预扫描预处理器
    "RuleScanPreprocessor",
    "PreScanConfig",
    "PreScanResult",
    "PreScanStatus",
    "RiskSummary",
    "CategorySummary",
    # 深度分析增强器
    "DeepAnalysisEnhancer",
    "EnhancementConfig",
    "EnhancementResult",
    "EnhancedSite",
    "CallChainInfo",
    "TaintInfo",
    # 调用链上下文收集
    "ChainContextCollector",
    "ChainContext",
    "ChainNode",
    # 交互式审计
    "InteractiveAuditAgent",
    "InteractiveFinding",
    "AgentResponse",
    "AgentResponseType",
    "FindingStatus",
    "InteractiveAnalysisContext",
    "InteractiveSessionManager",
    "SessionInfo",
    "SessionStatus",
    # Function Calling 适配器
    "FunctionCallingAdapter",
    "FCAdapterConfig",
    "FCAnalysisResult",
    "FCSecurityTools",
    "FCToolCall",
    "FCToolStatus",
]
