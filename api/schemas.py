"""API 数据模型 - Pydantic schemas"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


# ============ 枚举类型 ============

class SeverityLevel(str, Enum):
    """严重性级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    """扫描状态"""
    PENDING = "pending"
    INDEXING = "indexing"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class VulnTypeEnum(str, Enum):
    """漏洞类型"""
    RCE = "rce"
    COMMAND_INJECTION = "command_injection"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_UPLOAD = "file_upload"
    PATH_TRAVERSAL = "path_traversal"
    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    SSRF = "ssrf"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    SSTI = "ssti"
    AUTH_BYPASS = "auth_bypass"
    AUTHZ_BYPASS = "authz_bypass"
    IDOR = "idor"
    LOGIC_FLAW = "logic_flaw"
    RACE_CONDITION = "race_condition"
    MASS_ASSIGNMENT = "mass_assignment"
    XSS = "xss"
    OTHER = "other"


# ============ 请求模型 ============

class ScanRequest(BaseModel):
    """扫描请求"""
    target_path: str = Field(..., description="要扫描的目标路径")
    languages: Optional[List[str]] = Field(None, description="限定语言列表")
    vuln_types: Optional[List[VulnTypeEnum]] = Field(None, description="漏洞类型过滤")
    use_llm: bool = Field(True, description="是否使用 LLM 深度分析")
    scan_logic: bool = Field(True, description="是否扫描业务逻辑漏洞")
    max_issues: int = Field(50, description="最大分析候选数量")
    reindex: bool = Field(False, description="是否重新索引")
    skip_index: bool = Field(False, description="跳过向量索引（小项目推荐，直接遍历文件）")
    use_chain_analysis: bool = Field(True, description="是否使用链级分析（P0推荐流程）")
    max_chain_depth: int = Field(5, description="最大调用链深度")


class IndexRequest(BaseModel):
    """索引请求"""
    target_path: str = Field(..., description="要索引的目标路径")
    clear_existing: bool = Field(False, description="是否清空现有索引")


class SearchRequest(BaseModel):
    """搜索请求"""
    query: str = Field(..., description="搜索查询")
    top_k: int = Field(10, description="返回结果数量")
    language: Optional[str] = Field(None, description="限定语言")
    file_pattern: Optional[str] = Field(None, description="文件路径模式")


class CallGraphRequest(BaseModel):
    """调用图分析请求"""
    target_path: str = Field(..., description="目标路径")
    max_depth: int = Field(10, description="最大调用链深度")
    find_taint: bool = Field(True, description="是否查找污点路径")


# ============ 响应模型 ============

class CodeSpanSchema(BaseModel):
    """代码范围"""
    start_line: int
    end_line: int
    start_col: Optional[int] = 0
    end_col: Optional[int] = 0


class CodeUnitSchema(BaseModel):
    """代码单元"""
    id: str
    language: str
    file_path: str
    symbol: str
    unit_type: str
    signature: Optional[str] = None
    span: CodeSpanSchema
    code: str
    docstring: Optional[str] = None
    calls: List[str] = []
    parent_class: Optional[str] = None
    decorators: List[str] = []
    imports: List[str] = []


class FindingSchema(BaseModel):
    """发现结果"""
    id: str
    title: str
    file_path: str
    line_start: int
    line_end: int
    symbol: str
    severity: SeverityLevel
    confidence: float
    category: str
    summary: str
    details: str
    evidence: List[Dict[str, Any]] = []
    attack_scenario: str
    fix_suggestion: str
    code_snippet: Optional[str] = None
    notes: Optional[str] = None
    rule_id: Optional[str] = None
    cwe_ids: List[str] = []


class VulnFindingSchema(BaseModel):
    """漏洞发现"""
    id: str
    name: str
    vuln_type: VulnTypeEnum
    severity: SeverityLevel
    confidence: float
    file_path: str
    line_start: int
    line_end: int
    function_name: str
    description: str
    attack_scenario: str
    fix_suggestion: str
    code_snippet: Optional[str] = None
    llm_analysis: Optional[str] = None
    needs_manual_review: bool = False
    review_notes: Optional[str] = None


class TaintPathSchema(BaseModel):
    """污点路径"""
    source_node: str
    sink_node: str
    path: List[str]
    is_sanitized: bool
    sanitizers: List[str]
    risk_level: str
    confidence: float
    description: str


class CallGraphStatsSchema(BaseModel):
    """调用图统计"""
    total_nodes: int
    total_edges: int
    entry_points: int
    sources: int
    sinks: int
    sanitizers: int


class ScanResultSchema(BaseModel):
    """扫描结果"""
    scan_id: str
    status: ScanStatus
    target_path: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    total_files: int = 0
    total_units: int = 0
    findings: List[FindingSchema] = []
    vuln_findings: List[VulnFindingSchema] = []
    taint_paths: List[TaintPathSchema] = []
    call_graph_stats: Optional[CallGraphStatsSchema] = None
    error_message: Optional[str] = None
    progress: float = 0.0
    current_step: str = ""


class IndexResultSchema(BaseModel):
    """索引结果"""
    target_path: str
    total_files: int
    total_units: int
    languages: Dict[str, int]
    indexed_at: datetime


class SearchResultSchema(BaseModel):
    """搜索结果"""
    query: str
    total: int
    results: List[CodeUnitSchema]


class StatsSchema(BaseModel):
    """统计信息"""
    total_units: int
    collection_name: str
    languages: Dict[str, int] = {}
    unit_types: Dict[str, int] = {}


class RuleSchema(BaseModel):
    """安全规则"""
    id: str
    name: str
    rule_type: str
    category: str
    risk_level: str
    languages: List[str]
    patterns: List[str]
    description: str
    fix_suggestion: str


class RuleListSchema(BaseModel):
    """规则列表"""
    total: int
    rules: List[RuleSchema]


# ============ 通用响应 ============

class APIResponse(BaseModel):
    """通用 API 响应"""
    success: bool
    message: str
    data: Optional[Any] = None


class ErrorResponse(BaseModel):
    """错误响应"""
    success: bool = False
    error: str
    detail: Optional[str] = None
