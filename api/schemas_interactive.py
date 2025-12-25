"""交互式审计 API 数据模型"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


# ============ 枚举类型 ============

class InteractiveSessionStatus(str, Enum):
    """交互式会话状态"""
    INITIALIZING = "initializing"
    READY = "ready"
    ANALYZING = "analyzing"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


class InteractiveFindingStatus(str, Enum):
    """发现状态"""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class AgentResponseTypeEnum(str, Enum):
    """代理响应类型"""
    ANALYSIS = "analysis"
    CHAT = "chat"
    SUMMARY = "summary"
    FINDING = "finding"
    ERROR = "error"
    STATUS = "status"


# ============ 请求模型 ============

class CreateSessionRequest(BaseModel):
    """创建会话请求"""
    target_path: str = Field(..., description="目标代码路径")
    languages: Optional[List[str]] = Field(None, description="限定语言列表")
    max_chain_depth: int = Field(5, description="最大调用链深度")
    skip_index: bool = Field(True, description="是否跳过向量索引（推荐 True）")


class AnalyzeSelectionRequest(BaseModel):
    """分析选择请求"""
    session_id: str = Field(..., description="会话 ID")
    selected_chain_ids: List[str] = Field(default_factory=list, description="选中的调用链 ID 列表")
    selected_unit_ids: List[str] = Field(default_factory=list, description="选中的代码单元 ID 列表")
    focus_areas: Optional[List[str]] = Field(None, description="关注的漏洞类型")
    custom_prompt: Optional[str] = Field(None, description="用户自定义提示")


class ChatRequest(BaseModel):
    """对话请求"""
    session_id: str = Field(..., description="会话 ID")
    message: str = Field(..., description="用户消息")


class DigDeeperRequest(BaseModel):
    """深入分析请求"""
    session_id: str = Field(..., description="会话 ID")
    finding_id: str = Field(..., description="发现 ID")
    direction: str = Field("expand", description="分析方向: expand/trace_source/trace_sink/verify")


class ConfirmFindingRequest(BaseModel):
    """确认发现请求"""
    notes: str = Field("", description="用户备注")


class RejectFindingRequest(BaseModel):
    """拒绝发现请求"""
    reason: str = Field("", description="拒绝原因")


class UpdateFindingNotesRequest(BaseModel):
    """更新发现备注请求"""
    notes: str = Field(..., description="新备注")


# ============ 响应模型 ============

class SessionInfoSchema(BaseModel):
    """会话信息"""
    session_id: str
    target_path: str
    status: InteractiveSessionStatus
    created_at: datetime
    updated_at: datetime

    # 统计信息
    code_units_count: int = 0
    sink_sites_count: int = 0
    chain_contexts_count: int = 0
    pending_findings_count: int = 0
    confirmed_findings_count: int = 0
    rejected_findings_count: int = 0

    # 配置
    languages: List[str] = []
    max_chain_depth: int = 5

    # 错误信息
    error_message: Optional[str] = None


class EvidenceSchema(BaseModel):
    """证据"""
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    description: str


class InteractiveFindingSchema(BaseModel):
    """交互式发现"""
    id: str
    title: str
    category: str
    severity: str
    confidence: float
    file_path: str
    line_start: int
    line_end: int
    symbol: str
    summary: str
    details: str
    evidence: List[EvidenceSchema] = []
    attack_scenario: str = ""
    fix_suggestion: str = ""

    # 状态管理
    status: InteractiveFindingStatus
    user_notes: str = ""
    confirmed_at: Optional[datetime] = None
    rejected_reason: str = ""

    # 来源信息
    source_chain_id: Optional[str] = None
    source_sink_site_id: Optional[str] = None


class AgentResponseSchema(BaseModel):
    """代理响应"""
    response_type: AgentResponseTypeEnum
    content: str
    findings: List[InteractiveFindingSchema] = []
    suggestions: List[str] = []
    metadata: Dict[str, Any] = {}
    error: Optional[str] = None


class SinkSiteSchema(BaseModel):
    """Sink 触发点"""
    id: str
    symbol: str
    file_path: str
    line_start: int
    line_end: int
    sink_category: str
    risk_level: str
    call_snippet: str = ""


class ChainNodeSchema(BaseModel):
    """调用链节点"""
    symbol: str
    qualified_name: str
    file_path: str
    line_start: int
    line_end: int
    node_type: str
    code: str
    is_sink: bool = False


class ChainContextSchema(BaseModel):
    """调用链上下文"""
    id: str
    sink_site: SinkSiteSchema
    chain_nodes: List[ChainNodeSchema] = []
    entry_point: Optional[ChainNodeSchema] = None
    chain_length: int
    has_user_input: bool
    sanitizers_on_path: List[str] = []
    risk_level: str
    confidence: float
    prompt_text: str = ""


class CodeUnitBriefSchema(BaseModel):
    """代码单元简要信息"""
    id: str
    symbol: str
    file_path: str
    language: str
    unit_type: str
    line_start: int
    line_end: int


class CodeUnitDetailSchema(BaseModel):
    """代码单元详细信息"""
    id: str
    language: str
    file_path: str
    symbol: str
    unit_type: str
    signature: Optional[str] = None
    span: Dict[str, int]
    code: str
    docstring: Optional[str] = None
    calls: List[str] = []
    parent_class: Optional[str] = None
    decorators: List[str] = []
    imports: List[str] = []


class SinkSiteBriefSchema(BaseModel):
    """Sink 触发点简要信息"""
    id: str
    symbol: str
    file_path: str
    line_start: int
    line_end: int
    sink_category: str
    risk_level: str
    call_snippet: str = ""


class FindingsGroupSchema(BaseModel):
    """发现分组"""
    pending: List[InteractiveFindingSchema] = []
    confirmed: List[InteractiveFindingSchema] = []
    rejected: List[InteractiveFindingSchema] = []


class SessionListItemSchema(BaseModel):
    """会话列表项"""
    session_id: str
    target_path: str
    status: InteractiveSessionStatus
    created_at: datetime
    updated_at: datetime
    code_units_count: int = 0
    pending_findings_count: int = 0
    confirmed_findings_count: int = 0


# ============ WebSocket 消息模型 ============

class WSMessageBase(BaseModel):
    """WebSocket 消息基类"""
    type: str
    session_id: str
    timestamp: datetime = Field(default_factory=datetime.now)


class WSProgressMessage(WSMessageBase):
    """进度消息"""
    type: str = "progress"
    status: str
    progress: float = 0.0
    current_step: str = ""


class WSChatStreamMessage(WSMessageBase):
    """LLM 聊天流消息"""
    type: str = "chat_stream"
    content: str
    is_done: bool = False


class WSFindingMessage(WSMessageBase):
    """发现消息"""
    type: str = "finding"
    finding: InteractiveFindingSchema


class WSErrorMessage(WSMessageBase):
    """错误消息"""
    type: str = "error"
    error: str
    detail: Optional[str] = None
