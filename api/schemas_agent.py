"""统一智能体 API 数据模型"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


# ============ 枚举类型 ============

class UnifiedSessionStatus(str, Enum):
    """统一会话状态"""
    INITIALIZING = "initializing"
    READY = "ready"
    PROCESSING = "processing"
    IDLE = "idle"
    ERROR = "error"
    ARCHIVED = "archived"  # 历史会话（未激活）


class ToolCallStatusEnum(str, Enum):
    """工具调用状态"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


# ============ 请求模型 ============

class CreateUnifiedSessionRequest(BaseModel):
    """创建统一会话请求"""
    target_path: str = Field(..., description="目标代码路径")
    languages: Optional[List[str]] = Field(None, description="限定语言列表")
    enable_call_chain: bool = Field(True, description="是否启用调用链分析")
    enable_variant_analysis: bool = Field(True, description="是否启用变体分析")
    # === 预扫描配置 ===
    enable_prescan: bool = Field(True, description="是否启用规则预扫描")
    prescan_risk_levels: List[str] = Field(
        default=["high", "critical"],
        description="预扫描风险等级过滤 (low/medium/high/critical)"
    )
    enable_deep_enhancement: bool = Field(True, description="是否启用深度增强分析")


class UnifiedChatRequest(BaseModel):
    """统一智能体对话请求"""
    message: str = Field(..., description="用户消息")


class IndexProjectRequest(BaseModel):
    """索引项目请求"""
    target_path: Optional[str] = Field(None, description="目标路径（不填则使用会话路径）")
    languages: Optional[List[str]] = Field(None, description="语言列表")
    force_reindex: bool = Field(False, description="强制重新索引")


# ============ 响应模型 ============

class ToolCallEventSchema(BaseModel):
    """工具调用事件"""
    id: str
    tool_name: str
    arguments: Dict[str, Any] = {}
    status: ToolCallStatusEnum
    result: Optional[Any] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_ms: int = 0


class AgentMessageSchema(BaseModel):
    """智能体消息"""
    role: str  # user, assistant, tool
    content: str
    tool_calls: List[ToolCallEventSchema] = []
    timestamp: datetime
    metadata: Dict[str, Any] = {}


class UnifiedSessionInfoSchema(BaseModel):
    """统一会话信息"""
    session_id: str
    target_path: Optional[str] = None
    status: UnifiedSessionStatus
    title: Optional[str] = None  # 会话标题
    created_at: datetime
    updated_at: datetime

    # 统计
    messages_count: int = 0
    tool_calls_count: int = 0
    total_llm_calls: int = 0
    total_tokens_used: int = 0

    # 可用工具
    available_tools: List[str] = []

    # 配置
    enable_call_chain: bool = True
    enable_variant_analysis: bool = True

    # 错误
    error_message: Optional[str] = None


class UnifiedChatResponseSchema(BaseModel):
    """统一对话响应"""
    message: AgentMessageSchema
    session_status: UnifiedSessionStatus
    tool_calls_count: int = 0


class ToolDefinitionSchema(BaseModel):
    """工具定义"""
    name: str
    description: str
    category: str
    parameters: Dict[str, Any] = {}


class TokenBreakdownSchema(BaseModel):
    """Token 使用分布"""
    total: int = 0
    conversation: int = 0
    code: int = 0
    tool_results: int = 0
    findings: int = 0
    summaries: int = 0


class SessionStatsSchema(BaseModel):
    """会话统计"""
    messages_count: int = 0
    tool_calls_count: int = 0
    total_llm_calls: int = 0
    total_tokens_used: int = 0
    tokens_breakdown: TokenBreakdownSchema = TokenBreakdownSchema()


# ============ WebSocket 事件模型 ============

class WSEventType(str, Enum):
    """WebSocket 事件类型"""
    CONNECTED = "connected"
    TOOL_CALL_START = "tool_call_start"
    TOOL_CALL_END = "tool_call_end"
    MESSAGE_CHUNK = "message_chunk"
    MESSAGE_COMPLETE = "message_complete"
    ERROR = "error"
    PING = "ping"
    PONG = "pong"
    # === 预扫描事件 ===
    PRESCAN_START = "prescan_start"
    PRESCAN_PROGRESS = "prescan_progress"
    PRESCAN_COMPLETE = "prescan_complete"
    ENHANCEMENT_START = "enhancement_start"
    ENHANCEMENT_COMPLETE = "enhancement_complete"


class WSEvent(BaseModel):
    """WebSocket 事件"""
    type: WSEventType
    session_id: str
    timestamp: datetime = Field(default_factory=datetime.now)
    data: Optional[Dict[str, Any]] = None
