"""
Agent 模块 - LLM Function Calling 驱动的代码分析代理

功能：
- 代码导航工具供 LLM 调用
- 支持 OpenAI Function Calling 格式
- 工具调用日志记录
- 统一审计智能体（支持自主工具调用）
"""

from .code_agent import CodeAnalysisAgent, SecurityAnalysisAgent, AgentResult, ToolCallRecord
from .enhanced_agent import EnhancedSecurityAgent
from .logged_agent import LoggedCodeAgent, LoggedSecurityAgent, LoggedAgentResult
from .logged_enhanced_agent import LoggedEnhancedSecurityAgent
from .tools.executor import ToolExecutor, ToolResult, LoggingToolExecutor
from .tools.registry import (
    ToolRegistry,
    CODE_NAVIGATION_TOOLS,
    SECURITY_ANALYSIS_TOOLS,
    create_default_registry,
    create_security_registry,
)
from .tools.manager import AgentToolManager, ToolDefinition, ToolCategory
from .unified_agent import (
    UnifiedAuditAgent,
    UnifiedAgentConfig,
    AgentMessage,
    ToolCallEvent,
    ToolCallStatus,
    create_unified_agent,
)
from .context_manager import (
    ContextManager,
    ContextManagerConfig,
    ContextItem,
    ContextType,
    create_context_manager,
)

# 为了向后兼容，创建别名
CODE_READER_TOOLS = CODE_NAVIGATION_TOOLS


def get_tool_by_name(name: str):
    """获取工具定义（向后兼容）"""
    registry = create_security_registry()
    return registry.get(name)


def get_tool_names():
    """获取所有工具名称（向后兼容）"""
    registry = create_security_registry()
    return registry.get_names()


__all__ = [
    # 代码导航工具
    "CODE_READER_TOOLS",
    "CODE_NAVIGATION_TOOLS",
    "SECURITY_ANALYSIS_TOOLS",
    "get_tool_by_name",
    "get_tool_names",
    # Agent 类
    "CodeAnalysisAgent",
    "SecurityAnalysisAgent",
    "EnhancedSecurityAgent",
    "AgentResult",
    "ToolCallRecord",
    # 带日志的 Agent
    "LoggedCodeAgent",
    "LoggedSecurityAgent",
    "LoggedAgentResult",
    "LoggedEnhancedSecurityAgent",
    # 工具系统
    "ToolExecutor",
    "ToolResult",
    "LoggingToolExecutor",
    "ToolRegistry",
    "create_default_registry",
    "create_security_registry",
    # 统一工具管理器
    "AgentToolManager",
    "ToolDefinition",
    "ToolCategory",
    # 统一审计智能体
    "UnifiedAuditAgent",
    "UnifiedAgentConfig",
    "AgentMessage",
    "ToolCallEvent",
    "ToolCallStatus",
    "create_unified_agent",
    # 上下文管理器
    "ContextManager",
    "ContextManagerConfig",
    "ContextItem",
    "ContextType",
    "create_context_manager",
]
