"""
Agent 工具模块 - 工具执行器与日志记录

提供带日志记录的工具执行器，支持将 LLM 工具调用过程记录到数据库。
"""

from .executor import ToolExecutor, ToolResult
from .registry import (
    ToolRegistry,
    CODE_NAVIGATION_TOOLS,
    SECURITY_ANALYSIS_TOOLS,
    create_default_registry,
    create_security_registry,
)
from .manager import AgentToolManager, ToolDefinition, ToolCategory
from .callchain_tools import (
    CALLCHAIN_TOOL_DEFINITIONS,
    CallChainToolExecutor,
    get_callchain_tool_definitions,
    create_callchain_executor,
)
from .variant_tools import (
    VARIANT_TOOL_DEFINITIONS,
    VariantToolExecutor,
    get_variant_tool_definitions,
    create_variant_executor,
)

# 向后兼容别名
CODE_READER_TOOLS = CODE_NAVIGATION_TOOLS

__all__ = [
    # 执行器
    "ToolExecutor",
    "ToolResult",
    # 注册表
    "ToolRegistry",
    "CODE_NAVIGATION_TOOLS",
    "CODE_READER_TOOLS",
    "SECURITY_ANALYSIS_TOOLS",
    "create_default_registry",
    "create_security_registry",
    # 统一工具管理器
    "AgentToolManager",
    "ToolDefinition",
    "ToolCategory",
    # 调用链工具
    "CALLCHAIN_TOOL_DEFINITIONS",
    "CallChainToolExecutor",
    "get_callchain_tool_definitions",
    "create_callchain_executor",
    # 变体分析工具
    "VARIANT_TOOL_DEFINITIONS",
    "VariantToolExecutor",
    "get_variant_tool_definitions",
    "create_variant_executor",
]
