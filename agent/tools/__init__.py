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

# 向后兼容别名
CODE_READER_TOOLS = CODE_NAVIGATION_TOOLS

__all__ = [
    "ToolExecutor",
    "ToolResult",
    "ToolRegistry",
    "CODE_NAVIGATION_TOOLS",
    "CODE_READER_TOOLS",
    "SECURITY_ANALYSIS_TOOLS",
    "create_default_registry",
    "create_security_registry",
]
