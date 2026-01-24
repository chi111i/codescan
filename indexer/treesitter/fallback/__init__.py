"""
解析失败回退处理模块

提供 Tree-sitter 解析失败时的回退策略：
- 回退到正则解析器
- 返回部分解析结果
- 错误标记和报告
- 回退链机制
"""

from .strategy import (
    FallbackStrategy,
    ParseError,
    ParseErrorType,
    PartialParseResult,
)
from .error_marker import ErrorMarkedUnit, mark_units_with_errors
from .regex_fallback import RegexFallbackParser, FallbackChain, ParseSource

__all__ = [
    # 原有导出
    "FallbackStrategy",
    "ParseError",
    "ParseErrorType",
    "PartialParseResult",
    "ErrorMarkedUnit",
    "mark_units_with_errors",
    # 新增导出（兼容 __init__.py 导入）
    "RegexFallbackParser",
    "FallbackChain",
    "ParseSource",
]
