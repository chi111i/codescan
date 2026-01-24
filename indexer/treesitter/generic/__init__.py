"""
Generic AST 模块

提供跨语言的通用 AST 表示，支持：
- 统一的节点类型定义
- 语言特定 AST 到 Generic AST 的转换
- 跨语言安全模式匹配
"""

from .nodes import (
    NodeKind,
    Span,
    GenericNode,
    GenericFunction,
    GenericClass,
    GenericCall,
    GenericParameter,
    GenericVariable,
    GenericBlock,
    GenericImport,
)
from .converter import GenericASTConverter
from .patterns import SecurityPattern, CROSS_LANGUAGE_PATTERNS, match_security_patterns

__all__ = [
    # 节点类型
    "NodeKind",
    "Span",
    "GenericNode",
    "GenericFunction",
    "GenericClass",
    "GenericCall",
    "GenericParameter",
    "GenericVariable",
    "GenericBlock",
    "GenericImport",
    # 转换器
    "GenericASTConverter",
    # 安全模式
    "SecurityPattern",
    "CROSS_LANGUAGE_PATTERNS",
    "match_security_patterns",
]
