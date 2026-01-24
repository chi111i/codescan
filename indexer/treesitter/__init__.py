"""
Tree-sitter 多语言解析器模块

提供基于 Tree-sitter 的代码解析能力，支持：
- 多语言统一解析接口
- Generic AST 中间层
- 解析失败回退策略
- .scm 查询文件管理

支持的语言：
- JavaScript/TypeScript
- PHP
- Java
- Go
- Rust
- C/C++
- C#
- Ruby
- Kotlin
- Python (可选模式)
"""

from .base import TreeSitterParser, TreeSitterParserRegistry, TREE_SITTER_AVAILABLE
from .loader import LanguageLoader
from .query_engine import QueryEngine
from .utils import (
    node_text,
    node_span,
    get_node_text,
    position_to_line_col,
)

# 导入所有语言解析器（触发注册）
from . import javascript
from . import php
from . import java
from . import go
from . import rust
from . import cpp
from . import csharp
from . import ruby
from . import kotlin

# 导入框架支持
from .frameworks import (
    FrameworkType,
    FrameworkDetector,
    FrameworkAnalyzer,
    RouteInfo,
    FrameworkInfo,
)

# 导入统一解析器
from .unified_parser import UnifiedParser, get_unified_parser, parse_file, parse_directory

# 导入回退策略
from .fallback import FallbackChain, PartialParseResult, RegexFallbackParser

# 导入性能优化
from .optimization import (
    OptimizedTreeSitterParser,
    get_optimized_parser,
    ParserPool,
    ParseCache,
)

__all__ = [
    # 核心类
    "TreeSitterParser",
    "TreeSitterParserRegistry",
    "LanguageLoader",
    "QueryEngine",
    # 统一解析器
    "UnifiedParser",
    "get_unified_parser",
    "parse_file",
    "parse_directory",
    # 回退策略
    "FallbackChain",
    "PartialParseResult",
    "RegexFallbackParser",
    # 性能优化
    "OptimizedTreeSitterParser",
    "get_optimized_parser",
    "ParserPool",
    "ParseCache",
    # 常量
    "TREE_SITTER_AVAILABLE",
    # 工具函数
    "node_text",
    "node_span",
    "get_node_text",
    "position_to_line_col",
    # 框架支持
    "FrameworkType",
    "FrameworkDetector",
    "FrameworkAnalyzer",
    "RouteInfo",
    "FrameworkInfo",
]
