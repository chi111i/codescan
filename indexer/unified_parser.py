"""
统一解析器管理模块

提供 Tree-sitter 和正则解析器的统一接口，支持：
- 配置化的解析器选择
- 自动回退机制
- 解析结果合并
"""

import logging
from typing import List, Optional, Dict, Any, Type, Union
from pathlib import Path

from .models import CodeUnit
from .parser import (
    BaseLanguageParser,
    PythonParser,
    JavaScriptParser,
    PHPParser,
    get_parser_for_file,
)

logger = logging.getLogger(__name__)

# 尝试导入 Tree-sitter 模块
try:
    from .treesitter import TreeSitterParserRegistry
    from .treesitter.base import TreeSitterParser, TREE_SITTER_AVAILABLE
    from .treesitter.fallback import FallbackStrategy, PartialParseResult
    # 导入解析器以触发注册
    from .treesitter import javascript, php
    TREESITTER_MODULE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Tree-sitter 模块不可用: {e}")
    TREESITTER_MODULE_AVAILABLE = False
    TREE_SITTER_AVAILABLE = False
    TreeSitterParserRegistry = None
    TreeSitterParser = None
    FallbackStrategy = None
    PartialParseResult = None


class ParserStrategy:
    """解析器策略枚举"""
    TREESITTER = "treesitter"      # 优先使用 Tree-sitter
    REGEX = "regex"                # 使用正则解析器
    AUTO = "auto"                  # 自动选择（有 Tree-sitter 就用）
    HYBRID = "hybrid"              # 混合模式（Tree-sitter + 回退）


class ParserConfig:
    """解析器配置"""

    def __init__(
        self,
        strategy: str = ParserStrategy.AUTO,
        use_treesitter_for: Optional[List[str]] = None,
        python_parser: str = "ast",  # "ast" 或 "treesitter"
        fallback_enabled: bool = True,
        error_threshold: float = 0.3,
    ):
        """初始化配置

        Args:
            strategy: 解析器策略
            use_treesitter_for: 使用 Tree-sitter 的语言列表
            python_parser: Python 解析器选择
            fallback_enabled: 是否启用回退
            error_threshold: 触发回退的错误率阈值
        """
        self.strategy = strategy
        self.use_treesitter_for = use_treesitter_for or [
            "javascript", "typescript", "php"
        ]
        self.python_parser = python_parser
        self.fallback_enabled = fallback_enabled
        self.error_threshold = error_threshold

    @classmethod
    def from_dict(cls, config: Dict[str, Any]) -> 'ParserConfig':
        """从字典创建配置"""
        return cls(
            strategy=config.get("strategy", ParserStrategy.AUTO),
            use_treesitter_for=config.get("use_treesitter_for"),
            python_parser=config.get("python_parser", "ast"),
            fallback_enabled=config.get("fallback_enabled", True),
            error_threshold=config.get("error_threshold", 0.3),
        )


class UnifiedParser:
    """统一解析器

    提供 Tree-sitter 和正则解析器的统一接口。
    根据配置自动选择解析器，并在需要时进行回退。
    """

    def __init__(self, config: Optional[ParserConfig] = None):
        """初始化统一解析器

        Args:
            config: 解析器配置
        """
        self.config = config or ParserConfig()
        self._regex_parsers: Dict[str, BaseLanguageParser] = {
            "python": PythonParser(),
            "javascript": JavaScriptParser(),
            "typescript": JavaScriptParser(),  # JS 解析器也支持 TS
            "php": PHPParser(),
        }
        self._fallback_strategies: Dict[str, FallbackStrategy] = {}

        # 初始化回退策略
        if TREESITTER_MODULE_AVAILABLE and self.config.fallback_enabled:
            for lang, regex_parser in self._regex_parsers.items():
                self._fallback_strategies[lang] = FallbackStrategy(
                    regex_parser=regex_parser,
                    error_threshold=self.config.error_threshold,
                )

    def parse_file(self, file_path: str, content: str) -> List[CodeUnit]:
        """解析文件

        根据配置选择解析器，并在需要时进行回退。

        Args:
            file_path: 文件路径
            content: 文件内容

        Returns:
            CodeUnit 列表
        """
        language = self._detect_language(file_path)
        if not language:
            logger.warning(f"无法检测文件语言: {file_path}")
            return []

        # 决定使用哪个解析器
        use_treesitter = self._should_use_treesitter(language)

        if use_treesitter and TREESITTER_MODULE_AVAILABLE and TREE_SITTER_AVAILABLE:
            return self._parse_with_treesitter(file_path, content, language)
        else:
            return self._parse_with_regex(file_path, content, language)

    def _should_use_treesitter(self, language: str) -> bool:
        """判断是否应该使用 Tree-sitter"""
        if self.config.strategy == ParserStrategy.REGEX:
            return False

        if self.config.strategy == ParserStrategy.TREESITTER:
            return True

        # AUTO 或 HYBRID 模式
        if language == "python" and self.config.python_parser == "ast":
            return False

        return language in self.config.use_treesitter_for

    def _parse_with_treesitter(
        self,
        file_path: str,
        content: str,
        language: str
    ) -> List[CodeUnit]:
        """使用 Tree-sitter 解析"""
        ts_parser = TreeSitterParserRegistry.get(language)
        if not ts_parser:
            logger.warning(f"Tree-sitter 解析器不可用 ({language})，回退到正则")
            return self._parse_with_regex(file_path, content, language)

        try:
            # 解析
            units = ts_parser.parse_file(file_path, content)

            # 检查是否需要回退
            if self.config.fallback_enabled and self.config.strategy == ParserStrategy.HYBRID:
                source = content.encode('utf-8')
                tree = ts_parser.parse(source)
                if tree:
                    fallback = self._fallback_strategies.get(language)
                    if fallback:
                        should_fallback, errors, _ = fallback.analyze_tree(tree, source)
                        if should_fallback:
                            result = fallback.execute_fallback(file_path, content,
                                PartialParseResult(successful_units=units, errors=errors))
                            return result.all_units

            return units

        except Exception as e:
            logger.error(f"Tree-sitter 解析失败 ({file_path}): {e}")
            if self.config.fallback_enabled:
                return self._parse_with_regex(file_path, content, language)
            return []

    def _parse_with_regex(
        self,
        file_path: str,
        content: str,
        language: str
    ) -> List[CodeUnit]:
        """使用正则解析器"""
        parser = self._regex_parsers.get(language)
        if not parser:
            parser = get_parser_for_file(file_path)

        if not parser:
            logger.warning(f"没有可用的解析器: {language}")
            return []

        try:
            return parser.parse_file(file_path, content)
        except Exception as e:
            logger.error(f"正则解析失败 ({file_path}): {e}")
            return []

    def _detect_language(self, file_path: str) -> Optional[str]:
        """检测文件语言"""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".mjs": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".php": "php",
            ".phtml": "php",
        }

        path = Path(file_path)
        return ext_map.get(path.suffix.lower())

    def get_available_parsers(self) -> Dict[str, Dict[str, bool]]:
        """获取可用解析器信息"""
        result = {}

        for lang in ["python", "javascript", "typescript", "php"]:
            result[lang] = {
                "regex": lang in self._regex_parsers,
                "treesitter": False,
            }

            if TREESITTER_MODULE_AVAILABLE and TREE_SITTER_AVAILABLE:
                result[lang]["treesitter"] = TreeSitterParserRegistry.is_available(lang)

        return result


# 全局解析器实例
_unified_parser: Optional[UnifiedParser] = None


def get_unified_parser(config: Optional[ParserConfig] = None) -> UnifiedParser:
    """获取统一解析器实例（单例）"""
    global _unified_parser
    if _unified_parser is None or config is not None:
        _unified_parser = UnifiedParser(config)
    return _unified_parser


def parse_file(file_path: str, content: str) -> List[CodeUnit]:
    """便捷函数：解析文件"""
    return get_unified_parser().parse_file(file_path, content)
