"""
统一解析器

提供统一的代码解析入口，自动检测语言并选择最佳解析器。
整合 Tree-sitter 解析、回退策略和框架检测。
"""

import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Union

from ..models import CodeUnit, CodeUnitType
from .base import TreeSitterParser, TreeSitterParserRegistry, TREE_SITTER_AVAILABLE
from .fallback import FallbackChain, PartialParseResult
from .frameworks import FrameworkAnalyzer, FrameworkInfo

logger = logging.getLogger(__name__)


# 文件扩展名到语言的映射
EXTENSION_TO_LANGUAGE: Dict[str, str] = {
    # JavaScript/TypeScript
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    # PHP
    ".php": "php",
    # Java
    ".java": "java",
    # Go
    ".go": "go",
    # Rust
    ".rs": "rust",
    # C/C++
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".hh": "cpp",
    # C#
    ".cs": "c_sharp",
    # Ruby
    ".rb": "ruby",
    ".rake": "ruby",
    ".gemspec": "ruby",
    # Kotlin
    ".kt": "kotlin",
    ".kts": "kotlin",
    # Python
    ".py": "python",
    ".pyw": "python",
}


class UnifiedParser:
    """统一解析器

    提供统一的代码解析入口，自动：
    - 检测文件语言
    - 选择最佳解析器（Tree-sitter 或回退）
    - 处理解析错误
    - 提取框架信息
    """

    def __init__(
        self,
        enable_fallback: bool = True,
        enable_framework_detection: bool = True,
    ):
        """初始化统一解析器

        Args:
            enable_fallback: 是否启用回退策略
            enable_framework_detection: 是否启用框架检测
        """
        self.enable_fallback = enable_fallback
        self.enable_framework_detection = enable_framework_detection
        self.fallback_chain = FallbackChain() if enable_fallback else None
        self.framework_analyzer = FrameworkAnalyzer() if enable_framework_detection else None
        self._stats = {
            "files_parsed": 0,
            "treesitter_success": 0,
            "fallback_used": 0,
            "parse_errors": 0,
        }

    def detect_language(self, file_path: Union[str, Path]) -> Optional[str]:
        """检测文件语言

        Args:
            file_path: 文件路径

        Returns:
            语言名称，如果无法识别则返回 None
        """
        path = Path(file_path)
        ext = path.suffix.lower()
        return EXTENSION_TO_LANGUAGE.get(ext)

    def parse_file(
        self,
        file_path: Union[str, Path],
        language: Optional[str] = None,
    ) -> List[CodeUnit]:
        """解析单个文件

        Args:
            file_path: 文件路径
            language: 语言名称（可选，自动检测）

        Returns:
            解析出的 CodeUnit 列表
        """
        path = Path(file_path)

        if not path.exists():
            logger.warning(f"File not found: {path}")
            return []

        # 检测语言
        if language is None:
            language = self.detect_language(path)

        if language is None:
            logger.debug(f"Unknown language for file: {path}")
            return []

        # 读取文件内容
        try:
            content = path.read_bytes()
        except Exception as e:
            logger.error(f"Failed to read file {path}: {e}")
            return []

        self._stats["files_parsed"] += 1

        # 尝试 Tree-sitter 解析
        parser = TreeSitterParserRegistry.get_parser(language)

        if parser and TREE_SITTER_AVAILABLE:
            try:
                units = parser.parse_file(str(path))
                if units:
                    self._stats["treesitter_success"] += 1
                    return units
            except Exception as e:
                logger.warning(f"Tree-sitter parse failed for {path}: {e}")

        # 回退解析
        if self.fallback_chain:
            try:
                result = self.fallback_chain.parse_with_fallback(
                    content, language, str(path)
                )
                self._stats["fallback_used"] += 1
                if result.errors:
                    logger.debug(f"Parse warnings for {path}: {result.errors}")
                return result.units
            except Exception as e:
                logger.error(f"Fallback parse failed for {path}: {e}")
                self._stats["parse_errors"] += 1

        return []

    def parse_content(
        self,
        content: Union[str, bytes],
        language: str,
        file_path: str = "<string>",
    ) -> List[CodeUnit]:
        """解析代码内容

        Args:
            content: 代码内容
            language: 语言名称
            file_path: 虚拟文件路径

        Returns:
            解析出的 CodeUnit 列表
        """
        if isinstance(content, str):
            content = content.encode("utf-8")

        self._stats["files_parsed"] += 1

        # 尝试 Tree-sitter 解析
        parser = TreeSitterParserRegistry.get_parser(language)

        if parser and TREE_SITTER_AVAILABLE:
            try:
                units = parser.parse_content(content, file_path)
                if units:
                    self._stats["treesitter_success"] += 1
                    return units
            except Exception as e:
                logger.warning(f"Tree-sitter parse failed: {e}")

        # 回退解析
        if self.fallback_chain:
            try:
                result = self.fallback_chain.parse_with_fallback(
                    content, language, file_path
                )
                self._stats["fallback_used"] += 1
                return result.units
            except Exception as e:
                logger.error(f"Fallback parse failed: {e}")
                self._stats["parse_errors"] += 1

        return []

    def parse_directory(
        self,
        directory: Union[str, Path],
        recursive: bool = True,
        extensions: Optional[List[str]] = None,
    ) -> List[CodeUnit]:
        """解析目录中的所有文件

        Args:
            directory: 目录路径
            recursive: 是否递归处理子目录
            extensions: 要处理的文件扩展名列表

        Returns:
            所有解析出的 CodeUnit 列表
        """
        dir_path = Path(directory)

        if not dir_path.is_dir():
            logger.warning(f"Not a directory: {dir_path}")
            return []

        all_units: List[CodeUnit] = []

        # 确定要处理的扩展名
        if extensions is None:
            extensions = list(EXTENSION_TO_LANGUAGE.keys())

        # 遍历文件
        pattern = "**/*" if recursive else "*"
        for file_path in dir_path.glob(pattern):
            if file_path.is_file() and file_path.suffix.lower() in extensions:
                units = self.parse_file(file_path)
                all_units.extend(units)

        return all_units

    def parse_with_framework_info(
        self,
        file_path: Union[str, Path],
        language: Optional[str] = None,
    ) -> tuple[List[CodeUnit], Optional[FrameworkInfo]]:
        """解析文件并提取框架信息

        Args:
            file_path: 文件路径
            language: 语言名称

        Returns:
            (CodeUnit 列表, 框架信息)
        """
        path = Path(file_path)
        units = self.parse_file(path, language)

        framework_info = None
        if self.framework_analyzer and units:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                detected_language = language or self.detect_language(path)
                if detected_language:
                    imports = [u.imports for u in units if u.imports]
                    flat_imports = [imp for sublist in imports for imp in sublist]
                    framework_info = self.framework_analyzer.analyze_file(
                        content, str(path), detected_language, flat_imports
                    )
            except Exception as e:
                logger.warning(f"Framework detection failed for {path}: {e}")

        return units, framework_info

    def get_stats(self) -> Dict[str, Any]:
        """获取解析统计信息"""
        stats = self._stats.copy()
        if stats["files_parsed"] > 0:
            stats["treesitter_rate"] = round(
                stats["treesitter_success"] / stats["files_parsed"] * 100, 1
            )
            stats["fallback_rate"] = round(
                stats["fallback_used"] / stats["files_parsed"] * 100, 1
            )
            stats["error_rate"] = round(
                stats["parse_errors"] / stats["files_parsed"] * 100, 1
            )
        return stats

    def reset_stats(self):
        """重置统计信息"""
        self._stats = {
            "files_parsed": 0,
            "treesitter_success": 0,
            "fallback_used": 0,
            "parse_errors": 0,
        }

    @staticmethod
    def get_supported_languages() -> List[str]:
        """获取支持的语言列表"""
        return list(set(EXTENSION_TO_LANGUAGE.values()))

    @staticmethod
    def get_supported_extensions() -> List[str]:
        """获取支持的文件扩展名列表"""
        return list(EXTENSION_TO_LANGUAGE.keys())


# 全局解析器实例
_global_parser: Optional[UnifiedParser] = None


def get_unified_parser() -> UnifiedParser:
    """获取全局统一解析器实例"""
    global _global_parser
    if _global_parser is None:
        _global_parser = UnifiedParser()
    return _global_parser


def parse_file(file_path: Union[str, Path], language: Optional[str] = None) -> List[CodeUnit]:
    """便捷函数：解析单个文件"""
    return get_unified_parser().parse_file(file_path, language)


def parse_directory(
    directory: Union[str, Path],
    recursive: bool = True,
) -> List[CodeUnit]:
    """便捷函数：解析目录"""
    return get_unified_parser().parse_directory(directory, recursive)
