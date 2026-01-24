"""
正则表达式回退解析器和回退链

当 Tree-sitter 解析失败时，提供多级回退机制：
1. 部分结果恢复：从不完整的解析中提取有效部分
2. 正则表达式回退：使用正则匹配提取基本结构
3. 错误标记：保留错误信息供后续分析
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum

from ...models import CodeUnit, CodeUnitType, CodeSpan

logger = logging.getLogger(__name__)


class ParseSource(Enum):
    """解析来源"""
    TREE_SITTER = "tree_sitter"
    REGEX_FALLBACK = "regex_fallback"
    PARTIAL_RECOVERY = "partial_recovery"
    MANUAL = "manual"


@dataclass
class SimpleParseResult:
    """简单解析结果（用于回退解析器）

    当解析不完全成功时，保存已解析的部分和错误信息。
    """
    units: List[CodeUnit] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    parse_source: ParseSource = ParseSource.TREE_SITTER
    coverage: float = 1.0  # 解析覆盖率 0.0-1.0

    def add_unit(self, unit: CodeUnit):
        """添加解析单元"""
        self.units.append(unit)

    def add_error(self, error: str):
        """添加错误信息"""
        self.errors.append(error)

    def add_warning(self, warning: str):
        """添加警告信息"""
        self.warnings.append(warning)

    def merge(self, other: 'SimpleParseResult'):
        """合并另一个结果"""
        self.units.extend(other.units)
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        # 取较低的覆盖率
        self.coverage = min(self.coverage, other.coverage)

    @property
    def success(self) -> bool:
        """是否解析成功（无错误）"""
        return len(self.errors) == 0

    @property
    def has_units(self) -> bool:
        """是否有解析结果"""
        return len(self.units) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "units_count": len(self.units),
            "errors": self.errors,
            "warnings": self.warnings,
            "parse_source": self.parse_source.value,
            "coverage": self.coverage,
            "success": self.success,
        }


class RegexFallbackParser:
    """正则表达式回退解析器

    当 Tree-sitter 失败时，使用正则表达式提取基本代码结构。
    支持多种语言的基本模式。
    """

    # 语言特定的函数模式
    FUNCTION_PATTERNS: Dict[str, List[re.Pattern]] = {
        "python": [
            re.compile(r"^\s*(async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*(?:->([^:]+))?:", re.MULTILINE),
        ],
        "javascript": [
            re.compile(r"(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE),
            re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>", re.MULTILINE),
            re.compile(r"(\w+)\s*:\s*(?:async\s+)?function\s*\(([^)]*)\)", re.MULTILINE),
        ],
        "typescript": [
            re.compile(r"(?:async\s+)?function\s+(\w+)\s*(?:<[^>]+>)?\s*\(([^)]*)\)", re.MULTILINE),
            re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>", re.MULTILINE),
        ],
        "php": [
            re.compile(r"(?:public|private|protected|static)?\s*function\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE),
        ],
        "java": [
            re.compile(r"(?:public|private|protected)?\s*(?:static\s+)?(?:[\w<>\[\]]+)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*\{", re.MULTILINE),
        ],
        "go": [
            re.compile(r"func\s+(?:\([^)]+\)\s*)?(\w+)\s*\(([^)]*)\)", re.MULTILINE),
        ],
        "rust": [
            re.compile(r"(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]+>)?\s*\(([^)]*)\)", re.MULTILINE),
        ],
        "c": [
            re.compile(r"(?:\w+\s+)+(\w+)\s*\(([^)]*)\)\s*\{", re.MULTILINE),
        ],
        "cpp": [
            re.compile(r"(?:\w+\s+)+(\w+)\s*\(([^)]*)\)\s*(?:const)?\s*(?:override)?\s*\{", re.MULTILINE),
        ],
        "c_sharp": [
            re.compile(r"(?:public|private|protected|internal)?\s*(?:static\s+)?(?:async\s+)?(?:[\w<>\[\]]+)\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE),
        ],
        "ruby": [
            re.compile(r"def\s+(?:self\.)?(\w+)(?:\(([^)]*)\))?", re.MULTILINE),
        ],
        "kotlin": [
            re.compile(r"(?:suspend\s+)?fun\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE),
        ],
    }

    # 类模式
    CLASS_PATTERNS: Dict[str, List[re.Pattern]] = {
        "python": [
            re.compile(r"^class\s+(\w+)(?:\(([^)]*)\))?:", re.MULTILINE),
        ],
        "javascript": [
            re.compile(r"class\s+(\w+)(?:\s+extends\s+(\w+))?", re.MULTILINE),
        ],
        "typescript": [
            re.compile(r"(?:export\s+)?(?:abstract\s+)?class\s+(\w+)(?:<[^>]+>)?(?:\s+extends\s+(\w+))?", re.MULTILINE),
        ],
        "php": [
            re.compile(r"(?:abstract\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?", re.MULTILINE),
        ],
        "java": [
            re.compile(r"(?:public\s+)?(?:abstract\s+)?class\s+(\w+)(?:<[^>]+>)?(?:\s+extends\s+(\w+))?", re.MULTILINE),
        ],
        "go": [
            re.compile(r"type\s+(\w+)\s+struct\s*\{", re.MULTILINE),
        ],
        "rust": [
            re.compile(r"(?:pub\s+)?struct\s+(\w+)(?:<[^>]+>)?", re.MULTILINE),
        ],
        "c_sharp": [
            re.compile(r"(?:public|internal)?\s*(?:abstract|sealed)?\s*class\s+(\w+)(?:<[^>]+>)?", re.MULTILINE),
        ],
        "ruby": [
            re.compile(r"class\s+(\w+)(?:\s*<\s*(\w+))?", re.MULTILINE),
        ],
        "kotlin": [
            re.compile(r"(?:data\s+)?class\s+(\w+)(?:<[^>]+>)?", re.MULTILINE),
        ],
    }

    def parse(
        self,
        content: bytes,
        language: str,
        file_path: str,
    ) -> SimpleParseResult:
        """使用正则表达式解析代码"""
        result = SimpleParseResult(
            parse_source=ParseSource.REGEX_FALLBACK,
            coverage=0.5,  # 正则解析覆盖率较低
        )

        try:
            text = content.decode("utf-8", errors="replace")
        except Exception as e:
            result.add_error(f"Failed to decode content: {e}")
            return result

        # 提取函数
        functions = self._extract_functions(text, language, file_path)
        for func in functions:
            result.add_unit(func)

        # 提取类
        classes = self._extract_classes(text, language, file_path)
        for cls in classes:
            result.add_unit(cls)

        if not result.has_units:
            result.add_warning("No code units extracted by regex fallback")

        return result

    def _extract_functions(
        self,
        text: str,
        language: str,
        file_path: str,
    ) -> List[CodeUnit]:
        """提取函数"""
        units: List[CodeUnit] = []
        patterns = self.FUNCTION_PATTERNS.get(language, [])

        for pattern in patterns:
            for match in pattern.finditer(text):
                name = match.group(1)
                if not name:
                    continue

                # 计算行号
                line = text[:match.start()].count("\n") + 1
                end_line = text[:match.end()].count("\n") + 1

                span = CodeSpan(start_line=line, end_line=end_line)
                unit_id = CodeUnit.generate_id(file_path, name, span)

                unit = CodeUnit(
                    id=unit_id,
                    language=language,
                    file_path=file_path,
                    symbol=name,
                    unit_type=CodeUnitType.FUNCTION,
                    signature=match.group(0).strip(),
                    span=span,
                    code=match.group(0),
                    calls=[],
                    imports=[],
                    metadata={"parse_source": "regex_fallback"},
                )
                units.append(unit)

        return units

    def _extract_classes(
        self,
        text: str,
        language: str,
        file_path: str,
    ) -> List[CodeUnit]:
        """提取类"""
        units: List[CodeUnit] = []
        patterns = self.CLASS_PATTERNS.get(language, [])

        for pattern in patterns:
            for match in pattern.finditer(text):
                name = match.group(1)
                if not name:
                    continue

                line = text[:match.start()].count("\n") + 1
                end_line = text[:match.end()].count("\n") + 1

                span = CodeSpan(start_line=line, end_line=end_line)
                unit_id = CodeUnit.generate_id(file_path, name, span)

                unit = CodeUnit(
                    id=unit_id,
                    language=language,
                    file_path=file_path,
                    symbol=name,
                    unit_type=CodeUnitType.CLASS,
                    signature=match.group(0).strip(),
                    span=span,
                    code=match.group(0),
                    calls=[],
                    imports=[],
                    metadata={"parse_source": "regex_fallback"},
                )
                units.append(unit)

        return units


class PartialRecoveryParser:
    """部分恢复解析器

    从包含语法错误的 Tree-sitter 解析树中恢复有效部分。
    """

    def recover_from_tree(
        self,
        tree: Any,  # Tree-sitter Tree
        source: bytes,
        language: str,
        file_path: str,
    ) -> SimpleParseResult:
        """从解析树中恢复有效节点"""
        result = SimpleParseResult(
            parse_source=ParseSource.PARTIAL_RECOVERY,
        )

        if tree is None:
            result.add_error("No parse tree available")
            return result

        root = tree.root_node
        if root is None:
            result.add_error("Empty parse tree")
            return result

        # 检查是否有错误
        error_count = self._count_errors(root)
        if error_count > 0:
            result.add_warning(f"Parse tree contains {error_count} error nodes")
            result.coverage = max(0.3, 1.0 - (error_count * 0.1))

        # 尝试从有效节点中提取信息
        valid_nodes = self._collect_valid_nodes(root)
        result.add_warning(f"Recovered {len(valid_nodes)} valid nodes")

        return result

    def _count_errors(self, node: Any) -> int:
        """统计错误节点数量"""
        count = 0
        if hasattr(node, "type") and node.type == "ERROR":
            count += 1
        if hasattr(node, "children"):
            for child in node.children:
                count += self._count_errors(child)
        return count

    def _collect_valid_nodes(self, node: Any) -> List[Any]:
        """收集有效节点"""
        valid = []
        if hasattr(node, "type") and node.type != "ERROR":
            valid.append(node)
        if hasattr(node, "children"):
            for child in node.children:
                valid.extend(self._collect_valid_nodes(child))
        return valid


class FallbackChain:
    """回退链

    按优先级尝试多种解析方式：
    1. Tree-sitter 完整解析
    2. Tree-sitter 部分恢复
    3. 正则表达式回退
    """

    def __init__(self):
        self.regex_fallback = RegexFallbackParser()
        self.partial_recovery = PartialRecoveryParser()

    def parse_with_fallback(
        self,
        content: bytes,
        language: str,
        file_path: str,
        tree: Any = None,  # 可选的 Tree-sitter 解析树
    ) -> SimpleParseResult:
        """使用回退链解析代码

        Args:
            content: 代码内容
            language: 语言名称
            file_path: 文件路径
            tree: 可选的 Tree-sitter 解析树（如果已有）

        Returns:
            解析结果
        """
        # 如果有解析树，尝试部分恢复
        if tree is not None:
            result = self.partial_recovery.recover_from_tree(
                tree, content, language, file_path
            )
            if result.has_units:
                return result

        # 正则表达式回退
        result = self.regex_fallback.parse(content, language, file_path)
        return result

    def get_best_result(
        self,
        results: List[SimpleParseResult],
    ) -> SimpleParseResult:
        """从多个结果中选择最佳结果"""
        if not results:
            return SimpleParseResult()

        # 按覆盖率和单元数量排序
        sorted_results = sorted(
            results,
            key=lambda r: (r.coverage, len(r.units), -len(r.errors)),
            reverse=True,
        )

        return sorted_results[0]
