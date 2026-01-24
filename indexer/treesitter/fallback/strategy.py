"""
解析失败回退策略

实现 Tree-sitter 解析失败时的回退机制：
1. 检测语法错误节点
2. 回退到正则解析器
3. 合并部分结果
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Callable, TYPE_CHECKING
from enum import Enum

if TYPE_CHECKING:
    from tree_sitter import Tree, Node
    from ...models import CodeUnit
    from ...parser import BaseLanguageParser

logger = logging.getLogger(__name__)


class ParseErrorType(Enum):
    """解析错误类型"""
    SYNTAX_ERROR = "syntax_error"      # 语法错误
    MISSING_NODE = "missing_node"      # 缺失节点
    UNEXPECTED_TOKEN = "unexpected"    # 意外 token
    ENCODING_ERROR = "encoding"        # 编码错误
    TIMEOUT = "timeout"                # 解析超时
    UNKNOWN = "unknown"                # 未知错误


@dataclass
class ParseError:
    """解析错误信息

    记录解析过程中遇到的错误，用于诊断和报告。
    """
    error_type: ParseErrorType
    line: int
    column: int
    message: str
    context: str = ""  # 错误上下文（前后几行代码）
    node_type: str = ""  # 错误节点类型

    def to_dict(self) -> dict:
        return {
            "error_type": self.error_type.value,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "context": self.context,
            "node_type": self.node_type,
        }

    def __str__(self) -> str:
        return f"[{self.error_type.value}] L{self.line}:{self.column} - {self.message}"


@dataclass
class PartialParseResult:
    """部分解析结果

    当 Tree-sitter 解析遇到错误时，记录成功解析的部分、
    错误信息、以及正则回退的结果。
    """
    successful_units: List['CodeUnit'] = field(default_factory=list)
    errors: List[ParseError] = field(default_factory=list)
    fallback_units: List['CodeUnit'] = field(default_factory=list)
    coverage: float = 1.0  # 解析覆盖率 (0-1)
    used_fallback: bool = False

    @property
    def has_errors(self) -> bool:
        """是否有解析错误"""
        return len(self.errors) > 0

    @property
    def error_count(self) -> int:
        """错误数量"""
        return len(self.errors)

    @property
    def total_units(self) -> int:
        """总代码单元数"""
        return len(self.successful_units) + len(self.fallback_units)

    @property
    def all_units(self) -> List['CodeUnit']:
        """合并所有解析结果

        去重策略：如果 Tree-sitter 和正则都解析到同一个函数，
        优先使用 Tree-sitter 结果（更准确）。
        """
        seen_ids = {unit.id for unit in self.successful_units}
        merged = list(self.successful_units)

        for unit in self.fallback_units:
            if unit.id not in seen_ids:
                merged.append(unit)
                seen_ids.add(unit.id)

        return merged

    def add_error(
        self,
        error_type: ParseErrorType,
        line: int,
        column: int,
        message: str,
        context: str = "",
        node_type: str = ""
    ) -> None:
        """添加错误"""
        self.errors.append(ParseError(
            error_type=error_type,
            line=line,
            column=column,
            message=message,
            context=context,
            node_type=node_type,
        ))

    def to_dict(self) -> dict:
        return {
            "successful_count": len(self.successful_units),
            "fallback_count": len(self.fallback_units),
            "error_count": self.error_count,
            "coverage": self.coverage,
            "used_fallback": self.used_fallback,
            "errors": [e.to_dict() for e in self.errors],
        }


class FallbackStrategy:
    """解析失败回退策略

    当 Tree-sitter 解析失败或产生过多错误时，
    自动回退到正则解析器以获取部分结果。
    """

    def __init__(
        self,
        regex_parser: Optional['BaseLanguageParser'] = None,
        error_threshold: float = 0.3,
        context_lines: int = 2,
    ):
        """初始化回退策略

        Args:
            regex_parser: 正则解析器实例（用于回退）
            error_threshold: 错误率阈值，超过此值触发回退
            context_lines: 错误上下文行数
        """
        self.regex_parser = regex_parser
        self.error_threshold = error_threshold
        self.context_lines = context_lines

    def analyze_tree(
        self,
        tree: 'Tree',
        source: bytes
    ) -> Tuple[bool, List[ParseError], float]:
        """分析语法树，检测错误

        Args:
            tree: Tree-sitter 语法树
            source: 源代码字节串

        Returns:
            (是否需要回退, 错误列表, 错误率)
        """
        errors: List[ParseError] = []
        total_nodes = 0
        error_nodes = 0

        def analyze_node(node: 'Node'):
            nonlocal total_nodes, error_nodes
            total_nodes += 1

            if node.is_error:
                error_nodes += 1
                errors.append(ParseError(
                    error_type=ParseErrorType.SYNTAX_ERROR,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    message=f"语法错误",
                    context=self._get_context(source, node.start_byte, node.end_byte),
                    node_type=node.type,
                ))
            elif node.is_missing:
                error_nodes += 1
                errors.append(ParseError(
                    error_type=ParseErrorType.MISSING_NODE,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    message=f"缺失节点: {node.type}",
                    context=self._get_context(source, node.start_byte, node.end_byte),
                    node_type=node.type,
                ))

            for child in node.children:
                analyze_node(child)

        analyze_node(tree.root_node)

        error_ratio = error_nodes / total_nodes if total_nodes > 0 else 0
        should_fallback = error_ratio > self.error_threshold

        if should_fallback:
            logger.warning(
                f"解析错误率 {error_ratio:.1%} 超过阈值 {self.error_threshold:.1%}，"
                f"将回退到正则解析器"
            )

        return should_fallback, errors, error_ratio

    def execute_fallback(
        self,
        file_path: str,
        content: str,
        partial_result: PartialParseResult,
    ) -> PartialParseResult:
        """执行正则解析器回退

        Args:
            file_path: 文件路径
            content: 文件内容
            partial_result: 已有的部分结果

        Returns:
            更新后的 PartialParseResult
        """
        if not self.regex_parser:
            logger.warning("未配置正则解析器，无法执行回退")
            return partial_result

        try:
            logger.info(f"执行正则解析器回退: {file_path}")
            regex_units = self.regex_parser.parse_file(file_path, content)
            partial_result.fallback_units = regex_units
            partial_result.used_fallback = True

            # 计算覆盖率
            ts_count = len(partial_result.successful_units)
            regex_count = len(regex_units)
            total = ts_count + regex_count

            if total > 0:
                # 估算覆盖率：Tree-sitter 结果权重更高
                partial_result.coverage = (ts_count * 1.0 + regex_count * 0.8) / total

            logger.info(
                f"回退完成: Tree-sitter={ts_count}, 正则={regex_count}, "
                f"合并后={len(partial_result.all_units)}"
            )

        except Exception as e:
            logger.error(f"正则解析器回退失败: {e}")
            partial_result.add_error(
                error_type=ParseErrorType.UNKNOWN,
                line=0,
                column=0,
                message=f"正则解析器回退失败: {str(e)}",
            )

        return partial_result

    def parse_with_fallback(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str,
        content: str,
        ts_parse_func: Callable[['Tree', bytes, str], List['CodeUnit']],
    ) -> PartialParseResult:
        """带回退的解析

        Args:
            tree: Tree-sitter 语法树
            source: 源代码字节串
            file_path: 文件路径
            content: 文件内容
            ts_parse_func: Tree-sitter 解析函数

        Returns:
            PartialParseResult
        """
        result = PartialParseResult()

        # 分析语法树错误
        should_fallback, errors, error_ratio = self.analyze_tree(tree, source)
        result.errors = errors
        result.coverage = 1.0 - error_ratio

        # 尝试 Tree-sitter 解析
        try:
            ts_units = ts_parse_func(tree, source, file_path)
            result.successful_units = ts_units
            logger.debug(f"Tree-sitter 解析得到 {len(ts_units)} 个代码单元")
        except Exception as e:
            logger.error(f"Tree-sitter 解析失败: {e}")
            result.add_error(
                error_type=ParseErrorType.UNKNOWN,
                line=0,
                column=0,
                message=f"Tree-sitter 解析异常: {str(e)}",
            )
            should_fallback = True

        # 如果需要回退
        if should_fallback:
            result = self.execute_fallback(file_path, content, result)

        return result

    def _get_context(
        self,
        source: bytes,
        start_byte: int,
        end_byte: int
    ) -> str:
        """获取错误上下文

        Args:
            source: 源代码
            start_byte: 起始字节位置
            end_byte: 结束字节位置

        Returns:
            上下文文本
        """
        try:
            text = source.decode('utf-8', errors='replace')
            lines = text.split('\n')

            # 找到起始行
            current_pos = 0
            start_line = 0
            for i, line in enumerate(lines):
                if current_pos + len(line) >= start_byte:
                    start_line = i
                    break
                current_pos += len(line) + 1

            # 提取上下文
            context_start = max(0, start_line - self.context_lines)
            context_end = min(len(lines), start_line + self.context_lines + 1)

            context_lines = []
            for i in range(context_start, context_end):
                prefix = ">>> " if i == start_line else "    "
                context_lines.append(f"{prefix}{i+1}: {lines[i]}")

            return '\n'.join(context_lines)
        except Exception:
            return ""

    def should_skip_file(self, file_path: str, content: str) -> Tuple[bool, str]:
        """检查是否应该跳过此文件

        Args:
            file_path: 文件路径
            content: 文件内容

        Returns:
            (是否跳过, 原因)
        """
        # 检查文件大小
        max_size = 1024 * 1024  # 1MB
        if len(content) > max_size:
            return True, f"文件过大 ({len(content)} bytes)"

        # 检查是否为二进制文件
        try:
            content.encode('utf-8')
        except UnicodeError:
            return True, "可能是二进制文件"

        # 检查是否为生成的代码
        generated_markers = [
            "// Generated",
            "/* Generated",
            "# Generated",
            "AUTO-GENERATED",
            "DO NOT EDIT",
        ]
        first_lines = '\n'.join(content.split('\n')[:10])
        for marker in generated_markers:
            if marker.lower() in first_lines.lower():
                return True, f"生成的代码 (包含 '{marker}')"

        return False, ""
