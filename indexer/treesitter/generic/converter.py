"""
Generic AST 转换器

定义从语言特定 AST 到 Generic AST 的转换接口。
每种语言需要实现自己的转换器。
"""

import logging
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any

from .nodes import (
    GenericNode,
    GenericFunction,
    GenericClass,
    GenericCall,
    GenericImport,
    GenericParameter,
    Span,
    NodeKind,
)

logger = logging.getLogger(__name__)

# 尝试导入 tree-sitter
try:
    from tree_sitter import Node, Tree
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = None
    Tree = None


class GenericASTConverter(ABC):
    """Generic AST 转换器基类

    语言特定 AST 到 Generic AST 的转换器抽象基类。
    每种语言需要实现自己的转换器，将 Tree-sitter 节点
    转换为通用的 GenericNode 表示。

    这种设计借鉴了 Semgrep 的 Generic AST 架构，
    使得跨语言规则编写成为可能。
    """

    language_name: str = ""

    def __init__(self):
        """初始化转换器"""
        self._source: bytes = b""
        self._file_path: str = ""

    def set_context(self, source: bytes, file_path: str) -> None:
        """设置转换上下文

        Args:
            source: 源代码字节串
            file_path: 文件路径
        """
        self._source = source
        self._file_path = file_path

    def get_node_text(self, node: 'Node') -> str:
        """获取节点文本

        Args:
            node: Tree-sitter 节点

        Returns:
            节点对应的文本
        """
        return self._source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

    def get_node_span(self, node: 'Node') -> Span:
        """获取节点位置

        Args:
            node: Tree-sitter 节点

        Returns:
            Span 对象
        """
        return Span(
            start_line=node.start_point[0] + 1,
            start_column=node.start_point[1],
            end_line=node.end_point[0] + 1,
            end_column=node.end_point[1],
            start_byte=node.start_byte,
            end_byte=node.end_byte,
        )

    @abstractmethod
    def convert_function(self, node: 'Node') -> Optional[GenericFunction]:
        """将语言特定的函数节点转换为 GenericFunction

        Args:
            node: Tree-sitter 函数节点

        Returns:
            GenericFunction 对象，转换失败返回 None
        """
        pass

    @abstractmethod
    def convert_class(self, node: 'Node') -> Optional[GenericClass]:
        """将语言特定的类节点转换为 GenericClass

        Args:
            node: Tree-sitter 类节点

        Returns:
            GenericClass 对象，转换失败返回 None
        """
        pass

    @abstractmethod
    def convert_call(self, node: 'Node') -> Optional[GenericCall]:
        """将语言特定的调用节点转换为 GenericCall

        Args:
            node: Tree-sitter 调用节点

        Returns:
            GenericCall 对象，转换失败返回 None
        """
        pass

    @abstractmethod
    def convert_import(self, node: 'Node') -> Optional[GenericImport]:
        """将语言特定的导入节点转换为 GenericImport

        Args:
            node: Tree-sitter 导入节点

        Returns:
            GenericImport 对象，转换失败返回 None
        """
        pass

    @abstractmethod
    def extract_full_call_name(self, node: 'Node') -> str:
        """提取完整的调用名称

        如 os.system, obj.method, Class.staticMethod

        Args:
            node: 调用表达式节点

        Returns:
            完整限定名
        """
        pass

    @abstractmethod
    def get_function_node_types(self) -> List[str]:
        """获取函数节点类型列表

        Returns:
            该语言中表示函数的节点类型列表
        """
        pass

    @abstractmethod
    def get_class_node_types(self) -> List[str]:
        """获取类节点类型列表

        Returns:
            该语言中表示类的节点类型列表
        """
        pass

    @abstractmethod
    def get_call_node_types(self) -> List[str]:
        """获取调用节点类型列表

        Returns:
            该语言中表示调用的节点类型列表
        """
        pass

    def convert_tree(self, tree: 'Tree', source: bytes, file_path: str) -> List[GenericNode]:
        """转换整棵语法树

        Args:
            tree: Tree-sitter 语法树
            source: 源代码
            file_path: 文件路径

        Returns:
            所有顶层 GenericNode 列表
        """
        self.set_context(source, file_path)
        results: List[GenericNode] = []
        self._visit_node(tree.root_node, results)
        return results

    def _visit_node(self, node: 'Node', results: List[GenericNode]) -> None:
        """递归访问节点

        Args:
            node: 当前节点
            results: 结果列表
        """
        generic_node = self._try_convert(node)
        if generic_node:
            results.append(generic_node)
        else:
            # 如果当前节点无法转换，继续访问子节点
            for child in node.children:
                self._visit_node(child, results)

    def _try_convert(self, node: 'Node') -> Optional[GenericNode]:
        """尝试将节点转换为 GenericNode

        Args:
            node: Tree-sitter 节点

        Returns:
            转换后的 GenericNode，如果不是支持的类型返回 None
        """
        node_type = node.type

        # 尝试转换为函数
        if node_type in self.get_function_node_types():
            return self.convert_function(node)

        # 尝试转换为类
        if node_type in self.get_class_node_types():
            return self.convert_class(node)

        # 调用节点通常在函数内部处理，不单独转换为顶层节点
        return None

    def extract_calls_from_node(self, node: 'Node') -> List[GenericCall]:
        """从节点中提取所有函数调用

        Args:
            node: Tree-sitter 节点

        Returns:
            GenericCall 列表
        """
        calls: List[GenericCall] = []
        call_types = self.get_call_node_types()

        def visit(n: 'Node'):
            if n.type in call_types:
                call = self.convert_call(n)
                if call:
                    calls.append(call)
            for child in n.children:
                visit(child)

        visit(node)
        return calls

    def extract_parameters(self, params_node: 'Node') -> List[GenericParameter]:
        """从参数列表节点提取参数

        子类可以重写此方法以处理语言特定的参数语法。

        Args:
            params_node: 参数列表节点

        Returns:
            GenericParameter 列表
        """
        # 默认实现，子类应该重写
        return []


class ConverterRegistry:
    """转换器注册表

    管理所有语言的 GenericASTConverter。
    """

    _converters: Dict[str, type] = {}
    _instances: Dict[str, GenericASTConverter] = {}

    @classmethod
    def register(cls, converter_class: type) -> type:
        """注册转换器类

        可以作为装饰器使用：
            @ConverterRegistry.register
            class JavaScriptConverter(GenericASTConverter):
                ...
        """
        if not hasattr(converter_class, 'language_name') or not converter_class.language_name:
            raise ValueError(f"转换器类 {converter_class.__name__} 未设置 language_name")

        cls._converters[converter_class.language_name] = converter_class
        logger.debug(f"已注册 Generic AST 转换器: {converter_class.language_name}")
        return converter_class

    @classmethod
    def get(cls, language: str) -> Optional[GenericASTConverter]:
        """获取指定语言的转换器实例"""
        if language in cls._instances:
            return cls._instances[language]

        converter_class = cls._converters.get(language)
        if converter_class is None:
            return None

        try:
            instance = converter_class()
            cls._instances[language] = instance
            return instance
        except Exception as e:
            logger.error(f"创建转换器实例失败 ({language}): {e}")
            return None

    @classmethod
    def list_languages(cls) -> List[str]:
        """列出所有已注册的语言"""
        return list(cls._converters.keys())

    @classmethod
    def clear(cls) -> None:
        """清空注册表（主要用于测试）"""
        cls._converters.clear()
        cls._instances.clear()
