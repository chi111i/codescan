"""
Tree-sitter 解析器基类

提供统一的 Tree-sitter 解析接口，所有语言解析器都需要继承此基类。
"""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Dict, Any, Type, Tuple

from ..models import CodeUnit, CodeUnitType, CodeSpan

logger = logging.getLogger(__name__)

# 尝试导入 tree-sitter，如果不可用则设置标志
try:
    import tree_sitter
    from tree_sitter import Language, Parser, Node, Tree
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Language = None
    Parser = None
    Node = None
    Tree = None
    logger.warning("tree-sitter 未安装，Tree-sitter 解析器将不可用")


class TreeSitterParser(ABC):
    """Tree-sitter 解析器抽象基类

    所有语言特定的 Tree-sitter 解析器都需要继承此类并实现抽象方法。

    Attributes:
        language_name: 语言名称（如 "javascript", "python"）
        extensions: 支持的文件扩展名列表
        parser: Tree-sitter Parser 实例
        language: Tree-sitter Language 实例
    """

    language_name: str = ""
    extensions: List[str] = []

    def __init__(self):
        """初始化解析器"""
        if not TREE_SITTER_AVAILABLE:
            raise RuntimeError("tree-sitter 未安装，无法使用 Tree-sitter 解析器")

        self.parser = Parser()
        self.language = self._load_language()
        if self.language:
            self.parser.language = self.language
        self._queries: Dict[str, Any] = {}
        self._queries_dir: Optional[Path] = None

    def is_available(self) -> bool:
        """检查解析器是否可用（语言是否成功加载）

        Returns:
            语言已加载且解析器就绪返回 True
        """
        return self.language is not None

    @abstractmethod
    def _load_language(self) -> Optional['Language']:
        """加载语言语法

        子类必须实现此方法，返回对应语言的 Language 对象。

        Returns:
            Language 对象，如果加载失败返回 None
        """
        pass

    @abstractmethod
    def _extract_functions(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        """从语法树中提取函数定义

        Args:
            tree: Tree-sitter 语法树
            source: 源代码字节串
            file_path: 文件路径

        Returns:
            CodeUnit 列表
        """
        pass

    @abstractmethod
    def _extract_classes(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        """从语法树中提取类定义

        Args:
            tree: Tree-sitter 语法树
            source: 源代码字节串
            file_path: 文件路径

        Returns:
            CodeUnit 列表
        """
        pass

    @abstractmethod
    def _extract_calls(self, node: 'Node', source: bytes) -> List[str]:
        """从节点中提取函数调用

        Args:
            node: Tree-sitter 节点
            source: 源代码字节串

        Returns:
            函数调用名称列表（包含完整限定名）
        """
        pass

    def parse(self, source: bytes) -> Optional['Tree']:
        """解析源代码

        Args:
            source: 源代码字节串

        Returns:
            Tree-sitter 语法树，解析失败返回 None
        """
        if not self.language:
            logger.error(f"语言 {self.language_name} 未正确加载")
            return None

        try:
            return self.parser.parse(source)
        except Exception as e:
            logger.error(f"解析失败: {e}")
            return None

    def parse_file(self, file_path: str, content: str = None) -> List[CodeUnit]:
        """解析文件，返回 CodeUnit 列表

        这是主要的解析入口点，会调用子类实现的具体提取方法。

        Args:
            file_path: 文件路径（相对于项目根目录）
            content: 文件内容（可选，如果不提供则从文件读取）

        Returns:
            CodeUnit 列表
        """
        if content is None:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
            except Exception as e:
                logger.error(f"无法读取文件 {file_path}: {e}")
                return []

        source = content.encode('utf-8')
        tree = self.parse(source)

        if tree is None:
            logger.warning(f"无法解析文件: {file_path}")
            return []

        units: List[CodeUnit] = []

        # 提取函数
        try:
            functions = self._extract_functions(tree, source, file_path)
            units.extend(functions)
        except Exception as e:
            logger.error(f"提取函数失败 ({file_path}): {e}")

        # 提取类
        try:
            classes = self._extract_classes(tree, source, file_path)
            units.extend(classes)
        except Exception as e:
            logger.error(f"提取类失败 ({file_path}): {e}")

        return units

    def parse_content(self, content: bytes, file_path: str = "<string>") -> List[CodeUnit]:
        """解析代码内容，返回 CodeUnit 列表

        Args:
            content: 代码内容（字节串）
            file_path: 虚拟文件路径

        Returns:
            CodeUnit 列表
        """
        tree = self.parse(content)

        if tree is None:
            logger.warning(f"无法解析内容")
            return []

        units: List[CodeUnit] = []

        # 提取函数
        try:
            functions = self._extract_functions(tree, content, file_path)
            units.extend(functions)
        except Exception as e:
            logger.error(f"提取函数失败: {e}")

        # 提取类
        try:
            classes = self._extract_classes(tree, content, file_path)
            units.extend(classes)
        except Exception as e:
            logger.error(f"提取类失败: {e}")

        return units

    def supports_file(self, file_path: str) -> bool:
        """检查是否支持该文件

        Args:
            file_path: 文件路径

        Returns:
            是否支持
        """
        return any(file_path.endswith(ext) for ext in self.extensions)

    def set_queries_dir(self, queries_dir: Path) -> None:
        """设置查询文件目录

        Args:
            queries_dir: 查询文件目录路径
        """
        self._queries_dir = queries_dir

    def load_query(self, query_name: str, query_path: Optional[Path] = None) -> bool:
        """加载 .scm 查询文件

        Args:
            query_name: 查询名称（如 "functions", "classes"）
            query_path: 查询文件路径，如果不指定则从默认目录加载

        Returns:
            是否加载成功
        """
        if not self.language:
            return False

        if query_path is None:
            if self._queries_dir is None:
                # 使用默认路径
                self._queries_dir = Path(__file__).parent / "queries" / self.language_name
            query_path = self._queries_dir / f"{query_name}.scm"

        if not query_path.exists():
            logger.warning(f"查询文件不存在: {query_path}")
            return False

        try:
            with open(query_path, 'r', encoding='utf-8') as f:
                query_source = f.read()
            self._queries[query_name] = self.language.query(query_source)
            logger.debug(f"已加载查询: {query_name} from {query_path}")
            return True
        except Exception as e:
            logger.error(f"加载查询失败 ({query_path}): {e}")
            return False

    def execute_query(
        self,
        query_name: str,
        node: 'Node'
    ) -> List[Tuple['Node', str]]:
        """执行查询，返回匹配结果

        Args:
            query_name: 查询名称
            node: 要查询的节点（通常是 tree.root_node）

        Returns:
            (节点, 捕获名称) 元组列表
        """
        if query_name not in self._queries:
            if not self.load_query(query_name):
                return []

        try:
            return self._queries[query_name].captures(node)
        except Exception as e:
            logger.error(f"执行查询失败 ({query_name}): {e}")
            return []

    def get_node_text(self, node: 'Node', source: bytes) -> str:
        """获取节点对应的源代码文本

        Args:
            node: Tree-sitter 节点
            source: 源代码字节串

        Returns:
            节点对应的文本
        """
        return source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

    def get_node_span(self, node: 'Node') -> CodeSpan:
        """获取节点的代码位置

        Args:
            node: Tree-sitter 节点

        Returns:
            CodeSpan 对象
        """
        return CodeSpan(
            start_line=node.start_point[0] + 1,  # Tree-sitter 使用 0-based 行号
            end_line=node.end_point[0] + 1,
            start_col=node.start_point[1],
            end_col=node.end_point[1],
        )

    def has_error_nodes(self, tree: 'Tree') -> bool:
        """检查语法树是否包含错误节点

        Args:
            tree: Tree-sitter 语法树

        Returns:
            是否包含错误节点
        """
        def check_node(node: 'Node') -> bool:
            if node.is_error or node.is_missing:
                return True
            for child in node.children:
                if check_node(child):
                    return True
            return False

        return check_node(tree.root_node)

    def count_error_nodes(self, tree: 'Tree') -> Tuple[int, int]:
        """统计语法树中的错误节点数量

        Args:
            tree: Tree-sitter 语法树

        Returns:
            (错误节点数, 总节点数) 元组
        """
        error_count = 0
        total_count = 0

        def count_node(node: 'Node'):
            nonlocal error_count, total_count
            total_count += 1
            if node.is_error or node.is_missing:
                error_count += 1
            for child in node.children:
                count_node(child)

        count_node(tree.root_node)
        return error_count, total_count


class TreeSitterParserRegistry:
    """Tree-sitter 解析器注册表

    管理所有已注册的 Tree-sitter 解析器，提供按语言或文件获取解析器的能力。
    """

    _parsers: Dict[str, Type[TreeSitterParser]] = {}
    _instances: Dict[str, TreeSitterParser] = {}

    @classmethod
    def register(cls, parser_class: Type[TreeSitterParser]) -> Type[TreeSitterParser]:
        """注册解析器类

        可以作为装饰器使用：
            @TreeSitterParserRegistry.register
            class JavaScriptTSParser(TreeSitterParser):
                ...

        Args:
            parser_class: 解析器类

        Returns:
            原始解析器类（用于装饰器链）
        """
        if not parser_class.language_name:
            raise ValueError(f"解析器类 {parser_class.__name__} 未设置 language_name")

        cls._parsers[parser_class.language_name] = parser_class
        logger.debug(f"已注册 Tree-sitter 解析器: {parser_class.language_name}")
        return parser_class

    @classmethod
    def get(cls, language: str) -> Optional[TreeSitterParser]:
        """获取指定语言的解析器实例

        Args:
            language: 语言名称

        Returns:
            解析器实例，如果不存在返回 None
        """
        if language in cls._instances:
            return cls._instances[language]

        parser_class = cls._parsers.get(language)
        if parser_class is None:
            return None

        try:
            instance = parser_class()
            cls._instances[language] = instance
            return instance
        except Exception as e:
            logger.error(f"创建解析器实例失败 ({language}): {e}")
            return None

    @classmethod
    def get_parser(cls, language: str) -> Optional[TreeSitterParser]:
        """获取指定语言的解析器实例（别名）

        Args:
            language: 语言名称

        Returns:
            解析器实例，如果不存在返回 None
        """
        return cls.get(language)

    @classmethod
    def get_for_file(cls, file_path: str) -> Optional[TreeSitterParser]:
        """根据文件扩展名获取解析器实例

        Args:
            file_path: 文件路径

        Returns:
            解析器实例，如果不存在返回 None
        """
        for language, parser_class in cls._parsers.items():
            # 检查扩展名
            if any(file_path.endswith(ext) for ext in parser_class.extensions):
                return cls.get(language)
        return None

    @classmethod
    def list_languages(cls) -> List[str]:
        """列出所有已注册的语言

        Returns:
            语言名称列表
        """
        return list(cls._parsers.keys())

    @classmethod
    def is_available(cls, language: str) -> bool:
        """检查指定语言的解析器是否可用

        Args:
            language: 语言名称

        Returns:
            是否可用
        """
        return language in cls._parsers

    @classmethod
    def clear(cls) -> None:
        """清空所有注册的解析器（主要用于测试）"""
        cls._parsers.clear()
        cls._instances.clear()
