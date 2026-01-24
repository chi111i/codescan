"""
Tree-sitter 查询引擎

负责管理和执行 .scm 查询文件。
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable

logger = logging.getLogger(__name__)

# 尝试导入 tree-sitter
try:
    from tree_sitter import Language, Node, Query
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Language = None
    Node = None
    Query = None


class QueryEngine:
    """查询引擎

    管理 .scm 查询文件的加载、缓存和执行。
    支持按功能分类的查询组织方式。
    """

    def __init__(self, language: 'Language', queries_dir: Optional[Path] = None):
        """初始化查询引擎

        Args:
            language: Tree-sitter Language 对象
            queries_dir: 查询文件目录
        """
        if not TREE_SITTER_AVAILABLE:
            raise RuntimeError("tree-sitter 未安装")

        self.language = language
        self.queries_dir = queries_dir
        self._queries: Dict[str, 'Query'] = {}
        self._query_sources: Dict[str, str] = {}

    def load_query(self, name: str, source: Optional[str] = None) -> bool:
        """加载查询

        Args:
            name: 查询名称（如 "functions", "classes"）
            source: 查询源码，如果不提供则从文件加载

        Returns:
            是否加载成功
        """
        if source is None:
            # 从文件加载
            if self.queries_dir is None:
                logger.error("未设置查询目录")
                return False

            query_path = self.queries_dir / f"{name}.scm"
            if not query_path.exists():
                logger.warning(f"查询文件不存在: {query_path}")
                return False

            try:
                with open(query_path, 'r', encoding='utf-8') as f:
                    source = f.read()
            except Exception as e:
                logger.error(f"读取查询文件失败: {e}")
                return False

        try:
            self._queries[name] = self.language.query(source)
            self._query_sources[name] = source
            logger.debug(f"已加载查询: {name}")
            return True
        except Exception as e:
            logger.error(f"编译查询失败 ({name}): {e}")
            return False

    def load_all_queries(self) -> int:
        """加载目录下的所有查询文件

        Returns:
            成功加载的查询数量
        """
        if self.queries_dir is None or not self.queries_dir.exists():
            return 0

        count = 0
        for query_path in self.queries_dir.glob("*.scm"):
            name = query_path.stem
            if self.load_query(name):
                count += 1

        return count

    def execute(
        self,
        name: str,
        node: 'Node'
    ) -> List[Tuple['Node', str]]:
        """执行查询

        Args:
            name: 查询名称
            node: 要查询的节点

        Returns:
            (节点, 捕获名称) 元组列表
        """
        if name not in self._queries:
            if not self.load_query(name):
                return []

        try:
            return self._queries[name].captures(node)
        except Exception as e:
            logger.error(f"执行查询失败 ({name}): {e}")
            return []

    def execute_with_callback(
        self,
        name: str,
        node: 'Node',
        callback: Callable[['Node', str], None]
    ) -> int:
        """执行查询并对每个结果调用回调

        Args:
            name: 查询名称
            node: 要查询的节点
            callback: 回调函数，接收 (节点, 捕获名称)

        Returns:
            处理的结果数量
        """
        captures = self.execute(name, node)
        for captured_node, capture_name in captures:
            callback(captured_node, capture_name)
        return len(captures)

    def get_captures_by_name(
        self,
        name: str,
        node: 'Node',
        capture_name: str
    ) -> List['Node']:
        """获取指定捕获名称的所有节点

        Args:
            name: 查询名称
            node: 要查询的节点
            capture_name: 捕获名称（如 "function.name"）

        Returns:
            匹配的节点列表
        """
        captures = self.execute(name, node)
        return [n for n, cn in captures if cn == capture_name]

    def group_captures(
        self,
        name: str,
        node: 'Node'
    ) -> Dict[str, List['Node']]:
        """按捕获名称分组查询结果

        Args:
            name: 查询名称
            node: 要查询的节点

        Returns:
            捕获名称 -> 节点列表 的字典
        """
        captures = self.execute(name, node)
        groups: Dict[str, List['Node']] = {}

        for captured_node, capture_name in captures:
            if capture_name not in groups:
                groups[capture_name] = []
            groups[capture_name].append(captured_node)

        return groups

    def has_query(self, name: str) -> bool:
        """检查是否已加载指定查询

        Args:
            name: 查询名称

        Returns:
            是否已加载
        """
        return name in self._queries

    def list_queries(self) -> List[str]:
        """列出所有已加载的查询名称

        Returns:
            查询名称列表
        """
        return list(self._queries.keys())

    def get_query_source(self, name: str) -> Optional[str]:
        """获取查询源码

        Args:
            name: 查询名称

        Returns:
            查询源码
        """
        return self._query_sources.get(name)

    def clear(self) -> None:
        """清空所有已加载的查询"""
        self._queries.clear()
        self._query_sources.clear()


class QueryBuilder:
    """查询构建器

    帮助动态构建 Tree-sitter 查询字符串。
    """

    def __init__(self):
        self._patterns: List[str] = []

    def add_pattern(self, pattern: str) -> 'QueryBuilder':
        """添加查询模式

        Args:
            pattern: S-expression 模式字符串

        Returns:
            self（用于链式调用）
        """
        self._patterns.append(pattern)
        return self

    def add_function_pattern(
        self,
        node_type: str,
        name_field: str = "name",
        capture_name: str = "function"
    ) -> 'QueryBuilder':
        """添加函数匹配模式

        Args:
            node_type: 节点类型（如 "function_declaration"）
            name_field: 名称字段
            capture_name: 捕获名称

        Returns:
            self
        """
        pattern = f"""
({node_type}
  {name_field}: (identifier) @{capture_name}.name) @{capture_name}
"""
        return self.add_pattern(pattern.strip())

    def add_call_pattern(
        self,
        node_type: str = "call_expression",
        function_field: str = "function",
        capture_name: str = "call"
    ) -> 'QueryBuilder':
        """添加函数调用匹配模式

        Args:
            node_type: 节点类型
            function_field: 函数字段
            capture_name: 捕获名称

        Returns:
            self
        """
        pattern = f"""
({node_type}
  {function_field}: (identifier) @{capture_name}.name) @{capture_name}
"""
        return self.add_pattern(pattern.strip())

    def build(self) -> str:
        """构建最终的查询字符串

        Returns:
            完整的查询字符串
        """
        return "\n\n".join(self._patterns)

    def clear(self) -> 'QueryBuilder':
        """清空所有模式

        Returns:
            self
        """
        self._patterns.clear()
        return self
