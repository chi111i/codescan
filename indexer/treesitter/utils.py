"""
Tree-sitter 工具函数

提供常用的节点操作和转换函数。
"""

import logging
from typing import Optional, List, Tuple, Iterator

from ..models import CodeSpan

logger = logging.getLogger(__name__)

# 尝试导入 tree-sitter
try:
    from tree_sitter import Node, Tree
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = None
    Tree = None


def node_text(node: 'Node', source: bytes) -> str:
    """获取节点对应的源代码文本

    Args:
        node: Tree-sitter 节点
        source: 源代码字节串

    Returns:
        节点对应的文本
    """
    return source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')


def get_node_text(node: 'Node', source: bytes) -> str:
    """获取节点对应的源代码文本（node_text 的别名）"""
    return node_text(node, source)


def node_span(node: 'Node') -> CodeSpan:
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


def position_to_line_col(source: bytes, byte_offset: int) -> Tuple[int, int]:
    """将字节偏移转换为行列位置

    Args:
        source: 源代码字节串
        byte_offset: 字节偏移

    Returns:
        (行号, 列号) 元组，行号从 1 开始
    """
    text = source[:byte_offset].decode('utf-8', errors='replace')
    lines = text.split('\n')
    line = len(lines)
    col = len(lines[-1]) if lines else 0
    return line, col


def find_child_by_type(node: 'Node', type_name: str) -> Optional['Node']:
    """查找指定类型的第一个子节点

    Args:
        node: 父节点
        type_name: 节点类型名称

    Returns:
        找到的子节点，未找到返回 None
    """
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def find_children_by_type(node: 'Node', type_name: str) -> List['Node']:
    """查找指定类型的所有子节点

    Args:
        node: 父节点
        type_name: 节点类型名称

    Returns:
        子节点列表
    """
    return [child for child in node.children if child.type == type_name]


def find_child_by_field(node: 'Node', field_name: str) -> Optional['Node']:
    """通过字段名查找子节点

    Args:
        node: 父节点
        field_name: 字段名称

    Returns:
        找到的子节点
    """
    return node.child_by_field_name(field_name)


def walk_tree(node: 'Node') -> Iterator['Node']:
    """深度优先遍历语法树

    Args:
        node: 起始节点

    Yields:
        遍历到的每个节点
    """
    yield node
    for child in node.children:
        yield from walk_tree(child)


def walk_tree_bfs(node: 'Node') -> Iterator['Node']:
    """广度优先遍历语法树

    Args:
        node: 起始节点

    Yields:
        遍历到的每个节点
    """
    queue = [node]
    while queue:
        current = queue.pop(0)
        yield current
        queue.extend(current.children)


def find_ancestor_by_type(node: 'Node', type_name: str) -> Optional['Node']:
    """查找指定类型的祖先节点

    Args:
        node: 起始节点
        type_name: 节点类型名称

    Returns:
        找到的祖先节点
    """
    current = node.parent
    while current:
        if current.type == type_name:
            return current
        current = current.parent
    return None


def find_all_by_type(node: 'Node', type_name: str) -> List['Node']:
    """递归查找所有指定类型的节点

    Args:
        node: 起始节点
        type_name: 节点类型名称

    Returns:
        节点列表
    """
    result = []
    for n in walk_tree(node):
        if n.type == type_name:
            result.append(n)
    return result


def get_named_children(node: 'Node') -> List['Node']:
    """获取所有命名子节点（排除匿名节点如括号、分号等）

    Args:
        node: 父节点

    Returns:
        命名子节点列表
    """
    return [child for child in node.children if child.is_named]


def is_inside_node_type(node: 'Node', type_name: str) -> bool:
    """检查节点是否在指定类型的节点内部

    Args:
        node: 要检查的节点
        type_name: 节点类型名称

    Returns:
        是否在指定类型节点内部
    """
    return find_ancestor_by_type(node, type_name) is not None


def get_node_path(node: 'Node') -> List[str]:
    """获取节点到根的路径

    Args:
        node: 节点

    Returns:
        节点类型路径列表
    """
    path = []
    current = node
    while current:
        path.append(current.type)
        current = current.parent
    return list(reversed(path))


def extract_identifier_chain(node: 'Node', source: bytes) -> str:
    """提取标识符链（如 a.b.c）

    适用于成员表达式等包含点号分隔的标识符链。

    Args:
        node: 节点
        source: 源代码

    Returns:
        标识符链字符串
    """
    if node.type == 'identifier':
        return node_text(node, source)

    if node.type in ('member_expression', 'field_expression', 'attribute'):
        parts = []
        current = node
        while current:
            if current.type == 'identifier':
                parts.append(node_text(current, source))
                break
            elif current.type in ('property_identifier', 'field_identifier'):
                parts.append(node_text(current, source))
            elif current.type in ('member_expression', 'field_expression', 'attribute'):
                # 获取属性名
                prop = find_child_by_field(current, 'property') or \
                       find_child_by_field(current, 'field') or \
                       find_child_by_field(current, 'attribute')
                if prop:
                    parts.append(node_text(prop, source))
                # 继续处理对象部分
                current = find_child_by_field(current, 'object') or \
                         find_child_by_field(current, 'value')
                continue
            current = current.children[0] if current.children else None

        return '.'.join(reversed(parts))

    return node_text(node, source)


def count_nodes(node: 'Node') -> int:
    """统计节点总数

    Args:
        node: 起始节点

    Returns:
        节点总数
    """
    count = 1
    for child in node.children:
        count += count_nodes(child)
    return count


def has_error_descendant(node: 'Node') -> bool:
    """检查节点或其后代是否包含错误

    Args:
        node: 节点

    Returns:
        是否包含错误
    """
    if node.is_error or node.is_missing:
        return True
    for child in node.children:
        if has_error_descendant(child):
            return True
    return False


def get_sibling_nodes(node: 'Node') -> Tuple[Optional['Node'], Optional['Node']]:
    """获取相邻节点

    Args:
        node: 节点

    Returns:
        (前一个节点, 后一个节点) 元组
    """
    return node.prev_sibling, node.next_sibling


def format_node_for_debug(node: 'Node', source: bytes, max_text_len: int = 50) -> str:
    """格式化节点信息用于调试

    Args:
        node: 节点
        source: 源代码
        max_text_len: 文本最大长度

    Returns:
        格式化的字符串
    """
    text = node_text(node, source)
    if len(text) > max_text_len:
        text = text[:max_text_len] + "..."
    text = text.replace('\n', '\\n')

    return (
        f"[{node.type}] "
        f"L{node.start_point[0]+1}:{node.start_point[1]}-"
        f"L{node.end_point[0]+1}:{node.end_point[1]} "
        f"'{text}'"
    )
