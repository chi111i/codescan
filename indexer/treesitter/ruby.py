"""
Ruby Tree-sitter 解析器

支持 Ruby 语法，包括：
- 类、模块
- 方法（def、块）
- Rails 控制器/路由识别
- 危险方法检测
"""

import logging
from pathlib import Path
from typing import List, Optional, Set, Dict, Any

from ..models import CodeUnit, CodeUnitType, CodeSpan
from .base import TreeSitterParser, TreeSitterParserRegistry
from .loader import LanguageLoader
from .utils import (
    node_text,
    node_span,
    find_child_by_field,
    find_child_by_type,
    find_all_by_type,
    walk_tree,
)
from .generic.nodes import (
    GenericFunction,
    GenericClass,
    GenericCall,
    GenericParameter,
    Span,
    NodeKind,
    Visibility,
)
from .generic.converter import GenericASTConverter, ConverterRegistry

logger = logging.getLogger(__name__)

try:
    from tree_sitter import Language, Node, Tree
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Language = None
    Node = None
    Tree = None


# Ruby 危险方法
RUBY_DANGEROUS_METHODS = {
    # 命令执行
    "system", "exec", "spawn", "`", "%x", "IO.popen",
    "Open3.popen3", "Open3.capture2", "Open3.capture3",
    # eval 类
    "eval", "instance_eval", "class_eval", "module_eval",
    "send", "__send__", "public_send",
    # 文件操作
    "File.open", "File.read", "File.write", "File.delete",
    "FileUtils.rm", "FileUtils.rm_rf",
    # 反序列化
    "Marshal.load", "YAML.load", "JSON.parse",
    # 网络
    "Net::HTTP.get", "open-uri", "HTTParty",
    "RestClient.get", "Faraday.get",
    # SQL (ActiveRecord)
    "where", "find_by_sql", "execute", "connection.execute",
    # 渲染
    "render", "render_inline", "html_safe", "raw",
}

# Rails 路由方法
RAILS_ROUTE_METHODS = {
    "get", "post", "put", "patch", "delete",
    "resources", "resource", "match", "root",
}


@TreeSitterParserRegistry.register
class RubyTSParser(TreeSitterParser):
    """Ruby Tree-sitter 解析器"""

    language_name = "ruby"
    extensions = [".rb", ".rake", ".gemspec"]

    def _load_language(self) -> Optional['Language']:
        return LanguageLoader.load("ruby")

    def _extract_functions(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        units: List[CodeUnit] = []

        # 顶层方法
        for node in find_all_by_type(tree.root_node, "method"):
            unit = self._parse_method_node(node, source, file_path)
            if unit:
                units.append(unit)

        # 单例方法 (self.method)
        for node in find_all_by_type(tree.root_node, "singleton_method"):
            unit = self._parse_singleton_method_node(node, source, file_path)
            if unit:
                units.append(unit)

        # 类/模块内的方法
        for class_node in self._find_class_or_module_nodes(tree.root_node):
            class_name = self._get_node_name(class_node, source)
            if not class_name:
                continue

            body = find_child_by_type(class_node, "body_statement")
            if body:
                for method_node in find_all_by_type(body, "method"):
                    unit = self._parse_method_node(
                        method_node, source, file_path, class_name
                    )
                    if unit:
                        units.append(unit)

                for method_node in find_all_by_type(body, "singleton_method"):
                    unit = self._parse_singleton_method_node(
                        method_node, source, file_path, class_name
                    )
                    if unit:
                        units.append(unit)

        return units

    def _extract_classes(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        units: List[CodeUnit] = []

        # 类
        for node in find_all_by_type(tree.root_node, "class"):
            unit = self._parse_class_node(node, source, file_path)
            if unit:
                units.append(unit)

        # 模块
        for node in find_all_by_type(tree.root_node, "module"):
            unit = self._parse_module_node(node, source, file_path)
            if unit:
                units.append(unit)

        return units

    def _find_class_or_module_nodes(self, root: 'Node') -> List['Node']:
        nodes = []
        nodes.extend(find_all_by_type(root, "class"))
        nodes.extend(find_all_by_type(root, "module"))
        return nodes

    def _extract_calls(self, node: 'Node', source: bytes) -> List[str]:
        calls: Set[str] = set()

        # 方法调用
        for call_node in find_all_by_type(node, "call"):
            method = find_child_by_field(call_node, "method")
            receiver = find_child_by_field(call_node, "receiver")
            if method:
                method_name = node_text(method, source)
                if receiver:
                    receiver_text = node_text(receiver, source)
                    calls.add(f"{receiver_text}.{method_name}")
                else:
                    calls.add(method_name)

        # 标识符调用 (隐式方法调用)
        for id_node in find_all_by_type(node, "identifier"):
            # 只记录可能是方法调用的标识符
            parent = id_node.parent
            if parent and parent.type == "call":
                continue  # 已经在上面处理过
            calls.add(node_text(id_node, source))

        # 命令调用 (system "ls")
        for cmd_node in find_all_by_type(node, "command"):
            name_node = cmd_node.children[0] if cmd_node.children else None
            if name_node:
                calls.add(node_text(name_node, source))

        return list(calls)

    def _parse_method_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        class_name: Optional[str] = None,
    ) -> Optional[CodeUnit]:
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        # 获取参数
        params_node = find_child_by_field(node, "parameters")
        params = node_text(params_node, source) if params_node else ""

        # 检查可见性 (通过前面的 private/protected/public 调用)
        visibility = "public"  # Ruby 默认 public

        signature = f"def {name}{params}"

        calls = self._extract_calls(node, source)
        dangerous_calls = [c for c in calls if any(d in c for d in RUBY_DANGEROUS_METHODS)]

        # 检查是否是 Rails 控制器动作
        unit_type = CodeUnitType.METHOD
        if class_name and "Controller" in class_name:
            unit_type = CodeUnitType.HANDLER

        symbol = f"{class_name}#{name}" if class_name else name
        unit_id = CodeUnit.generate_id(file_path, symbol, span)

        return CodeUnit(
            id=unit_id,
            language=self.language_name,
            file_path=file_path,
            symbol=name,
            unit_type=unit_type,
            signature=signature,
            span=span,
            code=code,
            calls=calls,
            parent_class=class_name,
            imports=[],
            metadata={
                "visibility": visibility,
                "dangerous_calls": dangerous_calls,
            } if dangerous_calls else {"visibility": visibility},
        )

    def _parse_singleton_method_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        class_name: Optional[str] = None,
    ) -> Optional[CodeUnit]:
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        params_node = find_child_by_field(node, "parameters")
        params = node_text(params_node, source) if params_node else ""

        signature = f"def self.{name}{params}"
        calls = self._extract_calls(node, source)

        symbol = f"{class_name}.{name}" if class_name else f"self.{name}"
        unit_id = CodeUnit.generate_id(file_path, symbol, span)

        return CodeUnit(
            id=unit_id,
            language=self.language_name,
            file_path=file_path,
            symbol=name,
            unit_type=CodeUnitType.METHOD,
            signature=signature,
            span=span,
            code=code,
            calls=calls,
            parent_class=class_name,
            imports=[],
            metadata={"is_singleton": True},
        )

    def _parse_class_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
    ) -> Optional[CodeUnit]:
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        # 获取父类
        superclass_node = find_child_by_field(node, "superclass")
        superclass = node_text(superclass_node, source) if superclass_node else None

        signature = f"class {name}"
        if superclass:
            signature += f" < {superclass}"

        # 检查是否是 Rails 控制器
        unit_type = CodeUnitType.CLASS
        if "Controller" in name or (superclass and "Controller" in superclass):
            unit_type = CodeUnitType.HANDLER

        unit_id = CodeUnit.generate_id(file_path, name, span)

        return CodeUnit(
            id=unit_id,
            language=self.language_name,
            file_path=file_path,
            symbol=name,
            unit_type=unit_type,
            signature=signature,
            span=span,
            code=code,
            calls=[],
            imports=[],
            metadata={
                "superclass": superclass,
                "is_controller": "Controller" in name,
            } if superclass or "Controller" in name else {},
        )

    def _parse_module_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
    ) -> Optional[CodeUnit]:
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        signature = f"module {name}"
        unit_id = CodeUnit.generate_id(file_path, name, span)

        return CodeUnit(
            id=unit_id,
            language=self.language_name,
            file_path=file_path,
            symbol=name,
            unit_type=CodeUnitType.CLASS,
            signature=signature,
            span=span,
            code=code,
            calls=[],
            imports=[],
            metadata={"is_module": True},
        )

    def _get_node_name(self, node: 'Node', source: bytes) -> Optional[str]:
        name_node = find_child_by_field(node, "name")
        return node_text(name_node, source) if name_node else None


@ConverterRegistry.register
class RubyConverter(GenericASTConverter):
    """Ruby Generic AST 转换器"""

    language_name = "ruby"

    def get_function_node_types(self) -> List[str]:
        return ["method", "singleton_method", "lambda", "block"]

    def get_class_node_types(self) -> List[str]:
        return ["class", "module"]

    def get_call_node_types(self) -> List[str]:
        return ["call", "command", "command_call"]

    def convert_function(self, node: 'Node') -> Optional[GenericFunction]:
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<block>"

        kind = NodeKind.METHOD
        if node.type == "singleton_method":
            kind = NodeKind.STATIC_METHOD
        elif node.type in ("lambda", "block"):
            kind = NodeKind.LAMBDA

        return GenericFunction(
            kind=kind,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
        )

    def convert_class(self, node: 'Node') -> Optional[GenericClass]:
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<anonymous>"

        kind = NodeKind.CLASS
        if node.type == "module":
            kind = NodeKind.MODULE

        return GenericClass(
            kind=kind,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
        )

    def convert_call(self, node: 'Node') -> Optional[GenericCall]:
        method_node = node.child_by_field_name("method")
        receiver_node = node.child_by_field_name("receiver")

        method_name = self.get_node_text(method_node) if method_node else ""
        receiver = self.get_node_text(receiver_node) if receiver_node else ""

        full_name = f"{receiver}.{method_name}" if receiver else method_name

        return GenericCall(
            kind=NodeKind.CALL,
            name=method_name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
            callee=method_name,
            full_name=full_name,
            receiver=receiver if receiver else None,
        )
