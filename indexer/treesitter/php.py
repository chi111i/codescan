"""
PHP Tree-sitter 解析器

替代现有的正则表达式解析器，提供更准确的 PHP 代码解析。
支持 PHP 5.x - 8.x 语法。
"""

import logging
from pathlib import Path
from typing import List, Optional, Set

from ..models import CodeUnit, CodeUnitType, CodeSpan
from .base import TreeSitterParser, TreeSitterParserRegistry
from .loader import LanguageLoader
from .utils import (
    node_text,
    node_span,
    find_child_by_field,
    find_child_by_type,
    find_children_by_type,
    find_all_by_type,
    walk_tree,
)
from .generic.nodes import (
    GenericFunction,
    GenericClass,
    GenericCall,
    GenericParameter,
    GenericImport,
    Span,
    NodeKind,
    Visibility,
)
from .generic.converter import GenericASTConverter, ConverterRegistry

logger = logging.getLogger(__name__)

# 尝试导入 tree-sitter
try:
    from tree_sitter import Language, Node, Tree
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Language = None
    Node = None
    Tree = None


# PHP 危险函数列表
PHP_DANGEROUS_FUNCTIONS = {
    # RCE
    "eval", "assert", "create_function", "call_user_func", "call_user_func_array",
    "preg_replace",
    # 命令执行
    "exec", "shell_exec", "system", "passthru", "popen", "proc_open", "pcntl_exec",
    # 文件操作
    "file_get_contents", "file_put_contents", "fopen", "fread", "fwrite",
    "readfile", "file", "include", "include_once", "require", "require_once",
    "copy", "unlink", "rename", "move_uploaded_file",
    # SQL
    "mysql_query", "mysqli_query", "pg_query", "sqlite_query",
    # 反序列化
    "unserialize",
    # SSRF
    "curl_exec", "curl_init", "fsockopen", "pfsockopen",
}


@TreeSitterParserRegistry.register
class PHPTSParser(TreeSitterParser):
    """PHP Tree-sitter 解析器

    支持:
    - PHP 5.x - 8.x 语法
    - 类、接口、Trait
    - 命名空间
    - 闭包和箭头函数
    - 属性和注解 (PHP 8)
    """

    language_name = "php"
    extensions = [".php", ".phtml", ".php5", ".php7", ".php8"]

    def _load_language(self) -> Optional['Language']:
        """加载 PHP 语法"""
        return LanguageLoader.load("php")

    def _extract_functions(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        """提取函数定义"""
        units: List[CodeUnit] = []
        imports = self._extract_imports_list(tree.root_node, source)

        # 顶层函数
        for node in find_all_by_type(tree.root_node, "function_definition"):
            unit = self._parse_function_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        return units

    def _extract_classes(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        """提取类定义"""
        units: List[CodeUnit] = []
        imports = self._extract_imports_list(tree.root_node, source)

        # 类
        for node in find_all_by_type(tree.root_node, "class_declaration"):
            class_unit = self._parse_class_node(node, source, file_path, imports)
            if class_unit:
                units.append(class_unit)

            # 类中的方法
            class_name = self._get_node_name(node, source)
            body = find_child_by_field(node, "body")
            if body and class_name:
                for method_node in find_all_by_type(body, "method_declaration"):
                    method_unit = self._parse_method_node(
                        method_node, source, file_path, imports, class_name
                    )
                    if method_unit:
                        units.append(method_unit)

        # 接口
        for node in find_all_by_type(tree.root_node, "interface_declaration"):
            unit = self._parse_interface_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        # Trait
        for node in find_all_by_type(tree.root_node, "trait_declaration"):
            unit = self._parse_trait_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        return units

    def _extract_calls(self, node: 'Node', source: bytes) -> List[str]:
        """提取函数调用"""
        calls: Set[str] = set()

        # 普通函数调用
        for call_node in find_all_by_type(node, "function_call_expression"):
            func_node = find_child_by_field(call_node, "function")
            if func_node:
                call_name = node_text(func_node, source)
                calls.add(call_name)

        # 方法调用
        for call_node in find_all_by_type(node, "member_call_expression"):
            name_node = find_child_by_field(call_node, "name")
            obj_node = find_child_by_field(call_node, "object")
            if name_node:
                method_name = node_text(name_node, source)
                calls.add(method_name)
                if obj_node:
                    obj_text = node_text(obj_node, source)
                    calls.add(f"{obj_text}->{method_name}")

        # 静态调用
        for call_node in find_all_by_type(node, "scoped_call_expression"):
            scope_node = find_child_by_field(call_node, "scope")
            name_node = find_child_by_field(call_node, "name")
            if scope_node and name_node:
                scope = node_text(scope_node, source)
                method = node_text(name_node, source)
                calls.add(f"{scope}::{method}")
                calls.add(method)

        # 对象创建
        for new_node in find_all_by_type(node, "object_creation_expression"):
            for child in new_node.children:
                if child.type in ("name", "qualified_name"):
                    calls.add(node_text(child, source))
                    break

        return list(calls)

    def _parse_function_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        """解析函数节点"""
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        # 构建签名
        params_node = find_child_by_field(node, "parameters")
        params = node_text(params_node, source) if params_node else "()"

        # 返回类型
        return_type = ""
        for child in node.children:
            if child.type == ":":
                next_idx = node.children.index(child) + 1
                if next_idx < len(node.children):
                    return_type = node_text(node.children[next_idx], source)
                break

        signature = f"function {name}{params}"
        if return_type:
            signature += f": {return_type}"

        calls = self._extract_calls(node, source)

        # 检查是否包含危险函数
        dangerous_calls = [c for c in calls if c in PHP_DANGEROUS_FUNCTIONS]

        unit_id = CodeUnit.generate_id(file_path, name, span)

        return CodeUnit(
            id=unit_id,
            language=self.language_name,
            file_path=file_path,
            symbol=name,
            unit_type=CodeUnitType.FUNCTION,
            signature=signature,
            span=span,
            code=code,
            calls=calls,
            imports=imports,
            metadata={
                "dangerous_calls": dangerous_calls,
            } if dangerous_calls else {},
        )

    def _parse_class_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        """解析类节点"""
        name = self._get_node_name(node, source)
        if not name:
            return None

        span = node_span(node)
        code = node_text(node, source)

        # 检查修饰符
        is_abstract = any(c.type == "abstract_modifier" for c in node.children)
        is_final = any(c.type == "final_modifier" for c in node.children)

        # 获取基类
        base_class = None
        base_clause = find_child_by_type(node, "base_clause")
        if base_clause:
            for child in base_clause.children:
                if child.type == "name":
                    base_class = node_text(child, source)
                    break

        # 获取接口
        interfaces = []
        interface_clause = find_child_by_type(node, "class_interface_clause")
        if interface_clause:
            for child in interface_clause.children:
                if child.type == "name":
                    interfaces.append(node_text(child, source))

        # 构建签名
        prefix = ""
        if is_abstract:
            prefix = "abstract "
        if is_final:
            prefix = "final "

        signature = f"{prefix}class {name}"
        if base_class:
            signature += f" extends {base_class}"
        if interfaces:
            signature += f" implements {', '.join(interfaces)}"

        calls = self._extract_calls(node, source)

        # 检查是否是控制器
        unit_type = CodeUnitType.CLASS
        if "Controller" in name or "controller" in file_path.lower():
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
            calls=calls,
            imports=imports,
            metadata={
                "base": base_class,
                "interfaces": interfaces,
                "is_abstract": is_abstract,
                "is_final": is_final,
            },
        )

    def _parse_method_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
        class_name: str,
    ) -> Optional[CodeUnit]:
        """解析方法节点"""
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        # 获取修饰符
        visibility = "public"
        is_static = False
        is_abstract = False

        for child in node.children:
            if child.type == "visibility_modifier":
                visibility = node_text(child, source)
            elif child.type == "static_modifier":
                is_static = True
            elif child.type == "abstract_modifier":
                is_abstract = True

        # 构建签名
        params_node = find_child_by_field(node, "parameters")
        params = node_text(params_node, source) if params_node else "()"

        prefix = f"{visibility} "
        if is_static:
            prefix += "static "
        if is_abstract:
            prefix += "abstract "

        signature = f"{prefix}function {name}{params}"

        calls = self._extract_calls(node, source)

        # 检查是否是动作方法
        unit_type = CodeUnitType.METHOD
        if name.endswith("Action") or name.endswith("action"):
            unit_type = CodeUnitType.HANDLER

        unit_id = CodeUnit.generate_id(file_path, f"{class_name}::{name}", span)

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
            imports=imports,
            metadata={
                "visibility": visibility,
                "is_static": is_static,
                "is_abstract": is_abstract,
            },
        )

    def _parse_interface_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        """解析接口节点"""
        name = self._get_node_name(node, source)
        if not name:
            return None

        span = node_span(node)
        code = node_text(node, source)

        signature = f"interface {name}"

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
            imports=imports,
            metadata={"is_interface": True},
        )

    def _parse_trait_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        """解析 Trait 节点"""
        name = self._get_node_name(node, source)
        if not name:
            return None

        span = node_span(node)
        code = node_text(node, source)

        signature = f"trait {name}"
        calls = self._extract_calls(node, source)

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
            calls=calls,
            imports=imports,
            metadata={"is_trait": True},
        )

    def _get_node_name(self, node: 'Node', source: bytes) -> Optional[str]:
        """获取节点名称"""
        name_node = find_child_by_field(node, "name")
        if name_node:
            return node_text(name_node, source)
        return None

    def _extract_imports_list(self, node: 'Node', source: bytes) -> List[str]:
        """提取导入列表"""
        imports: List[str] = []

        # use 语句
        for use_node in find_all_by_type(node, "namespace_use_declaration"):
            for child in walk_tree(use_node):
                if child.type in ("name", "qualified_name"):
                    imports.append(node_text(child, source))

        # require/include
        for include_type in ("include_expression", "include_once_expression",
                            "require_expression", "require_once_expression"):
            for inc_node in find_all_by_type(node, include_type):
                for child in inc_node.children:
                    if child.type == "string":
                        path = node_text(child, source).strip("'\"")
                        imports.append(path)

        return imports


# ============================================================
# Generic AST 转换器
# ============================================================

@ConverterRegistry.register
class PHPConverter(GenericASTConverter):
    """PHP Generic AST 转换器"""

    language_name = "php"

    def get_function_node_types(self) -> List[str]:
        return [
            "function_definition",
            "method_declaration",
            "anonymous_function_creation_expression",
            "arrow_function",
        ]

    def get_class_node_types(self) -> List[str]:
        return [
            "class_declaration",
            "interface_declaration",
            "trait_declaration",
            "enum_declaration",
        ]

    def get_call_node_types(self) -> List[str]:
        return [
            "function_call_expression",
            "member_call_expression",
            "scoped_call_expression",
            "object_creation_expression",
        ]

    def convert_function(self, node: 'Node') -> Optional[GenericFunction]:
        """转换函数节点"""
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<anonymous>"

        # 提取参数
        params = []
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = self.extract_parameters(params_node)

        # 提取调用
        calls = self.extract_calls_from_node(node)

        # 获取可见性
        visibility = Visibility.PUBLIC
        is_static = False
        for child in node.children:
            if child.type == "visibility_modifier":
                vis_text = self.get_node_text(child).lower()
                if vis_text == "private":
                    visibility = Visibility.PRIVATE
                elif vis_text == "protected":
                    visibility = Visibility.PROTECTED
            elif child.type == "static_modifier":
                is_static = True

        return GenericFunction(
            kind=NodeKind.FUNCTION if node.type == "function_definition" else NodeKind.METHOD,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
            parameters=params,
            calls=calls,
            visibility=visibility,
            is_static=is_static,
        )

    def convert_class(self, node: 'Node') -> Optional[GenericClass]:
        """转换类节点"""
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<anonymous>"

        # 获取基类
        bases = []
        for child in node.children:
            if child.type == "base_clause":
                for c in child.children:
                    if c.type == "name":
                        bases.append(self.get_node_text(c))

        # 获取接口
        for child in node.children:
            if child.type == "class_interface_clause":
                for c in child.children:
                    if c.type == "name":
                        bases.append(self.get_node_text(c))

        is_interface = node.type == "interface_declaration"
        is_abstract = any(c.type == "abstract_modifier" for c in node.children)

        return GenericClass(
            kind=NodeKind.INTERFACE if is_interface else NodeKind.CLASS,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
            bases=bases,
            is_abstract=is_abstract,
            is_interface=is_interface,
        )

    def convert_call(self, node: 'Node') -> Optional[GenericCall]:
        """转换调用节点"""
        full_name = self.extract_full_call_name(node)
        parts = full_name.replace("::", "->").split("->")

        if len(parts) >= 2:
            receiver = "->".join(parts[:-1])
            callee = parts[-1]
        else:
            receiver = None
            callee = full_name

        is_constructor = node.type == "object_creation_expression"
        is_static = node.type == "scoped_call_expression"

        return GenericCall(
            kind=NodeKind.CALL,
            name=callee,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
            callee=callee,
            receiver=receiver,
            full_name=full_name,
            is_constructor=is_constructor,
            is_static=is_static,
        )

    def convert_import(self, node: 'Node') -> Optional[GenericImport]:
        """转换导入节点"""
        names = []
        for child in node.children:
            if child.type in ("name", "qualified_name"):
                names.append(self.get_node_text(child))

        if not names:
            return None

        return GenericImport(
            module=names[0],
            names=names,
            span=self.get_node_span(node),
        )

    def extract_full_call_name(self, node: 'Node') -> str:
        """提取完整调用名"""
        if node.type == "function_call_expression":
            func = node.child_by_field_name("function")
            return self.get_node_text(func) if func else ""

        if node.type == "member_call_expression":
            obj = node.child_by_field_name("object")
            name = node.child_by_field_name("name")
            obj_text = self.get_node_text(obj) if obj else ""
            name_text = self.get_node_text(name) if name else ""
            return f"{obj_text}->{name_text}"

        if node.type == "scoped_call_expression":
            scope = node.child_by_field_name("scope")
            name = node.child_by_field_name("name")
            scope_text = self.get_node_text(scope) if scope else ""
            name_text = self.get_node_text(name) if name else ""
            return f"{scope_text}::{name_text}"

        if node.type == "object_creation_expression":
            for child in node.children:
                if child.type in ("name", "qualified_name"):
                    return self.get_node_text(child)

        return self.get_node_text(node)

    def extract_parameters(self, params_node: 'Node') -> List[GenericParameter]:
        """提取参数列表"""
        params = []
        for child in params_node.children:
            if child.type == "simple_parameter":
                name_node = child.child_by_field_name("name")
                if name_node:
                    name = self.get_node_text(name_node).lstrip("$")
                    type_node = child.child_by_field_name("type")
                    type_ann = self.get_node_text(type_node) if type_node else None
                    params.append(GenericParameter(
                        name=name,
                        type_annotation=type_ann,
                    ))
            elif child.type == "variadic_parameter":
                name_node = child.child_by_field_name("name")
                if name_node:
                    params.append(GenericParameter(
                        name=self.get_node_text(name_node).lstrip("$"),
                        is_variadic=True,
                    ))
        return params
