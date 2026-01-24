"""
JavaScript/TypeScript Tree-sitter 解析器

替代现有的正则表达式解析器，提供更准确的 JS/TS 代码解析。
支持 ES6+、JSX、TSX 语法。
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


@TreeSitterParserRegistry.register
class JavaScriptTSParser(TreeSitterParser):
    """JavaScript Tree-sitter 解析器

    支持:
    - ES6+ 语法
    - 函数声明、箭头函数、生成器
    - 类、方法、字段
    - 模块导入导出
    - JSX (React)
    """

    language_name = "javascript"
    extensions = [".js", ".jsx", ".mjs", ".cjs"]

    def _load_language(self) -> Optional['Language']:
        """加载 JavaScript 语法"""
        return LanguageLoader.load("javascript")

    def _extract_functions(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        """提取函数定义"""
        units: List[CodeUnit] = []
        imports = self._extract_imports_list(tree.root_node, source)

        # 函数声明
        for node in find_all_by_type(tree.root_node, "function_declaration"):
            unit = self._parse_function_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        # 生成器函数
        for node in find_all_by_type(tree.root_node, "generator_function_declaration"):
            unit = self._parse_function_node(node, source, file_path, imports, is_generator=True)
            if unit:
                units.append(unit)

        # 箭头函数（作为变量声明）
        for node in find_all_by_type(tree.root_node, "lexical_declaration"):
            unit = self._parse_arrow_function(node, source, file_path, imports)
            if unit:
                units.append(unit)

        for node in find_all_by_type(tree.root_node, "variable_declaration"):
            unit = self._parse_arrow_function(node, source, file_path, imports)
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

        for node in find_all_by_type(tree.root_node, "class_declaration"):
            # 解析类
            class_unit = self._parse_class_node(node, source, file_path, imports)
            if class_unit:
                units.append(class_unit)

            # 解析类中的方法
            class_name = self._get_node_name(node, source)
            body = find_child_by_field(node, "body")
            if body and class_name:
                for method_node in find_children_by_type(body, "method_definition"):
                    method_unit = self._parse_method_node(
                        method_node, source, file_path, imports, class_name
                    )
                    if method_unit:
                        units.append(method_unit)

        return units

    def _extract_calls(self, node: 'Node', source: bytes) -> List[str]:
        """提取函数调用"""
        calls: Set[str] = set()

        for call_node in find_all_by_type(node, "call_expression"):
            func_node = find_child_by_field(call_node, "function")
            if func_node:
                call_name = self._extract_call_name(func_node, source)
                if call_name:
                    calls.add(call_name)
                    # 添加短名
                    if '.' in call_name:
                        calls.add(call_name.split('.')[-1])

        # new 表达式
        for new_node in find_all_by_type(node, "new_expression"):
            constructor = find_child_by_field(new_node, "constructor")
            if constructor:
                call_name = self._extract_call_name(constructor, source)
                if call_name:
                    calls.add(call_name)

        return list(calls)

    def _extract_call_name(self, node: 'Node', source: bytes) -> str:
        """提取调用名称（完整限定名）"""
        if node.type == "identifier":
            return node_text(node, source)

        if node.type == "member_expression":
            parts = []
            current = node
            while current and current.type == "member_expression":
                prop = find_child_by_field(current, "property")
                if prop:
                    parts.append(node_text(prop, source))
                current = find_child_by_field(current, "object")

            if current:
                if current.type == "identifier":
                    parts.append(node_text(current, source))
                elif current.type == "this":
                    parts.append("this")

            return '.'.join(reversed(parts))

        return node_text(node, source)

    def _parse_function_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
        is_generator: bool = False,
    ) -> Optional[CodeUnit]:
        """解析函数节点"""
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        # 检查是否是 async
        is_async = any(child.type == "async" for child in node.children if not child.is_named)

        # 构建签名
        params_node = find_child_by_field(node, "parameters")
        params = node_text(params_node, source) if params_node else "()"

        prefix = ""
        if is_async:
            prefix = "async "
        if is_generator:
            prefix += "function* "
        else:
            prefix += "function "

        signature = f"{prefix}{name}{params}"

        # 提取调用
        calls = self._extract_calls(node, source)

        # 检查是否是处理器
        unit_type = CodeUnitType.FUNCTION
        handler_params = {"req", "res", "request", "response", "ctx", "context", "next"}
        if params_node:
            param_text = node_text(params_node, source).lower()
            if any(hp in param_text for hp in handler_params):
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
                "is_async": is_async,
                "is_generator": is_generator,
            },
        )

    def _parse_arrow_function(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        """解析箭头函数"""
        # 查找 variable_declarator
        declarators = find_children_by_type(node, "variable_declarator")
        if not declarators:
            return None

        declarator = declarators[0]
        name_node = find_child_by_field(declarator, "name")
        value_node = find_child_by_field(declarator, "value")

        if not name_node or not value_node:
            return None

        # 检查是否是箭头函数或函数表达式
        if value_node.type not in ("arrow_function", "function_expression"):
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        # 检查 async
        is_async = any(
            child.type == "async" for child in value_node.children if not child.is_named
        )

        # 构建签名
        params_node = find_child_by_field(value_node, "parameters")
        params = node_text(params_node, source) if params_node else "()"

        if value_node.type == "arrow_function":
            signature = f"const {name} = {'async ' if is_async else ''}{params} =>"
        else:
            signature = f"const {name} = {'async ' if is_async else ''}function{params}"

        calls = self._extract_calls(value_node, source)

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
            metadata={"is_async": is_async, "is_arrow": True},
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

        # 获取基类
        base_class = None
        heritage = find_child_by_type(node, "class_heritage")
        if heritage:
            extends = find_child_by_type(heritage, "extends_clause")
            if extends:
                for child in extends.children:
                    if child.type == "identifier":
                        base_class = node_text(child, source)
                        break

        signature = f"class {name}"
        if base_class:
            signature += f" extends {base_class}"

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
            metadata={"base": base_class} if base_class else {},
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

        # 检查修饰符
        is_async = any(child.type == "async" for child in node.children if not child.is_named)
        is_static = any(child.type == "static" for child in node.children if not child.is_named)
        is_getter = any(child.type == "get" for child in node.children if not child.is_named)
        is_setter = any(child.type == "set" for child in node.children if not child.is_named)

        params_node = find_child_by_field(node, "parameters")
        params = node_text(params_node, source) if params_node else "()"

        # 构建签名
        prefix = ""
        if is_static:
            prefix += "static "
        if is_async:
            prefix += "async "
        if is_getter:
            prefix += "get "
        if is_setter:
            prefix += "set "

        signature = f"{prefix}{name}{params}"

        calls = self._extract_calls(node, source)

        unit_id = CodeUnit.generate_id(file_path, f"{class_name}.{name}", span)

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
            imports=imports,
            metadata={
                "is_async": is_async,
                "is_static": is_static,
                "is_getter": is_getter,
                "is_setter": is_setter,
            },
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

        # ES6 imports
        for import_node in find_all_by_type(node, "import_statement"):
            source_node = find_child_by_field(import_node, "source")
            if source_node:
                module = node_text(source_node, source).strip("'\"")
                imports.append(module)

        # CommonJS require
        for call in find_all_by_type(node, "call_expression"):
            func = find_child_by_field(call, "function")
            if func and node_text(func, source) == "require":
                args = find_child_by_field(call, "arguments")
                if args and args.children:
                    for arg in args.children:
                        if arg.type == "string":
                            module = node_text(arg, source).strip("'\"")
                            imports.append(module)
                            break

        return imports


@TreeSitterParserRegistry.register
class TypeScriptTSParser(JavaScriptTSParser):
    """TypeScript Tree-sitter 解析器

    继承 JavaScript 解析器，添加 TypeScript 特定支持：
    - 类型注解
    - 接口
    - 泛型
    - 装饰器
    """

    language_name = "typescript"
    extensions = [".ts", ".tsx"]

    def _load_language(self) -> Optional['Language']:
        """加载 TypeScript 语法"""
        return LanguageLoader.load("typescript")


# ============================================================
# Generic AST 转换器
# ============================================================

@ConverterRegistry.register
class JavaScriptConverter(GenericASTConverter):
    """JavaScript Generic AST 转换器"""

    language_name = "javascript"

    def get_function_node_types(self) -> List[str]:
        return [
            "function_declaration",
            "generator_function_declaration",
            "arrow_function",
            "function_expression",
        ]

    def get_class_node_types(self) -> List[str]:
        return ["class_declaration", "class"]

    def get_call_node_types(self) -> List[str]:
        return ["call_expression", "new_expression"]

    def convert_function(self, node: 'Node') -> Optional[GenericFunction]:
        """转换函数节点"""
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<anonymous>"

        # 检查 async/generator
        is_async = any(c.type == "async" for c in node.children if not c.is_named)
        is_generator = node.type == "generator_function_declaration"

        # 提取参数
        params = []
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = self.extract_parameters(params_node)

        # 提取调用
        calls = self.extract_calls_from_node(node)

        return GenericFunction(
            kind=NodeKind.FUNCTION,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
            parameters=params,
            calls=calls,
            is_async=is_async,
            is_generator=is_generator,
        )

    def convert_class(self, node: 'Node') -> Optional[GenericClass]:
        """转换类节点"""
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<anonymous>"

        # 获取基类
        bases = []
        heritage = None
        for child in node.children:
            if child.type == "class_heritage":
                heritage = child
                break
        if heritage:
            for child in heritage.children:
                if child.type == "extends_clause":
                    for c in child.children:
                        if c.type == "identifier":
                            bases.append(self.get_node_text(c))

        return GenericClass(
            kind=NodeKind.CLASS,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
            bases=bases,
        )

    def convert_call(self, node: 'Node') -> Optional[GenericCall]:
        """转换调用节点"""
        if node.type == "new_expression":
            constructor = node.child_by_field_name("constructor")
            callee = self.extract_full_call_name(constructor) if constructor else ""
            return GenericCall(
                kind=NodeKind.CALL,
                name=callee,
                span=self.get_node_span(node),
                source_language=self.language_name,
                raw_node=node,
                callee=callee,
                is_constructor=True,
            )

        func_node = node.child_by_field_name("function")
        if not func_node:
            return None

        full_name = self.extract_full_call_name(func_node)
        parts = full_name.rsplit('.', 1)
        if len(parts) == 2:
            receiver, callee = parts
        else:
            receiver, callee = None, full_name

        return GenericCall(
            kind=NodeKind.CALL,
            name=callee,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
            callee=callee,
            receiver=receiver,
            full_name=full_name,
        )

    def convert_import(self, node: 'Node') -> Optional[GenericImport]:
        """转换导入节点"""
        source_node = node.child_by_field_name("source")
        if not source_node:
            return None

        module = self.get_node_text(source_node).strip("'\"")

        return GenericImport(
            module=module,
            span=self.get_node_span(node),
        )

    def extract_full_call_name(self, node: 'Node') -> str:
        """提取完整调用名"""
        if node.type == "identifier":
            return self.get_node_text(node)

        if node.type == "member_expression":
            parts = []
            current = node
            while current and current.type == "member_expression":
                prop = current.child_by_field_name("property")
                if prop:
                    parts.append(self.get_node_text(prop))
                current = current.child_by_field_name("object")

            if current:
                if current.type == "identifier":
                    parts.append(self.get_node_text(current))
                elif current.type == "this":
                    parts.append("this")

            return '.'.join(reversed(parts))

        return self.get_node_text(node)

    def extract_parameters(self, params_node: 'Node') -> List[GenericParameter]:
        """提取参数列表"""
        params = []
        for child in params_node.children:
            if child.type in ("identifier", "required_parameter", "optional_parameter"):
                name = self.get_node_text(child)
                # 去除类型注解部分
                if ":" in name:
                    name = name.split(":")[0].strip()
                params.append(GenericParameter(name=name))
            elif child.type == "rest_pattern":
                # ...args
                for c in child.children:
                    if c.type == "identifier":
                        params.append(GenericParameter(
                            name=self.get_node_text(c),
                            is_variadic=True
                        ))
        return params
