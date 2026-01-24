"""
Rust Tree-sitter 解析器

支持 Rust 语法，包括：
- 函数和方法
- 结构体、枚举、Trait
- impl 块
- 宏调用
- unsafe 块检测
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


# Rust 危险函数/宏
RUST_DANGEROUS_PATTERNS = {
    # Unsafe 操作
    "unsafe", "transmute", "from_raw", "as_ptr", "as_mut_ptr",
    # 命令执行
    "Command::new", "Command::output", "Command::spawn",
    "std::process::Command",
    # 文件操作
    "File::open", "File::create", "read_to_string", "write_all",
    "std::fs::read", "std::fs::write",
    # 网络
    "TcpStream::connect", "reqwest::get", "reqwest::Client",
    # 反序列化
    "serde_json::from_str", "serde_yaml::from_str",
    "bincode::deserialize",
    # FFI
    "extern", "CString", "CStr",
}


@TreeSitterParserRegistry.register
class RustTSParser(TreeSitterParser):
    """Rust Tree-sitter 解析器"""

    language_name = "rust"
    extensions = [".rs"]

    def _load_language(self) -> Optional['Language']:
        return LanguageLoader.load("rust")

    def _extract_functions(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        units: List[CodeUnit] = []
        imports = self._extract_imports_list(tree.root_node, source)

        # 顶层函数
        for node in find_all_by_type(tree.root_node, "function_item"):
            unit = self._parse_function_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        # impl 块中的方法
        for impl_node in find_all_by_type(tree.root_node, "impl_item"):
            impl_type = self._get_impl_type(impl_node, source)
            for method_node in find_all_by_type(impl_node, "function_item"):
                unit = self._parse_function_node(
                    method_node, source, file_path, imports, impl_type
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
        imports = self._extract_imports_list(tree.root_node, source)

        # 结构体
        for node in find_all_by_type(tree.root_node, "struct_item"):
            unit = self._parse_struct_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        # 枚举
        for node in find_all_by_type(tree.root_node, "enum_item"):
            unit = self._parse_enum_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        # Trait
        for node in find_all_by_type(tree.root_node, "trait_item"):
            unit = self._parse_trait_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        return units

    def _extract_calls(self, node: 'Node', source: bytes) -> List[str]:
        calls: Set[str] = set()

        # 函数调用
        for call_node in find_all_by_type(node, "call_expression"):
            func_node = find_child_by_field(call_node, "function")
            if func_node:
                calls.add(node_text(func_node, source))

        # 宏调用
        for macro_node in find_all_by_type(node, "macro_invocation"):
            macro_name = find_child_by_field(macro_node, "macro")
            if macro_name:
                calls.add(node_text(macro_name, source) + "!")

        # 方法调用
        for method_node in find_all_by_type(node, "method_call_expression"):
            name_node = find_child_by_field(method_node, "name")
            if name_node:
                calls.add(node_text(name_node, source))

        return list(calls)

    def _parse_function_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
        impl_type: Optional[str] = None,
    ) -> Optional[CodeUnit]:
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        # 检查可见性
        visibility = "private"
        for child in node.children:
            if child.type == "visibility_modifier":
                visibility = "public"
                break

        # 检查 async/unsafe
        is_async = any(c.type == "async" for c in node.children)
        is_unsafe = any(c.type == "unsafe" for c in node.children)

        # 获取参数和返回类型
        params_node = find_child_by_field(node, "parameters")
        params = node_text(params_node, source) if params_node else "()"

        return_type = ""
        ret_node = find_child_by_field(node, "return_type")
        if ret_node:
            return_type = node_text(ret_node, source)

        # 构建签名
        prefix = ""
        if visibility == "public":
            prefix = "pub "
        if is_async:
            prefix += "async "
        if is_unsafe:
            prefix += "unsafe "

        signature = f"{prefix}fn {name}{params}"
        if return_type:
            signature += f" {return_type}"

        calls = self._extract_calls(node, source)
        dangerous_calls = [c for c in calls if any(d in c for d in RUST_DANGEROUS_PATTERNS)]

        unit_type = CodeUnitType.METHOD if impl_type else CodeUnitType.FUNCTION

        symbol = f"{impl_type}::{name}" if impl_type else name
        unit_id = CodeUnit.generate_id(file_path, symbol, span)

        return CodeUnit(
            id=unit_id,
            language=self.language_name,
            file_path=file_path,
            symbol=name,
            unit_type=unit_type,
            signature=signature.strip(),
            span=span,
            code=code,
            calls=calls,
            parent_class=impl_type,
            imports=imports,
            metadata={
                "visibility": visibility,
                "is_async": is_async,
                "is_unsafe": is_unsafe,
                "dangerous_calls": dangerous_calls,
            } if dangerous_calls or is_unsafe else {
                "visibility": visibility,
            },
        )

    def _parse_struct_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        visibility = "private"
        for child in node.children:
            if child.type == "visibility_modifier":
                visibility = "public"
                break

        signature = f"{'pub ' if visibility == 'public' else ''}struct {name}"
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
            metadata={"is_struct": True, "visibility": visibility},
        )

    def _parse_enum_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        signature = f"enum {name}"
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
            metadata={"is_enum": True},
        )

    def _parse_trait_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        signature = f"trait {name}"
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
            metadata={"is_trait": True},
        )

    def _get_impl_type(self, node: 'Node', source: bytes) -> Optional[str]:
        type_node = find_child_by_field(node, "type")
        if type_node:
            return node_text(type_node, source)
        return None

    def _extract_imports_list(self, node: 'Node', source: bytes) -> List[str]:
        imports: List[str] = []
        for use_node in find_all_by_type(node, "use_declaration"):
            imports.append(node_text(use_node, source))
        return imports


@ConverterRegistry.register
class RustConverter(GenericASTConverter):
    """Rust Generic AST 转换器"""

    language_name = "rust"

    def get_function_node_types(self) -> List[str]:
        return ["function_item", "closure_expression"]

    def get_class_node_types(self) -> List[str]:
        return ["struct_item", "enum_item", "trait_item"]

    def get_call_node_types(self) -> List[str]:
        return ["call_expression", "method_call_expression", "macro_invocation"]

    def convert_function(self, node: 'Node') -> Optional[GenericFunction]:
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<closure>"

        params = []
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = self.extract_parameters(params_node)

        calls = self.extract_calls_from_node(node)

        visibility = Visibility.PRIVATE
        for child in node.children:
            if child.type == "visibility_modifier":
                visibility = Visibility.PUBLIC
                break

        return GenericFunction(
            kind=NodeKind.FUNCTION,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
            parameters=params,
            calls=calls,
            visibility=visibility,
        )

    def convert_class(self, node: 'Node') -> Optional[GenericClass]:
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<anonymous>"

        kind = NodeKind.STRUCT
        if node.type == "trait_item":
            kind = NodeKind.INTERFACE
        elif node.type == "enum_item":
            kind = NodeKind.ENUM

        return GenericClass(
            kind=kind,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
        )

    def convert_call(self, node: 'Node') -> Optional[GenericCall]:
        if node.type == "macro_invocation":
            macro_node = node.child_by_field_name("macro")
            name = self.get_node_text(macro_node) + "!" if macro_node else "macro!"
        else:
            func_node = node.child_by_field_name("function") or node.child_by_field_name("name")
            name = self.get_node_text(func_node) if func_node else ""

        return GenericCall(
            kind=NodeKind.CALL,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
            callee=name,
            full_name=name,
        )

    def extract_parameters(self, params_node: 'Node') -> List[GenericParameter]:
        params = []
        for child in params_node.children:
            if child.type == "parameter":
                pattern = child.child_by_field_name("pattern")
                type_node = child.child_by_field_name("type")
                if pattern:
                    params.append(GenericParameter(
                        name=self.get_node_text(pattern),
                        type_annotation=self.get_node_text(type_node) if type_node else None,
                    ))
        return params
