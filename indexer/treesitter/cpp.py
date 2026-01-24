"""
C/C++ Tree-sitter 解析器

支持 C11/C17 和 C++11/14/17/20 语法，包括：
- 函数和方法
- 类、结构体、联合体
- 模板
- 命名空间
- 危险函数检测
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


# C/C++ 危险函数
C_DANGEROUS_FUNCTIONS = {
    # 命令执行
    "system", "popen", "exec", "execl", "execle", "execlp",
    "execv", "execve", "execvp", "fork",
    # 内存操作 (缓冲区溢出)
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "scanf", "sscanf", "fscanf",
    # 格式化字符串
    "printf", "fprintf", "snprintf", "vprintf", "vfprintf",
    # 文件操作
    "fopen", "fread", "fwrite", "fgets", "fputs",
    "open", "read", "write",
    # 内存分配
    "malloc", "calloc", "realloc", "free",
    "alloca",
    # 网络
    "socket", "connect", "bind", "listen", "accept",
    "send", "recv", "sendto", "recvfrom",
    # 其他
    "getenv", "setenv", "putenv",
    "dlopen", "dlsym",
}


@TreeSitterParserRegistry.register
class CTSParser(TreeSitterParser):
    """C Tree-sitter 解析器"""

    language_name = "c"
    extensions = [".c", ".h"]

    def _load_language(self) -> Optional['Language']:
        return LanguageLoader.load("c")

    def _extract_functions(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        units: List[CodeUnit] = []

        for node in find_all_by_type(tree.root_node, "function_definition"):
            unit = self._parse_function_node(node, source, file_path)
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

        # 结构体
        for node in find_all_by_type(tree.root_node, "struct_specifier"):
            unit = self._parse_struct_node(node, source, file_path)
            if unit:
                units.append(unit)

        # 联合体
        for node in find_all_by_type(tree.root_node, "union_specifier"):
            unit = self._parse_union_node(node, source, file_path)
            if unit:
                units.append(unit)

        # 枚举
        for node in find_all_by_type(tree.root_node, "enum_specifier"):
            unit = self._parse_enum_node(node, source, file_path)
            if unit:
                units.append(unit)

        return units

    def _extract_calls(self, node: 'Node', source: bytes) -> List[str]:
        calls: Set[str] = set()

        for call_node in find_all_by_type(node, "call_expression"):
            func_node = find_child_by_field(call_node, "function")
            if func_node:
                calls.add(node_text(func_node, source))

        return list(calls)

    def _parse_function_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
    ) -> Optional[CodeUnit]:
        # 获取声明器
        declarator = find_child_by_field(node, "declarator")
        if not declarator:
            return None

        # 从声明器中获取函数名
        name = self._get_function_name(declarator, source)
        if not name:
            return None

        span = node_span(node)
        code = node_text(node, source)

        # 获取返回类型
        type_node = find_child_by_field(node, "type")
        return_type = node_text(type_node, source) if type_node else ""

        # 获取参数
        params = self._get_parameters(declarator, source)

        signature = f"{return_type} {name}({params})"

        calls = self._extract_calls(node, source)
        dangerous_calls = [c for c in calls if c in C_DANGEROUS_FUNCTIONS]

        unit_id = CodeUnit.generate_id(file_path, name, span)

        return CodeUnit(
            id=unit_id,
            language=self.language_name,
            file_path=file_path,
            symbol=name,
            unit_type=CodeUnitType.FUNCTION,
            signature=signature.strip(),
            span=span,
            code=code,
            calls=calls,
            imports=[],
            metadata={
                "return_type": return_type,
                "dangerous_calls": dangerous_calls,
            } if dangerous_calls else {"return_type": return_type},
        )

    def _parse_struct_node(
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

        signature = f"struct {name}"
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
            metadata={"is_struct": True},
        )

    def _parse_union_node(
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

        signature = f"union {name}"
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
            metadata={"is_union": True},
        )

    def _parse_enum_node(
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
            imports=[],
            metadata={"is_enum": True},
        )

    def _get_function_name(self, declarator: 'Node', source: bytes) -> Optional[str]:
        """从声明器中提取函数名"""
        if declarator.type == "function_declarator":
            name_node = find_child_by_field(declarator, "declarator")
            if name_node:
                return node_text(name_node, source)
        elif declarator.type == "pointer_declarator":
            inner = find_child_by_field(declarator, "declarator")
            if inner:
                return self._get_function_name(inner, source)
        return None

    def _get_parameters(self, declarator: 'Node', source: bytes) -> str:
        """获取参数列表"""
        if declarator.type == "function_declarator":
            params_node = find_child_by_field(declarator, "parameters")
            if params_node:
                return node_text(params_node, source).strip("()")
        elif declarator.type == "pointer_declarator":
            inner = find_child_by_field(declarator, "declarator")
            if inner:
                return self._get_parameters(inner, source)
        return ""


@TreeSitterParserRegistry.register
class CppTSParser(CTSParser):
    """C++ Tree-sitter 解析器"""

    language_name = "cpp"
    extensions = [".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".hh", ".h"]

    def _load_language(self) -> Optional['Language']:
        return LanguageLoader.load("cpp")

    def _extract_classes(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        units = super()._extract_classes(tree, source, file_path)

        # C++ 类
        for node in find_all_by_type(tree.root_node, "class_specifier"):
            unit = self._parse_class_node(node, source, file_path)
            if unit:
                units.append(unit)

        return units

    def _extract_functions(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        units = super()._extract_functions(tree, source, file_path)

        # 类内方法
        for class_node in find_all_by_type(tree.root_node, "class_specifier"):
            class_name = self._get_class_name(class_node, source)
            body = find_child_by_field(class_node, "body")
            if body and class_name:
                for method in find_all_by_type(body, "function_definition"):
                    unit = self._parse_method_node(method, source, file_path, class_name)
                    if unit:
                        units.append(unit)

        return units

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

        # 获取基类
        bases = []
        base_clause = find_child_by_type(node, "base_class_clause")
        if base_clause:
            for child in base_clause.children:
                if child.type == "type_identifier":
                    bases.append(node_text(child, source))

        signature = f"class {name}"
        if bases:
            signature += f" : {', '.join(bases)}"

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
            metadata={"bases": bases},
        )

    def _parse_method_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        class_name: str,
    ) -> Optional[CodeUnit]:
        unit = self._parse_function_node(node, source, file_path)
        if unit:
            unit.unit_type = CodeUnitType.METHOD
            unit.parent_class = class_name
            unit.id = CodeUnit.generate_id(
                file_path, f"{class_name}::{unit.symbol}", unit.span
            )
        return unit

    def _get_class_name(self, node: 'Node', source: bytes) -> Optional[str]:
        name_node = find_child_by_field(node, "name")
        return node_text(name_node, source) if name_node else None


@ConverterRegistry.register
class CConverter(GenericASTConverter):
    """C Generic AST 转换器"""

    language_name = "c"

    def get_function_node_types(self) -> List[str]:
        return ["function_definition"]

    def get_class_node_types(self) -> List[str]:
        return ["struct_specifier", "union_specifier", "enum_specifier"]

    def get_call_node_types(self) -> List[str]:
        return ["call_expression"]

    def convert_function(self, node: 'Node') -> Optional[GenericFunction]:
        declarator = node.child_by_field_name("declarator")
        name = self._get_func_name(declarator) if declarator else "<unknown>"

        return GenericFunction(
            kind=NodeKind.FUNCTION,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
        )

    def convert_class(self, node: 'Node') -> Optional[GenericClass]:
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<anonymous>"

        kind = NodeKind.STRUCT
        if node.type == "enum_specifier":
            kind = NodeKind.ENUM

        return GenericClass(
            kind=kind,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
        )

    def convert_call(self, node: 'Node') -> Optional[GenericCall]:
        func_node = node.child_by_field_name("function")
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

    def _get_func_name(self, declarator: 'Node') -> str:
        if declarator.type == "function_declarator":
            inner = declarator.child_by_field_name("declarator")
            return self.get_node_text(inner) if inner else ""
        elif declarator.type == "pointer_declarator":
            inner = declarator.child_by_field_name("declarator")
            return self._get_func_name(inner) if inner else ""
        return self.get_node_text(declarator)


@ConverterRegistry.register
class CppConverter(CConverter):
    """C++ Generic AST 转换器"""

    language_name = "cpp"

    def get_class_node_types(self) -> List[str]:
        return super().get_class_node_types() + ["class_specifier"]
