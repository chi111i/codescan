"""
C# Tree-sitter 解析器

支持 C# 语法，包括：
- 类、结构体、接口、记录
- 方法、属性、事件
- async/await
- LINQ
- 特性 (Attributes)
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


# C# 危险方法
CSHARP_DANGEROUS_METHODS = {
    # 命令执行
    "Process.Start", "ProcessStartInfo",
    # 反序列化
    "BinaryFormatter.Deserialize", "XmlSerializer.Deserialize",
    "JsonConvert.DeserializeObject", "JavaScriptSerializer.Deserialize",
    "DataContractSerializer.ReadObject",
    # SQL
    "ExecuteNonQuery", "ExecuteReader", "ExecuteScalar",
    "SqlCommand", "SqlDataAdapter",
    # 文件操作
    "File.ReadAllText", "File.WriteAllText", "File.ReadAllBytes",
    "FileStream", "StreamReader", "StreamWriter",
    # 反射
    "Assembly.Load", "Activator.CreateInstance",
    "Type.InvokeMember", "MethodInfo.Invoke",
    # 网络
    "HttpClient", "WebClient", "WebRequest",
    "HttpWebRequest.Create",
    # LDAP
    "DirectorySearcher", "DirectoryEntry",
    # XPath
    "XPathNavigator.Evaluate", "XmlDocument.SelectNodes",
}


@TreeSitterParserRegistry.register
class CSharpTSParser(TreeSitterParser):
    """C# Tree-sitter 解析器"""

    language_name = "c_sharp"
    extensions = [".cs"]

    def _load_language(self) -> Optional['Language']:
        return LanguageLoader.load("c_sharp")

    def _extract_functions(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        units: List[CodeUnit] = []
        imports = self._extract_imports_list(tree.root_node, source)

        # 遍历类/结构体/接口
        for class_node in self._find_type_nodes(tree.root_node):
            class_name = self._get_node_name(class_node, source)
            if not class_name:
                continue

            # 方法
            for method_node in find_all_by_type(class_node, "method_declaration"):
                unit = self._parse_method_node(
                    method_node, source, file_path, imports, class_name
                )
                if unit:
                    units.append(unit)

            # 构造函数
            for ctor_node in find_all_by_type(class_node, "constructor_declaration"):
                unit = self._parse_constructor_node(
                    ctor_node, source, file_path, imports, class_name
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

        # 类
        for node in find_all_by_type(tree.root_node, "class_declaration"):
            unit = self._parse_class_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        # 结构体
        for node in find_all_by_type(tree.root_node, "struct_declaration"):
            unit = self._parse_struct_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        # 接口
        for node in find_all_by_type(tree.root_node, "interface_declaration"):
            unit = self._parse_interface_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        # 记录 (C# 9+)
        for node in find_all_by_type(tree.root_node, "record_declaration"):
            unit = self._parse_record_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        return units

    def _find_type_nodes(self, root: 'Node') -> List['Node']:
        types = ["class_declaration", "struct_declaration",
                 "interface_declaration", "record_declaration"]
        nodes = []
        for t in types:
            nodes.extend(find_all_by_type(root, t))
        return nodes

    def _extract_calls(self, node: 'Node', source: bytes) -> List[str]:
        calls: Set[str] = set()

        # 方法调用
        for call_node in find_all_by_type(node, "invocation_expression"):
            expr = find_child_by_field(call_node, "function")
            if expr:
                calls.add(node_text(expr, source))

        # 对象创建
        for new_node in find_all_by_type(node, "object_creation_expression"):
            type_node = find_child_by_field(new_node, "type")
            if type_node:
                calls.add(f"new {node_text(type_node, source)}")

        return list(calls)

    def _parse_method_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
        class_name: str,
    ) -> Optional[CodeUnit]:
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        # 修饰符
        modifiers = self._extract_modifiers(node, source)
        visibility = modifiers.get("visibility", "private")
        is_static = modifiers.get("is_static", False)
        is_async = modifiers.get("is_async", False)

        # 返回类型
        return_type = ""
        type_node = find_child_by_field(node, "type")
        if type_node:
            return_type = node_text(type_node, source)

        # 参数
        params_node = find_child_by_field(node, "parameters")
        params = node_text(params_node, source) if params_node else "()"

        # 构建签名
        prefix = f"{visibility} "
        if is_static:
            prefix += "static "
        if is_async:
            prefix += "async "

        signature = f"{prefix}{return_type} {name}{params}"

        calls = self._extract_calls(node, source)
        dangerous_calls = [c for c in calls if any(d in c for d in CSHARP_DANGEROUS_METHODS)]

        # 检查是否是控制器方法
        attributes = self._extract_attributes(node, source)
        unit_type = CodeUnitType.METHOD
        if any(attr in ["HttpGet", "HttpPost", "HttpPut", "HttpDelete", "Route"]
               for attr in attributes):
            unit_type = CodeUnitType.HANDLER

        unit_id = CodeUnit.generate_id(file_path, f"{class_name}.{name}", span)

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
            parent_class=class_name,
            imports=imports,
            metadata={
                "visibility": visibility,
                "is_static": is_static,
                "is_async": is_async,
                "attributes": attributes,
                "dangerous_calls": dangerous_calls,
            } if dangerous_calls or attributes else {
                "visibility": visibility,
            },
        )

    def _parse_constructor_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
        class_name: str,
    ) -> Optional[CodeUnit]:
        name_node = find_child_by_field(node, "name")
        name = node_text(name_node, source) if name_node else class_name

        span = node_span(node)
        code = node_text(node, source)

        modifiers = self._extract_modifiers(node, source)
        visibility = modifiers.get("visibility", "private")

        params_node = find_child_by_field(node, "parameters")
        params = node_text(params_node, source) if params_node else "()"

        signature = f"{visibility} {name}{params}"
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
            metadata={"is_constructor": True, "visibility": visibility},
        )

    def _parse_class_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        name = self._get_node_name(node, source)
        if not name:
            return None

        span = node_span(node)
        code = node_text(node, source)

        modifiers = self._extract_modifiers(node, source)
        visibility = modifiers.get("visibility", "internal")
        is_abstract = modifiers.get("is_abstract", False)
        is_sealed = modifiers.get("is_sealed", False)

        # 基类和接口
        bases = self._extract_bases(node, source)

        prefix = f"{visibility} "
        if is_abstract:
            prefix += "abstract "
        if is_sealed:
            prefix += "sealed "

        signature = f"{prefix}class {name}"
        if bases:
            signature += f" : {', '.join(bases)}"

        # 检查是否是控制器
        attributes = self._extract_attributes(node, source)
        unit_type = CodeUnitType.CLASS
        if "Controller" in name or "ApiController" in attributes:
            unit_type = CodeUnitType.HANDLER

        unit_id = CodeUnit.generate_id(file_path, name, span)

        return CodeUnit(
            id=unit_id,
            language=self.language_name,
            file_path=file_path,
            symbol=name,
            unit_type=unit_type,
            signature=signature.strip(),
            span=span,
            code=code,
            calls=[],
            imports=imports,
            metadata={
                "visibility": visibility,
                "is_abstract": is_abstract,
                "is_sealed": is_sealed,
                "bases": bases,
                "attributes": attributes,
            },
        )

    def _parse_struct_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        name = self._get_node_name(node, source)
        if not name:
            return None

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
            imports=imports,
            metadata={"is_struct": True},
        )

    def _parse_interface_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
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

    def _parse_record_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        name = self._get_node_name(node, source)
        if not name:
            return None

        span = node_span(node)
        code = node_text(node, source)

        signature = f"record {name}"
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
            metadata={"is_record": True},
        )

    def _extract_modifiers(self, node: 'Node', source: bytes) -> Dict[str, Any]:
        result = {
            "visibility": "private",
            "is_static": False,
            "is_abstract": False,
            "is_sealed": False,
            "is_async": False,
            "is_virtual": False,
            "is_override": False,
        }

        for child in node.children:
            if child.type == "modifier":
                text = node_text(child, source)
                if text in ("public", "private", "protected", "internal"):
                    result["visibility"] = text
                elif text == "static":
                    result["is_static"] = True
                elif text == "abstract":
                    result["is_abstract"] = True
                elif text == "sealed":
                    result["is_sealed"] = True
                elif text == "async":
                    result["is_async"] = True
                elif text == "virtual":
                    result["is_virtual"] = True
                elif text == "override":
                    result["is_override"] = True

        return result

    def _extract_attributes(self, node: 'Node', source: bytes) -> List[str]:
        attributes = []
        for child in node.children:
            if child.type == "attribute_list":
                for attr in child.children:
                    if attr.type == "attribute":
                        name_node = find_child_by_field(attr, "name")
                        if name_node:
                            attributes.append(node_text(name_node, source))
        return attributes

    def _extract_bases(self, node: 'Node', source: bytes) -> List[str]:
        bases = []
        base_list = find_child_by_type(node, "base_list")
        if base_list:
            for child in base_list.children:
                if child.type in ("identifier", "generic_name", "qualified_name"):
                    bases.append(node_text(child, source))
        return bases

    def _get_node_name(self, node: 'Node', source: bytes) -> Optional[str]:
        name_node = find_child_by_field(node, "name")
        return node_text(name_node, source) if name_node else None

    def _extract_imports_list(self, node: 'Node', source: bytes) -> List[str]:
        imports = []
        for using_node in find_all_by_type(node, "using_directive"):
            name_node = find_child_by_field(using_node, "name")
            if name_node:
                imports.append(node_text(name_node, source))
        return imports


@ConverterRegistry.register
class CSharpConverter(GenericASTConverter):
    """C# Generic AST 转换器"""

    language_name = "c_sharp"

    def get_function_node_types(self) -> List[str]:
        return ["method_declaration", "constructor_declaration", "lambda_expression"]

    def get_class_node_types(self) -> List[str]:
        return ["class_declaration", "struct_declaration",
                "interface_declaration", "record_declaration", "enum_declaration"]

    def get_call_node_types(self) -> List[str]:
        return ["invocation_expression", "object_creation_expression"]

    def convert_function(self, node: 'Node') -> Optional[GenericFunction]:
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<lambda>"

        return GenericFunction(
            kind=NodeKind.METHOD,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
        )

    def convert_class(self, node: 'Node') -> Optional[GenericClass]:
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<anonymous>"

        kind = NodeKind.CLASS
        if node.type == "interface_declaration":
            kind = NodeKind.INTERFACE
        elif node.type == "enum_declaration":
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
