"""
Kotlin Tree-sitter 解析器

支持 Kotlin 语法，包括：
- 类、对象、接口、数据类
- 函数、扩展函数
- 协程 (suspend)
- Spring/Ktor 框架识别
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


# Kotlin 危险方法
KOTLIN_DANGEROUS_METHODS = {
    # 命令执行
    "Runtime.getRuntime().exec", "ProcessBuilder",
    "exec", "execCommand",
    # 反序列化
    "ObjectInputStream", "readObject",
    "Gson.fromJson", "Json.decodeFromString",
    "ObjectMapper.readValue",
    # 文件操作
    "File", "FileInputStream", "FileOutputStream",
    "readText", "writeText", "readBytes", "writeBytes",
    # 网络
    "HttpClient", "OkHttpClient", "Retrofit",
    "URL.openConnection", "HttpURLConnection",
    # SQL
    "executeQuery", "executeUpdate", "rawQuery",
    "createQuery", "createNativeQuery",
    # 反射
    "Class.forName", "newInstance", "invoke",
    "KClass", "callBy",
    # Android 特定
    "WebView.loadUrl", "evaluateJavascript",
    "ContentResolver.query",
}

# Kotlin/Spring 注解
KOTLIN_HANDLER_ANNOTATIONS = {
    "GetMapping", "PostMapping", "PutMapping", "DeleteMapping",
    "RequestMapping", "RestController", "Controller",
    # Ktor
    "get", "post", "put", "delete", "route",
}


@TreeSitterParserRegistry.register
class KotlinTSParser(TreeSitterParser):
    """Kotlin Tree-sitter 解析器"""

    language_name = "kotlin"
    extensions = [".kt", ".kts"]

    def _load_language(self) -> Optional['Language']:
        return LanguageLoader.load("kotlin")

    def _extract_functions(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        units: List[CodeUnit] = []
        imports = self._extract_imports_list(tree.root_node, source)

        # 顶层函数
        for node in find_all_by_type(tree.root_node, "function_declaration"):
            # 跳过类内方法（稍后处理）
            if self._is_inside_class(node):
                continue
            unit = self._parse_function_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        # 类内方法
        for class_node in self._find_class_nodes(tree.root_node):
            class_name = self._get_class_name(class_node, source)
            if not class_name:
                continue

            body = find_child_by_type(class_node, "class_body")
            if body:
                for func_node in find_all_by_type(body, "function_declaration"):
                    unit = self._parse_function_node(
                        func_node, source, file_path, imports, class_name
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

        # 对象声明
        for node in find_all_by_type(tree.root_node, "object_declaration"):
            unit = self._parse_object_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        return units

    def _find_class_nodes(self, root: 'Node') -> List['Node']:
        nodes = []
        nodes.extend(find_all_by_type(root, "class_declaration"))
        nodes.extend(find_all_by_type(root, "object_declaration"))
        return nodes

    def _is_inside_class(self, node: 'Node') -> bool:
        """检查节点是否在类体内"""
        parent = node.parent
        while parent:
            if parent.type == "class_body":
                return True
            parent = parent.parent
        return False

    def _extract_calls(self, node: 'Node', source: bytes) -> List[str]:
        calls: Set[str] = set()

        # 函数调用
        for call_node in find_all_by_type(node, "call_expression"):
            expr = call_node.children[0] if call_node.children else None
            if expr:
                calls.add(node_text(expr, source))

        # 导航表达式调用 (obj.method())
        for nav_node in find_all_by_type(node, "navigation_expression"):
            calls.add(node_text(nav_node, source))

        return list(calls)

    def _parse_function_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
        class_name: Optional[str] = None,
    ) -> Optional[CodeUnit]:
        # 获取函数名
        name = None
        for child in node.children:
            if child.type == "simple_identifier":
                name = node_text(child, source)
                break

        if not name:
            return None

        span = node_span(node)
        code = node_text(node, source)

        # 提取修饰符
        modifiers = self._extract_modifiers(node, source)
        visibility = modifiers.get("visibility", "public")
        is_suspend = modifiers.get("is_suspend", False)

        # 获取参数
        params_node = find_child_by_type(node, "function_value_parameters")
        params = node_text(params_node, source) if params_node else "()"

        # 获取返回类型
        return_type = ""
        for child in node.children:
            if child.type == "type":
                return_type = node_text(child, source)
                break

        # 构建签名
        prefix = f"{visibility} "
        if is_suspend:
            prefix += "suspend "

        signature = f"{prefix}fun {name}{params}"
        if return_type:
            signature += f": {return_type}"

        calls = self._extract_calls(node, source)
        dangerous_calls = [c for c in calls if any(d in c for d in KOTLIN_DANGEROUS_METHODS)]

        # 检查是否是处理器方法
        annotations = self._extract_annotations(node, source)
        unit_type = CodeUnitType.METHOD if class_name else CodeUnitType.FUNCTION
        if any(ann in KOTLIN_HANDLER_ANNOTATIONS for ann in annotations):
            unit_type = CodeUnitType.HANDLER

        symbol = f"{class_name}.{name}" if class_name else name
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
            parent_class=class_name,
            imports=imports,
            metadata={
                "visibility": visibility,
                "is_suspend": is_suspend,
                "annotations": annotations,
                "dangerous_calls": dangerous_calls,
            } if dangerous_calls or annotations or is_suspend else {
                "visibility": visibility,
            },
        )

    def _parse_class_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        name = self._get_class_name(node, source)
        if not name:
            return None

        span = node_span(node)
        code = node_text(node, source)

        modifiers = self._extract_modifiers(node, source)
        visibility = modifiers.get("visibility", "public")
        is_data = modifiers.get("is_data", False)
        is_sealed = modifiers.get("is_sealed", False)
        is_abstract = modifiers.get("is_abstract", False)

        # 获取父类/接口
        bases = self._extract_supertypes(node, source)

        # 构建签名
        prefix = f"{visibility} "
        if is_data:
            prefix += "data "
        if is_sealed:
            prefix += "sealed "
        if is_abstract:
            prefix += "abstract "

        signature = f"{prefix}class {name}"
        if bases:
            signature += f" : {', '.join(bases)}"

        # 检查是否是控制器
        annotations = self._extract_annotations(node, source)
        unit_type = CodeUnitType.CLASS
        if "Controller" in name or any(ann in ("RestController", "Controller") for ann in annotations):
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
                "is_data": is_data,
                "is_sealed": is_sealed,
                "is_abstract": is_abstract,
                "bases": bases,
                "annotations": annotations,
            },
        )

    def _parse_object_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        name = self._get_class_name(node, source)
        if not name:
            return None

        span = node_span(node)
        code = node_text(node, source)

        signature = f"object {name}"
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
            metadata={"is_object": True},
        )

    def _extract_modifiers(self, node: 'Node', source: bytes) -> Dict[str, Any]:
        result = {
            "visibility": "public",
            "is_suspend": False,
            "is_data": False,
            "is_sealed": False,
            "is_abstract": False,
            "is_open": False,
        }

        modifiers_node = find_child_by_type(node, "modifiers")
        if modifiers_node:
            for child in modifiers_node.children:
                text = node_text(child, source)
                if text in ("public", "private", "protected", "internal"):
                    result["visibility"] = text
                elif text == "suspend":
                    result["is_suspend"] = True
                elif text == "data":
                    result["is_data"] = True
                elif text == "sealed":
                    result["is_sealed"] = True
                elif text == "abstract":
                    result["is_abstract"] = True
                elif text == "open":
                    result["is_open"] = True

        return result

    def _extract_annotations(self, node: 'Node', source: bytes) -> List[str]:
        annotations = []
        modifiers_node = find_child_by_type(node, "modifiers")
        if modifiers_node:
            for child in modifiers_node.children:
                if child.type == "annotation":
                    # 提取注解名称
                    for sub in child.children:
                        if sub.type == "user_type" or sub.type == "simple_identifier":
                            annotations.append(node_text(sub, source))
                            break
        return annotations

    def _extract_supertypes(self, node: 'Node', source: bytes) -> List[str]:
        bases = []
        delegation = find_child_by_type(node, "delegation_specifiers")
        if delegation:
            for child in delegation.children:
                if child.type in ("delegation_specifier", "user_type", "constructor_invocation"):
                    bases.append(node_text(child, source))
        return bases

    def _get_class_name(self, node: 'Node', source: bytes) -> Optional[str]:
        for child in node.children:
            if child.type == "type_identifier" or child.type == "simple_identifier":
                return node_text(child, source)
        return None

    def _extract_imports_list(self, node: 'Node', source: bytes) -> List[str]:
        imports = []
        for import_node in find_all_by_type(node, "import_header"):
            imports.append(node_text(import_node, source).replace("import ", "").strip())
        return imports


@ConverterRegistry.register
class KotlinConverter(GenericASTConverter):
    """Kotlin Generic AST 转换器"""

    language_name = "kotlin"

    def get_function_node_types(self) -> List[str]:
        return ["function_declaration", "lambda_literal", "anonymous_function"]

    def get_class_node_types(self) -> List[str]:
        return ["class_declaration", "object_declaration"]

    def get_call_node_types(self) -> List[str]:
        return ["call_expression", "navigation_expression"]

    def convert_function(self, node: 'Node') -> Optional[GenericFunction]:
        name = None
        for child in node.children:
            if child.type == "simple_identifier":
                name = self.get_node_text(child)
                break

        if not name:
            name = "<lambda>" if node.type == "lambda_literal" else "<anonymous>"

        return GenericFunction(
            kind=NodeKind.FUNCTION,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
        )

    def convert_class(self, node: 'Node') -> Optional[GenericClass]:
        name = None
        for child in node.children:
            if child.type in ("type_identifier", "simple_identifier"):
                name = self.get_node_text(child)
                break

        if not name:
            name = "<anonymous>"

        kind = NodeKind.CLASS
        if node.type == "object_declaration":
            kind = NodeKind.OBJECT

        return GenericClass(
            kind=kind,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
        )

    def convert_call(self, node: 'Node') -> Optional[GenericCall]:
        name = ""
        if node.children:
            name = self.get_node_text(node.children[0])

        return GenericCall(
            kind=NodeKind.CALL,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
            callee=name,
            full_name=name,
        )
