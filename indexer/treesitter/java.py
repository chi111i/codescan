"""
Java Tree-sitter 解析器

支持 Java 8 - 21 语法，包括：
- 类、接口、枚举、记录（Java 14+）
- 方法、构造函数、Lambda 表达式
- 注解处理
- 泛型支持
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


# Java 危险函数/方法列表
JAVA_DANGEROUS_METHODS = {
    # RCE - Runtime/ProcessBuilder
    "exec", "start", "command",
    "Runtime.exec", "Runtime.getRuntime().exec",
    "ProcessBuilder.start", "ProcessBuilder.command",
    # 脚本执行
    "eval", "ScriptEngine.eval",
    # 反序列化
    "readObject", "readUnshared", "readResolve",
    "ObjectInputStream.readObject",
    "XMLDecoder.readObject",
    # JNDI 注入
    "lookup", "InitialContext.lookup",
    "Context.lookup", "NamingManager.getObjectInstance",
    # SQL
    "executeQuery", "executeUpdate", "execute", "executeBatch",
    "Statement.execute", "Statement.executeQuery",
    "PreparedStatement.execute",
    # 文件操作
    "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
    "Files.readAllBytes", "Files.write", "Files.copy",
    "RandomAccessFile",
    # SSRF
    "openConnection", "openStream",
    "URL.openConnection", "URL.openStream",
    "HttpURLConnection", "HttpClient.send",
    # LDAP
    "search", "DirContext.search",
    # XPath
    "evaluate", "XPath.evaluate",
    # 表达式语言
    "getValue", "setValue",
    "SpelExpressionParser", "ELProcessor.eval",
    # 反射
    "invoke", "Method.invoke",
    "newInstance", "Class.forName",
    "getMethod", "getDeclaredMethod",
}

# Spring 框架相关注解
SPRING_CONTROLLER_ANNOTATIONS = {
    "Controller", "RestController", "RequestMapping",
    "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping",
}

SPRING_SERVICE_ANNOTATIONS = {
    "Service", "Component", "Repository", "Bean",
}


@TreeSitterParserRegistry.register
class JavaTSParser(TreeSitterParser):
    """Java Tree-sitter 解析器

    支持:
    - Java 8 - 21 语法
    - 类、接口、枚举、记录
    - 方法、构造函数
    - Lambda 表达式
    - 注解
    - 泛型
    """

    language_name = "java"
    extensions = [".java"]

    def _load_language(self) -> Optional['Language']:
        """加载 Java 语法"""
        return LanguageLoader.load("java")

    def _extract_functions(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        """提取方法和构造函数"""
        units: List[CodeUnit] = []
        imports = self._extract_imports_list(tree.root_node, source)

        # 遍历所有类/接口/枚举
        for class_node in self._find_class_like_nodes(tree.root_node):
            class_name = self._get_node_name(class_node, source) or ""
            body = find_child_by_field(class_node, "body")
            if not body:
                continue

            # 方法
            for method_node in find_all_by_type(body, "method_declaration"):
                unit = self._parse_method_node(
                    method_node, source, file_path, imports, class_name
                )
                if unit:
                    units.append(unit)

            # 构造函数
            for ctor_node in find_all_by_type(body, "constructor_declaration"):
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
        """提取类、接口、枚举、记录"""
        units: List[CodeUnit] = []
        imports = self._extract_imports_list(tree.root_node, source)

        # 类
        for node in find_all_by_type(tree.root_node, "class_declaration"):
            unit = self._parse_class_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        # 接口
        for node in find_all_by_type(tree.root_node, "interface_declaration"):
            unit = self._parse_interface_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        # 枚举
        for node in find_all_by_type(tree.root_node, "enum_declaration"):
            unit = self._parse_enum_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        # 记录 (Java 14+)
        for node in find_all_by_type(tree.root_node, "record_declaration"):
            unit = self._parse_record_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        return units

    def _find_class_like_nodes(self, root: 'Node') -> List['Node']:
        """查找所有类似类的节点"""
        types = ["class_declaration", "interface_declaration",
                 "enum_declaration", "record_declaration"]
        nodes = []
        for t in types:
            nodes.extend(find_all_by_type(root, t))
        return nodes

    def _extract_calls(self, node: 'Node', source: bytes) -> List[str]:
        """提取方法调用"""
        calls: Set[str] = set()

        # 方法调用
        for call_node in find_all_by_type(node, "method_invocation"):
            name_node = find_child_by_field(call_node, "name")
            obj_node = find_child_by_field(call_node, "object")
            if name_node:
                method_name = node_text(name_node, source)
                calls.add(method_name)
                if obj_node:
                    obj_text = node_text(obj_node, source)
                    calls.add(f"{obj_text}.{method_name}")

        # 对象创建
        for new_node in find_all_by_type(node, "object_creation_expression"):
            type_node = find_child_by_field(new_node, "type")
            if type_node:
                type_name = node_text(type_node, source)
                # 移除泛型参数
                if "<" in type_name:
                    type_name = type_name.split("<")[0]
                calls.add(type_name)
                calls.add(f"new {type_name}")

        # 静态方法调用（通过类型标识符）
        for access_node in find_all_by_type(node, "field_access"):
            obj_node = find_child_by_field(access_node, "object")
            field_node = find_child_by_field(access_node, "field")
            if obj_node and field_node:
                calls.add(f"{node_text(obj_node, source)}.{node_text(field_node, source)}")

        return list(calls)

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
        modifiers = self._extract_modifiers(node, source)
        visibility = modifiers.get("visibility", "package")
        is_static = modifiers.get("is_static", False)
        is_abstract = modifiers.get("is_abstract", False)

        # 获取注解
        annotations = self._extract_annotations(node, source)

        # 获取返回类型
        return_type = ""
        type_node = find_child_by_field(node, "type")
        if type_node:
            return_type = node_text(type_node, source)

        # 构建签名
        params_node = find_child_by_field(node, "parameters")
        params = node_text(params_node, source) if params_node else "()"

        prefix = f"{visibility} "
        if is_static:
            prefix += "static "
        if is_abstract:
            prefix += "abstract "

        signature = f"{prefix}{return_type} {name}{params}"

        calls = self._extract_calls(node, source)

        # 检查是否包含危险方法
        dangerous_calls = [c for c in calls if any(d in c for d in JAVA_DANGEROUS_METHODS)]

        # 判断是否是控制器方法（入口点）
        unit_type = CodeUnitType.METHOD
        is_handler = any(
            ann in SPRING_CONTROLLER_ANNOTATIONS
            for ann in annotations
        )
        if is_handler:
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
                "is_abstract": is_abstract,
                "annotations": annotations,
                "return_type": return_type,
                "dangerous_calls": dangerous_calls,
            } if annotations or dangerous_calls else {
                "visibility": visibility,
                "is_static": is_static,
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
        """解析构造函数节点"""
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        modifiers = self._extract_modifiers(node, source)
        visibility = modifiers.get("visibility", "package")

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
            metadata={
                "is_constructor": True,
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
        """解析类节点"""
        name = self._get_node_name(node, source)
        if not name:
            return None

        span = node_span(node)
        code = node_text(node, source)

        modifiers = self._extract_modifiers(node, source)
        visibility = modifiers.get("visibility", "package")
        is_abstract = modifiers.get("is_abstract", False)
        is_final = modifiers.get("is_final", False)

        annotations = self._extract_annotations(node, source)

        # 获取父类
        superclass = None
        superclass_node = find_child_by_type(node, "superclass")
        if superclass_node:
            for child in superclass_node.children:
                if child.type == "type_identifier":
                    superclass = node_text(child, source)
                    break

        # 获取接口
        interfaces = []
        interfaces_node = find_child_by_type(node, "super_interfaces")
        if interfaces_node:
            for child in interfaces_node.children:
                if child.type == "type_identifier":
                    interfaces.append(node_text(child, source))

        # 构建签名
        prefix = f"{visibility} "
        if is_abstract:
            prefix += "abstract "
        if is_final:
            prefix += "final "

        signature = f"{prefix}class {name}"
        if superclass:
            signature += f" extends {superclass}"
        if interfaces:
            signature += f" implements {', '.join(interfaces)}"

        calls = self._extract_calls(node, source)

        # 检查是否是控制器
        unit_type = CodeUnitType.CLASS
        is_controller = any(
            ann in SPRING_CONTROLLER_ANNOTATIONS
            for ann in annotations
        )
        if is_controller or "Controller" in name:
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
            calls=calls,
            imports=imports,
            metadata={
                "visibility": visibility,
                "is_abstract": is_abstract,
                "is_final": is_final,
                "superclass": superclass,
                "interfaces": interfaces,
                "annotations": annotations,
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

        modifiers = self._extract_modifiers(node, source)
        visibility = modifiers.get("visibility", "package")

        # 获取父接口
        extends = []
        extends_node = find_child_by_type(node, "extends_interfaces")
        if extends_node:
            for child in extends_node.children:
                if child.type == "type_identifier":
                    extends.append(node_text(child, source))

        signature = f"{visibility} interface {name}"
        if extends:
            signature += f" extends {', '.join(extends)}"

        unit_id = CodeUnit.generate_id(file_path, name, span)

        return CodeUnit(
            id=unit_id,
            language=self.language_name,
            file_path=file_path,
            symbol=name,
            unit_type=CodeUnitType.CLASS,
            signature=signature.strip(),
            span=span,
            code=code,
            calls=[],
            imports=imports,
            metadata={
                "is_interface": True,
                "visibility": visibility,
                "extends": extends,
            },
        )

    def _parse_enum_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        """解析枚举节点"""
        name = self._get_node_name(node, source)
        if not name:
            return None

        span = node_span(node)
        code = node_text(node, source)

        modifiers = self._extract_modifiers(node, source)
        visibility = modifiers.get("visibility", "package")

        signature = f"{visibility} enum {name}"

        # 提取枚举常量
        constants = []
        body = find_child_by_field(node, "body")
        if body:
            for const_node in find_all_by_type(body, "enum_constant"):
                name_node = find_child_by_field(const_node, "name")
                if name_node:
                    constants.append(node_text(name_node, source))

        unit_id = CodeUnit.generate_id(file_path, name, span)

        return CodeUnit(
            id=unit_id,
            language=self.language_name,
            file_path=file_path,
            symbol=name,
            unit_type=CodeUnitType.CLASS,
            signature=signature.strip(),
            span=span,
            code=code,
            calls=[],
            imports=imports,
            metadata={
                "is_enum": True,
                "visibility": visibility,
                "constants": constants,
            },
        )

    def _parse_record_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        """解析记录节点 (Java 14+)"""
        name = self._get_node_name(node, source)
        if not name:
            return None

        span = node_span(node)
        code = node_text(node, source)

        modifiers = self._extract_modifiers(node, source)
        visibility = modifiers.get("visibility", "package")

        # 获取记录组件
        components = []
        params_node = find_child_by_field(node, "parameters")
        if params_node:
            components_text = node_text(params_node, source)
            signature = f"{visibility} record {name}{components_text}"
        else:
            signature = f"{visibility} record {name}()"

        unit_id = CodeUnit.generate_id(file_path, name, span)

        return CodeUnit(
            id=unit_id,
            language=self.language_name,
            file_path=file_path,
            symbol=name,
            unit_type=CodeUnitType.CLASS,
            signature=signature.strip(),
            span=span,
            code=code,
            calls=[],
            imports=imports,
            metadata={
                "is_record": True,
                "visibility": visibility,
            },
        )

    def _extract_modifiers(self, node: 'Node', source: bytes) -> Dict[str, Any]:
        """提取修饰符"""
        result = {
            "visibility": "package",  # Java 默认包私有
            "is_static": False,
            "is_final": False,
            "is_abstract": False,
            "is_synchronized": False,
            "is_native": False,
        }

        modifiers_node = find_child_by_type(node, "modifiers")
        if not modifiers_node:
            return result

        for child in modifiers_node.children:
            text = node_text(child, source)
            if text in ("public", "private", "protected"):
                result["visibility"] = text
            elif text == "static":
                result["is_static"] = True
            elif text == "final":
                result["is_final"] = True
            elif text == "abstract":
                result["is_abstract"] = True
            elif text == "synchronized":
                result["is_synchronized"] = True
            elif text == "native":
                result["is_native"] = True

        return result

    def _extract_annotations(self, node: 'Node', source: bytes) -> List[str]:
        """提取注解"""
        annotations = []
        modifiers_node = find_child_by_type(node, "modifiers")
        if modifiers_node:
            for child in modifiers_node.children:
                if child.type in ("annotation", "marker_annotation"):
                    name_node = find_child_by_field(child, "name")
                    if name_node:
                        annotations.append(node_text(name_node, source))
                    else:
                        # 简单注解
                        ann_text = node_text(child, source)
                        if ann_text.startswith("@"):
                            annotations.append(ann_text[1:].split("(")[0])
        return annotations

    def _get_node_name(self, node: 'Node', source: bytes) -> Optional[str]:
        """获取节点名称"""
        name_node = find_child_by_field(node, "name")
        if name_node:
            return node_text(name_node, source)
        return None

    def _extract_imports_list(self, node: 'Node', source: bytes) -> List[str]:
        """提取导入列表"""
        imports: List[str] = []

        for import_node in find_all_by_type(node, "import_declaration"):
            for child in import_node.children:
                if child.type == "scoped_identifier":
                    imports.append(node_text(child, source))

        return imports


# ============================================================
# Generic AST 转换器
# ============================================================

@ConverterRegistry.register
class JavaConverter(GenericASTConverter):
    """Java Generic AST 转换器"""

    language_name = "java"

    def get_function_node_types(self) -> List[str]:
        return [
            "method_declaration",
            "constructor_declaration",
            "lambda_expression",
        ]

    def get_class_node_types(self) -> List[str]:
        return [
            "class_declaration",
            "interface_declaration",
            "enum_declaration",
            "record_declaration",
            "annotation_type_declaration",
        ]

    def get_call_node_types(self) -> List[str]:
        return [
            "method_invocation",
            "object_creation_expression",
            "explicit_constructor_invocation",
        ]

    def convert_function(self, node: 'Node') -> Optional[GenericFunction]:
        """转换方法节点"""
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<constructor>"

        # 提取参数
        params = []
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = self.extract_parameters(params_node)

        # 提取调用
        calls = self.extract_calls_from_node(node)

        # 获取可见性
        visibility = Visibility.PACKAGE
        is_static = False
        is_abstract = False

        for child in node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    mod_text = self.get_node_text(mod).lower()
                    if mod_text == "public":
                        visibility = Visibility.PUBLIC
                    elif mod_text == "private":
                        visibility = Visibility.PRIVATE
                    elif mod_text == "protected":
                        visibility = Visibility.PROTECTED
                    elif mod_text == "static":
                        is_static = True
                    elif mod_text == "abstract":
                        is_abstract = True

        # 返回类型
        return_type = None
        type_node = node.child_by_field_name("type")
        if type_node:
            return_type = self.get_node_text(type_node)

        kind = NodeKind.METHOD
        if node.type == "constructor_declaration":
            kind = NodeKind.CONSTRUCTOR
        elif node.type == "lambda_expression":
            kind = NodeKind.LAMBDA

        return GenericFunction(
            kind=kind,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
            parameters=params,
            return_type=return_type,
            calls=calls,
            visibility=visibility,
            is_static=is_static,
            is_abstract=is_abstract,
        )

    def convert_class(self, node: 'Node') -> Optional[GenericClass]:
        """转换类节点"""
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<anonymous>"

        # 获取父类和接口
        bases = []
        for child in node.children:
            if child.type == "superclass":
                for c in child.children:
                    if c.type == "type_identifier":
                        bases.append(self.get_node_text(c))
            elif child.type == "super_interfaces":
                for c in child.children:
                    if c.type == "type_identifier":
                        bases.append(self.get_node_text(c))

        is_interface = node.type == "interface_declaration"
        is_abstract = False

        for child in node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    if self.get_node_text(mod) == "abstract":
                        is_abstract = True

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
            bases=bases,
            is_abstract=is_abstract,
            is_interface=is_interface,
        )

    def convert_call(self, node: 'Node') -> Optional[GenericCall]:
        """转换调用节点"""
        full_name = self.extract_full_call_name(node)

        # 分离 receiver 和 callee
        if "." in full_name:
            parts = full_name.rsplit(".", 1)
            receiver = parts[0]
            callee = parts[1]
        else:
            receiver = None
            callee = full_name

        is_constructor = node.type == "object_creation_expression"

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
        )

    def convert_import(self, node: 'Node') -> Optional[GenericImport]:
        """转换导入节点"""
        for child in node.children:
            if child.type == "scoped_identifier":
                module = self.get_node_text(child)
                # 分解为模块和名称
                parts = module.rsplit(".", 1)
                if len(parts) == 2:
                    return GenericImport(
                        module=parts[0],
                        names=[parts[1]],
                        span=self.get_node_span(node),
                    )
                else:
                    return GenericImport(
                        module=module,
                        names=[],
                        span=self.get_node_span(node),
                    )
        return None

    def extract_full_call_name(self, node: 'Node') -> str:
        """提取完整调用名"""
        if node.type == "method_invocation":
            obj = node.child_by_field_name("object")
            name = node.child_by_field_name("name")
            obj_text = self.get_node_text(obj) if obj else ""
            name_text = self.get_node_text(name) if name else ""
            if obj_text:
                return f"{obj_text}.{name_text}"
            return name_text

        if node.type == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            if type_node:
                return self.get_node_text(type_node)

        return self.get_node_text(node)

    def extract_parameters(self, params_node: 'Node') -> List[GenericParameter]:
        """提取参数列表"""
        params = []
        for child in params_node.children:
            if child.type == "formal_parameter":
                name_node = child.child_by_field_name("name")
                type_node = child.child_by_field_name("type")
                if name_node:
                    params.append(GenericParameter(
                        name=self.get_node_text(name_node),
                        type_annotation=self.get_node_text(type_node) if type_node else None,
                    ))
            elif child.type == "spread_parameter":
                name_node = child.child_by_field_name("name")
                if name_node:
                    params.append(GenericParameter(
                        name=self.get_node_text(name_node),
                        is_variadic=True,
                    ))
        return params
