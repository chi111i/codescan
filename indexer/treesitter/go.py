"""
Go Tree-sitter 解析器

支持 Go 1.x 语法，包括：
- 函数和方法
- 结构体、接口
- 包和导入
- Goroutine 和 Channel
- 泛型 (Go 1.18+)
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


# Go 危险函数列表
GO_DANGEROUS_FUNCTIONS = {
    # 命令执行
    "exec.Command", "exec.CommandContext",
    "os.StartProcess", "syscall.Exec",
    "syscall.ForkExec", "syscall.StartProcess",
    # 文件操作
    "os.Open", "os.OpenFile", "os.Create",
    "os.ReadFile", "os.WriteFile",
    "ioutil.ReadFile", "ioutil.WriteFile",
    "io.Copy", "io.ReadAll",
    # SQL
    "db.Query", "db.QueryRow", "db.Exec",
    "DB.Query", "DB.QueryRow", "DB.Exec",
    "tx.Query", "tx.QueryRow", "tx.Exec",
    "Tx.Query", "Tx.QueryRow", "Tx.Exec",
    # HTTP/网络
    "http.Get", "http.Post", "http.Do",
    "http.NewRequest", "http.Client.Do",
    "net.Dial", "net.DialTimeout",
    # 模板（SSTI）
    "template.HTML", "template.JS", "template.URL",
    "template.Must", "template.ParseFiles",
    # 反序列化
    "json.Unmarshal", "xml.Unmarshal",
    "gob.Decode", "yaml.Unmarshal",
    # 反射
    "reflect.Value.Call", "reflect.Value.Method",
    # 不安全操作
    "unsafe.Pointer",
}

# HTTP 处理器模式
HTTP_HANDLER_PATTERNS = {
    "HandleFunc", "Handle", "HandlerFunc",
    "Get", "Post", "Put", "Delete", "Patch",
    "ServeHTTP",
}

# 常见 Go Web 框架
GO_WEB_FRAMEWORKS = {
    "gin": {"GET", "POST", "PUT", "DELETE", "PATCH", "Handle", "Any", "Group"},
    "echo": {"GET", "POST", "PUT", "DELETE", "PATCH", "Add", "Group"},
    "fiber": {"Get", "Post", "Put", "Delete", "Patch", "All", "Group"},
    "chi": {"Get", "Post", "Put", "Delete", "Patch", "Handle", "Route"},
    "mux": {"HandleFunc", "Handle", "Methods"},
}


@TreeSitterParserRegistry.register
class GoTSParser(TreeSitterParser):
    """Go Tree-sitter 解析器

    支持:
    - Go 1.x 语法
    - 函数和方法
    - 结构体、接口
    - 泛型 (Go 1.18+)
    - HTTP 处理器识别
    """

    language_name = "go"
    extensions = [".go"]

    def _load_language(self) -> Optional['Language']:
        """加载 Go 语法"""
        return LanguageLoader.load("go")

    def _extract_functions(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        """提取函数和方法"""
        units: List[CodeUnit] = []
        imports = self._extract_imports_list(tree.root_node, source)

        # 顶层函数
        for node in find_all_by_type(tree.root_node, "function_declaration"):
            unit = self._parse_function_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        # 方法（带接收者的函数）
        for node in find_all_by_type(tree.root_node, "method_declaration"):
            unit = self._parse_method_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        return units

    def _extract_classes(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        """提取结构体和接口"""
        units: List[CodeUnit] = []
        imports = self._extract_imports_list(tree.root_node, source)

        # 类型声明
        for type_decl in find_all_by_type(tree.root_node, "type_declaration"):
            for spec in find_all_by_type(type_decl, "type_spec"):
                unit = self._parse_type_spec(spec, source, file_path, imports)
                if unit:
                    units.append(unit)

        return units

    def _extract_calls(self, node: 'Node', source: bytes) -> List[str]:
        """提取函数调用"""
        calls: Set[str] = set()

        # 函数调用
        for call_node in find_all_by_type(node, "call_expression"):
            func_node = find_child_by_field(call_node, "function")
            if func_node:
                call_text = node_text(func_node, source)
                calls.add(call_text)

                # 提取包.函数 格式
                if func_node.type == "selector_expression":
                    operand = find_child_by_field(func_node, "operand")
                    field = find_child_by_field(func_node, "field")
                    if operand and field:
                        calls.add(f"{node_text(operand, source)}.{node_text(field, source)}")

        # go 语句（goroutine）
        for go_node in find_all_by_type(node, "go_statement"):
            for call_node in find_all_by_type(go_node, "call_expression"):
                func_node = find_child_by_field(call_node, "function")
                if func_node:
                    calls.add(f"go {node_text(func_node, source)}")

        # defer 语句
        for defer_node in find_all_by_type(node, "defer_statement"):
            for call_node in find_all_by_type(defer_node, "call_expression"):
                func_node = find_child_by_field(call_node, "function")
                if func_node:
                    calls.add(f"defer {node_text(func_node, source)}")

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

        # 获取参数
        params_node = find_child_by_field(node, "parameters")
        params = node_text(params_node, source) if params_node else "()"

        # 获取返回类型
        result_node = find_child_by_field(node, "result")
        return_type = node_text(result_node, source) if result_node else ""

        # 构建签名
        signature = f"func {name}{params}"
        if return_type:
            signature += f" {return_type}"

        calls = self._extract_calls(node, source)

        # 检查危险函数
        dangerous_calls = [c for c in calls if any(d in c for d in GO_DANGEROUS_FUNCTIONS)]

        # 判断是否是导出函数（首字母大写）
        is_exported = name[0].isupper() if name else False

        # 判断是否是 HTTP 处理器
        unit_type = CodeUnitType.FUNCTION
        is_handler = self._is_http_handler(name, params, code)
        if is_handler:
            unit_type = CodeUnitType.HANDLER

        # 特殊函数
        if name == "main":
            unit_type = CodeUnitType.HANDLER  # main 作为入口点
        elif name == "init":
            unit_type = CodeUnitType.FUNCTION  # init 函数

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
                "is_exported": is_exported,
                "return_type": return_type,
                "dangerous_calls": dangerous_calls,
            } if dangerous_calls else {
                "is_exported": is_exported,
                "return_type": return_type,
            },
        )

    def _parse_method_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        """解析方法节点（带接收者）"""
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        # 获取接收者
        receiver_node = find_child_by_field(node, "receiver")
        receiver = ""
        receiver_type = ""
        if receiver_node:
            receiver = node_text(receiver_node, source)
            # 提取接收者类型
            for child in walk_tree(receiver_node):
                if child.type == "type_identifier":
                    receiver_type = node_text(child, source)
                    break
                elif child.type == "pointer_type":
                    for c in child.children:
                        if c.type == "type_identifier":
                            receiver_type = "*" + node_text(c, source)
                            break

        # 获取参数和返回类型
        params_node = find_child_by_field(node, "parameters")
        params = node_text(params_node, source) if params_node else "()"

        result_node = find_child_by_field(node, "result")
        return_type = node_text(result_node, source) if result_node else ""

        # 构建签名
        signature = f"func {receiver} {name}{params}"
        if return_type:
            signature += f" {return_type}"

        calls = self._extract_calls(node, source)

        # 检查危险函数
        dangerous_calls = [c for c in calls if any(d in c for d in GO_DANGEROUS_FUNCTIONS)]

        # 判断是否是 HTTP 处理器
        unit_type = CodeUnitType.METHOD
        is_handler = self._is_http_handler(name, params, code)
        if is_handler or name == "ServeHTTP":
            unit_type = CodeUnitType.HANDLER

        # 清理接收者类型名
        clean_receiver = receiver_type.lstrip("*")

        unit_id = CodeUnit.generate_id(file_path, f"{clean_receiver}.{name}", span)

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
            parent_class=clean_receiver,
            imports=imports,
            metadata={
                "receiver": receiver,
                "receiver_type": receiver_type,
                "is_exported": name[0].isupper() if name else False,
                "return_type": return_type,
                "dangerous_calls": dangerous_calls,
            } if dangerous_calls else {
                "receiver": receiver,
                "receiver_type": receiver_type,
                "is_exported": name[0].isupper() if name else False,
            },
        )

    def _parse_type_spec(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
    ) -> Optional[CodeUnit]:
        """解析类型规范（结构体、接口等）"""
        name_node = find_child_by_field(node, "name")
        if not name_node:
            return None

        name = node_text(name_node, source)
        span = node_span(node)
        code = node_text(node, source)

        # 获取类型
        type_node = find_child_by_field(node, "type")
        if not type_node:
            return None

        type_kind = type_node.type

        if type_kind == "struct_type":
            return self._parse_struct(name, node, type_node, source, file_path, imports, span, code)
        elif type_kind == "interface_type":
            return self._parse_interface(name, node, type_node, source, file_path, imports, span, code)
        else:
            # 类型别名
            signature = f"type {name} {node_text(type_node, source)}"
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
                metadata={
                    "is_type_alias": True,
                    "is_exported": name[0].isupper() if name else False,
                },
            )

    def _parse_struct(
        self,
        name: str,
        node: 'Node',
        type_node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
        span: CodeSpan,
        code: str,
    ) -> CodeUnit:
        """解析结构体"""
        # 提取字段
        fields = []
        field_list = find_child_by_type(type_node, "field_declaration_list")
        if field_list:
            for field in find_all_by_type(field_list, "field_declaration"):
                field_names = []
                field_type = ""
                for child in field.children:
                    if child.type == "field_identifier":
                        field_names.append(node_text(child, source))
                    elif child.type in ("type_identifier", "pointer_type",
                                        "slice_type", "map_type", "array_type"):
                        field_type = node_text(child, source)

                for fn in field_names:
                    fields.append({"name": fn, "type": field_type})

        # 检查嵌入字段
        embedded = []
        if field_list:
            for child in field_list.children:
                if child.type == "field_declaration":
                    # 没有字段名的就是嵌入
                    has_name = any(c.type == "field_identifier" for c in child.children)
                    if not has_name:
                        for c in child.children:
                            if c.type in ("type_identifier", "pointer_type"):
                                embedded.append(node_text(c, source))

        signature = f"type {name} struct"

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
            metadata={
                "is_struct": True,
                "is_exported": name[0].isupper() if name else False,
                "fields": fields,
                "embedded": embedded,
            },
        )

    def _parse_interface(
        self,
        name: str,
        node: 'Node',
        type_node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
        span: CodeSpan,
        code: str,
    ) -> CodeUnit:
        """解析接口"""
        # 提取方法签名
        methods = []
        for method in find_all_by_type(type_node, "method_spec"):
            method_name = ""
            for child in method.children:
                if child.type == "field_identifier":
                    method_name = node_text(child, source)
                    break
            if method_name:
                methods.append(method_name)

        # 检查嵌入接口
        embedded = []
        for child in type_node.children:
            if child.type == "type_identifier":
                embedded.append(node_text(child, source))

        signature = f"type {name} interface"

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
            metadata={
                "is_interface": True,
                "is_exported": name[0].isupper() if name else False,
                "methods": methods,
                "embedded": embedded,
            },
        )

    def _is_http_handler(self, name: str, params: str, code: str) -> bool:
        """判断是否是 HTTP 处理器"""
        # 检查函数名
        if name in HTTP_HANDLER_PATTERNS:
            return True

        # 检查参数签名
        handler_signatures = [
            "http.ResponseWriter",
            "*http.Request",
            "gin.Context",
            "echo.Context",
            "fiber.Ctx",
            "*fiber.Ctx",
        ]
        for sig in handler_signatures:
            if sig in params:
                return True

        return False

    def _extract_imports_list(self, node: 'Node', source: bytes) -> List[str]:
        """提取导入列表"""
        imports: List[str] = []

        for import_decl in find_all_by_type(node, "import_declaration"):
            for import_spec in find_all_by_type(import_decl, "import_spec"):
                path_node = find_child_by_field(import_spec, "path")
                if path_node:
                    path = node_text(path_node, source).strip('"')
                    imports.append(path)

        return imports


# ============================================================
# Generic AST 转换器
# ============================================================

@ConverterRegistry.register
class GoConverter(GenericASTConverter):
    """Go Generic AST 转换器"""

    language_name = "go"

    def get_function_node_types(self) -> List[str]:
        return [
            "function_declaration",
            "method_declaration",
            "func_literal",
        ]

    def get_class_node_types(self) -> List[str]:
        return [
            "type_spec",  # 包含 struct 和 interface
        ]

    def get_call_node_types(self) -> List[str]:
        return [
            "call_expression",
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

        # 返回类型
        return_type = None
        result_node = node.child_by_field_name("result")
        if result_node:
            return_type = self.get_node_text(result_node)

        # Go 使用首字母大小写决定可见性
        visibility = Visibility.PUBLIC if name and name[0].isupper() else Visibility.PRIVATE

        kind = NodeKind.FUNCTION
        if node.type == "method_declaration":
            kind = NodeKind.METHOD
        elif node.type == "func_literal":
            kind = NodeKind.LAMBDA

        # 获取接收者类型
        receiver_type = None
        if node.type == "method_declaration":
            receiver_node = node.child_by_field_name("receiver")
            if receiver_node:
                for child in receiver_node.children:
                    if child.type == "parameter_declaration":
                        type_node = child.child_by_field_name("type")
                        if type_node:
                            receiver_type = self.get_node_text(type_node)

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
            receiver_type=receiver_type,
        )

    def convert_class(self, node: 'Node') -> Optional[GenericClass]:
        """转换类型节点（结构体/接口）"""
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<anonymous>"

        type_node = node.child_by_field_name("type")
        if not type_node:
            return None

        is_interface = type_node.type == "interface_type"
        kind = NodeKind.INTERFACE if is_interface else NodeKind.STRUCT

        # 获取嵌入类型
        bases = []
        if type_node.type == "struct_type":
            field_list = type_node.child_by_field_name("field_declaration_list") or \
                         next((c for c in type_node.children if c.type == "field_declaration_list"), None)
            if field_list:
                for field in field_list.children:
                    if field.type == "field_declaration":
                        # 检查是否是嵌入字段
                        has_name = any(c.type == "field_identifier" for c in field.children)
                        if not has_name:
                            for c in field.children:
                                if c.type in ("type_identifier", "pointer_type"):
                                    bases.append(self.get_node_text(c))

        return GenericClass(
            kind=kind,
            name=name,
            span=self.get_node_span(node),
            source_language=self.language_name,
            raw_node=node,
            bases=bases,
            is_interface=is_interface,
        )

    def convert_call(self, node: 'Node') -> Optional[GenericCall]:
        """转换调用节点"""
        func_node = node.child_by_field_name("function")
        if not func_node:
            return None

        full_name = self.get_node_text(func_node)

        # 分离包/对象和函数名
        if func_node.type == "selector_expression":
            operand = func_node.child_by_field_name("operand")
            field = func_node.child_by_field_name("field")
            receiver = self.get_node_text(operand) if operand else None
            callee = self.get_node_text(field) if field else full_name
        else:
            receiver = None
            callee = full_name

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
        path_node = node.child_by_field_name("path")
        if path_node:
            module = self.get_node_text(path_node).strip('"')
            # 获取别名
            name_node = node.child_by_field_name("name")
            alias = self.get_node_text(name_node) if name_node else None

            return GenericImport(
                module=module,
                names=[],
                alias=alias,
                span=self.get_node_span(node),
            )
        return None

    def extract_parameters(self, params_node: 'Node') -> List[GenericParameter]:
        """提取参数列表"""
        params = []
        for child in params_node.children:
            if child.type == "parameter_declaration":
                # Go 参数可以是 name type 或 多个name type
                names = []
                type_ann = None
                for c in child.children:
                    if c.type == "identifier":
                        names.append(self.get_node_text(c))
                    elif c.type in ("type_identifier", "pointer_type",
                                    "slice_type", "map_type", "array_type",
                                    "interface_type", "struct_type",
                                    "function_type", "channel_type"):
                        type_ann = self.get_node_text(c)

                for name in names:
                    params.append(GenericParameter(
                        name=name,
                        type_annotation=type_ann,
                    ))

            elif child.type == "variadic_parameter_declaration":
                name_node = child.child_by_field_name("name")
                if name_node:
                    params.append(GenericParameter(
                        name=self.get_node_text(name_node),
                        is_variadic=True,
                    ))

        return params
