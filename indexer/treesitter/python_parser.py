"""
Python Tree-sitter 解析器

提供基于 Tree-sitter 的 Python 解析能力，作为原生 AST 解析器的可选替代。

特性：
- 与原生 AST 解析器保持 API 兼容
- 支持 Python 3.6+ 语法
- 更好的错误恢复能力
- 统一的 Generic AST 中间层

使用场景：
- 需要与其他语言统一处理时
- 需要更好的错误恢复时
- 跨语言分析场景
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


# Python 危险函数（与原生解析器保持一致）
PYTHON_DANGEROUS_FUNCTIONS = {
    # 命令执行
    "os.system", "os.popen", "os.spawn", "os.spawnl", "os.spawnle",
    "os.spawnlp", "os.spawnlpe", "os.spawnv", "os.spawnve", "os.spawnvp",
    "os.exec", "os.execl", "os.execle", "os.execlp", "os.execlpe",
    "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "commands.getoutput", "commands.getstatusoutput",
    # eval 类
    "eval", "exec", "compile", "execfile",
    # 反序列化
    "pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load",
    "marshal.loads", "marshal.load",
    "yaml.load", "yaml.unsafe_load",
    "shelve.open",
    # 文件操作
    "open", "file", "os.open", "io.open",
    "os.read", "os.write", "os.remove", "os.unlink",
    "os.rename", "os.mkdir", "os.makedirs", "os.rmdir", "os.removedirs",
    "shutil.rmtree", "shutil.copy", "shutil.move",
    "pathlib.Path.read_text", "pathlib.Path.write_text",
    "pathlib.Path.read_bytes", "pathlib.Path.write_bytes",
    # 网络
    "urllib.request.urlopen", "urllib2.urlopen",
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "httplib.HTTPConnection", "http.client.HTTPConnection",
    "socket.socket", "socket.create_connection",
    # SQL
    "cursor.execute", "cursor.executemany",
    "connection.execute", "engine.execute",
    # 模板
    "render_template_string", "Template",
    "jinja2.Template", "mako.template.Template",
    # 反射
    "getattr", "setattr", "delattr",
    "__import__", "importlib.import_module",
}

# Flask/Django/FastAPI 路由装饰器
PYTHON_ROUTE_DECORATORS = {
    "route", "get", "post", "put", "delete", "patch",
    "api_view", "action",
    "app.route", "app.get", "app.post",
    "router.get", "router.post", "router.put", "router.delete",
    "blueprint.route",
}


# 注意：不使用 @TreeSitterParserRegistry.register
# Python 默认使用原生 AST，Tree-sitter 版本作为可选
class PythonTSParser(TreeSitterParser):
    """Python Tree-sitter 解析器（可选模式）

    不会自动注册，需要显式启用。
    """

    language_name = "python"
    extensions = [".py", ".pyw"]

    def _load_language(self) -> Optional['Language']:
        return LanguageLoader.load("python")

    def _extract_functions(
        self,
        tree: 'Tree',
        source: bytes,
        file_path: str
    ) -> List[CodeUnit]:
        units: List[CodeUnit] = []
        imports = self._extract_imports_list(tree.root_node, source)

        # 顶层函数
        for node in find_all_by_type(tree.root_node, "function_definition"):
            if self._is_top_level(node):
                unit = self._parse_function_node(node, source, file_path, imports)
                if unit:
                    units.append(unit)

        # 类内方法
        for class_node in find_all_by_type(tree.root_node, "class_definition"):
            class_name = self._get_node_name(class_node, source)
            if not class_name:
                continue

            body = find_child_by_field(class_node, "body")
            if body:
                for func_node in find_all_by_type(body, "function_definition"):
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

        for node in find_all_by_type(tree.root_node, "class_definition"):
            unit = self._parse_class_node(node, source, file_path, imports)
            if unit:
                units.append(unit)

        return units

    def _is_top_level(self, node: 'Node') -> bool:
        """检查节点是否在顶层"""
        parent = node.parent
        while parent:
            if parent.type == "class_definition":
                return False
            if parent.type == "function_definition":
                return False
            parent = parent.parent
        return True

    def _extract_calls(self, node: 'Node', source: bytes) -> List[str]:
        calls: Set[str] = set()

        for call_node in find_all_by_type(node, "call"):
            func_node = find_child_by_field(call_node, "function")
            if func_node:
                call_text = node_text(func_node, source)
                calls.add(call_text)

        return list(calls)

    def _parse_function_node(
        self,
        node: 'Node',
        source: bytes,
        file_path: str,
        imports: List[str],
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
        params = node_text(params_node, source) if params_node else "()"

        # 获取返回类型注解
        return_type = ""
        ret_node = find_child_by_field(node, "return_type")
        if ret_node:
            return_type = node_text(ret_node, source)

        # 检查装饰器
        decorators = self._extract_decorators(node, source)
        is_async = any(c.type == "async" for c in node.parent.children) if node.parent else False
        is_static = "staticmethod" in decorators
        is_classmethod = "classmethod" in decorators
        is_property = "property" in decorators

        # 构建签名
        prefix = ""
        if is_async:
            prefix = "async "

        signature = f"{prefix}def {name}{params}"
        if return_type:
            signature += f" -> {return_type}"

        calls = self._extract_calls(node, source)
        dangerous_calls = [c for c in calls if c in PYTHON_DANGEROUS_FUNCTIONS or
                          any(d in c for d in PYTHON_DANGEROUS_FUNCTIONS)]

        # 检查是否是路由处理器
        unit_type = CodeUnitType.METHOD if class_name else CodeUnitType.FUNCTION
        if any(dec in PYTHON_ROUTE_DECORATORS for dec in decorators):
            unit_type = CodeUnitType.HANDLER

        symbol = f"{class_name}.{name}" if class_name else name
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
            imports=imports,
            metadata={
                "decorators": decorators,
                "is_async": is_async,
                "is_static": is_static,
                "is_classmethod": is_classmethod,
                "is_property": is_property,
                "dangerous_calls": dangerous_calls,
            } if decorators or dangerous_calls or is_async else {},
        )

    def _parse_class_node(
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

        # 获取基类
        bases = []
        superclasses = find_child_by_field(node, "superclasses")
        if superclasses:
            for child in superclasses.children:
                if child.type not in (",", "(", ")"):
                    bases.append(node_text(child, source))

        # 检查装饰器
        decorators = self._extract_decorators(node, source)

        signature = f"class {name}"
        if bases:
            signature += f"({', '.join(bases)})"

        # 检查是否是控制器/视图类
        unit_type = CodeUnitType.CLASS
        if any(base in ("View", "APIView", "ViewSet", "Controller") for base in bases):
            unit_type = CodeUnitType.HANDLER
        if "controller" in decorators or "Controller" in name:
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
            imports=imports,
            metadata={
                "bases": bases,
                "decorators": decorators,
            } if bases or decorators else {},
        )

    def _extract_decorators(self, node: 'Node', source: bytes) -> List[str]:
        """提取装饰器名称"""
        decorators = []

        # 查找前面的 decorated_definition
        parent = node.parent
        if parent and parent.type == "decorated_definition":
            for child in parent.children:
                if child.type == "decorator":
                    # 提取装饰器名称
                    for sub in child.children:
                        if sub.type in ("identifier", "attribute", "call"):
                            dec_text = node_text(sub, source)
                            # 移除括号和参数
                            if "(" in dec_text:
                                dec_text = dec_text.split("(")[0]
                            decorators.append(dec_text)
                            break

        return decorators

    def _get_node_name(self, node: 'Node', source: bytes) -> Optional[str]:
        name_node = find_child_by_field(node, "name")
        return node_text(name_node, source) if name_node else None

    def _extract_imports_list(self, node: 'Node', source: bytes) -> List[str]:
        imports = []

        # import xxx
        for import_node in find_all_by_type(node, "import_statement"):
            imports.append(node_text(import_node, source))

        # from xxx import yyy
        for import_node in find_all_by_type(node, "import_from_statement"):
            imports.append(node_text(import_node, source))

        return imports


@ConverterRegistry.register
class PythonTSConverter(GenericASTConverter):
    """Python Tree-sitter Generic AST 转换器"""

    language_name = "python_ts"  # 避免与原生 Python 解析器冲突

    def get_function_node_types(self) -> List[str]:
        return ["function_definition", "lambda"]

    def get_class_node_types(self) -> List[str]:
        return ["class_definition"]

    def get_call_node_types(self) -> List[str]:
        return ["call"]

    def convert_function(self, node: 'Node') -> Optional[GenericFunction]:
        if node.type == "lambda":
            return GenericFunction(
                kind=NodeKind.LAMBDA,
                name="<lambda>",
                span=self.get_node_span(node),
                source_language="python",
                raw_node=node,
            )

        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<unknown>"

        # 检查是否在类内
        is_method = False
        parent = node.parent
        while parent:
            if parent.type == "class_definition":
                is_method = True
                break
            parent = parent.parent

        params = []
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = self._extract_parameters(params_node)

        calls = self.extract_calls_from_node(node)

        return GenericFunction(
            kind=NodeKind.METHOD if is_method else NodeKind.FUNCTION,
            name=name,
            span=self.get_node_span(node),
            source_language="python",
            raw_node=node,
            parameters=params,
            calls=calls,
        )

    def convert_class(self, node: 'Node') -> Optional[GenericClass]:
        name_node = node.child_by_field_name("name")
        name = self.get_node_text(name_node) if name_node else "<unknown>"

        bases = []
        superclasses = node.child_by_field_name("superclasses")
        if superclasses:
            for child in superclasses.children:
                if child.type not in (",", "(", ")"):
                    bases.append(self.get_node_text(child))

        return GenericClass(
            kind=NodeKind.CLASS,
            name=name,
            span=self.get_node_span(node),
            source_language="python",
            raw_node=node,
            bases=bases,
        )

    def convert_call(self, node: 'Node') -> Optional[GenericCall]:
        func_node = node.child_by_field_name("function")
        name = self.get_node_text(func_node) if func_node else ""

        # 提取参数
        args = []
        args_node = node.child_by_field_name("arguments")
        if args_node:
            for child in args_node.children:
                if child.type not in (",", "(", ")"):
                    args.append(self.get_node_text(child))

        return GenericCall(
            kind=NodeKind.CALL,
            name=name,
            span=self.get_node_span(node),
            source_language="python",
            raw_node=node,
            callee=name,
            full_name=name,
            arguments=args,
        )

    def _extract_parameters(self, params_node: 'Node') -> List[GenericParameter]:
        params = []
        for child in params_node.children:
            if child.type == "identifier":
                params.append(GenericParameter(name=self.get_node_text(child)))
            elif child.type == "typed_parameter":
                name_node = child.children[0] if child.children else None
                type_node = child.child_by_field_name("type")
                params.append(GenericParameter(
                    name=self.get_node_text(name_node) if name_node else "",
                    type_annotation=self.get_node_text(type_node) if type_node else None,
                ))
            elif child.type == "default_parameter":
                name_node = child.child_by_field_name("name")
                value_node = child.child_by_field_name("value")
                params.append(GenericParameter(
                    name=self.get_node_text(name_node) if name_node else "",
                    default_value=self.get_node_text(value_node) if value_node else None,
                ))
        return params


def enable_python_treesitter():
    """启用 Python Tree-sitter 解析器

    调用此函数后，Python 文件将使用 Tree-sitter 解析器而非原生 AST。
    """
    TreeSitterParserRegistry.register(PythonTSParser)
    logger.info("Python Tree-sitter parser enabled")


def disable_python_treesitter():
    """禁用 Python Tree-sitter 解析器

    恢复使用原生 AST 解析器。
    """
    if "python" in TreeSitterParserRegistry._parsers:
        del TreeSitterParserRegistry._parsers["python"]
        logger.info("Python Tree-sitter parser disabled")
