"""
Generic AST 节点定义

提供跨语言的通用 AST 节点类型，借鉴 Semgrep 的 Generic AST 设计。
所有语言特定的 AST 都可以转换为这些通用节点，便于：
- 编写跨语言的安全规则
- 统一的分析接口
- 简化漏洞检测逻辑
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union
from enum import Enum


class NodeKind(Enum):
    """通用节点类型枚举

    定义所有支持的 AST 节点类型。
    """
    # 定义类型
    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    INTERFACE = "interface"
    STRUCT = "struct"
    TRAIT = "trait"
    ENUM = "enum"
    MODULE = "module"

    # 表达式类型
    CALL = "call"
    VARIABLE = "variable"
    PARAMETER = "parameter"
    LITERAL = "literal"
    OPERATOR = "operator"
    ASSIGNMENT = "assignment"
    BINARY_EXPR = "binary_expression"
    UNARY_EXPR = "unary_expression"
    MEMBER_ACCESS = "member_access"
    INDEX_ACCESS = "index_access"
    CONDITIONAL = "conditional"

    # 语句类型
    BLOCK = "block"
    IF = "if"
    FOR = "for"
    WHILE = "while"
    RETURN = "return"
    THROW = "throw"
    TRY = "try"

    # 声明类型
    IMPORT = "import"
    EXPORT = "export"
    DECORATOR = "decorator"
    ANNOTATION = "annotation"

    # 其他
    COMMENT = "comment"
    UNKNOWN = "unknown"


class Visibility(Enum):
    """可见性修饰符"""
    PUBLIC = "public"
    PRIVATE = "private"
    PROTECTED = "protected"
    INTERNAL = "internal"
    PACKAGE = "package"


@dataclass
class Span:
    """代码位置信息

    表示代码在源文件中的位置范围。
    """
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    start_byte: int = 0
    end_byte: int = 0

    def contains(self, other: 'Span') -> bool:
        """检查是否包含另一个位置"""
        return (
            self.start_line <= other.start_line and
            self.end_line >= other.end_line and
            (self.start_line < other.start_line or self.start_column <= other.start_column) and
            (self.end_line > other.end_line or self.end_column >= other.end_column)
        )

    def overlaps(self, other: 'Span') -> bool:
        """检查是否与另一个位置重叠"""
        return not (
            self.end_line < other.start_line or
            other.end_line < self.start_line or
            (self.end_line == other.start_line and self.end_column < other.start_column) or
            (other.end_line == self.start_line and other.end_column < self.start_column)
        )

    def to_dict(self) -> Dict[str, int]:
        """转换为字典"""
        return {
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "start_byte": self.start_byte,
            "end_byte": self.end_byte,
        }


@dataclass
class GenericNode:
    """通用 AST 节点基类

    所有 Generic AST 节点的基类，包含通用属性。
    """
    kind: NodeKind
    name: str
    span: Span
    source_language: str
    raw_node: Any = None  # 保留原始 Tree-sitter 节点引用（可选）
    attributes: Dict[str, Any] = field(default_factory=dict)
    children: List['GenericNode'] = field(default_factory=list)

    def find_children_by_kind(self, kind: NodeKind) -> List['GenericNode']:
        """查找指定类型的子节点"""
        return [child for child in self.children if child.kind == kind]

    def find_descendant_by_kind(self, kind: NodeKind) -> Optional['GenericNode']:
        """递归查找指定类型的后代节点"""
        for child in self.children:
            if child.kind == kind:
                return child
            result = child.find_descendant_by_kind(kind)
            if result:
                return result
        return None

    def find_all_descendants_by_kind(self, kind: NodeKind) -> List['GenericNode']:
        """递归查找所有指定类型的后代节点"""
        result = []
        for child in self.children:
            if child.kind == kind:
                result.append(child)
            result.extend(child.find_all_descendants_by_kind(kind))
        return result

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "kind": self.kind.value,
            "name": self.name,
            "span": self.span.to_dict(),
            "source_language": self.source_language,
            "attributes": self.attributes,
            "children": [child.to_dict() for child in self.children],
        }


@dataclass
class GenericParameter:
    """通用参数表示

    表示函数/方法的参数。
    """
    name: str
    type_annotation: Optional[str] = None
    default_value: Optional[str] = None
    is_variadic: bool = False  # *args / ...rest / vararg
    is_keyword: bool = False   # **kwargs
    span: Optional[Span] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type_annotation": self.type_annotation,
            "default_value": self.default_value,
            "is_variadic": self.is_variadic,
            "is_keyword": self.is_keyword,
        }


@dataclass
class GenericVariable:
    """通用变量表示

    表示变量声明或字段。
    """
    name: str
    type_annotation: Optional[str] = None
    value: Optional[str] = None
    is_const: bool = False
    visibility: Visibility = Visibility.PUBLIC
    span: Optional[Span] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type_annotation": self.type_annotation,
            "value": self.value,
            "is_const": self.is_const,
            "visibility": self.visibility.value,
        }


@dataclass
class GenericBlock:
    """通用代码块

    表示一个代码块（花括号包围的语句列表）。
    """
    statements: List[GenericNode] = field(default_factory=list)
    span: Optional[Span] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "statements": [stmt.to_dict() for stmt in self.statements],
            "span": self.span.to_dict() if self.span else None,
        }


@dataclass
class GenericImport:
    """通用导入表示

    表示导入语句。
    """
    module: str
    names: List[str] = field(default_factory=list)  # 导入的具体名称
    alias: Optional[str] = None
    is_wildcard: bool = False  # import *
    is_default: bool = False   # import default
    span: Optional[Span] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "names": self.names,
            "alias": self.alias,
            "is_wildcard": self.is_wildcard,
            "is_default": self.is_default,
        }


@dataclass
class GenericCall(GenericNode):
    """通用函数调用表示

    表示函数/方法调用。
    """
    callee: str = ""  # 被调用的函数/方法名
    receiver: Optional[str] = None  # obj.method() 中的 obj
    arguments: List[GenericNode] = field(default_factory=list)
    is_constructor: bool = False  # new Class()
    is_static: bool = False       # Class.method()
    full_name: str = ""           # 完整限定名，如 os.system

    def __post_init__(self):
        if not self.full_name:
            if self.receiver:
                self.full_name = f"{self.receiver}.{self.callee}"
            else:
                self.full_name = self.callee

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "callee": self.callee,
            "receiver": self.receiver,
            "full_name": self.full_name,
            "is_constructor": self.is_constructor,
            "is_static": self.is_static,
            "arguments": [arg.to_dict() for arg in self.arguments],
        })
        return base


@dataclass
class GenericFunction(GenericNode):
    """通用函数表示

    表示函数或方法定义。
    """
    parameters: List[GenericParameter] = field(default_factory=list)
    return_type: Optional[str] = None
    body: Optional[GenericBlock] = None
    calls: List[GenericCall] = field(default_factory=list)
    decorators: List[str] = field(default_factory=list)
    is_async: bool = False
    is_generator: bool = False
    is_static: bool = False
    is_abstract: bool = False
    visibility: Visibility = Visibility.PUBLIC
    parent_class: Optional[str] = None
    docstring: Optional[str] = None

    def get_signature(self) -> str:
        """生成函数签名"""
        params = ", ".join([
            f"{p.name}: {p.type_annotation}" if p.type_annotation else p.name
            for p in self.parameters
        ])
        sig = f"{'async ' if self.is_async else ''}def {self.name}({params})"
        if self.return_type:
            sig += f" -> {self.return_type}"
        return sig

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "parameters": [p.to_dict() for p in self.parameters],
            "return_type": self.return_type,
            "calls": [c.to_dict() for c in self.calls],
            "decorators": self.decorators,
            "is_async": self.is_async,
            "is_generator": self.is_generator,
            "is_static": self.is_static,
            "visibility": self.visibility.value,
            "parent_class": self.parent_class,
            "docstring": self.docstring,
        })
        return base


@dataclass
class GenericClass(GenericNode):
    """通用类表示

    表示类、接口、结构体等类型定义。
    """
    methods: List[GenericFunction] = field(default_factory=list)
    fields: List[GenericVariable] = field(default_factory=list)
    bases: List[str] = field(default_factory=list)  # 父类/接口
    decorators: List[str] = field(default_factory=list)
    is_abstract: bool = False
    is_interface: bool = False
    visibility: Visibility = Visibility.PUBLIC
    docstring: Optional[str] = None

    def get_method(self, name: str) -> Optional[GenericFunction]:
        """获取指定名称的方法"""
        for method in self.methods:
            if method.name == name:
                return method
        return None

    def get_field(self, name: str) -> Optional[GenericVariable]:
        """获取指定名称的字段"""
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "methods": [m.to_dict() for m in self.methods],
            "fields": [f.to_dict() for f in self.fields],
            "bases": self.bases,
            "decorators": self.decorators,
            "is_abstract": self.is_abstract,
            "is_interface": self.is_interface,
            "visibility": self.visibility.value,
            "docstring": self.docstring,
        })
        return base
