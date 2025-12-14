"""
代码属性图模块 (Code Property Graph)

功能：
1. 为每个函数构建图结构
2. 节点：语句/表达式/变量
3. 边：控制流/数据流/调用
4. 序列化为结构化摘要供 LLM 使用

参考：AST + CFG + DFG 合成的 Code Property Graph
"""

import json
import logging
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """节点类型"""
    # 声明类
    FUNCTION = "function"
    CLASS = "class"
    METHOD = "method"
    PARAMETER = "parameter"
    VARIABLE = "variable"
    CONSTANT = "constant"

    # 语句类
    ASSIGNMENT = "assignment"
    RETURN = "return"
    IF = "if"
    LOOP = "loop"
    TRY = "try"
    RAISE = "raise"
    CALL = "call"
    IMPORT = "import"

    # 表达式类
    BINARY_OP = "binary_op"
    UNARY_OP = "unary_op"
    ATTRIBUTE = "attribute"
    SUBSCRIPT = "subscript"
    LITERAL = "literal"

    # 特殊类
    ENTRY = "entry"
    EXIT = "exit"
    UNKNOWN = "unknown"


class EdgeType(Enum):
    """边类型"""
    # 控制流
    CONTROL_FLOW = "control_flow"           # 顺序执行
    CONTROL_TRUE = "control_true"           # 条件为真
    CONTROL_FALSE = "control_false"         # 条件为假
    CONTROL_EXCEPTION = "control_exception" # 异常流
    CONTROL_RETURN = "control_return"       # 返回

    # 数据流
    DATA_DEF = "data_def"                   # 变量定义
    DATA_USE = "data_use"                   # 变量使用
    DATA_FLOW = "data_flow"                 # 数据传递

    # 调用关系
    CALL = "call"                           # 函数调用
    CALL_ARG = "call_arg"                   # 调用参数
    CALL_RETURN = "call_return"             # 调用返回

    # AST 关系
    AST_CHILD = "ast_child"                 # AST 子节点
    AST_SIBLING = "ast_sibling"             # AST 兄弟节点


@dataclass
class GraphNode:
    """图节点"""
    id: str
    node_type: NodeType
    name: str                               # 节点名称（变量名/函数名等）
    line: int                               # 所在行号
    column: int = 0                         # 所在列

    # 代码信息
    code: str = ""                          # 节点对应的代码片段
    code_hash: str = ""                     # 代码 hash

    # 类型信息
    value_type: str = ""                    # 值类型（如果能推断）
    is_tainted: bool = False                # 是否被污染

    # 属性
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "node_type": self.node_type.value
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GraphNode":
        data["node_type"] = NodeType(data.get("node_type", "unknown"))
        return cls(**data)


@dataclass
class GraphEdge:
    """图边"""
    source_id: str
    target_id: str
    edge_type: EdgeType

    # 属性
    label: str = ""                         # 边标签
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "edge_type": self.edge_type.value
        }


@dataclass
class CodePropertyGraph:
    """代码属性图"""
    id: str
    name: str                               # 函数/类名
    file_path: str
    language: str

    # 图结构
    nodes: Dict[str, GraphNode] = field(default_factory=dict)
    edges: List[GraphEdge] = field(default_factory=list)

    # 索引
    entry_node_id: Optional[str] = None
    exit_node_ids: List[str] = field(default_factory=list)

    # 代码范围
    line_start: int = 0
    line_end: int = 0
    code: str = ""

    # 元数据
    complexity: int = 0                     # 圈复杂度
    depth: int = 0                          # 最大嵌套深度

    def add_node(self, node: GraphNode) -> None:
        """添加节点"""
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """添加边"""
        self.edges.append(edge)

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """获取节点"""
        return self.nodes.get(node_id)

    def get_successors(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[str]:
        """获取后继节点"""
        successors = []
        for edge in self.edges:
            if edge.source_id == node_id:
                if edge_type is None or edge.edge_type == edge_type:
                    successors.append(edge.target_id)
        return successors

    def get_predecessors(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[str]:
        """获取前驱节点"""
        predecessors = []
        for edge in self.edges:
            if edge.target_id == node_id:
                if edge_type is None or edge.edge_type == edge_type:
                    predecessors.append(edge.source_id)
        return predecessors

    def get_data_flow_paths(
        self,
        source_id: str,
        sink_id: str,
        max_depth: int = 10,
    ) -> List[List[str]]:
        """获取数据流路径"""
        paths = []
        visited = set()

        def dfs(current: str, path: List[str]):
            if len(path) > max_depth:
                return
            if current == sink_id:
                paths.append(path.copy())
                return
            if current in visited:
                return

            visited.add(current)
            path.append(current)

            # 沿数据流边遍历
            for edge in self.edges:
                if edge.source_id == current and edge.edge_type in (
                    EdgeType.DATA_FLOW, EdgeType.DATA_USE, EdgeType.CALL_ARG
                ):
                    dfs(edge.target_id, path)

            path.pop()
            visited.remove(current)

        dfs(source_id, [])
        return paths

    def get_control_flow_paths(
        self,
        start_id: Optional[str] = None,
        end_id: Optional[str] = None,
        max_paths: int = 10,
    ) -> List[List[str]]:
        """获取控制流路径"""
        start = start_id or self.entry_node_id
        if not start:
            return []

        paths = []
        visited = set()

        def dfs(current: str, path: List[str]):
            if len(paths) >= max_paths:
                return
            if end_id and current == end_id:
                paths.append(path.copy())
                return
            if current in self.exit_node_ids and not end_id:
                paths.append(path.copy())
                return
            if current in visited:
                return

            visited.add(current)
            path.append(current)

            # 沿控制流边遍历
            for edge in self.edges:
                if edge.source_id == current and edge.edge_type in (
                    EdgeType.CONTROL_FLOW, EdgeType.CONTROL_TRUE,
                    EdgeType.CONTROL_FALSE, EdgeType.CONTROL_RETURN
                ):
                    dfs(edge.target_id, path)

            path.pop()
            visited.remove(current)

        dfs(start, [])
        return paths

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "file_path": self.file_path,
            "language": self.language,
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
            "entry_node_id": self.entry_node_id,
            "exit_node_ids": self.exit_node_ids,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "complexity": self.complexity,
            "depth": self.depth,
        }

    def to_summary(self, max_nodes: int = 20) -> str:
        """生成结构化摘要供 LLM 使用"""
        lines = [
            f"=== 函数: {self.name} ===",
            f"文件: {self.file_path}:{self.line_start}-{self.line_end}",
            f"复杂度: {self.complexity}, 嵌套深度: {self.depth}",
            "",
            "【数据流摘要】"
        ]

        # 提取关键数据流
        data_flows = self._extract_key_data_flows()
        for flow in data_flows[:5]:
            lines.append(f"  {flow}")

        lines.append("")
        lines.append("【控制流摘要】")

        # 提取关键控制结构
        control_structures = self._extract_control_structures()
        for struct in control_structures[:5]:
            lines.append(f"  {struct}")

        lines.append("")
        lines.append("【外部调用】")

        # 提取外部调用
        calls = self._extract_external_calls()
        for call in calls[:10]:
            lines.append(f"  - {call}")

        return "\n".join(lines)

    def _extract_key_data_flows(self) -> List[str]:
        """提取关键数据流描述"""
        flows = []

        # 找到所有参数节点
        params = [n for n in self.nodes.values() if n.node_type == NodeType.PARAMETER]

        for param in params:
            # 追踪参数的数据流
            uses = []
            for edge in self.edges:
                if edge.source_id == param.id and edge.edge_type in (
                    EdgeType.DATA_FLOW, EdgeType.DATA_USE
                ):
                    target = self.nodes.get(edge.target_id)
                    if target:
                        uses.append(target.name or target.code[:30])

            if uses:
                flows.append(f"参数 '{param.name}' → {' → '.join(uses[:3])}")

        return flows

    def _extract_control_structures(self) -> List[str]:
        """提取控制结构描述"""
        structures = []

        for node in self.nodes.values():
            if node.node_type == NodeType.IF:
                structures.append(f"条件分支 @ L{node.line}: {node.code[:50]}")
            elif node.node_type == NodeType.LOOP:
                structures.append(f"循环 @ L{node.line}: {node.code[:50]}")
            elif node.node_type == NodeType.TRY:
                structures.append(f"异常处理 @ L{node.line}")

        return structures

    def _extract_external_calls(self) -> List[str]:
        """提取外部调用"""
        calls = []

        for node in self.nodes.values():
            if node.node_type == NodeType.CALL:
                call_name = node.properties.get("callee", node.name)
                calls.append(f"{call_name}() @ L{node.line}")

        return calls


class CodeGraphBuilder:
    """代码图构建器"""

    def __init__(self, language: str = "python"):
        self.language = language
        self._node_counter = 0
        # 变量定义追踪：变量名 -> 定义节点ID
        self._var_definitions: Dict[str, str] = {}
        # 变量使用追踪：变量名 -> [使用节点ID列表]
        self._var_uses: Dict[str, List[str]] = defaultdict(list)
        # 前一个语句节点（用于控制流）
        self._prev_stmt_node: Optional[str] = None
        # 作用域栈（用于处理嵌套作用域）
        self._scope_stack: List[Dict[str, str]] = [{}]

    def _new_node_id(self) -> str:
        """生成新节点ID"""
        self._node_counter += 1
        return f"n{self._node_counter}"

    def _reset_state(self):
        """重置构建状态"""
        self._node_counter = 0
        self._var_definitions = {}
        self._var_uses = defaultdict(list)
        self._prev_stmt_node = None
        self._scope_stack = [{}]

    def _define_var(self, var_name: str, node_id: str):
        """记录变量定义"""
        self._var_definitions[var_name] = node_id
        if self._scope_stack:
            self._scope_stack[-1][var_name] = node_id

    def _use_var(self, var_name: str, node_id: str):
        """记录变量使用"""
        self._var_uses[var_name].append(node_id)

    def _get_var_definition(self, var_name: str) -> Optional[str]:
        """获取变量定义节点"""
        # 从内层作用域向外查找
        for scope in reversed(self._scope_stack):
            if var_name in scope:
                return scope[var_name]
        return self._var_definitions.get(var_name)

    def build_from_ast(
        self,
        ast_node: Any,
        file_path: str,
        code: str,
    ) -> CodePropertyGraph:
        """从 AST 构建代码图

        Args:
            ast_node: AST 节点（tree-sitter 或标准库 ast）
            file_path: 文件路径
            code: 原始代码

        Returns:
            代码属性图
        """
        # 根据语言选择具体实现
        if self.language == "python":
            return self._build_python_graph(ast_node, file_path, code)
        elif self.language in ("javascript", "typescript"):
            return self._build_js_graph(ast_node, file_path, code)
        else:
            return self._build_generic_graph(ast_node, file_path, code)

    def _build_python_graph(
        self,
        ast_node: Any,
        file_path: str,
        code: str,
    ) -> CodePropertyGraph:
        """构建 Python 代码图"""
        import ast as python_ast

        # 重置状态
        self._reset_state()

        graph_id = hashlib.md5(f"{file_path}:{code[:100]}".encode()).hexdigest()[:12]

        graph = CodePropertyGraph(
            id=graph_id,
            name="",
            file_path=file_path,
            language="python",
            code=code,
        )

        # 解析 AST
        try:
            tree = python_ast.parse(code)
        except SyntaxError as e:
            logger.warning(f"Failed to parse Python code: {e}")
            return graph

        # 遍历 AST 构建图
        self._process_python_node(tree, graph, None)

        # 构建数据流边
        self._build_data_flow_edges(graph)

        # 计算复杂度
        graph.complexity = self._calculate_complexity(graph)
        graph.depth = self._calculate_depth(tree)

        return graph

    def _build_data_flow_edges(self, graph: CodePropertyGraph):
        """构建数据流边：从变量定义到变量使用"""
        for var_name, use_nodes in self._var_uses.items():
            def_node_id = self._get_var_definition(var_name)
            if def_node_id and def_node_id in graph.nodes:
                for use_node_id in use_nodes:
                    if use_node_id in graph.nodes and use_node_id != def_node_id:
                        graph.add_edge(GraphEdge(
                            source_id=def_node_id,
                            target_id=use_node_id,
                            edge_type=EdgeType.DATA_FLOW,
                            label=var_name,
                        ))

    def _process_python_node(
        self,
        node: Any,
        graph: CodePropertyGraph,
        parent_id: Optional[str],
    ) -> Optional[str]:
        """处理 Python AST 节点"""
        import ast as python_ast

        node_id = self._new_node_id()

        # 根据节点类型创建图节点
        if isinstance(node, python_ast.FunctionDef):
            gnode = GraphNode(
                id=node_id,
                node_type=NodeType.FUNCTION,
                name=node.name,
                line=node.lineno,
                column=node.col_offset,
                code=python_ast.unparse(node) if hasattr(python_ast, 'unparse') else "",
            )
            graph.name = node.name
            graph.line_start = node.lineno
            graph.line_end = node.end_lineno or node.lineno
            graph.entry_node_id = node_id

            # 进入新作用域
            self._scope_stack.append({})

            # 处理参数 - 作为变量定义
            for arg in node.args.args:
                arg_id = self._new_node_id()
                arg_node = GraphNode(
                    id=arg_id,
                    node_type=NodeType.PARAMETER,
                    name=arg.arg,
                    line=arg.lineno if hasattr(arg, 'lineno') else node.lineno,
                )
                graph.add_node(arg_node)
                graph.add_edge(GraphEdge(
                    source_id=node_id,
                    target_id=arg_id,
                    edge_type=EdgeType.AST_CHILD,
                ))
                # 记录参数定义
                self._define_var(arg.arg, arg_id)

            # 添加节点后处理函数体
            graph.add_node(gnode)

            # 处理函数体，收集语句节点用于控制流
            prev_stmt = None
            for stmt in node.body:
                stmt_id = self._process_python_node(stmt, graph, node_id)
                if stmt_id and prev_stmt:
                    # 添加顺序控制流边
                    graph.add_edge(GraphEdge(
                        source_id=prev_stmt,
                        target_id=stmt_id,
                        edge_type=EdgeType.CONTROL_FLOW,
                    ))
                if stmt_id:
                    # 从函数入口到第一个语句的控制流
                    if prev_stmt is None:
                        graph.add_edge(GraphEdge(
                            source_id=node_id,
                            target_id=stmt_id,
                            edge_type=EdgeType.CONTROL_FLOW,
                        ))
                    prev_stmt = stmt_id

            # 离开作用域
            self._scope_stack.pop()
            return node_id

        elif isinstance(node, python_ast.ClassDef):
            gnode = GraphNode(
                id=node_id,
                node_type=NodeType.CLASS,
                name=node.name,
                line=node.lineno,
            )

        elif isinstance(node, python_ast.Assign):
            # 获取赋值目标
            targets = []
            for t in node.targets:
                if isinstance(t, python_ast.Name):
                    targets.append(t.id)
                    # 记录变量定义
                    self._define_var(t.id, node_id)
                elif isinstance(t, python_ast.Tuple):
                    for elt in t.elts:
                        if isinstance(elt, python_ast.Name):
                            targets.append(elt.id)
                            self._define_var(elt.id, node_id)

            gnode = GraphNode(
                id=node_id,
                node_type=NodeType.ASSIGNMENT,
                name=", ".join(targets) if targets else "assign",
                line=node.lineno,
                code=python_ast.unparse(node) if hasattr(python_ast, 'unparse') else "",
            )

            # 检查赋值右侧的变量使用
            self._extract_var_uses(node.value, node_id)

        elif isinstance(node, python_ast.If):
            gnode = GraphNode(
                id=node_id,
                node_type=NodeType.IF,
                name="if",
                line=node.lineno,
                code=python_ast.unparse(node.test) if hasattr(python_ast, 'unparse') else "",
            )
            # 检查条件中的变量使用
            self._extract_var_uses(node.test, node_id)

            # 处理 if 分支
            graph.add_node(gnode)

            # 处理 then 分支
            if node.body:
                first_then = None
                prev_then = None
                for stmt in node.body:
                    stmt_id = self._process_python_node(stmt, graph, node_id)
                    if stmt_id:
                        if first_then is None:
                            first_then = stmt_id
                            graph.add_edge(GraphEdge(
                                source_id=node_id,
                                target_id=stmt_id,
                                edge_type=EdgeType.CONTROL_TRUE,
                            ))
                        if prev_then:
                            graph.add_edge(GraphEdge(
                                source_id=prev_then,
                                target_id=stmt_id,
                                edge_type=EdgeType.CONTROL_FLOW,
                            ))
                        prev_then = stmt_id

            # 处理 else 分支
            if node.orelse:
                first_else = None
                prev_else = None
                for stmt in node.orelse:
                    stmt_id = self._process_python_node(stmt, graph, node_id)
                    if stmt_id:
                        if first_else is None:
                            first_else = stmt_id
                            graph.add_edge(GraphEdge(
                                source_id=node_id,
                                target_id=stmt_id,
                                edge_type=EdgeType.CONTROL_FALSE,
                            ))
                        if prev_else:
                            graph.add_edge(GraphEdge(
                                source_id=prev_else,
                                target_id=stmt_id,
                                edge_type=EdgeType.CONTROL_FLOW,
                            ))
                        prev_else = stmt_id

            return node_id

        elif isinstance(node, (python_ast.For, python_ast.While)):
            gnode = GraphNode(
                id=node_id,
                node_type=NodeType.LOOP,
                name="for" if isinstance(node, python_ast.For) else "while",
                line=node.lineno,
                code=python_ast.unparse(node.iter if isinstance(node, python_ast.For) else node.test)
                     if hasattr(python_ast, 'unparse') else "",
            )

            # 对于 for 循环，记录循环变量定义
            if isinstance(node, python_ast.For):
                if isinstance(node.target, python_ast.Name):
                    self._define_var(node.target.id, node_id)
                self._extract_var_uses(node.iter, node_id)
            else:
                self._extract_var_uses(node.test, node_id)

            graph.add_node(gnode)

            # 处理循环体
            prev_body = None
            for stmt in node.body:
                stmt_id = self._process_python_node(stmt, graph, node_id)
                if stmt_id:
                    if prev_body is None:
                        graph.add_edge(GraphEdge(
                            source_id=node_id,
                            target_id=stmt_id,
                            edge_type=EdgeType.CONTROL_TRUE,
                        ))
                    else:
                        graph.add_edge(GraphEdge(
                            source_id=prev_body,
                            target_id=stmt_id,
                            edge_type=EdgeType.CONTROL_FLOW,
                        ))
                    prev_body = stmt_id

            return node_id

        elif isinstance(node, python_ast.Try):
            gnode = GraphNode(
                id=node_id,
                node_type=NodeType.TRY,
                name="try",
                line=node.lineno,
            )

        elif isinstance(node, python_ast.Return):
            gnode = GraphNode(
                id=node_id,
                node_type=NodeType.RETURN,
                name="return",
                line=node.lineno,
                code=python_ast.unparse(node) if hasattr(python_ast, 'unparse') else "",
            )
            graph.exit_node_ids.append(node_id)

            # 检查返回值中的变量使用
            if node.value:
                self._extract_var_uses(node.value, node_id)

        elif isinstance(node, python_ast.Expr):
            # 表达式语句（如函数调用）
            if isinstance(node.value, python_ast.Call):
                return self._process_python_node(node.value, graph, parent_id)
            else:
                gnode = GraphNode(
                    id=node_id,
                    node_type=NodeType.UNKNOWN,
                    name="expr",
                    line=node.lineno,
                )

        elif isinstance(node, python_ast.Call):
            callee = ""
            if isinstance(node.func, python_ast.Name):
                callee = node.func.id
            elif isinstance(node.func, python_ast.Attribute):
                # 处理 obj.method() 形式
                if isinstance(node.func.value, python_ast.Name):
                    callee = f"{node.func.value.id}.{node.func.attr}"
                    # 记录对象的使用
                    self._use_var(node.func.value.id, node_id)
                else:
                    callee = node.func.attr

            gnode = GraphNode(
                id=node_id,
                node_type=NodeType.CALL,
                name=callee,
                line=node.lineno,
                code=python_ast.unparse(node) if hasattr(python_ast, 'unparse') else "",
                properties={"callee": callee}
            )

            # 检查参数中的变量使用
            for arg in node.args:
                self._extract_var_uses(arg, node_id)
            for kw in node.keywords:
                self._extract_var_uses(kw.value, node_id)

        elif isinstance(node, python_ast.Name):
            # 变量引用
            gnode = GraphNode(
                id=node_id,
                node_type=NodeType.VARIABLE,
                name=node.id,
                line=node.lineno if hasattr(node, 'lineno') else 0,
            )
            # 记录变量使用
            if isinstance(node.ctx, python_ast.Load):
                self._use_var(node.id, node_id)

        elif isinstance(node, python_ast.Module):
            # 模块节点，直接处理子节点
            prev_stmt = None
            for stmt in node.body:
                stmt_id = self._process_python_node(stmt, graph, None)
                if stmt_id and prev_stmt:
                    graph.add_edge(GraphEdge(
                        source_id=prev_stmt,
                        target_id=stmt_id,
                        edge_type=EdgeType.CONTROL_FLOW,
                    ))
                prev_stmt = stmt_id
            return None

        else:
            gnode = GraphNode(
                id=node_id,
                node_type=NodeType.UNKNOWN,
                name=type(node).__name__,
                line=getattr(node, 'lineno', 0),
            )

        graph.add_node(gnode)

        # 添加 AST 父子边
        if parent_id:
            graph.add_edge(GraphEdge(
                source_id=parent_id,
                target_id=node_id,
                edge_type=EdgeType.AST_CHILD,
            ))

        return node_id

    def _extract_var_uses(self, node: Any, use_node_id: str):
        """从 AST 节点中提取变量使用"""
        import ast as python_ast

        if isinstance(node, python_ast.Name):
            if isinstance(node.ctx, python_ast.Load):
                self._use_var(node.id, use_node_id)
        elif isinstance(node, python_ast.BinOp):
            self._extract_var_uses(node.left, use_node_id)
            self._extract_var_uses(node.right, use_node_id)
        elif isinstance(node, python_ast.Compare):
            self._extract_var_uses(node.left, use_node_id)
            for comp in node.comparators:
                self._extract_var_uses(comp, use_node_id)
        elif isinstance(node, python_ast.Call):
            if isinstance(node.func, python_ast.Name):
                pass  # 函数名不算变量使用
            elif isinstance(node.func, python_ast.Attribute):
                if isinstance(node.func.value, python_ast.Name):
                    self._use_var(node.func.value.id, use_node_id)
            for arg in node.args:
                self._extract_var_uses(arg, use_node_id)
            for kw in node.keywords:
                self._extract_var_uses(kw.value, use_node_id)
        elif isinstance(node, python_ast.Subscript):
            self._extract_var_uses(node.value, use_node_id)
            self._extract_var_uses(node.slice, use_node_id)
        elif isinstance(node, python_ast.Attribute):
            self._extract_var_uses(node.value, use_node_id)
        elif isinstance(node, (python_ast.List, python_ast.Tuple, python_ast.Set)):
            for elt in node.elts:
                self._extract_var_uses(elt, use_node_id)
        elif isinstance(node, python_ast.Dict):
            for k in node.keys:
                if k:
                    self._extract_var_uses(k, use_node_id)
            for v in node.values:
                self._extract_var_uses(v, use_node_id)
        elif isinstance(node, python_ast.JoinedStr):  # f-string
            for val in node.values:
                if isinstance(val, python_ast.FormattedValue):
                    self._extract_var_uses(val.value, use_node_id)
        elif isinstance(node, python_ast.UnaryOp):
            self._extract_var_uses(node.operand, use_node_id)
        elif isinstance(node, python_ast.IfExp):
            self._extract_var_uses(node.test, use_node_id)
            self._extract_var_uses(node.body, use_node_id)
            self._extract_var_uses(node.orelse, use_node_id)

    def _build_js_graph(
        self,
        ast_node: Any,
        file_path: str,
        code: str,
    ) -> CodePropertyGraph:
        """构建 JavaScript 代码图（简化版）"""
        graph_id = hashlib.md5(f"{file_path}:{code[:100]}".encode()).hexdigest()[:12]

        graph = CodePropertyGraph(
            id=graph_id,
            name="",
            file_path=file_path,
            language="javascript",
            code=code,
        )

        # 简单的正则解析（实际应使用 tree-sitter）
        import re

        # 提取函数
        func_pattern = r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))'
        for match in re.finditer(func_pattern, code):
            name = match.group(1) or match.group(2)
            node_id = self._new_node_id()
            graph.add_node(GraphNode(
                id=node_id,
                node_type=NodeType.FUNCTION,
                name=name,
                line=code[:match.start()].count('\n') + 1,
            ))
            if not graph.name:
                graph.name = name
                graph.entry_node_id = node_id

        # 提取调用
        call_pattern = r'(\w+)\s*\('
        for match in re.finditer(call_pattern, code):
            name = match.group(1)
            if name not in ('if', 'while', 'for', 'function', 'class'):
                node_id = self._new_node_id()
                graph.add_node(GraphNode(
                    id=node_id,
                    node_type=NodeType.CALL,
                    name=name,
                    line=code[:match.start()].count('\n') + 1,
                    properties={"callee": name}
                ))

        return graph

    def _build_generic_graph(
        self,
        ast_node: Any,
        file_path: str,
        code: str,
    ) -> CodePropertyGraph:
        """构建通用代码图（基于正则的简化版）"""
        graph_id = hashlib.md5(f"{file_path}:{code[:100]}".encode()).hexdigest()[:12]

        return CodePropertyGraph(
            id=graph_id,
            name="unknown",
            file_path=file_path,
            language=self.language,
            code=code,
        )

    def _calculate_complexity(self, graph: CodePropertyGraph) -> int:
        """计算圈复杂度"""
        # 圈复杂度 = E - N + 2P
        # 简化：计算决策点数量 + 1
        decision_count = 0
        for node in graph.nodes.values():
            if node.node_type in (NodeType.IF, NodeType.LOOP, NodeType.TRY):
                decision_count += 1
        return decision_count + 1

    def _calculate_depth(self, ast_node: Any) -> int:
        """计算最大嵌套深度"""
        import ast as python_ast

        max_depth = 0

        def visit(node, depth):
            nonlocal max_depth
            max_depth = max(max_depth, depth)

            for child in python_ast.iter_child_nodes(node):
                if isinstance(child, (python_ast.If, python_ast.For, python_ast.While,
                                     python_ast.Try, python_ast.With)):
                    visit(child, depth + 1)
                else:
                    visit(child, depth)

        visit(ast_node, 0)
        return max_depth


class CodeGraphManager:
    """代码图管理器"""

    def __init__(self, storage_dir: str = ".audit_data/code_graphs"):
        self.storage_dir = storage_dir
        self.graphs: Dict[str, CodePropertyGraph] = {}

        # 创建存储目录
        from pathlib import Path
        Path(storage_dir).mkdir(parents=True, exist_ok=True)

    def build_graph(
        self,
        code: str,
        file_path: str,
        language: str,
    ) -> CodePropertyGraph:
        """构建并存储代码图"""
        builder = CodeGraphBuilder(language)
        graph = builder.build_from_ast(None, file_path, code)

        self.graphs[graph.id] = graph
        return graph

    def get_graph(self, graph_id: str) -> Optional[CodePropertyGraph]:
        """获取代码图"""
        return self.graphs.get(graph_id)

    def search_similar_structures(
        self,
        pattern_graph: CodePropertyGraph,
        top_k: int = 10,
    ) -> List[Tuple[str, float]]:
        """搜索相似结构的代码图"""
        similarities = []

        pattern_features = self._extract_features(pattern_graph)

        for graph_id, graph in self.graphs.items():
            if graph_id == pattern_graph.id:
                continue

            features = self._extract_features(graph)
            similarity = self._calculate_similarity(pattern_features, features)
            similarities.append((graph_id, similarity))

        # 按相似度排序
        similarities.sort(key=lambda x: x[1], reverse=True)
        return similarities[:top_k]

    def _extract_features(self, graph: CodePropertyGraph) -> Dict[str, Any]:
        """提取图特征"""
        node_types = defaultdict(int)
        edge_types = defaultdict(int)

        for node in graph.nodes.values():
            node_types[node.node_type.value] += 1

        for edge in graph.edges:
            edge_types[edge.edge_type.value] += 1

        return {
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "node_types": dict(node_types),
            "edge_types": dict(edge_types),
            "complexity": graph.complexity,
            "depth": graph.depth,
        }

    def _calculate_similarity(
        self,
        features1: Dict[str, Any],
        features2: Dict[str, Any],
    ) -> float:
        """计算特征相似度"""
        # 简单的特征向量余弦相似度
        all_node_types = set(features1.get("node_types", {}).keys()) | \
                        set(features2.get("node_types", {}).keys())

        vec1 = [features1.get("node_types", {}).get(t, 0) for t in all_node_types]
        vec2 = [features2.get("node_types", {}).get(t, 0) for t in all_node_types]

        # 添加其他特征
        vec1.extend([features1.get("complexity", 0), features1.get("depth", 0)])
        vec2.extend([features2.get("complexity", 0), features2.get("depth", 0)])

        # 余弦相似度
        dot = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = sum(a * a for a in vec1) ** 0.5
        norm2 = sum(b * b for b in vec2) ** 0.5

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return dot / (norm1 * norm2)

    def export_to_json(self, graph_id: str) -> Optional[str]:
        """导出图为 JSON"""
        graph = self.graphs.get(graph_id)
        if not graph:
            return None

        return json.dumps(graph.to_dict(), ensure_ascii=False, indent=2)

    def export_to_dot(self, graph_id: str) -> Optional[str]:
        """导出图为 DOT 格式（用于 Graphviz 可视化）"""
        graph = self.graphs.get(graph_id)
        if not graph:
            return None

        lines = ["digraph CodeGraph {"]
        lines.append("  rankdir=TB;")
        lines.append("  node [shape=box];")

        # 节点
        for node_id, node in graph.nodes.items():
            label = f"{node.node_type.value}\\n{node.name}"
            color = self._get_node_color(node.node_type)
            lines.append(f'  "{node_id}" [label="{label}", fillcolor="{color}", style="filled"];')

        # 边
        for edge in graph.edges:
            style = "solid" if edge.edge_type in (
                EdgeType.CONTROL_FLOW, EdgeType.CONTROL_TRUE, EdgeType.CONTROL_FALSE
            ) else "dashed"
            color = self._get_edge_color(edge.edge_type)
            lines.append(f'  "{edge.source_id}" -> "{edge.target_id}" [style="{style}", color="{color}"];')

        lines.append("}")
        return "\n".join(lines)

    def _get_node_color(self, node_type: NodeType) -> str:
        """获取节点颜色"""
        colors = {
            NodeType.FUNCTION: "#a8d5ba",
            NodeType.CLASS: "#a8c5d5",
            NodeType.CALL: "#f5d5a8",
            NodeType.IF: "#d5a8d5",
            NodeType.LOOP: "#d5d5a8",
            NodeType.RETURN: "#d5a8a8",
            NodeType.VARIABLE: "#e8e8e8",
            NodeType.PARAMETER: "#c8e8c8",
        }
        return colors.get(node_type, "#ffffff")

    def _get_edge_color(self, edge_type: EdgeType) -> str:
        """获取边颜色"""
        colors = {
            EdgeType.CONTROL_FLOW: "#333333",
            EdgeType.CONTROL_TRUE: "#00aa00",
            EdgeType.CONTROL_FALSE: "#aa0000",
            EdgeType.DATA_FLOW: "#0000aa",
            EdgeType.CALL: "#aa5500",
        }
        return colors.get(edge_type, "#666666")

    def get_summary_for_llm(self, graph_id: str) -> Optional[str]:
        """获取供 LLM 使用的结构化摘要"""
        graph = self.graphs.get(graph_id)
        if not graph:
            return None
        return graph.to_summary()

    def list_graphs(self) -> List[Dict[str, Any]]:
        """列出所有图"""
        return [
            {
                "id": g.id,
                "name": g.name,
                "file_path": g.file_path,
                "language": g.language,
                "node_count": len(g.nodes),
                "edge_count": len(g.edges),
                "complexity": g.complexity,
            }
            for g in self.graphs.values()
        ]
