"""
Code Graph API Router
Provides API endpoints for building and analyzing code property graphs (CPG).
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid
import ast

router = APIRouter(prefix="/graph", tags=["graph"])

# In-memory storage for graphs (in production, use database)
_graphs_store: Dict[str, Dict[str, Any]] = {}


# ============ Pydantic Models ============

class BuildGraphRequest(BaseModel):
    """Request for building a code graph."""
    language: str = Field(default="python", description="Programming language")
    file_path: str = Field(default="example.py", description="File path")
    code: str = Field(..., description="Source code to analyze")


class DataFlowRequest(BaseModel):
    """Request for data flow analysis."""
    graph_id: str = Field(..., description="Graph ID")
    source_node_id: str = Field(..., description="Source node ID")
    sink_node_id: str = Field(..., description="Sink node ID")
    max_depth: int = Field(default=10, description="Maximum path depth")


class GraphNode(BaseModel):
    """A node in the code graph."""
    id: str
    name: str
    node_type: str
    line: int = 0
    code: Optional[str] = None


class GraphEdge(BaseModel):
    """An edge in the code graph."""
    source_id: str
    target_id: str
    edge_type: str
    label: Optional[str] = None


class GraphResponse(BaseModel):
    """Response containing a code graph."""
    success: bool
    graph: Optional[Dict[str, Any]] = None
    summary: Optional[str] = None
    error: Optional[str] = None


# ============ Helper Functions ============

def _generate_graph_id() -> str:
    """Generate a unique graph ID."""
    return str(uuid.uuid4())[:8]


def _parse_python_to_graph(code: str, file_path: str) -> Dict[str, Any]:
    """
    Parse Python code and build a code property graph.
    Returns nodes, edges, and metadata.
    """
    nodes = {}
    edges = []

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        # Return minimal graph for invalid code
        node_id = "error_0"
        nodes[node_id] = {
            "id": node_id,
            "name": "SyntaxError",
            "node_type": "error",
            "line": e.lineno or 0,
            "code": str(e)
        }
        return {
            "nodes": nodes,
            "edges": edges,
            "complexity": 0,
            "depth": 0
        }

    node_counter = [0]  # Use list to allow mutation in nested function

    def get_node_id() -> str:
        node_id = f"node_{node_counter[0]}"
        node_counter[0] += 1
        return node_id

    def visit_node(node: ast.AST, parent_id: Optional[str] = None, depth: int = 0) -> Optional[str]:
        """Recursively visit AST nodes and build graph."""
        node_id = None

        if isinstance(node, ast.FunctionDef):
            node_id = get_node_id()
            nodes[node_id] = {
                "id": node_id,
                "name": node.name,
                "node_type": "function",
                "line": node.lineno,
                "code": ast.get_source_segment(code, node) if hasattr(ast, 'get_source_segment') else None
            }

            # Add parameters
            for arg in node.args.args:
                arg_id = get_node_id()
                nodes[arg_id] = {
                    "id": arg_id,
                    "name": arg.arg,
                    "node_type": "parameter",
                    "line": node.lineno,
                    "code": None
                }
                edges.append({
                    "source_id": node_id,
                    "target_id": arg_id,
                    "edge_type": "has_parameter",
                    "label": "param"
                })

        elif isinstance(node, ast.ClassDef):
            node_id = get_node_id()
            nodes[node_id] = {
                "id": node_id,
                "name": node.name,
                "node_type": "class",
                "line": node.lineno,
                "code": None
            }

        elif isinstance(node, ast.Call):
            node_id = get_node_id()
            call_name = ""
            if isinstance(node.func, ast.Name):
                call_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    call_name = f"{node.func.value.id}.{node.func.attr}"
                else:
                    call_name = node.func.attr

            nodes[node_id] = {
                "id": node_id,
                "name": call_name,
                "node_type": "call",
                "line": node.lineno,
                "code": None
            }

        elif isinstance(node, ast.Assign):
            node_id = get_node_id()
            target_names = []
            for target in node.targets:
                if isinstance(target, ast.Name):
                    target_names.append(target.id)

            nodes[node_id] = {
                "id": node_id,
                "name": ", ".join(target_names) if target_names else "assignment",
                "node_type": "assignment",
                "line": node.lineno,
                "code": None
            }

        elif isinstance(node, ast.If):
            node_id = get_node_id()
            nodes[node_id] = {
                "id": node_id,
                "name": "if",
                "node_type": "if",
                "line": node.lineno,
                "code": None
            }

        elif isinstance(node, (ast.For, ast.While)):
            node_id = get_node_id()
            nodes[node_id] = {
                "id": node_id,
                "name": "for" if isinstance(node, ast.For) else "while",
                "node_type": "loop",
                "line": node.lineno,
                "code": None
            }

        elif isinstance(node, ast.Return):
            node_id = get_node_id()
            nodes[node_id] = {
                "id": node_id,
                "name": "return",
                "node_type": "return",
                "line": node.lineno,
                "code": None
            }

        # Add edge from parent
        if node_id and parent_id:
            edges.append({
                "source_id": parent_id,
                "target_id": node_id,
                "edge_type": "control_flow",
                "label": None
            })

        # Visit children
        current_parent = node_id or parent_id
        for child in ast.iter_child_nodes(node):
            child_id = visit_node(child, current_parent, depth + 1)

            # Add data flow edges for certain node types
            if child_id and node_id:
                child_node = nodes.get(child_id, {})
                if child_node.get("node_type") in ["call", "assignment"]:
                    edges.append({
                        "source_id": node_id,
                        "target_id": child_id,
                        "edge_type": "data_flow",
                        "label": None
                    })

        return node_id

    # Visit all top-level nodes
    for node in ast.iter_child_nodes(tree):
        visit_node(node)

    # Calculate complexity (simplified cyclomatic complexity)
    complexity = 1
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.For, ast.While, ast.ExceptHandler)):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1

    # Calculate max depth
    max_depth = 0
    def calc_depth(node, current_depth=0):
        nonlocal max_depth
        max_depth = max(max_depth, current_depth)
        for child in ast.iter_child_nodes(node):
            calc_depth(child, current_depth + 1)
    calc_depth(tree)

    return {
        "nodes": nodes,
        "edges": edges,
        "complexity": complexity,
        "depth": max_depth
    }


def _generate_graph_summary(graph: Dict[str, Any]) -> str:
    """Generate a text summary of the code graph."""
    nodes = graph.get("nodes", {})
    edges = graph.get("edges", [])

    # Count node types
    type_counts = {}
    for node in nodes.values():
        node_type = node.get("node_type", "unknown")
        type_counts[node_type] = type_counts.get(node_type, 0) + 1

    # Count edge types
    edge_type_counts = {}
    for edge in edges:
        edge_type = edge.get("edge_type", "unknown")
        edge_type_counts[edge_type] = edge_type_counts.get(edge_type, 0) + 1

    # Find functions
    functions = [n["name"] for n in nodes.values() if n.get("node_type") == "function"]

    # Find calls
    calls = [n["name"] for n in nodes.values() if n.get("node_type") == "call"]

    summary_lines = [
        f"=== Code Graph Summary ===",
        f"",
        f"Node Statistics:",
        f"  Total nodes: {len(nodes)}",
    ]

    for node_type, count in sorted(type_counts.items()):
        summary_lines.append(f"  - {node_type}: {count}")

    summary_lines.extend([
        f"",
        f"Edge Statistics:",
        f"  Total edges: {len(edges)}",
    ])

    for edge_type, count in sorted(edge_type_counts.items()):
        summary_lines.append(f"  - {edge_type}: {count}")

    summary_lines.extend([
        f"",
        f"Complexity: {graph.get('complexity', 0)}",
        f"Max Depth: {graph.get('depth', 0)}",
        f"",
        f"Functions: {', '.join(functions) if functions else 'None'}",
        f"Calls: {', '.join(set(calls)) if calls else 'None'}",
    ])

    return "\n".join(summary_lines)


def _find_data_flow_paths(
    graph: Dict[str, Any],
    source_id: str,
    sink_id: str,
    max_depth: int = 10
) -> List[List[str]]:
    """Find all data flow paths from source to sink."""
    nodes = graph.get("nodes", {})
    edges = graph.get("edges", [])

    if source_id not in nodes or sink_id not in nodes:
        return []

    # Build adjacency list for data flow and control flow edges
    adjacency = {node_id: [] for node_id in nodes}
    for edge in edges:
        src = edge.get("source_id")
        tgt = edge.get("target_id")
        if src in adjacency:
            adjacency[src].append(tgt)

    # DFS to find all paths
    paths = []

    def dfs(current: str, target: str, path: List[str], visited: set, depth: int):
        if depth > max_depth:
            return
        if current == target:
            paths.append(path.copy())
            return
        if current in visited:
            return

        visited.add(current)
        for neighbor in adjacency.get(current, []):
            path.append(neighbor)
            dfs(neighbor, target, path, visited, depth + 1)
            path.pop()
        visited.remove(current)

    dfs(source_id, sink_id, [source_id], set(), 0)
    return paths


# ============ API Endpoints ============

@router.get("/list")
async def list_graphs():
    """List all built code graphs."""
    graphs_list = []
    for graph_id, graph_data in _graphs_store.items():
        graphs_list.append({
            "id": graph_id,
            "name": graph_data.get("name", "Unnamed"),
            "language": graph_data.get("language", "python"),
            "file_path": graph_data.get("file_path", ""),
            "node_count": len(graph_data.get("nodes", {})),
            "edge_count": len(graph_data.get("edges", [])),
            "complexity": graph_data.get("complexity", 0),
            "created_at": graph_data.get("created_at", ""),
        })

    return {"success": True, "graphs": graphs_list}


@router.post("/build")
async def build_graph(request: BuildGraphRequest):
    """Build a code property graph from source code."""
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="Code cannot be empty")

    # Parse code and build graph
    if request.language == "python":
        graph_data = _parse_python_to_graph(request.code, request.file_path)
    else:
        # For non-Python languages, return a basic structure
        # In production, integrate with tree-sitter or language-specific parsers
        graph_data = {
            "nodes": {},
            "edges": [],
            "complexity": 0,
            "depth": 0
        }

    # Generate ID and store
    graph_id = _generate_graph_id()

    # Extract function name or use file path as name
    name = request.file_path
    for node in graph_data.get("nodes", {}).values():
        if node.get("node_type") == "function":
            name = node.get("name", name)
            break

    full_graph = {
        "id": graph_id,
        "name": name,
        "language": request.language,
        "file_path": request.file_path,
        "code": request.code,
        "created_at": datetime.now().isoformat(),
        **graph_data
    }

    _graphs_store[graph_id] = full_graph

    # Generate summary
    summary = _generate_graph_summary(full_graph)

    return {
        "success": True,
        "graph": full_graph,
        "summary": summary
    }


@router.get("/{graph_id}")
async def get_graph(graph_id: str):
    """Get a specific code graph by ID."""
    if graph_id not in _graphs_store:
        raise HTTPException(status_code=404, detail="Graph not found")

    return {"success": True, "graph": _graphs_store[graph_id]}


@router.get("/{graph_id}/summary")
async def get_graph_summary(graph_id: str):
    """Get summary for a specific code graph."""
    if graph_id not in _graphs_store:
        raise HTTPException(status_code=404, detail="Graph not found")

    summary = _generate_graph_summary(_graphs_store[graph_id])
    return {"success": True, "summary": summary}


@router.post("/{graph_id}/data-flow")
async def analyze_data_flow(graph_id: str, request: DataFlowRequest):
    """Analyze data flow paths between two nodes."""
    if graph_id not in _graphs_store:
        raise HTTPException(status_code=404, detail="Graph not found")

    graph = _graphs_store[graph_id]
    paths = _find_data_flow_paths(
        graph,
        request.source_node_id,
        request.sink_node_id,
        request.max_depth
    )

    return {
        "success": True,
        "paths": paths,
        "count": len(paths)
    }


@router.delete("/{graph_id}")
async def delete_graph(graph_id: str):
    """Delete a code graph."""
    if graph_id not in _graphs_store:
        raise HTTPException(status_code=404, detail="Graph not found")

    del _graphs_store[graph_id]
    return {"success": True, "message": "Graph deleted"}
