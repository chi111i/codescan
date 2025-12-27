# AST-Aware Code Chunker for CodeScan
# Based on ACI (augmented-codebase-indexer) best practices

import ast
import logging
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple, Callable

from .models import (
    CodeChunk,
    ChunkMetadata,
    ChunkType,
    SummaryArtifact,
    ArtifactType,
    ChunkingResult,
    ChunkerConfig,
)
from .smart_splitter import SmartChunkSplitter, SplitContext

logger = logging.getLogger(__name__)

# Try to import tiktoken for token counting
try:
    import tiktoken
    HAS_TIKTOKEN = True
except ImportError:
    HAS_TIKTOKEN = False
    logger.warning("tiktoken not available, using approximate token counting")


@dataclass
class ASTNodeInfo:
    """Information extracted from an AST node"""
    name: str
    node_type: str  # function, method, class
    start_line: int
    end_line: int
    code: str
    docstring: Optional[str] = None
    signature: Optional[str] = None
    decorators: List[str] = None
    parent_class: Optional[str] = None
    calls: List[str] = None
    params: List[str] = None
    return_type: Optional[str] = None
    base_classes: List[str] = None
    methods: List[str] = None


class ASTChunker:
    """AST-aware code chunker with multi-granularity indexing

    Features:
    - Function/method/class boundary detection
    - Token limit enforcement with smart splitting
    - Multi-granularity summary generation
    - Context preservation for oversized nodes

    Based on ACI best practices.
    """

    def __init__(self, config: Optional[ChunkerConfig] = None):
        """Initialize AST chunker

        Args:
            config: Chunking configuration
        """
        self.config = config or ChunkerConfig()
        self._tokenizer = None
        self._splitter = SmartChunkSplitter(config)

        if HAS_TIKTOKEN:
            try:
                self._tokenizer = tiktoken.get_encoding("cl100k_base")
            except Exception as e:
                logger.warning(f"Failed to load tiktoken: {e}")

    def count_tokens(self, text: str) -> int:
        """Count tokens in text

        Args:
            text: Input text

        Returns:
            Token count
        """
        if self._tokenizer:
            return len(self._tokenizer.encode(text))
        else:
            # Approximate: ~4 chars per token for English, ~2 for CJK
            return len(text) // 3

    def chunk_file(
        self,
        file_path: str,
        content: str,
        language: str = "python",
        generate_summaries: bool = True,
    ) -> ChunkingResult:
        """Chunk a file into semantic code chunks

        Args:
            file_path: Path to the file
            content: File content
            language: Programming language
            generate_summaries: Whether to generate summary artifacts

        Returns:
            ChunkingResult with chunks and summaries
        """
        if language == "python":
            return self._chunk_python_file(
                file_path, content, generate_summaries
            )
        else:
            # Fall back to fixed-size chunking for unsupported languages
            return self._chunk_fixed_size(file_path, content, language)

    def _chunk_python_file(
        self,
        file_path: str,
        content: str,
        generate_summaries: bool = True,
    ) -> ChunkingResult:
        """Chunk a Python file using AST

        Args:
            file_path: File path
            content: File content
            generate_summaries: Whether to generate summaries

        Returns:
            ChunkingResult
        """
        chunks: List[CodeChunk] = []
        summaries: List[SummaryArtifact] = []

        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            logger.warning(f"Syntax error in {file_path}: {e}")
            # Fall back to fixed-size chunking
            return self._chunk_fixed_size(file_path, content, "python")

        lines = content.split("\n")

        # Extract imports for context
        imports = self._extract_imports(tree)

        # Track all function and class names for file summary
        function_names: List[str] = []
        class_names: List[str] = []

        # Process top-level nodes
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Top-level function
                node_info = self._extract_function_info(node, lines)
                func_chunks = self._create_chunks_for_node(
                    node_info, file_path, "python", imports
                )
                chunks.extend(func_chunks)
                function_names.append(node_info.name)

                if generate_summaries:
                    summary = self._create_function_summary(node_info, file_path)
                    summaries.append(summary)

            elif isinstance(node, ast.ClassDef):
                # Class definition
                class_info = self._extract_class_info(node, lines)
                class_names.append(class_info.name)

                # Chunk class body (without methods)
                class_chunks = self._create_chunks_for_node(
                    class_info, file_path, "python", imports
                )
                chunks.extend(class_chunks)

                if generate_summaries:
                    class_summary = self._create_class_summary(class_info, file_path)
                    summaries.append(class_summary)

                # Process methods
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_info = self._extract_function_info(
                            item, lines, parent_class=node.name
                        )
                        method_chunks = self._create_chunks_for_node(
                            method_info, file_path, "python", imports
                        )
                        chunks.extend(method_chunks)

                        if generate_summaries:
                            method_summary = self._create_function_summary(
                                method_info, file_path
                            )
                            summaries.append(method_summary)

        # Generate file-level summary
        if generate_summaries and (function_names or class_names):
            file_summary = SummaryArtifact.create_file_summary(
                file_path=file_path,
                summary=self._generate_file_summary_text(
                    file_path, imports, class_names, function_names
                ),
                imports=imports,
                classes=class_names,
                functions=function_names,
            )
            summaries.append(file_summary)

        return ChunkingResult(chunks=chunks, summaries=summaries)

    def _extract_function_info(
        self,
        node: ast.FunctionDef,
        lines: List[str],
        parent_class: Optional[str] = None,
    ) -> ASTNodeInfo:
        """Extract information from a function/method node

        Args:
            node: AST function node
            lines: Source lines
            parent_class: Parent class name if this is a method

        Returns:
            ASTNodeInfo with function details
        """
        start_line = node.lineno
        end_line = node.end_lineno or node.lineno
        code = "\n".join(lines[start_line - 1:end_line])

        # Extract parameters
        params = []
        for arg in node.args.args:
            param = arg.arg
            if arg.annotation:
                param += f": {ast.unparse(arg.annotation)}"
            params.append(param)

        # Return type
        return_type = None
        if node.returns:
            return_type = ast.unparse(node.returns)

        # Build signature
        signature = f"def {node.name}({', '.join(params)})"
        if return_type:
            signature += f" -> {return_type}"

        # Extract decorators
        decorators = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                decorators.append(ast.unparse(dec))
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    decorators.append(dec.func.id)
                elif isinstance(dec.func, ast.Attribute):
                    decorators.append(ast.unparse(dec.func))

        # Extract function calls
        calls = self._extract_calls(node)

        node_type = "method" if parent_class else "function"

        return ASTNodeInfo(
            name=node.name,
            node_type=node_type,
            start_line=start_line,
            end_line=end_line,
            code=code,
            docstring=ast.get_docstring(node),
            signature=signature,
            decorators=decorators or [],
            parent_class=parent_class,
            calls=calls,
            params=params,
            return_type=return_type,
        )

    def _extract_class_info(
        self,
        node: ast.ClassDef,
        lines: List[str],
    ) -> ASTNodeInfo:
        """Extract information from a class node

        Args:
            node: AST class node
            lines: Source lines

        Returns:
            ASTNodeInfo with class details
        """
        start_line = node.lineno
        end_line = node.end_lineno or node.lineno

        # For class, we only include the class definition and docstring, not methods
        # Methods are chunked separately
        class_header_end = start_line
        for item in node.body:
            if isinstance(item, ast.Expr) and isinstance(item.value, ast.Constant):
                # Docstring
                class_header_end = item.end_lineno or item.lineno
                break
            elif not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Class variable or other statement
                class_header_end = max(class_header_end, item.end_lineno or item.lineno)
            else:
                break

        code = "\n".join(lines[start_line - 1:class_header_end])

        # Base classes
        base_classes = [ast.unparse(base) for base in node.bases]

        # Build signature
        signature = f"class {node.name}"
        if base_classes:
            signature += f"({', '.join(base_classes)})"

        # Extract decorators
        decorators = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.append(dec.id)
            else:
                decorators.append(ast.unparse(dec))

        # Collect method names
        methods = []
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods.append(item.name)

        return ASTNodeInfo(
            name=node.name,
            node_type="class",
            start_line=start_line,
            end_line=end_line,
            code=code,
            docstring=ast.get_docstring(node),
            signature=signature,
            decorators=decorators or [],
            base_classes=base_classes,
            methods=methods,
        )

    def _extract_imports(self, tree: ast.AST) -> List[str]:
        """Extract import statements from AST"""
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}")
        return imports

    def _extract_calls(self, node: ast.AST) -> List[str]:
        """Extract function calls from AST node"""
        calls = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    calls.add(child.func.id)
                elif isinstance(child.func, ast.Attribute):
                    # Get full qualified name
                    parts = []
                    current = child.func
                    while isinstance(current, ast.Attribute):
                        parts.append(current.attr)
                        current = current.value
                    if isinstance(current, ast.Name):
                        parts.append(current.id)
                    if parts:
                        parts.reverse()
                        calls.add(".".join(parts))
        return list(calls)

    def _create_chunks_for_node(
        self,
        node_info: ASTNodeInfo,
        file_path: str,
        language: str,
        imports: List[str],
    ) -> List[CodeChunk]:
        """Create chunks for an AST node, splitting if oversized

        Args:
            node_info: Node information
            file_path: File path
            language: Programming language
            imports: File imports

        Returns:
            List of CodeChunk objects
        """
        # Determine chunk type
        if node_info.node_type == "function":
            chunk_type = ChunkType.FUNCTION
        elif node_info.node_type == "method":
            chunk_type = ChunkType.METHOD
        elif node_info.node_type == "class":
            chunk_type = ChunkType.CLASS
        else:
            chunk_type = ChunkType.MODULE

        # Check if splitting is needed
        tokens = self.count_tokens(node_info.code)

        if tokens <= self.config.max_tokens:
            # Single chunk
            metadata = ChunkMetadata(
                function_name=node_info.name if node_info.node_type in ("function", "method") else None,
                class_name=node_info.parent_class if node_info.node_type == "method" else (node_info.name if node_info.node_type == "class" else None),
                parent_class=node_info.parent_class,
                imports=imports,
                decorators=node_info.decorators or [],
                calls=node_info.calls or [],
                docstring_included=node_info.docstring is not None,
            )

            chunk = CodeChunk.create(
                file_path=file_path,
                start_line=node_info.start_line,
                end_line=node_info.end_line,
                content=node_info.code,
                language=language,
                chunk_type=chunk_type,
                metadata=metadata,
            )
            return [chunk]

        # Need to split - use smart splitter
        context = SplitContext(
            file_path=file_path,
            language=language,
            function_name=node_info.name if node_info.node_type in ("function", "method") else None,
            class_name=node_info.parent_class if node_info.node_type == "method" else (node_info.name if node_info.node_type == "class" else None),
            docstring=node_info.docstring,
        )

        chunks = self._splitter.split_oversized_node(
            content=node_info.code,
            start_line=node_info.start_line,
            context=context,
            chunk_type=chunk_type,
        )

        # Add imports and calls to first chunk's metadata
        if chunks:
            chunks[0].metadata.imports = imports
            chunks[0].metadata.calls = node_info.calls or []
            chunks[0].metadata.decorators = node_info.decorators or []

        return chunks

    def _create_function_summary(
        self,
        node_info: ASTNodeInfo,
        file_path: str,
    ) -> SummaryArtifact:
        """Create a summary artifact for a function/method

        Args:
            node_info: Function information
            file_path: File path

        Returns:
            SummaryArtifact
        """
        # Generate summary text for embedding
        parts = [f"Function: {node_info.name}"]

        if node_info.parent_class:
            parts.append(f"Method of class {node_info.parent_class}")

        if node_info.signature:
            parts.append(f"Signature: {node_info.signature}")

        if node_info.docstring:
            parts.append(f"Description: {node_info.docstring[:300]}")

        if node_info.decorators:
            parts.append(f"Decorators: {', '.join(node_info.decorators)}")

        if node_info.calls:
            parts.append(f"Calls: {', '.join(node_info.calls[:10])}")

        summary_text = "\n".join(parts)

        return SummaryArtifact.create_function_summary(
            file_path=file_path,
            function_name=node_info.name,
            summary=summary_text,
            start_line=node_info.start_line,
            end_line=node_info.end_line,
            params=node_info.params,
            return_type=node_info.return_type,
            decorators=node_info.decorators,
        )

    def _create_class_summary(
        self,
        node_info: ASTNodeInfo,
        file_path: str,
    ) -> SummaryArtifact:
        """Create a summary artifact for a class

        Args:
            node_info: Class information
            file_path: File path

        Returns:
            SummaryArtifact
        """
        parts = [f"Class: {node_info.name}"]

        if node_info.base_classes:
            parts.append(f"Inherits from: {', '.join(node_info.base_classes)}")

        if node_info.docstring:
            parts.append(f"Description: {node_info.docstring[:300]}")

        if node_info.methods:
            parts.append(f"Methods: {', '.join(node_info.methods)}")

        if node_info.decorators:
            parts.append(f"Decorators: {', '.join(node_info.decorators)}")

        summary_text = "\n".join(parts)

        return SummaryArtifact.create_class_summary(
            file_path=file_path,
            class_name=node_info.name,
            summary=summary_text,
            start_line=node_info.start_line,
            end_line=node_info.end_line,
            methods=node_info.methods,
            base_classes=node_info.base_classes,
        )

    def _generate_file_summary_text(
        self,
        file_path: str,
        imports: List[str],
        classes: List[str],
        functions: List[str],
    ) -> str:
        """Generate summary text for a file

        Args:
            file_path: File path
            imports: Import statements
            classes: Class names
            functions: Function names

        Returns:
            Summary text for embedding
        """
        parts = [f"File: {file_path}"]

        if imports:
            parts.append(f"Imports: {', '.join(imports[:15])}")

        if classes:
            parts.append(f"Classes: {', '.join(classes)}")

        if functions:
            parts.append(f"Functions: {', '.join(functions)}")

        return "\n".join(parts)

    def _chunk_fixed_size(
        self,
        file_path: str,
        content: str,
        language: str,
    ) -> ChunkingResult:
        """Fall back to fixed-size chunking

        Args:
            file_path: File path
            content: File content
            language: Programming language

        Returns:
            ChunkingResult
        """
        chunks: List[CodeChunk] = []
        lines = content.split("\n")
        total_lines = len(lines)

        chunk_size = self.config.fixed_chunk_lines
        overlap = self.config.overlap_lines

        i = 0
        while i < total_lines:
            end_idx = min(i + chunk_size, total_lines)
            chunk_lines = lines[i:end_idx]
            chunk_content = "\n".join(chunk_lines)

            # Skip empty chunks
            if not chunk_content.strip():
                i += chunk_size - overlap
                continue

            metadata = ChunkMetadata(
                is_partial=True,
                part_index=len(chunks),
            )

            chunk = CodeChunk.create(
                file_path=file_path,
                start_line=i + 1,
                end_line=end_idx,
                content=chunk_content,
                language=language,
                chunk_type=ChunkType.FIXED,
                metadata=metadata,
            )
            chunks.append(chunk)

            i += chunk_size - overlap

        # Update total_parts in metadata
        for chunk in chunks:
            chunk.metadata.total_parts = len(chunks)

        return ChunkingResult(chunks=chunks, summaries=[])


def create_ast_chunker(config: Optional[ChunkerConfig] = None) -> ASTChunker:
    """Factory function for ASTChunker

    Args:
        config: Optional configuration

    Returns:
        Configured ASTChunker instance
    """
    return ASTChunker(config=config)
