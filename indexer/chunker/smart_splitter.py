# Smart Chunk Splitter for oversized code nodes
# Based on ACI (augmented-codebase-indexer) best practices

import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple, Callable

from .models import CodeChunk, ChunkMetadata, ChunkType, ChunkerConfig

logger = logging.getLogger(__name__)


# Try to import tiktoken for token counting
try:
    import tiktoken
    HAS_TIKTOKEN = True
except ImportError:
    HAS_TIKTOKEN = False
    logger.warning("tiktoken not available, using approximate token counting")


@dataclass
class SplitContext:
    """Context information for splitting"""
    file_path: str
    language: str
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    docstring: Optional[str] = None


class SmartChunkSplitter:
    """Smart splitter for oversized code nodes

    Implements intelligent splitting strategies:
    1. Empty line splitting (highest priority) - natural paragraph boundaries
    2. Statement boundary splitting - based on syntax patterns
    3. Indentation-based splitting - block boundaries
    4. Hard truncation (last resort) - with warning

    Features:
    - Context prefix injection for semantic continuity
    - Docstring preservation in first chunk
    - Binary search for token limit boundaries
    """

    # Statement boundary patterns (language-agnostic)
    STATEMENT_BOUNDARY_PATTERNS = [
        r"^\s*def\s+",       # Function definition
        r"^\s*class\s+",     # Class definition
        r"^\s*if\s+",        # if statement
        r"^\s*elif\s+",      # elif statement
        r"^\s*else\s*:",     # else statement
        r"^\s*for\s+",       # for loop
        r"^\s*while\s+",     # while loop
        r"^\s*try\s*:",      # try block
        r"^\s*except\s*",    # except block
        r"^\s*finally\s*:",  # finally block
        r"^\s*with\s+",      # with statement
        r"^\s*return\s",     # return statement
        r"^\s*yield\s",      # yield statement
        r"^\s*raise\s",      # raise statement
        r"^\s*@",            # Decorator
        r"^\s*async\s+def",  # Async function
        r"^\s*async\s+with", # Async with
        r"^\s*async\s+for",  # Async for
        # JavaScript/TypeScript
        r"^\s*function\s+",
        r"^\s*const\s+",
        r"^\s*let\s+",
        r"^\s*var\s+",
        r"^\s*export\s+",
        r"^\s*import\s+",
        # PHP
        r"^\s*public\s+function",
        r"^\s*private\s+function",
        r"^\s*protected\s+function",
    ]

    def __init__(self, config: Optional[ChunkerConfig] = None):
        """Initialize splitter

        Args:
            config: Chunking configuration
        """
        self.config = config or ChunkerConfig()
        self._tokenizer = None
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.STATEMENT_BOUNDARY_PATTERNS
        ]

        if HAS_TIKTOKEN:
            try:
                self._tokenizer = tiktoken.get_encoding("cl100k_base")
            except Exception as e:
                logger.warning(f"Failed to load tiktoken encoding: {e}")

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

    def split_oversized_node(
        self,
        content: str,
        start_line: int,
        context: SplitContext,
        chunk_type: ChunkType = ChunkType.FUNCTION,
    ) -> List[CodeChunk]:
        """Split an oversized code node into multiple chunks

        Args:
            content: Full code content
            start_line: Starting line number in source file
            context: Split context (file, function, class info)
            chunk_type: Type of the original node

        Returns:
            List of CodeChunk objects
        """
        lines = content.split("\n")
        total_lines = len(lines)

        # Check if splitting is actually needed
        if self.count_tokens(content) <= self.config.max_tokens:
            return [self._create_chunk(
                content=content,
                start_line=start_line,
                end_line=start_line + total_lines - 1,
                context=context,
                chunk_type=chunk_type,
                is_partial=False,
                part_index=0,
                total_parts=1,
            )]

        chunks = []
        current_line_idx = 0
        part_index = 0

        # Estimate total parts for metadata
        estimated_parts = max(1, self.count_tokens(content) // self.config.max_tokens + 1)

        while current_line_idx < total_lines:
            # Generate context prefix for non-first chunks
            context_prefix = ""
            if part_index > 0:
                context_prefix = self._generate_context_prefix(context)

            # Find the maximum end index that fits token limit
            max_end_idx = self._find_max_end_index(
                lines, current_line_idx, context_prefix
            )

            if max_end_idx <= current_line_idx:
                # Can't fit even one line - force include at least one
                max_end_idx = current_line_idx + 1
                logger.warning(
                    f"Single line exceeds token limit at {context.file_path}:{start_line + current_line_idx}"
                )

            # Find the best split point within the range
            split_idx = self._find_best_split_point(
                lines, current_line_idx, max_end_idx
            )

            # Extract chunk content
            chunk_lines = lines[current_line_idx:split_idx]
            chunk_content = "\n".join(chunk_lines)

            # Add context prefix if not first chunk
            if part_index > 0 and context_prefix:
                chunk_content = context_prefix + chunk_content

            # Add docstring to first chunk if available
            if part_index == 0 and context.docstring:
                # Docstring is already part of the content
                pass

            # Create chunk
            chunk = self._create_chunk(
                content=chunk_content,
                start_line=start_line + current_line_idx,
                end_line=start_line + split_idx - 1,
                context=context,
                chunk_type=chunk_type,
                is_partial=True,
                part_index=part_index,
                total_parts=estimated_parts,
                has_context_prefix=part_index > 0,
            )
            chunks.append(chunk)

            current_line_idx = split_idx
            part_index += 1

        # Update total_parts in metadata
        for chunk in chunks:
            chunk.metadata.total_parts = len(chunks)

        return chunks

    def _generate_context_prefix(self, context: SplitContext) -> str:
        """Generate context prefix for continuation chunks

        Args:
            context: Split context

        Returns:
            Context prefix string
        """
        parts = []

        if context.class_name:
            parts.append(f"class {context.class_name}")

        if context.function_name:
            if context.class_name:
                parts.append(f"method {context.function_name}")
            else:
                parts.append(f"function {context.function_name}")

        if parts:
            return f"# Context: {', '.join(parts)} (continued)\n"
        return ""

    def _find_max_end_index(
        self,
        lines: List[str],
        start_idx: int,
        prefix: str = "",
    ) -> int:
        """Find maximum end index that fits within token limit using binary search

        Args:
            lines: All lines
            start_idx: Starting line index
            prefix: Optional prefix to account for

        Returns:
            Maximum end index (exclusive)
        """
        max_tokens = self.config.max_tokens
        prefix_tokens = self.count_tokens(prefix) if prefix else 0
        available_tokens = max_tokens - prefix_tokens

        n = len(lines)
        if start_idx >= n:
            return start_idx

        # Binary search for maximum end
        lo, hi = start_idx, n
        result = start_idx

        while lo < hi:
            mid = (lo + hi + 1) // 2
            chunk_content = "\n".join(lines[start_idx:mid])
            tokens = self.count_tokens(chunk_content)

            if tokens <= available_tokens:
                result = mid
                lo = mid
            else:
                hi = mid - 1

        return result

    def _find_best_split_point(
        self,
        lines: List[str],
        start_idx: int,
        max_end_idx: int,
    ) -> int:
        """Find the best split point within the given range

        Priority:
        1. Empty lines (natural boundaries)
        2. Statement boundaries (def, class, if, etc.)
        3. Low indentation lines (block boundaries)
        4. Just use max_end_idx

        Args:
            lines: All lines
            start_idx: Starting line index
            max_end_idx: Maximum end index

        Returns:
            Best split point (exclusive)
        """
        if max_end_idx <= start_idx + 1:
            return max_end_idx

        # Try to find empty line (search from end)
        for i in range(max_end_idx - 1, start_idx, -1):
            if not lines[i].strip():
                return i + 1

        # Try to find statement boundary
        for i in range(max_end_idx - 1, start_idx, -1):
            line = lines[i]
            for pattern in self._compiled_patterns:
                if pattern.match(line):
                    return i

        # Try to find low indentation (potential block boundary)
        min_indent = float("inf")
        min_indent_idx = max_end_idx

        for i in range(start_idx + 1, max_end_idx):
            line = lines[i]
            if line.strip():  # Non-empty line
                indent = len(line) - len(line.lstrip())
                if indent < min_indent and indent > 0:
                    min_indent = indent
                    min_indent_idx = i

        if min_indent_idx < max_end_idx:
            return min_indent_idx

        # Fall back to max_end_idx
        return max_end_idx

    def _create_chunk(
        self,
        content: str,
        start_line: int,
        end_line: int,
        context: SplitContext,
        chunk_type: ChunkType,
        is_partial: bool,
        part_index: int,
        total_parts: int,
        has_context_prefix: bool = False,
    ) -> CodeChunk:
        """Create a CodeChunk with proper metadata

        Args:
            content: Chunk content
            start_line: Start line in source
            end_line: End line in source
            context: Split context
            chunk_type: Type of chunk
            is_partial: Whether this is a partial chunk
            part_index: Index of this part
            total_parts: Total number of parts
            has_context_prefix: Whether content includes context prefix

        Returns:
            CodeChunk object
        """
        metadata = ChunkMetadata(
            function_name=context.function_name,
            class_name=context.class_name,
            parent_class=context.class_name if context.function_name else None,
            is_partial=is_partial,
            part_index=part_index,
            total_parts=total_parts,
            has_context_prefix=has_context_prefix,
            docstring_included=part_index == 0 and context.docstring is not None,
        )

        return CodeChunk.create(
            file_path=context.file_path,
            start_line=start_line,
            end_line=end_line,
            content=content,
            language=context.language,
            chunk_type=chunk_type,
            metadata=metadata,
        )


def create_smart_splitter(config: Optional[ChunkerConfig] = None) -> SmartChunkSplitter:
    """Factory function for SmartChunkSplitter

    Args:
        config: Optional configuration

    Returns:
        Configured SmartChunkSplitter instance
    """
    return SmartChunkSplitter(config=config)
