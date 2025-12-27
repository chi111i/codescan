# Chunker data models for CodeScan
# Based on ACI (augmented-codebase-indexer) best practices

import hashlib
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any


class ChunkType(str, Enum):
    """Type of code chunk"""
    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    MODULE = "module"
    FIXED = "fixed"  # Fixed-size chunk (fallback)


class ArtifactType(str, Enum):
    """Type of indexable artifact for multi-granularity search"""
    CHUNK = "chunk"
    FUNCTION_SUMMARY = "function_summary"
    CLASS_SUMMARY = "class_summary"
    FILE_SUMMARY = "file_summary"
    MODULE_SUMMARY = "module_summary"


@dataclass
class ChunkMetadata:
    """Metadata for a code chunk"""
    # Identity
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    parent_class: Optional[str] = None  # For methods

    # Partial chunk info (for oversized nodes)
    is_partial: bool = False
    part_index: int = 0
    total_parts: int = 1

    # Content flags
    has_context_prefix: bool = False
    docstring_included: bool = False

    # Analysis hints
    imports: List[str] = field(default_factory=list)
    decorators: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)

    # File tracking
    file_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "function_name": self.function_name,
            "class_name": self.class_name,
            "parent_class": self.parent_class,
            "is_partial": self.is_partial,
            "part_index": self.part_index,
            "total_parts": self.total_parts,
            "has_context_prefix": self.has_context_prefix,
            "docstring_included": self.docstring_included,
            "imports": self.imports,
            "decorators": self.decorators,
            "calls": self.calls,
            "file_hash": self.file_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChunkMetadata":
        """Create from dictionary"""
        return cls(
            function_name=data.get("function_name"),
            class_name=data.get("class_name"),
            parent_class=data.get("parent_class"),
            is_partial=data.get("is_partial", False),
            part_index=data.get("part_index", 0),
            total_parts=data.get("total_parts", 1),
            has_context_prefix=data.get("has_context_prefix", False),
            docstring_included=data.get("docstring_included", False),
            imports=data.get("imports", []),
            decorators=data.get("decorators", []),
            calls=data.get("calls", []),
            file_hash=data.get("file_hash", ""),
        )


@dataclass
class CodeChunk:
    """A chunk of code for indexing

    Represents a semantic unit of code (function, method, class, or fixed-size block)
    that will be embedded and indexed for retrieval.
    """
    chunk_id: str
    file_path: str
    start_line: int  # 1-based
    end_line: int    # 1-based, inclusive
    content: str
    language: str
    chunk_type: ChunkType
    metadata: ChunkMetadata = field(default_factory=ChunkMetadata)

    @classmethod
    def create(
        cls,
        file_path: str,
        start_line: int,
        end_line: int,
        content: str,
        language: str,
        chunk_type: ChunkType,
        metadata: Optional[ChunkMetadata] = None,
    ) -> "CodeChunk":
        """Factory method with auto-generated chunk_id"""
        chunk_id = cls._generate_id(file_path, start_line, end_line, content)
        return cls(
            chunk_id=chunk_id,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            content=content,
            language=language,
            chunk_type=chunk_type,
            metadata=metadata or ChunkMetadata(),
        )

    @staticmethod
    def _generate_id(file_path: str, start_line: int, end_line: int, content: str) -> str:
        """Generate deterministic chunk ID based on content"""
        hash_input = f"{file_path}:{start_line}-{end_line}:{content[:200]}"
        content_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
        return f"{content_hash}"

    @property
    def symbol(self) -> str:
        """Get the primary symbol name for this chunk"""
        if self.metadata.function_name:
            if self.metadata.parent_class:
                return f"{self.metadata.parent_class}.{self.metadata.function_name}"
            return self.metadata.function_name
        if self.metadata.class_name:
            return self.metadata.class_name
        return f"chunk_{self.start_line}_{self.end_line}"

    @property
    def line_count(self) -> int:
        """Number of lines in this chunk"""
        return self.end_line - self.start_line + 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "chunk_id": self.chunk_id,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "content": self.content,
            "language": self.language,
            "chunk_type": self.chunk_type.value,
            "metadata": self.metadata.to_dict(),
            "symbol": self.symbol,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CodeChunk":
        """Create from dictionary"""
        return cls(
            chunk_id=data["chunk_id"],
            file_path=data["file_path"],
            start_line=data["start_line"],
            end_line=data["end_line"],
            content=data["content"],
            language=data["language"],
            chunk_type=ChunkType(data["chunk_type"]),
            metadata=ChunkMetadata.from_dict(data.get("metadata", {})),
        )


@dataclass
class SummaryArtifact:
    """A summary artifact for multi-granularity indexing

    Represents a generated summary of a code entity (function, class, or file)
    that provides higher-level semantic search capability.
    """
    artifact_id: str
    file_path: str
    artifact_type: ArtifactType
    name: str  # Function name, class name, or file name
    content: str  # Generated summary text (for embedding)
    start_line: int = 0  # 0 for file summaries
    end_line: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create_function_summary(
        cls,
        file_path: str,
        function_name: str,
        summary: str,
        start_line: int,
        end_line: int,
        params: Optional[List[str]] = None,
        return_type: Optional[str] = None,
        decorators: Optional[List[str]] = None,
    ) -> "SummaryArtifact":
        """Create a function summary artifact"""
        artifact_id = f"fn_{hashlib.sha256(f'{file_path}:{function_name}'.encode()).hexdigest()[:12]}"
        return cls(
            artifact_id=artifact_id,
            file_path=file_path,
            artifact_type=ArtifactType.FUNCTION_SUMMARY,
            name=function_name,
            content=summary,
            start_line=start_line,
            end_line=end_line,
            metadata={
                "params": params or [],
                "return_type": return_type,
                "decorators": decorators or [],
            },
        )

    @classmethod
    def create_class_summary(
        cls,
        file_path: str,
        class_name: str,
        summary: str,
        start_line: int,
        end_line: int,
        methods: Optional[List[str]] = None,
        base_classes: Optional[List[str]] = None,
    ) -> "SummaryArtifact":
        """Create a class summary artifact"""
        artifact_id = f"cls_{hashlib.sha256(f'{file_path}:{class_name}'.encode()).hexdigest()[:12]}"
        return cls(
            artifact_id=artifact_id,
            file_path=file_path,
            artifact_type=ArtifactType.CLASS_SUMMARY,
            name=class_name,
            content=summary,
            start_line=start_line,
            end_line=end_line,
            metadata={
                "methods": methods or [],
                "base_classes": base_classes or [],
            },
        )

    @classmethod
    def create_file_summary(
        cls,
        file_path: str,
        summary: str,
        imports: Optional[List[str]] = None,
        classes: Optional[List[str]] = None,
        functions: Optional[List[str]] = None,
    ) -> "SummaryArtifact":
        """Create a file summary artifact"""
        artifact_id = f"file_{hashlib.sha256(file_path.encode()).hexdigest()[:12]}"
        return cls(
            artifact_id=artifact_id,
            file_path=file_path,
            artifact_type=ArtifactType.FILE_SUMMARY,
            name=file_path.split("/")[-1].split("\\")[-1],  # Filename only
            content=summary,
            start_line=0,
            end_line=0,
            metadata={
                "imports": imports or [],
                "classes": classes or [],
                "functions": functions or [],
            },
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "artifact_id": self.artifact_id,
            "file_path": self.file_path,
            "artifact_type": self.artifact_type.value,
            "name": self.name,
            "content": self.content,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SummaryArtifact":
        """Create from dictionary"""
        return cls(
            artifact_id=data["artifact_id"],
            file_path=data["file_path"],
            artifact_type=ArtifactType(data["artifact_type"]),
            name=data["name"],
            content=data["content"],
            start_line=data.get("start_line", 0),
            end_line=data.get("end_line", 0),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ChunkingResult:
    """Result of chunking a file or AST nodes"""
    chunks: List[CodeChunk] = field(default_factory=list)
    summaries: List[SummaryArtifact] = field(default_factory=list)

    @property
    def total_chunks(self) -> int:
        return len(self.chunks)

    @property
    def total_summaries(self) -> int:
        return len(self.summaries)

    def merge(self, other: "ChunkingResult") -> "ChunkingResult":
        """Merge with another result"""
        return ChunkingResult(
            chunks=self.chunks + other.chunks,
            summaries=self.summaries + other.summaries,
        )


@dataclass
class ChunkerConfig:
    """Configuration for code chunking"""
    # Token limits
    max_tokens: int = 8192
    min_tokens: int = 50

    # Fixed-size chunking fallback
    fixed_chunk_lines: int = 50
    overlap_lines: int = 5

    # Summary generation
    generate_summaries: bool = True
    summary_max_length: int = 500

    # Language settings
    default_language: str = "python"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "max_tokens": self.max_tokens,
            "min_tokens": self.min_tokens,
            "fixed_chunk_lines": self.fixed_chunk_lines,
            "overlap_lines": self.overlap_lines,
            "generate_summaries": self.generate_summaries,
            "summary_max_length": self.summary_max_length,
            "default_language": self.default_language,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChunkerConfig":
        """Create from dictionary"""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
