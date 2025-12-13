"""
代码单元数据模型 - 表示可分析的代码片段
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
import hashlib


class CodeUnitType(Enum):
    """代码单元类型"""
    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    MODULE = "module"
    HANDLER = "handler"  # Web 处理器/控制器
    MIDDLEWARE = "middleware"
    UNKNOWN = "unknown"


@dataclass
class CodeSpan:
    """代码位置信息"""
    start_line: int
    end_line: int
    start_col: int = 0
    end_col: int = 0


@dataclass
class CodeUnit:
    """代码分析单元

    表示一个可以独立分析的代码片段（函数、方法、类等）
    """
    # 基本标识
    id: str  # 全局唯一 ID
    language: str  # python, javascript, typescript
    file_path: str  # 相对于项目根目录的路径

    # 符号信息
    symbol: str  # 函数/方法/类名
    unit_type: CodeUnitType
    signature: str  # 完整签名（包含参数）

    # 位置信息
    span: CodeSpan

    # 代码内容
    code: str  # 原始代码片段
    docstring: Optional[str] = None  # 文档字符串

    # 调用关系
    calls: List[str] = field(default_factory=list)  # 调用的函数/方法
    called_by: List[str] = field(default_factory=list)  # 被哪些函数调用

    # 上下文信息
    parent_class: Optional[str] = None  # 所属类（如果是方法）
    decorators: List[str] = field(default_factory=list)  # 装饰器列表
    imports: List[str] = field(default_factory=list)  # 相关导入

    # 元数据
    metadata: Dict[str, Any] = field(default_factory=dict)

    # 向量索引相关
    chunk_index: int = 0  # 如果代码被分块，这是块索引
    total_chunks: int = 1  # 总块数

    @staticmethod
    def generate_id(file_path: str, symbol: str, span: CodeSpan) -> str:
        """生成唯一 ID"""
        content = f"{file_path}:{symbol}:{span.start_line}:{span.end_line}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def to_embedding_text(self) -> str:
        """生成用于嵌入的文本描述

        包含足够的上下文信息，避免仅靠摘要产生幻觉
        """
        parts = [
            f"Language: {self.language}",
            f"File: {self.file_path}",
            f"Type: {self.unit_type.value}",
            f"Symbol: {self.symbol}",
            f"Signature: {self.signature}",
        ]

        if self.parent_class:
            parts.append(f"Class: {self.parent_class}")

        if self.decorators:
            parts.append(f"Decorators: {', '.join(self.decorators)}")

        if self.docstring:
            parts.append(f"Documentation: {self.docstring[:500]}")

        if self.calls:
            parts.append(f"Calls: {', '.join(self.calls[:20])}")

        # 包含原始代码（限制长度）
        code_preview = self.code[:2000] if len(self.code) > 2000 else self.code
        parts.append(f"Code:\n{code_preview}")

        return "\n".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（用于存储）"""
        return {
            "id": self.id,
            "language": self.language,
            "file_path": self.file_path,
            "symbol": self.symbol,
            "unit_type": self.unit_type.value,
            "signature": self.signature,
            "span": {
                "start_line": self.span.start_line,
                "end_line": self.span.end_line,
                "start_col": self.span.start_col,
                "end_col": self.span.end_col,
            },
            "code": self.code,
            "docstring": self.docstring,
            "calls": self.calls,
            "called_by": self.called_by,
            "parent_class": self.parent_class,
            "decorators": self.decorators,
            "imports": self.imports,
            "metadata": self.metadata,
            "chunk_index": self.chunk_index,
            "total_chunks": self.total_chunks,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CodeUnit":
        """从字典创建"""
        span_data = data["span"]
        return cls(
            id=data["id"],
            language=data["language"],
            file_path=data["file_path"],
            symbol=data["symbol"],
            unit_type=CodeUnitType(data["unit_type"]),
            signature=data["signature"],
            span=CodeSpan(
                start_line=span_data["start_line"],
                end_line=span_data["end_line"],
                start_col=span_data.get("start_col", 0),
                end_col=span_data.get("end_col", 0),
            ),
            code=data["code"],
            docstring=data.get("docstring"),
            calls=data.get("calls", []),
            called_by=data.get("called_by", []),
            parent_class=data.get("parent_class"),
            decorators=data.get("decorators", []),
            imports=data.get("imports", []),
            metadata=data.get("metadata", {}),
            chunk_index=data.get("chunk_index", 0),
            total_chunks=data.get("total_chunks", 1),
        )
