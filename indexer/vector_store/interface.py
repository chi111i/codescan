# Vector store interface and data models
# Based on ACI (augmented-codebase-indexer) best practices

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable
from enum import Enum


@dataclass
class SearchResult:
    """Search result from vector store"""
    code_unit: Any  # CodeUnit
    score: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UpsertResult:
    """Result of upsert operation"""
    inserted_count: int = 0
    updated_count: int = 0
    failed_count: int = 0
    failed_ids: List[str] = field(default_factory=list)


@dataclass
class DeleteResult:
    """Result of delete operation"""
    deleted_count: int = 0


@dataclass
class RerankerConfig:
    """Reranker configuration"""
    enable_reranking: bool = True

    # Score weights (should sum to 1.0)
    vector_weight: float = 0.4
    keyword_weight: float = 0.25
    security_weight: float = 0.2
    context_weight: float = 0.15

    # Security priority mode
    security_priority_mode: bool = True
    security_boost_factor: float = 1.5

    # Code quality factors
    prefer_entry_points: bool = True
    prefer_smaller_units: bool = True
    max_preferred_lines: int = 100


@dataclass
class HybridSearchConfig:
    """Hybrid search configuration"""
    enable_keyword_boost: bool = True
    keyword_boost_weight: float = 0.3
    metadata_filter_first: bool = True
    dangerous_keywords: List[str] = None
    reranker_config: RerankerConfig = None

    def __post_init__(self):
        if self.dangerous_keywords is None:
            self.dangerous_keywords = [
                # Authentication
                "auth", "login", "password", "token", "session", "jwt", "oauth",
                # Authorization
                "permission", "role", "admin", "privilege", "access",
                # Input handling
                "input", "request", "param", "query", "body", "header", "cookie",
                # Dangerous functions
                "exec", "eval", "system", "shell", "cmd", "popen", "subprocess",
                "sql", "query", "execute", "cursor",
                "file", "open", "read", "write", "path", "upload", "download",
                "serialize", "deserialize", "pickle", "yaml", "json",
                # Business keywords
                "payment", "money", "transfer", "balance", "order", "price",
                "delete", "remove", "update", "create", "modify",
            ]


class ArtifactType(Enum):
    """Type of indexed artifact"""
    CHUNK = "chunk"
    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    FILE_SUMMARY = "file_summary"
    MODULE_SUMMARY = "module_summary"


class VectorStoreError(Exception):
    """Base exception for vector store errors"""
    pass


class VectorConnectionError(VectorStoreError):
    """Connection to vector store failed"""
    pass


class VectorIndexError(VectorStoreError):
    """Indexing operation failed"""
    pass


# Backwards compatibility aliases (deprecated, will be removed in future)
# Note: These shadowed Python built-ins and should not be used
ConnectionError = VectorConnectionError
IndexError = VectorIndexError


class VectorStoreInterface(ABC):
    """Abstract interface for vector stores

    Implementations should handle:
    - CRUD operations for code units
    - Vector similarity search
    - Metadata filtering
    - Hybrid search (vector + keyword)
    """

    @abstractmethod
    def initialize(self) -> None:
        """Initialize storage (create collections, indexes, etc.)"""
        pass

    @abstractmethod
    def add(
        self,
        units: List[Any],  # List[CodeUnit]
        embeddings: List[List[float]]
    ) -> None:
        """Add code units with their embeddings

        Args:
            units: List of CodeUnit objects
            embeddings: Corresponding embedding vectors
        """
        pass

    @abstractmethod
    def search(
        self,
        query_embedding: List[float],
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[SearchResult]:
        """Search for similar code units

        Args:
            query_embedding: Query vector
            top_k: Number of results to return
            filters: Optional metadata filters

        Returns:
            List of SearchResult objects
        """
        pass

    @abstractmethod
    def get_by_id(self, unit_id: str) -> Optional[Any]:
        """Get a code unit by ID

        Args:
            unit_id: Unique identifier

        Returns:
            CodeUnit or None if not found
        """
        pass

    @abstractmethod
    def delete(self, unit_ids: List[str]) -> None:
        """Delete code units by IDs

        Args:
            unit_ids: List of IDs to delete
        """
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear all data from the store"""
        pass

    @abstractmethod
    def count(self) -> int:
        """Get total number of stored code units"""
        pass

    @abstractmethod
    def get_all(self, limit: int = 10000) -> List[Any]:
        """Get all code units (with limit)

        Args:
            limit: Maximum number to return

        Returns:
            List of CodeUnit objects
        """
        pass

    @abstractmethod
    def get_by_filter(
        self,
        filters: Dict[str, Any],
        limit: int = 1000
    ) -> List[Any]:
        """Get code units matching filters

        Args:
            filters: Metadata filters
            limit: Maximum number to return

        Returns:
            List of CodeUnit objects
        """
        pass

    def hybrid_search(
        self,
        query_embedding: List[float],
        query_text: str,
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None,
        hybrid_config: Optional[HybridSearchConfig] = None
    ) -> List[SearchResult]:
        """Hybrid search (vector + keyword + reranking)

        Default implementation: vector search only.
        Subclasses should override for full hybrid support.

        Args:
            query_embedding: Query vector
            query_text: Query text for keyword matching
            top_k: Number of results to return
            filters: Optional metadata filters
            hybrid_config: Hybrid search configuration

        Returns:
            List of SearchResult objects
        """
        return self.search(query_embedding, top_k, filters)

    async def upsert_batch_async(
        self,
        ids: List[str],
        vectors: List[List[float]],
        payloads: List[Dict[str, Any]]
    ) -> UpsertResult:
        """Async batch upsert (optional)

        Default implementation wraps sync add().

        Args:
            ids: Point IDs
            vectors: Embedding vectors
            payloads: Metadata payloads

        Returns:
            UpsertResult with counts
        """
        # Default: not implemented
        raise NotImplementedError("Async upsert not implemented")

    async def search_async(
        self,
        query_vector: List[float],
        limit: int = 10,
        file_filter: Optional[str] = None,
        artifact_types: Optional[List[str]] = None
    ) -> List[SearchResult]:
        """Async vector search (optional)

        Default implementation wraps sync search().

        Args:
            query_vector: Query vector
            limit: Number of results
            file_filter: Filter by file path pattern
            artifact_types: Filter by artifact types

        Returns:
            List of SearchResult objects
        """
        filters = {}
        if file_filter:
            filters["file_path"] = file_filter
        if artifact_types:
            filters["artifact_type"] = artifact_types
        return self.search(query_vector, limit, filters if filters else None)

    async def delete_by_file_async(self, file_path: str) -> DeleteResult:
        """Async delete by file path (optional)

        Args:
            file_path: File path to delete all vectors for

        Returns:
            DeleteResult with count
        """
        raise NotImplementedError("Async delete by file not implemented")


class CodeReranker:
    """Code search result reranker

    Reranks results based on multiple factors:
    1. Vector similarity (original score)
    2. Keyword matching
    3. Security relevance (dangerous functions, sensitive operations)
    4. Code context (entry points, code length)
    """

    ENTRY_POINT_PATTERNS = [
        "handler", "controller", "view", "endpoint", "route", "api",
        "get", "post", "put", "delete", "patch",
        "rpc", "grpc", "consumer", "subscriber", "listener",
        "command", "task", "job", "cron",
    ]

    HIGH_RISK_PATTERNS = [
        r"exec\s*\(", r"eval\s*\(", r"system\s*\(", r"popen\s*\(",
        r"subprocess", r"shell\s*=\s*True",
        r"execute\s*\(", r"raw\s*\(", r"cursor\.",
        r"SELECT.*FROM", r"INSERT.*INTO", r"UPDATE.*SET", r"DELETE.*FROM",
        r"open\s*\(", r"file\s*\(", r"read\s*\(", r"write\s*\(",
        r"pickle\.load", r"yaml\.load", r"unserialize",
        r"password", r"token", r"secret", r"credential",
        r"auth", r"login", r"session",
    ]

    def __init__(self, config: RerankerConfig = None):
        self.config = config or RerankerConfig()
        self._compile_patterns()

    def _compile_patterns(self):
        self._high_risk_re = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.HIGH_RISK_PATTERNS
        ]

    def rerank(
        self,
        results: List[SearchResult],
        query_text: str,
        dangerous_keywords: List[str] = None,
        top_k: int = None
    ) -> List[SearchResult]:
        """Rerank search results

        Args:
            results: Original search results
            query_text: Query text
            dangerous_keywords: List of dangerous keywords
            top_k: Number of results to return

        Returns:
            Reranked results
        """
        if not results or not self.config.enable_reranking:
            return results[:top_k] if top_k else results

        query_keywords = self._extract_keywords(query_text, dangerous_keywords or [])

        scored_results = []
        for result in results:
            scores = self._compute_scores(result, query_keywords, dangerous_keywords)
            final_score = self._combine_scores(scores, result.score)
            scored_results.append((result, final_score))

        scored_results.sort(key=lambda x: x[1], reverse=True)

        reranked = [r[0] for r in scored_results]
        if top_k:
            reranked = reranked[:top_k]

        # Update scores
        for i, result in enumerate(reranked):
            result.score = scored_results[i][1]

        return reranked

    def _extract_keywords(self, text: str, dangerous_keywords: List[str]) -> List[str]:
        words = re.findall(r'\b\w+\b', text.lower())
        keywords = []
        for word in words:
            if word in dangerous_keywords:
                keywords.append(word)
            for dk in dangerous_keywords:
                if dk in word or word in dk:
                    keywords.append(dk)
        return list(set(keywords)) or words[:5]

    def _compute_scores(
        self,
        result: SearchResult,
        query_keywords: List[str],
        dangerous_keywords: List[str] = None
    ) -> Dict[str, float]:
        unit = result.code_unit
        code_text = f"{unit.symbol} {unit.code} {getattr(unit, 'signature', '') or ''}"

        return {
            "keyword": self._compute_keyword_score(code_text, query_keywords, dangerous_keywords),
            "security": self._compute_security_score(unit),
            "context": self._compute_context_score(unit),
        }

    def _compute_keyword_score(
        self,
        code_text: str,
        query_keywords: List[str],
        dangerous_keywords: List[str] = None
    ) -> float:
        if not query_keywords:
            return 0.0

        code_lower = code_text.lower()
        matches = 0
        bonus = 0

        for keyword in query_keywords:
            if keyword in code_lower:
                matches += 1
                if dangerous_keywords and keyword in dangerous_keywords:
                    bonus += 0.1

        base_score = matches / len(query_keywords)
        return min(1.0, base_score + bonus)

    def _compute_security_score(self, unit: Any) -> float:
        code = unit.code.lower()
        score = 0.0
        matches = 0

        for pattern in self._high_risk_re:
            if pattern.search(code):
                matches += 1

        if matches > 0:
            score = min(1.0, 0.3 + matches * 0.15)

        symbol_lower = unit.symbol.lower()
        sensitive_in_name = any(
            kw in symbol_lower for kw in
            ["auth", "login", "password", "token", "admin", "delete", "payment", "transfer"]
        )
        if sensitive_in_name:
            score = min(1.0, score + 0.2)

        return score

    def _compute_context_score(self, unit: Any) -> float:
        score = 0.5

        if self.config.prefer_entry_points:
            symbol_lower = unit.symbol.lower()
            for pattern in self.ENTRY_POINT_PATTERNS:
                if pattern in symbol_lower:
                    score += 0.2
                    break

            for decorator in (getattr(unit, 'decorators', None) or []):
                dec_lower = decorator.lower()
                if any(p in dec_lower for p in ["route", "api", "get", "post", "put", "delete"]):
                    score += 0.15
                    break

        if self.config.prefer_smaller_units:
            lines = unit.code.count('\n') + 1
            if lines <= self.config.max_preferred_lines:
                score += 0.1 * (1 - lines / self.config.max_preferred_lines)
            else:
                score -= 0.1

        unit_type = unit.unit_type.value if hasattr(unit.unit_type, 'value') else str(unit.unit_type)
        if unit_type in ["function", "method"]:
            score += 0.1
        elif unit_type == "class":
            score += 0.05

        return min(1.0, max(0.0, score))

    def _combine_scores(self, scores: Dict[str, float], vector_score: float) -> float:
        cfg = self.config

        final_score = (
            vector_score * cfg.vector_weight +
            scores.get("keyword", 0) * cfg.keyword_weight +
            scores.get("security", 0) * cfg.security_weight +
            scores.get("context", 0) * cfg.context_weight
        )

        if cfg.security_priority_mode and scores.get("security", 0) > 0.5:
            final_score *= cfg.security_boost_factor

        return final_score
