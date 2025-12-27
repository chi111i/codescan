"""Code search result reranker

Reranks search results based on multiple factors:
1. Vector similarity (original score)
2. Keyword matching
3. Security relevance (dangerous functions, sensitive operations)
4. Code context (entry points, code length)

Based on CodeReranker from vector_store/interface.py
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
import logging

logger = logging.getLogger(__name__)


@dataclass
class RerankerConfig:
    """Reranker configuration"""
    enable_reranking: bool = True

    vector_weight: float = 0.4
    keyword_weight: float = 0.25
    security_weight: float = 0.2
    context_weight: float = 0.15

    security_priority_mode: bool = True
    security_boost_factor: float = 1.5

    prefer_entry_points: bool = True
    prefer_smaller_units: bool = True
    max_preferred_lines: int = 100


@dataclass
class RerankerResult:
    """Single reranked result"""
    item: Any
    original_score: float
    final_score: float
    scores: Dict[str, float] = field(default_factory=dict)


class CodeReranker:
    """Code search result reranker

    Reranks results based on multiple factors:
    1. Vector similarity (original score)
    2. Keyword matching
    3. Security relevance (dangerous functions, sensitive operations)
    4. Code context (entry points, code length)
    """

    ENTRY_POINT_PATTERNS: List[str] = [
        "handler", "controller", "view", "endpoint", "route", "api",
        "get", "post", "put", "delete", "patch",
        "rpc", "grpc", "consumer", "subscriber", "listener",
        "command", "task", "job", "cron",
    ]

    HIGH_RISK_PATTERNS: List[str] = [
        r"exec\s*\(", r"eval\s*\(", r"system\s*\(", r"popen\s*\(",
        r"subprocess", r"shell\s*=\s*True",
        r"execute\s*\(", r"raw\s*\(", r"cursor\.",
        r"SELECT.*FROM", r"INSERT.*INTO", r"UPDATE.*SET", r"DELETE.*FROM",
        r"open\s*\(", r"file\s*\(", r"read\s*\(", r"write\s*\(",
        r"pickle\.load", r"yaml\.load", r"unserialize",
        r"password", r"token", r"secret", r"credential",
        r"auth", r"login", r"session",
    ]

    SENSITIVE_NAMES: Set[str] = {
        "auth", "login", "password", "token", "admin",
        "delete", "payment", "transfer", "secret", "key",
        "session", "cookie", "credential", "permission",
    }

    DANGEROUS_KEYWORDS: List[str] = [
        "auth", "login", "password", "token", "session", "jwt", "oauth",
        "permission", "role", "admin", "privilege", "access",
        "input", "request", "param", "query", "body", "header", "cookie",
        "exec", "eval", "system", "shell", "cmd", "popen", "subprocess",
        "sql", "query", "execute", "cursor",
        "file", "open", "read", "write", "path", "upload", "download",
        "serialize", "deserialize", "pickle", "yaml", "json",
        "payment", "money", "transfer", "balance", "order", "price",
        "delete", "remove", "update", "create", "modify",
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
        results: List[Any],
        query_text: str,
        dangerous_keywords: List[str] = None,
        top_k: int = None,
        score_extractor: callable = None,
        code_extractor: callable = None,
        symbol_extractor: callable = None,
    ) -> List[RerankerResult]:
        """Rerank search results

        Args:
            results: Original search results
            query_text: Query text
            dangerous_keywords: List of dangerous keywords
            top_k: Number of results to return
            score_extractor: Function to extract score from result (default: r.score)
            code_extractor: Function to extract code from result (default: r.code_unit.code)
            symbol_extractor: Function to extract symbol from result (default: r.code_unit.symbol)

        Returns:
            List of RerankerResult with reranked items
        """
        if not results or not self.config.enable_reranking:
            return self._wrap_results(results[:top_k] if top_k else results, score_extractor)

        dangerous_keywords = dangerous_keywords or self.DANGEROUS_KEYWORDS
        query_keywords = self._extract_keywords(query_text, dangerous_keywords)

        score_fn = score_extractor or (lambda r: getattr(r, 'score', 0.5))
        code_fn = code_extractor or (lambda r: getattr(getattr(r, 'code_unit', r), 'code', ''))
        symbol_fn = symbol_extractor or (lambda r: getattr(getattr(r, 'code_unit', r), 'symbol', ''))

        scored_results = []
        for result in results:
            original_score = score_fn(result)
            code = code_fn(result)
            symbol = symbol_fn(result)

            scores = self._compute_scores(code, symbol, result, query_keywords, dangerous_keywords)
            final_score = self._combine_scores(scores, original_score)

            scored_results.append(RerankerResult(
                item=result,
                original_score=original_score,
                final_score=final_score,
                scores=scores
            ))

        scored_results.sort(key=lambda x: x.final_score, reverse=True)

        if top_k:
            scored_results = scored_results[:top_k]

        return scored_results

    def rerank_code_units(
        self,
        results: List[Any],
        query_text: str,
        dangerous_keywords: List[str] = None,
        top_k: int = None
    ) -> List[Any]:
        """Convenience method for reranking SearchResult objects

        Returns the original result objects with updated scores
        """
        if not results:
            return []

        reranked = self.rerank(
            results,
            query_text,
            dangerous_keywords,
            top_k,
            score_extractor=lambda r: r.score,
            code_extractor=lambda r: r.code_unit.code if hasattr(r, 'code_unit') else '',
            symbol_extractor=lambda r: r.code_unit.symbol if hasattr(r, 'code_unit') else '',
        )

        for rr in reranked:
            rr.item.score = rr.final_score

        return [rr.item for rr in reranked]

    def _wrap_results(
        self,
        results: List[Any],
        score_extractor: callable = None
    ) -> List[RerankerResult]:
        score_fn = score_extractor or (lambda r: getattr(r, 'score', 0.5))
        return [
            RerankerResult(item=r, original_score=score_fn(r), final_score=score_fn(r))
            for r in results
        ]

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
        code: str,
        symbol: str,
        result: Any,
        query_keywords: List[str],
        dangerous_keywords: List[str]
    ) -> Dict[str, float]:
        code_text = f"{symbol} {code}"

        return {
            "keyword": self._compute_keyword_score(code_text, query_keywords, dangerous_keywords),
            "security": self._compute_security_score(code, symbol),
            "context": self._compute_context_score(result, symbol, code),
        }

    def _compute_keyword_score(
        self,
        code_text: str,
        query_keywords: List[str],
        dangerous_keywords: List[str]
    ) -> float:
        if not query_keywords:
            return 0.0

        code_lower = code_text.lower()
        matches = 0
        bonus = 0

        for keyword in query_keywords:
            if keyword in code_lower:
                matches += 1
                if keyword in dangerous_keywords:
                    bonus += 0.1

        base_score = matches / len(query_keywords)
        return min(1.0, base_score + bonus)

    def _compute_security_score(self, code: str, symbol: str) -> float:
        code_lower = code.lower()
        score = 0.0
        matches = 0

        for pattern in self._high_risk_re:
            if pattern.search(code_lower):
                matches += 1

        if matches > 0:
            score = min(1.0, 0.3 + matches * 0.15)

        symbol_lower = symbol.lower()
        if any(kw in symbol_lower for kw in self.SENSITIVE_NAMES):
            score = min(1.0, score + 0.2)

        return score

    def _compute_context_score(self, result: Any, symbol: str, code: str) -> float:
        score = 0.5

        if self.config.prefer_entry_points:
            symbol_lower = symbol.lower()
            for pattern in self.ENTRY_POINT_PATTERNS:
                if pattern in symbol_lower:
                    score += 0.2
                    break

            unit = getattr(result, 'code_unit', result)
            for decorator in (getattr(unit, 'decorators', None) or []):
                dec_lower = decorator.lower()
                if any(p in dec_lower for p in ["route", "api", "get", "post", "put", "delete"]):
                    score += 0.15
                    break

        if self.config.prefer_smaller_units:
            lines = code.count('\n') + 1
            if lines <= self.config.max_preferred_lines:
                score += 0.1 * (1 - lines / self.config.max_preferred_lines)
            else:
                score -= 0.1

        unit = getattr(result, 'code_unit', result)
        unit_type = getattr(unit, 'unit_type', None)
        if unit_type:
            type_val = unit_type.value if hasattr(unit_type, 'value') else str(unit_type)
            if type_val in ["function", "method"]:
                score += 0.1
            elif type_val == "class":
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


class APIReranker:
    """Reranker using external API (e.g., Cohere, Jina)

    Placeholder for future implementation
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        model: str = "rerank-english-v2.0"
    ):
        self.api_url = api_url
        self.api_key = api_key
        self.model = model

    async def rerank(
        self,
        query: str,
        documents: List[str],
        top_k: int = 10
    ) -> List[Dict[str, Any]]:
        raise NotImplementedError("API reranker not yet implemented")
