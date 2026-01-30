"""Code search result reranker - Enhanced Security-First Reranking

Reranks search results based on multiple factors:
1. Vector similarity (original score)
2. Keyword matching
3. Security relevance (dangerous functions, sensitive operations)
4. Code context (entry points, code length)
5. Vulnerability patterns (sinks, sources, sanitizers)

Based on:
- CodeReranker from vector_store/interface.py
- ACI's OpenAICompatibleReranker
- ContextWeaver's security scoring

Features:
- Async support for API-based rerankers
- Security-first scoring with vulnerability pattern detection
- CWE-aware pattern matching
- Entry point prioritization
- Integration with SearchService's RerankerInterface
"""

from __future__ import annotations

import asyncio
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from ..search_service import HybridSearchResult

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


# ─────────────────────────────────────────────────────────────────
# Security-First Reranker for SearchService Integration
# ─────────────────────────────────────────────────────────────────

@dataclass
class SecurityRerankerConfig:
    """Configuration for security-first reranking"""
    # Base weights
    vector_weight: float = 0.35
    keyword_weight: float = 0.20
    security_weight: float = 0.30
    context_weight: float = 0.15

    # Security boosting
    security_boost_factor: float = 1.8
    high_risk_threshold: float = 0.6

    # Vulnerability pattern scoring
    sink_boost: float = 0.4
    source_boost: float = 0.3
    auth_boost: float = 0.35

    # Entry point preferences
    prefer_entry_points: bool = True
    entry_point_boost: float = 0.25

    # CWE-aware scoring
    enable_cwe_scoring: bool = True
    critical_cwe_boost: float = 0.5  # RCE, SQLi, File inclusion
    high_cwe_boost: float = 0.3      # XSS, SSRF, deserialization


class SecurityFirstReranker:
    """Security-First Reranker for SearchService integration

    Implements RerankerInterface from search_service.py.
    Prioritizes security-relevant code with vulnerability pattern detection.

    Features:
    - CWE-aware pattern matching
    - Sink/source/sanitizer detection
    - Entry point prioritization
    - Multi-factor security scoring

    Example:
        reranker = SecurityFirstReranker(config)
        results = await reranker.rerank(query, candidates, limit=10)
    """

    # Critical vulnerability patterns (CWE-78, CWE-89, CWE-94, CWE-502)
    CRITICAL_PATTERNS: List[str] = [
        # Command Injection (CWE-78)
        r'\bos\.system\s*\(', r'\bos\.popen\s*\(', r'\bsubprocess\.',
        r'\bexec\s*\(', r'\beval\s*\(', r'\bshell\s*=\s*True',
        r'\bsystem\s*\(', r'\bpopen\s*\(', r'\bpassthru\s*\(',
        r'\bshell_exec\s*\(', r'\bproc_open\s*\(',
        # SQL Injection (CWE-89)
        r'\.execute\s*\([^)]*%', r'\.raw\s*\(', r'cursor\.\w+\s*\(',
        r'SELECT\s+.*\s+FROM\s+.*WHERE.*\+', r'INSERT\s+INTO.*\+',
        r'mysql_query\s*\(', r'mysqli_query\s*\(',
        # Code Injection (CWE-94)
        r'\beval\s*\(', r'\bexec\s*\(', r'\bcompile\s*\(',
        r'\bcreate_function\s*\(', r'\bassert\s*\(',
        # Deserialization (CWE-502)
        r'pickle\.loads?\s*\(', r'yaml\.load\s*\(', r'yaml\.unsafe_load',
        r'unserialize\s*\(', r'jsonpickle\.decode',
    ]

    # High-risk patterns (CWE-22, CWE-79, CWE-918, CWE-611)
    HIGH_RISK_PATTERNS: List[str] = [
        # Path Traversal (CWE-22)
        r'open\s*\([^)]*\+', r'Path\s*\([^)]*\+', r'os\.path\.join\s*\(',
        r'file_get_contents\s*\(', r'fopen\s*\(', r'readfile\s*\(',
        r'send_file\s*\(', r'send_from_directory\s*\(',
        # XSS (CWE-79)
        r'\.innerHTML\s*=', r'document\.write\s*\(', r'v-html\s*=',
        r'dangerouslySetInnerHTML', r'\|safe\b', r'mark_safe\s*\(',
        # SSRF (CWE-918)
        r'requests\.(get|post|put|delete)\s*\(', r'urllib\.',
        r'http\.request\s*\(', r'curl_exec\s*\(', r'file_get_contents\s*\(',
        # XXE (CWE-611)
        r'xml\.etree', r'lxml\.etree', r'xml\.dom', r'XMLParser\s*\(',
        r'simplexml_load', r'DOMDocument',
    ]

    # Authentication/Authorization patterns
    AUTH_PATTERNS: List[str] = [
        r'\bauth', r'\blogin', r'\blogout', r'\bpassword', r'\btoken',
        r'\bsession', r'\bjwt', r'\boauth', r'\bcredential',
        r'\bpermission', r'\brole', r'\baccess', r'\bprivilege',
        r'\bdecorator.*auth', r'@login_required', r'@require_permission',
        r'IsAuthenticated', r'check_permission', r'verify_token',
    ]

    # Entry point indicators
    ENTRY_POINT_PATTERNS: List[str] = [
        r'@app\.(get|post|put|delete|patch)', r'@router\.',
        r'@api_view', r'@action', r'@route',
        r'def\s+(get|post|put|delete|patch)\s*\(',
        r'class\s+\w+View', r'class\s+\w+Controller',
        r'class\s+\w+Handler', r'class\s+\w+API',
        r'func\s+\w+Handler', r'func\s+\w+Controller',
    ]

    # Sensitive data indicators
    SENSITIVE_DATA_PATTERNS: List[str] = [
        r'\bpassword\b', r'\bsecret\b', r'\bapi_key\b', r'\btoken\b',
        r'\bcredential\b', r'\bprivate_key\b', r'\baccess_token\b',
        r'\brefresh_token\b', r'\bauth_token\b', r'\bsession_id\b',
        r'\bcredit_card\b', r'\bssn\b', r'\bsocial_security\b',
    ]

    def __init__(self, config: Optional[SecurityRerankerConfig] = None):
        self.config = config or SecurityRerankerConfig()
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for performance"""
        self._critical_re = [
            re.compile(p, re.IGNORECASE) for p in self.CRITICAL_PATTERNS
        ]
        self._high_risk_re = [
            re.compile(p, re.IGNORECASE) for p in self.HIGH_RISK_PATTERNS
        ]
        self._auth_re = [
            re.compile(p, re.IGNORECASE) for p in self.AUTH_PATTERNS
        ]
        self._entry_point_re = [
            re.compile(p, re.IGNORECASE) for p in self.ENTRY_POINT_PATTERNS
        ]
        self._sensitive_re = [
            re.compile(p, re.IGNORECASE) for p in self.SENSITIVE_DATA_PATTERNS
        ]

    async def rerank(
        self,
        query: str,
        results: List["HybridSearchResult"],
        limit: int,
    ) -> List["HybridSearchResult"]:
        """Rerank search results with security-first scoring

        Args:
            query: Search query
            results: List of HybridSearchResult to rerank
            limit: Maximum results to return

        Returns:
            Reranked list of HybridSearchResult
        """
        if not results:
            return []

        # Extract query keywords for keyword scoring
        query_keywords = self._extract_keywords(query)

        # Score each result
        scored_results = []
        for result in results:
            code = result.code_unit.code
            symbol = result.code_unit.symbol or ""

            scores = self._compute_all_scores(code, symbol, result, query_keywords)
            final_score = self._combine_scores(scores, result.score)

            # Update result metadata with scoring breakdown
            result.metadata["security_scores"] = scores
            result.metadata["reranked_score"] = final_score

            scored_results.append((result, final_score))

        # Sort by final score descending
        scored_results.sort(key=lambda x: x[1], reverse=True)

        # Update ranks and return
        reranked = []
        for rank, (result, score) in enumerate(scored_results[:limit]):
            result.score = score
            result.rank = rank
            reranked.append(result)

        return reranked

    def _extract_keywords(self, query: str) -> List[str]:
        """Extract meaningful keywords from query"""
        # Common stop words
        stop_words = {
            "the", "a", "an", "is", "are", "was", "were", "be", "been",
            "have", "has", "had", "do", "does", "did", "will", "would",
            "could", "should", "may", "might", "must", "to", "of", "in",
            "for", "on", "with", "at", "by", "from", "as", "into",
            "find", "search", "show", "get", "code", "function", "class",
        }
        words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', query.lower())
        return [w for w in words if w not in stop_words and len(w) >= 3]

    def _compute_all_scores(
        self,
        code: str,
        symbol: str,
        result: "HybridSearchResult",
        query_keywords: List[str],
    ) -> Dict[str, float]:
        """Compute all scoring factors"""
        return {
            "keyword": self._score_keyword_match(code, symbol, query_keywords),
            "security": self._score_security_relevance(code, symbol),
            "context": self._score_context(code, symbol, result),
            "vulnerability": self._score_vulnerability_patterns(code),
        }

    def _score_keyword_match(
        self,
        code: str,
        symbol: str,
        keywords: List[str],
    ) -> float:
        """Score based on keyword matches"""
        if not keywords:
            return 0.0

        text = f"{symbol} {code}".lower()
        matches = sum(1 for kw in keywords if kw in text)
        return min(1.0, matches / len(keywords))

    def _score_security_relevance(self, code: str, symbol: str) -> float:
        """Score security relevance based on patterns"""
        code_lower = code.lower()
        symbol_lower = symbol.lower()
        score = 0.0

        # Check for authentication/authorization patterns
        auth_matches = sum(1 for p in self._auth_re if p.search(code_lower) or p.search(symbol_lower))
        if auth_matches > 0:
            score += min(0.4, auth_matches * 0.1)

        # Check for sensitive data handling
        sensitive_matches = sum(1 for p in self._sensitive_re if p.search(code_lower))
        if sensitive_matches > 0:
            score += min(0.3, sensitive_matches * 0.1)

        # Entry point bonus
        if self.config.prefer_entry_points:
            if any(p.search(code_lower) for p in self._entry_point_re):
                score += self.config.entry_point_boost

        return min(1.0, score)

    def _score_context(
        self,
        code: str,
        symbol: str,
        result: "HybridSearchResult",
    ) -> float:
        """Score based on code context"""
        score = 0.5

        # Prefer smaller, more focused functions
        lines = code.count('\n') + 1
        if lines <= 50:
            score += 0.2
        elif lines <= 100:
            score += 0.1
        elif lines > 200:
            score -= 0.1

        # Prefer functions/methods over classes
        unit_type = result.code_unit.unit_type
        if unit_type:
            type_val = unit_type.value if hasattr(unit_type, 'value') else str(unit_type)
            if type_val in ["function", "method"]:
                score += 0.15
            elif type_val == "class":
                score += 0.05

        return min(1.0, max(0.0, score))

    def _score_vulnerability_patterns(self, code: str) -> float:
        """Score based on vulnerability pattern detection"""
        code_lower = code.lower()
        score = 0.0

        # Critical vulnerability patterns (highest weight)
        critical_matches = sum(1 for p in self._critical_re if p.search(code_lower))
        if critical_matches > 0:
            score += min(0.6, critical_matches * self.config.critical_cwe_boost)

        # High-risk patterns
        high_matches = sum(1 for p in self._high_risk_re if p.search(code_lower))
        if high_matches > 0:
            score += min(0.4, high_matches * self.config.high_cwe_boost)

        return min(1.0, score)

    def _combine_scores(self, scores: Dict[str, float], original_score: float) -> float:
        """Combine all scores with configured weights"""
        cfg = self.config

        # Base weighted combination
        final_score = (
            original_score * cfg.vector_weight +
            scores.get("keyword", 0) * cfg.keyword_weight +
            scores.get("security", 0) * cfg.security_weight +
            scores.get("context", 0) * cfg.context_weight
        )

        # Vulnerability pattern boost
        vuln_score = scores.get("vulnerability", 0)
        if vuln_score > 0:
            final_score += vuln_score * 0.3

        # Security boost for high-security-relevance results
        security_score = scores.get("security", 0)
        if security_score > cfg.high_risk_threshold:
            final_score *= cfg.security_boost_factor

        return final_score


# ─────────────────────────────────────────────────────────────────
# API-Based Reranker (OpenAI Compatible)
# ─────────────────────────────────────────────────────────────────

class APIReranker:
    """Reranker using external API (OpenAI-compatible /v1/rerank endpoint)

    Based on ACI's OpenAICompatibleReranker design.

    Expects API endpoint that accepts:
    {
        "model": "<model>",
        "query": "<query>",
        "documents": ["doc1", "doc2", ...],
        "top_n": <int>
    }
    and returns:
    {
        "data": [{"index": 0, "score": 0.9}, ...]
    }

    Example:
        reranker = APIReranker(
            api_url="https://api.jina.ai",
            api_key="your-key",
            model="jina-reranker-v2-base-multilingual"
        )
        results = await reranker.rerank(query, candidates, limit=10)
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        model: str = "rerank-english-v2.0",
        timeout: float = 30.0,
        endpoint: str = "/v1/rerank",
    ):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        self._client = None

    async def _get_client(self):
        """Get or create HTTP client"""
        if self._client is None:
            try:
                import httpx
                self._client = httpx.AsyncClient(
                    base_url=self.api_url,
                    timeout=self.timeout,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                )
            except ImportError:
                raise ImportError("httpx is required for API reranker: pip install httpx")
        return self._client

    async def rerank(
        self,
        query: str,
        results: List["HybridSearchResult"],
        limit: int,
    ) -> List["HybridSearchResult"]:
        """Rerank search results using external API

        Args:
            query: Search query
            results: List of HybridSearchResult to rerank
            limit: Maximum results to return

        Returns:
            Reranked list of HybridSearchResult
        """
        if not results:
            return []

        # Prepare documents for API
        documents = []
        for r in results:
            code_unit = r.code_unit
            doc = f"{code_unit.symbol or ''}\n{code_unit.code}"
            if code_unit.docstring:
                doc = f"{code_unit.docstring}\n{doc}"
            documents.append(doc)

        # Call API
        top_n = min(limit, len(results))
        payload = {
            "model": self.model,
            "query": query,
            "documents": documents,
            "top_n": top_n,
        }

        try:
            client = await self._get_client()
            response = await client.post(self.endpoint, json=payload)

            if response.status_code != 200:
                logger.warning(
                    f"Rerank API error: status={response.status_code}, "
                    f"body={response.text[:200]}"
                )
                return results[:limit]

            parsed = response.json()
            data = parsed.get("data", []) or parsed.get("results", [])

            if not data:
                logger.warning("Rerank returned no data, using original order")
                return results[:limit]

            # Build reranked results
            reranked = []
            for item in data:
                idx = item.get("index")
                score = item.get("score") or item.get("relevance_score", 0)

                if idx is None or idx >= len(results):
                    continue

                result = results[idx]
                result.score = float(score)
                result.metadata["api_reranked"] = True
                reranked.append(result)

            # Sort by score and assign ranks
            reranked.sort(key=lambda x: x.score, reverse=True)
            for rank, r in enumerate(reranked):
                r.rank = rank

            return reranked[:limit]

        except Exception as e:
            logger.error(f"Rerank API call failed: {e}")
            return results[:limit]

    async def aclose(self) -> None:
        """Close HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None


# ─────────────────────────────────────────────────────────────────
# Hybrid Reranker (Combines Local + API)
# ─────────────────────────────────────────────────────────────────

class HybridReranker:
    """Hybrid reranker combining local security scoring with optional API reranking

    Uses SecurityFirstReranker for local scoring, then optionally
    refines with API-based reranking.

    Example:
        reranker = HybridReranker(
            local_config=SecurityRerankerConfig(),
            api_reranker=APIReranker(api_url, api_key, model),
            use_api=True
        )
        results = await reranker.rerank(query, candidates, limit=10)
    """

    def __init__(
        self,
        local_config: Optional[SecurityRerankerConfig] = None,
        api_reranker: Optional[APIReranker] = None,
        use_api: bool = False,
        api_weight: float = 0.6,
        local_weight: float = 0.4,
    ):
        self.local_reranker = SecurityFirstReranker(local_config)
        self.api_reranker = api_reranker
        self.use_api = use_api and api_reranker is not None
        self.api_weight = api_weight
        self.local_weight = local_weight

    async def rerank(
        self,
        query: str,
        results: List["HybridSearchResult"],
        limit: int,
    ) -> List["HybridSearchResult"]:
        """Rerank with hybrid local + API scoring

        Args:
            query: Search query
            results: List of HybridSearchResult to rerank
            limit: Maximum results to return

        Returns:
            Reranked list of HybridSearchResult
        """
        if not results:
            return []

        # Always do local security-first reranking
        local_results = await self.local_reranker.rerank(query, results, limit * 2)

        if not self.use_api or not self.api_reranker:
            return local_results[:limit]

        # API reranking on top candidates
        try:
            api_results = await self.api_reranker.rerank(query, local_results, limit)

            # Combine scores
            local_scores = {id(r): r.score for r in local_results}
            for r in api_results:
                local_score = local_scores.get(id(r), r.score)
                r.score = (
                    r.score * self.api_weight +
                    local_score * self.local_weight
                )
                r.metadata["hybrid_reranked"] = True

            # Re-sort and return
            api_results.sort(key=lambda x: x.score, reverse=True)
            for rank, r in enumerate(api_results):
                r.rank = rank

            return api_results[:limit]

        except Exception as e:
            logger.warning(f"API reranking failed, using local results: {e}")
            return local_results[:limit]

    async def aclose(self) -> None:
        """Close resources"""
        if self.api_reranker:
            await self.api_reranker.aclose()


# ─────────────────────────────────────────────────────────────────
# Factory Functions
# ─────────────────────────────────────────────────────────────────

def create_security_reranker(
    config: Optional[SecurityRerankerConfig] = None
) -> SecurityFirstReranker:
    """Create a security-first reranker

    Args:
        config: Optional configuration

    Returns:
        Configured SecurityFirstReranker
    """
    return SecurityFirstReranker(config)


def create_api_reranker(
    api_url: str,
    api_key: str,
    model: str = "rerank-english-v2.0",
    timeout: float = 30.0,
) -> APIReranker:
    """Create an API-based reranker

    Args:
        api_url: API base URL
        api_key: API key
        model: Model name
        timeout: Request timeout

    Returns:
        Configured APIReranker
    """
    return APIReranker(api_url, api_key, model, timeout)


def create_hybrid_reranker(
    api_url: Optional[str] = None,
    api_key: Optional[str] = None,
    model: str = "rerank-english-v2.0",
    local_config: Optional[SecurityRerankerConfig] = None,
    use_api: bool = False,
) -> HybridReranker:
    """Create a hybrid reranker

    Args:
        api_url: Optional API URL for API reranking
        api_key: Optional API key
        model: Model name for API
        local_config: Local reranker config
        use_api: Whether to use API reranking

    Returns:
        Configured HybridReranker
    """
    api_reranker = None
    if api_url and api_key:
        api_reranker = APIReranker(api_url, api_key, model)

    return HybridReranker(
        local_config=local_config,
        api_reranker=api_reranker,
        use_api=use_api,
    )
