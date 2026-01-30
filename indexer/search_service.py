# Enhanced Search Service - Hybrid Search with RRF Fusion
# Based on ACI's SearchService and ContextWeaver's SearchService designs
#
# Features:
# - Hybrid search: Vector + Keyword (grep/regex)
# - RRF (Reciprocal Rank Fusion) for score fusion
# - Query modifier parsing (path:, -path:, exclude:)
# - Location-based deduplication
# - Score normalization
# - Reranker integration
# - Smart TopK cutoff

import asyncio
import fnmatch
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Callable, Dict, Any, Set, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from llm_client import BaseLLMClient

from .models import CodeUnit
from .vector_store import SearchResult, VectorStoreInterface

logger = logging.getLogger(__name__)


class SearchMode(Enum):
    """Search mode enumeration"""
    HYBRID = "hybrid"      # Vector + Keyword search
    VECTOR = "vector"      # Vector search only
    KEYWORD = "keyword"    # Keyword search only
    SUMMARY = "summary"    # Vector search on summaries only


@dataclass
class SearchConfig:
    """Configuration for search service"""
    # Result limits
    default_limit: int = 10
    vector_candidates: int = 20
    keyword_candidates: int = 20
    recall_multiplier: int = 5  # For reranking

    # RRF fusion parameters (from ContextWeaver)
    rrf_k: int = 60  # Smoothing constant for RRF
    vector_weight: float = 1.0
    keyword_weight: float = 0.8

    # Smart TopK cutoff (from ContextWeaver)
    enable_smart_cutoff: bool = True
    smart_ratio: float = 0.7  # Minimum ratio to top score
    smart_delta: float = 0.2  # Maximum absolute delta from top score
    smart_floor: float = 0.3  # Minimum absolute score
    smart_min_k: int = 3      # Safe harbor size
    smart_max_k: int = 20     # Maximum results

    # Keyword search
    keyword_context_lines: int = 3  # Lines of context around matches

    # Security focus
    security_boost: float = 1.5  # Boost for security-related results


@dataclass
class HybridSearchResult:
    """Result from hybrid search"""
    code_unit: CodeUnit
    score: float
    source: str  # 'vector', 'keyword', or 'both'
    rank: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def file_path(self) -> str:
        return self.code_unit.file_path

    @property
    def start_line(self) -> int:
        if self.code_unit.span:
            return getattr(self.code_unit.span, 'start_line', 1)
        return 1

    @property
    def end_line(self) -> int:
        if self.code_unit.span:
            return getattr(self.code_unit.span, 'end_line', 1)
        return 1


@dataclass
class ParsedQuery:
    """Parsed query with modifiers"""
    clean_query: str
    file_filter: Optional[str] = None
    exclude_patterns: List[str] = field(default_factory=list)
    language_filter: Optional[str] = None


class RerankerInterface:
    """Interface for result reranking"""

    async def rerank(
        self,
        query: str,
        results: List[HybridSearchResult],
        limit: int,
    ) -> List[HybridSearchResult]:
        """Rerank search results"""
        raise NotImplementedError


class SearchService:
    """Enhanced Hybrid Search Service

    Combines vector (semantic) search with keyword (lexical) search
    using RRF fusion. Based on ACI's SearchService and ContextWeaver's
    SearchService designs.

    Features:
    - HYBRID mode: Parallel vector + keyword search with RRF fusion
    - VECTOR mode: Pure semantic search
    - KEYWORD mode: Pure lexical search (regex/grep)
    - Query modifiers: path:, -path:, exclude:, lang:
    - Smart TopK cutoff with dynamic thresholds
    - Location-based deduplication
    - Reranker integration

    Example:
        service = SearchService(llm_client, vector_store)
        results = await service.search("SQL injection vulnerability", limit=10)
    """

    def __init__(
        self,
        llm_client: "BaseLLMClient",
        vector_store: VectorStoreInterface,
        config: Optional[SearchConfig] = None,
        reranker: Optional[RerankerInterface] = None,
        root_path: Optional[Path] = None,
    ):
        """Initialize search service

        Args:
            llm_client: LLM client for embedding generation
            vector_store: Vector store for semantic search
            config: Search configuration
            reranker: Optional reranker for result refinement
            root_path: Root path for keyword search
        """
        self.llm_client = llm_client
        self.vector_store = vector_store
        self.config = config or SearchConfig()
        self.reranker = reranker
        self.root_path = root_path

    async def search(
        self,
        query: str,
        limit: Optional[int] = None,
        file_filter: Optional[str] = None,
        language: Optional[str] = None,
        mode: SearchMode = SearchMode.HYBRID,
        use_rerank: bool = True,
    ) -> List[HybridSearchResult]:
        """Perform hybrid search

        Supports query modifiers:
        - `path:*.py` or `file:src/**` - include only matching paths
        - `-path:tests` or `exclude:tests` - exclude matching paths
        - `lang:python` - filter by language

        Args:
            query: Natural language search query (may include modifiers)
            limit: Maximum results to return
            file_filter: Optional glob pattern for file paths
            language: Optional language filter
            mode: Search mode (HYBRID, VECTOR, KEYWORD)
            use_rerank: Whether to use reranker if available

        Returns:
            List of HybridSearchResult sorted by relevance
        """
        # Validate query
        if not query or not query.strip():
            logger.warning("[Search] Empty query provided")
            return []

        limit = limit or self.config.default_limit
        start_time = time.time()

        # Parse query for modifiers
        parsed = self._parse_query_modifiers(query)
        effective_filter = parsed.file_filter or file_filter
        effective_language = parsed.language_filter or language
        search_query = parsed.clean_query or query

        will_rerank = use_rerank and self.reranker is not None

        logger.debug(
            f"[Search] query='{search_query}', mode={mode.value}, "
            f"filter={effective_filter}, lang={effective_language}"
        )

        # Execute searches based on mode
        vector_results, keyword_results = await self._dispatch_search(
            search_query,
            effective_filter,
            effective_language,
            mode,
            will_rerank,
        )

        # Merge and process results
        candidates = self._merge_results(
            vector_results,
            keyword_results,
            will_rerank,
        )

        # Apply exclusions
        if parsed.exclude_patterns:
            candidates = self._apply_exclusions(candidates, parsed.exclude_patterns)

        # Finalize results
        results = await self._finalize_results(
            candidates,
            search_query,
            limit,
            use_rerank,
        )

        elapsed = time.time() - start_time
        logger.info(
            f"[Search] Complete in {elapsed:.3f}s: "
            f"vector={len(vector_results)}, keyword={len(keyword_results)}, "
            f"merged={len(candidates)}, final={len(results)}"
        )

        return results

    def search_sync(
        self,
        query: str,
        limit: Optional[int] = None,
        file_filter: Optional[str] = None,
        language: Optional[str] = None,
        mode: SearchMode = SearchMode.HYBRID,
        use_rerank: bool = True,
    ) -> List[HybridSearchResult]:
        """Synchronous search wrapper for non-async contexts

        Note: This method blocks until search completes.
        Prefer async search() when possible.
        """
        import concurrent.futures

        try:
            # Check if we're already in an event loop
            loop = asyncio.get_running_loop()
            # We're in an async context, use thread pool
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(
                    asyncio.run,
                    self.search(query, limit, file_filter, language, mode, use_rerank)
                )
                return future.result()
        except RuntimeError:
            # No running loop, safe to use asyncio.run
            return asyncio.run(
                self.search(query, limit, file_filter, language, mode, use_rerank)
            )

    # ─────────────────────────────────────────────────────────────────
    # Query Parsing
    # ─────────────────────────────────────────────────────────────────

    def _parse_query_modifiers(self, query: str) -> ParsedQuery:
        """Parse query string for modifiers

        Supported syntax:
        - `path:*.py` or `file:src/**` - include only matching paths
        - `-path:tests` or `exclude:tests` - exclude matching paths
        - `lang:python` or `language:python` - filter by language

        Args:
            query: Raw query string

        Returns:
            ParsedQuery with parsed components
        """
        file_filter = None
        exclude_patterns = []
        language_filter = None
        clean_parts = []

        tokens = query.split()

        for token in tokens:
            lower_token = token.lower()

            if lower_token.startswith("path:") or lower_token.startswith("file:"):
                file_filter = token.split(":", 1)[1]
            elif lower_token.startswith("-path:") or lower_token.startswith("exclude:"):
                pattern = token.split(":", 1)[1]
                if pattern:
                    exclude_patterns.append(pattern)
            elif lower_token.startswith("lang:") or lower_token.startswith("language:"):
                language_filter = token.split(":", 1)[1].lower()
            else:
                clean_parts.append(token)

        clean_query = " ".join(clean_parts).strip()

        return ParsedQuery(
            clean_query=clean_query,
            file_filter=file_filter,
            exclude_patterns=exclude_patterns,
            language_filter=language_filter,
        )

    # ─────────────────────────────────────────────────────────────────
    # Search Dispatch
    # ─────────────────────────────────────────────────────────────────

    async def _dispatch_search(
        self,
        query: str,
        file_filter: Optional[str],
        language: Optional[str],
        mode: SearchMode,
        will_rerank: bool,
    ) -> Tuple[List[HybridSearchResult], List[HybridSearchResult]]:
        """Dispatch search based on mode"""

        if mode == SearchMode.HYBRID:
            return await self._execute_hybrid_search(
                query, file_filter, language, will_rerank
            )
        elif mode == SearchMode.VECTOR:
            results = await self._execute_vector_search(
                query, file_filter, language, will_rerank
            )
            return results, []
        elif mode == SearchMode.KEYWORD:
            results = await self._execute_keyword_search(
                query, file_filter, language
            )
            return [], results
        else:  # SUMMARY
            results = await self._execute_vector_search(
                query, file_filter, language, will_rerank
            )
            return results, []

    async def _execute_hybrid_search(
        self,
        query: str,
        file_filter: Optional[str],
        language: Optional[str],
        will_rerank: bool,
    ) -> Tuple[List[HybridSearchResult], List[HybridSearchResult]]:
        """Execute both vector and keyword search in parallel"""
        try:
            vector_task = self._execute_vector_search(
                query, file_filter, language, will_rerank
            )
            keyword_task = self._execute_keyword_search(
                query, file_filter, language
            )

            vector_results, keyword_results = await asyncio.gather(
                vector_task, keyword_task, return_exceptions=True
            )

            if isinstance(vector_results, Exception):
                logger.error(f"Vector search failed: {vector_results}")
                vector_results = []
            if isinstance(keyword_results, Exception):
                logger.error(f"Keyword search failed: {keyword_results}")
                keyword_results = []

            return vector_results, keyword_results

        except Exception as e:
            logger.error(f"Hybrid search failed: {e}")
            return [], []

    async def _execute_vector_search(
        self,
        query: str,
        file_filter: Optional[str],
        language: Optional[str],
        will_rerank: bool,
    ) -> List[HybridSearchResult]:
        """Execute vector (semantic) search"""
        try:
            # Generate query embedding
            response = await asyncio.to_thread(
                self.llm_client.embed, [query]
            )
            query_embedding = response.embeddings[0]

            # Determine fetch limit
            if will_rerank and self.reranker:
                fetch_limit = self.config.vector_candidates * self.config.recall_multiplier
            else:
                fetch_limit = self.config.vector_candidates

            # Build filters
            filters = {}
            if language:
                filters["language"] = language

            # Search vector store (wrap in thread for sync implementations)
            try:
                # Try async first if available
                if hasattr(self.vector_store, 'search_async'):
                    results = await self.vector_store.search_async(
                        query_embedding=query_embedding,
                        top_k=fetch_limit,
                        filters=filters if filters else None,
                    )
                else:
                    # Fallback to sync in thread
                    results = await asyncio.to_thread(
                        self.vector_store.search,
                        query_embedding=query_embedding,
                        top_k=fetch_limit,
                        filters=filters if filters else None,
                    )
            except TypeError:
                # Some implementations use positional args
                results = await asyncio.to_thread(
                    self.vector_store.search,
                    query_embedding,
                    fetch_limit,
                    filters if filters else None,
                )

            # Handle case where results is None
            if results is None:
                logger.warning("[Vector Search] Vector store returned None")
                return []

            # Apply file filter
            if file_filter:
                results = [
                    r for r in results
                    if self._match_file_filter(r.code_unit.file_path, file_filter)
                ]

            # Convert to HybridSearchResult with ranks
            hybrid_results = []
            for rank, result in enumerate(results):
                hybrid_results.append(HybridSearchResult(
                    code_unit=result.code_unit,
                    score=result.score,
                    source="vector",
                    rank=rank,
                    metadata={"original_score": result.score},
                ))

            return hybrid_results

        except Exception as e:
            logger.error(f"Vector search failed: {e}", exc_info=True)
            return []

    def _match_file_filter(self, file_path: str, pattern: str) -> bool:
        """Match file path against filter pattern with multiple strategies"""
        # Normalize path separators
        normalized_path = file_path.replace("\\", "/")
        normalized_pattern = pattern.replace("\\", "/")

        # Try exact fnmatch
        if fnmatch.fnmatch(normalized_path, normalized_pattern):
            return True

        # Try with wildcard prefix (for partial patterns like "*.py")
        if fnmatch.fnmatch(normalized_path, f"*/{normalized_pattern}"):
            return True

        # Try substring match for simple patterns
        if "*" not in pattern and "?" not in pattern:
            return pattern.lower() in file_path.lower()

        return False

    async def _execute_keyword_search(
        self,
        query: str,
        file_filter: Optional[str],
        language: Optional[str],
    ) -> List[HybridSearchResult]:
        """Execute keyword (lexical) search

        Uses regex pattern matching on indexed code units.
        """
        try:
            # Extract keywords from query
            keywords = self._extract_keywords(query)
            if not keywords:
                logger.debug("[Keyword Search] No keywords extracted from query")
                return []

            # Get all code units - handle different vector store implementations
            all_units = []
            try:
                if hasattr(self.vector_store, 'get_all'):
                    all_units = await asyncio.to_thread(
                        self.vector_store.get_all,
                        limit=10000
                    )
                elif hasattr(self.vector_store, 'get_all_units'):
                    all_units = await asyncio.to_thread(
                        self.vector_store.get_all_units,
                        limit=10000
                    )
                elif hasattr(self.vector_store, 'list_all'):
                    all_units = await asyncio.to_thread(
                        self.vector_store.list_all,
                        10000
                    )
                else:
                    logger.warning(
                        "[Keyword Search] Vector store does not support get_all, "
                        "keyword search unavailable"
                    )
                    return []
            except Exception as e:
                logger.warning(f"[Keyword Search] Failed to get all units: {e}")
                return []

            if not all_units:
                return []

            # Score each unit by keyword matches
            scored_results = []

            for unit in all_units:
                # Apply language filter
                unit_language = getattr(unit, 'language', None)
                if language and unit_language != language:
                    continue

                # Apply file filter
                unit_file_path = getattr(unit, 'file_path', '')
                if file_filter and not self._match_file_filter(unit_file_path, file_filter):
                    continue

                # Calculate keyword match score
                score = self._score_keyword_match(unit, keywords)
                if score > 0:
                    scored_results.append((unit, score))

            # Sort by score and take top candidates
            scored_results.sort(key=lambda x: x[1], reverse=True)
            top_results = scored_results[:self.config.keyword_candidates]

            # Convert to HybridSearchResult with ranks
            hybrid_results = []
            for rank, (unit, score) in enumerate(top_results):
                hybrid_results.append(HybridSearchResult(
                    code_unit=unit,
                    score=score,
                    source="keyword",
                    rank=rank,
                    metadata={"keyword_score": score},
                ))

            return hybrid_results

        except Exception as e:
            logger.error(f"Keyword search failed: {e}")
            return []

    def _extract_keywords(self, query: str) -> List[str]:
        """Extract keywords from query for lexical search"""
        # Remove common stop words and short words
        stop_words = {
            "the", "a", "an", "is", "are", "was", "were", "be", "been",
            "being", "have", "has", "had", "do", "does", "did", "will",
            "would", "could", "should", "may", "might", "must", "shall",
            "can", "need", "dare", "ought", "used", "to", "of", "in",
            "for", "on", "with", "at", "by", "from", "as", "into",
            "through", "during", "before", "after", "above", "below",
            "between", "under", "again", "further", "then", "once",
            "here", "there", "when", "where", "why", "how", "all",
            "each", "few", "more", "most", "other", "some", "such",
            "no", "nor", "not", "only", "own", "same", "so", "than",
            "too", "very", "just", "and", "but", "if", "or", "because",
            "until", "while", "this", "that", "these", "those", "it",
            "its", "what", "which", "who", "whom", "find", "search",
            "look", "get", "show", "code", "function", "class", "method",
        }

        # Tokenize and filter
        words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', query.lower())
        keywords = [
            w for w in words
            if w not in stop_words and len(w) >= 3
        ]

        return keywords

    def _score_keyword_match(
        self,
        unit: CodeUnit,
        keywords: List[str],
    ) -> float:
        """Score a code unit by keyword matches

        Uses token overlap scoring similar to ContextWeaver.
        """
        if not keywords:
            return 0.0

        # Build searchable text with safe attribute access
        text_parts = []

        # Get code safely
        code = getattr(unit, 'code', '') or ''
        text_parts.append(code.lower())

        # Get symbol safely
        symbol = getattr(unit, 'symbol', '') or ''
        text_parts.append(symbol.lower())

        # Get docstring safely
        docstring = getattr(unit, 'docstring', '') or ''
        text_parts.append(docstring.lower())

        text = " ".join(text_parts)

        if not text.strip():
            return 0.0

        score = 0.0

        for keyword in keywords:
            # Exact word boundary match (higher score)
            try:
                pattern = rf'\b{re.escape(keyword)}\b'
                matches = len(re.findall(pattern, text))
                if matches > 0:
                    score += matches * 1.0
                # Substring match (lower score)
                elif keyword in text:
                    score += 0.5
            except re.error:
                # Fallback to simple substring match if regex fails
                if keyword in text:
                    score += 0.5

        # Normalize by keyword count
        return score / len(keywords)

    # ─────────────────────────────────────────────────────────────────
    # Result Merging (RRF Fusion)
    # ─────────────────────────────────────────────────────────────────

    def _merge_results(
        self,
        vector_results: List[HybridSearchResult],
        keyword_results: List[HybridSearchResult],
        will_rerank: bool,
    ) -> List[HybridSearchResult]:
        """Merge vector and keyword results using RRF fusion

        RRF formula: score = Σ w_i / (k + rank_i)
        where k is the smoothing constant.
        """
        if not keyword_results:
            return self._deduplicate_by_location(vector_results)
        if not vector_results:
            return self._deduplicate_by_location(keyword_results)

        # Normalize scores if not reranking
        if not will_rerank:
            keyword_results, vector_results = self._normalize_scores(
                keyword_results, vector_results
            )

        # RRF fusion
        k = self.config.rrf_k
        w_vec = self.config.vector_weight
        w_key = self.config.keyword_weight

        # Build fusion map: key -> (score, result, sources)
        fusion_map: Dict[str, Tuple[float, HybridSearchResult, Set[str]]] = {}

        def get_key(result: HybridSearchResult) -> str:
            return f"{result.file_path}#{result.start_line}#{result.end_line}"

        # Process vector results
        for result in vector_results:
            key = get_key(result)
            rrf_score = w_vec / (k + result.rank)

            if key in fusion_map:
                existing_score, existing_result, sources = fusion_map[key]
                fusion_map[key] = (
                    existing_score + rrf_score,
                    existing_result,
                    sources | {"vector"},
                )
            else:
                fusion_map[key] = (rrf_score, result, {"vector"})

        # Process keyword results
        for result in keyword_results:
            key = get_key(result)
            rrf_score = w_key / (k + result.rank)

            if key in fusion_map:
                existing_score, existing_result, sources = fusion_map[key]
                fusion_map[key] = (
                    existing_score + rrf_score,
                    existing_result,
                    sources | {"keyword"},
                )
            else:
                fusion_map[key] = (rrf_score, result, {"keyword"})

        # Convert to results
        fused_results = []
        for key, (score, result, sources) in fusion_map.items():
            source = "both" if len(sources) > 1 else list(sources)[0]
            fused_results.append(HybridSearchResult(
                code_unit=result.code_unit,
                score=score,
                source=source,
                rank=0,
                metadata={**result.metadata, "fusion_sources": list(sources)},
            ))

        # Sort by fused score
        fused_results.sort(key=lambda r: r.score, reverse=True)

        # Assign new ranks
        for i, result in enumerate(fused_results):
            result.rank = i

        logger.debug(
            f"[RRF] Fused {len(vector_results)} vector + {len(keyword_results)} keyword "
            f"-> {len(fused_results)} results "
            f"({sum(1 for r in fused_results if r.source == 'both')} overlap)"
        )

        return fused_results

    def _normalize_scores(
        self,
        keyword_results: List[HybridSearchResult],
        vector_results: List[HybridSearchResult],
    ) -> Tuple[List[HybridSearchResult], List[HybridSearchResult]]:
        """Normalize keyword and vector scores to comparable range"""
        if not keyword_results or not vector_results:
            return keyword_results, vector_results

        max_vector = max(r.score for r in vector_results)
        max_keyword = max(r.score for r in keyword_results)

        if max_vector <= 0 or max_keyword <= 0:
            return keyword_results, vector_results

        scale_factor = max_vector / max_keyword

        normalized_keyword = []
        for result in keyword_results:
            normalized_keyword.append(HybridSearchResult(
                code_unit=result.code_unit,
                score=result.score * scale_factor,
                source=result.source,
                rank=result.rank,
                metadata=result.metadata,
            ))

        return normalized_keyword, vector_results

    def _deduplicate_by_location(
        self,
        results: List[HybridSearchResult],
    ) -> List[HybridSearchResult]:
        """Remove duplicates based on file location

        Keeps highest scoring result per (file_path, start_line, end_line).
        """
        seen: Dict[Tuple[str, int, int], HybridSearchResult] = {}

        for result in results:
            key = (result.file_path, result.start_line, result.end_line)
            if key not in seen or result.score > seen[key].score:
                seen[key] = result

        deduped = list(seen.values())
        deduped.sort(key=lambda r: r.score, reverse=True)
        return deduped

    def _apply_exclusions(
        self,
        results: List[HybridSearchResult],
        exclude_patterns: List[str],
    ) -> List[HybridSearchResult]:
        """Filter out results matching exclusion patterns"""
        if not exclude_patterns:
            return results

        filtered = []
        for result in results:
            excluded = False
            for pattern in exclude_patterns:
                if pattern in result.file_path:
                    excluded = True
                    break
                if fnmatch.fnmatch(result.file_path, f"*{pattern}*"):
                    excluded = True
                    break
            if not excluded:
                filtered.append(result)

        return filtered

    # ─────────────────────────────────────────────────────────────────
    # Result Finalization
    # ─────────────────────────────────────────────────────────────────

    async def _finalize_results(
        self,
        candidates: List[HybridSearchResult],
        query: str,
        limit: int,
        use_rerank: bool,
    ) -> List[HybridSearchResult]:
        """Apply reranking or smart cutoff and return final results"""
        if not candidates:
            return []

        # Apply reranker if available
        if use_rerank and self.reranker and candidates:
            reranked = await self.reranker.rerank(query, candidates, limit)
            return reranked

        # Apply smart cutoff
        if self.config.enable_smart_cutoff:
            candidates = self._apply_smart_cutoff(candidates)

        return candidates[:limit]

    def _apply_smart_cutoff(
        self,
        candidates: List[HybridSearchResult],
    ) -> List[HybridSearchResult]:
        """Apply smart TopK cutoff with dynamic thresholds

        Based on ContextWeaver's smart cutoff:
        1. Low confidence fallback: if top_score < floor -> return top1
        2. Dynamic threshold: max(floor, min(ratio_threshold, delta_threshold))
        3. Safe harbor: first min_k results only check floor
        """
        if not candidates:
            return []

        # Ensure sorted by score descending
        sorted_candidates = sorted(candidates, key=lambda r: r.score, reverse=True)

        config = self.config
        top_score = sorted_candidates[0].score

        # Low confidence fallback
        if top_score < config.smart_floor:
            logger.debug(
                f"[SmartCutoff] Top score {top_score:.3f} below floor "
                f"{config.smart_floor}, returning top1"
            )
            return [sorted_candidates[0]]

        # Calculate dynamic threshold
        ratio_threshold = top_score * config.smart_ratio
        delta_threshold = top_score - config.smart_delta
        dynamic_threshold = max(
            config.smart_floor,
            min(ratio_threshold, delta_threshold)
        )

        picked = []
        for i, candidate in enumerate(sorted_candidates):
            if len(picked) >= config.smart_max_k:
                break

            # Safe harbor: first min_k only check floor
            if i < config.smart_min_k:
                if candidate.score >= config.smart_floor:
                    picked.append(candidate)
                else:
                    break
            else:
                # Beyond safe harbor: check dynamic threshold
                if candidate.score >= dynamic_threshold:
                    picked.append(candidate)
                else:
                    break

        logger.debug(
            f"[SmartCutoff] {len(candidates)} -> {len(picked)} "
            f"(top={top_score:.3f}, threshold={dynamic_threshold:.3f})"
        )

        return picked

    # ─────────────────────────────────────────────────────────────────
    # Convenience Methods
    # ─────────────────────────────────────────────────────────────────

    async def search_by_file(
        self,
        query: str,
        file_path: str,
        limit: Optional[int] = None,
    ) -> List[HybridSearchResult]:
        """Search within a specific file"""
        return await self.search(
            query=query,
            limit=limit,
            file_filter=file_path,
            use_rerank=False,
        )

    async def search_security(
        self,
        query: str,
        limit: Optional[int] = None,
        language: Optional[str] = None,
    ) -> List[HybridSearchResult]:
        """Search with security focus

        Adds security-related keywords to boost relevant results.
        """
        security_query = f"{query} vulnerability security exploit injection"
        results = await self.search(
            query=security_query,
            limit=limit,
            language=language,
            mode=SearchMode.HYBRID,
        )

        # Boost results with security indicators
        for result in results:
            if self._has_security_indicators(result.code_unit):
                result.score *= self.config.security_boost
                result.metadata["security_boosted"] = True

        # Re-sort after boosting
        results.sort(key=lambda r: r.score, reverse=True)
        return results

    def _has_security_indicators(self, unit: CodeUnit) -> bool:
        """Check if code unit has security-related indicators"""
        security_patterns = [
            r'\bexec\b', r'\beval\b', r'\bsystem\b', r'\bshell\b',
            r'\bsql\b', r'\bquery\b', r'\binject\b',
            r'\bpassword\b', r'\bsecret\b', r'\btoken\b', r'\bauth\b',
            r'\bpickle\b', r'\bdeserialize\b', r'\bunserialize\b',
            r'\bfile_get_contents\b', r'\bfopen\b', r'\bread\b', r'\bwrite\b',
            r'\bcurl\b', r'\brequest\b', r'\bhttp\b',
            r'\b(?:md5|sha1|sha256)\b',
        ]

        text = f"{unit.code} {unit.symbol or ''} {unit.docstring or ''}".lower()

        for pattern in security_patterns:
            if re.search(pattern, text):
                return True

        return False

    def get_stats(self) -> Dict[str, Any]:
        """Get search service statistics"""
        return {
            "config": {
                "default_limit": self.config.default_limit,
                "vector_candidates": self.config.vector_candidates,
                "keyword_candidates": self.config.keyword_candidates,
                "rrf_k": self.config.rrf_k,
                "enable_smart_cutoff": self.config.enable_smart_cutoff,
            },
            "has_reranker": self.reranker is not None,
            "root_path": str(self.root_path) if self.root_path else None,
        }


# Factory function
def create_search_service(
    llm_client: "BaseLLMClient",
    vector_store: VectorStoreInterface,
    config: Optional[SearchConfig] = None,
    reranker: Optional[RerankerInterface] = None,
    root_path: Optional[Path] = None,
) -> SearchService:
    """Create a search service instance

    Args:
        llm_client: LLM client for embedding generation
        vector_store: Vector store for semantic search
        config: Optional search configuration
        reranker: Optional reranker for result refinement
        root_path: Optional root path for keyword search

    Returns:
        Configured SearchService instance
    """
    return SearchService(
        llm_client=llm_client,
        vector_store=vector_store,
        config=config,
        reranker=reranker,
        root_path=root_path,
    )
