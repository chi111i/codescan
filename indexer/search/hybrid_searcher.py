"""Hybrid search orchestrator

Combines vector search with keyword (grep) search for improved recall.
Parallel execution with score normalization and deduplication.

Features:
- Vector similarity search via VectorStoreInterface
- Keyword search via ripgrep (rg) or Python grep fallback
- Score normalization and fusion
- Result deduplication by file_path + line range
- Configurable weights and limits
"""

from __future__ import annotations

import asyncio
import subprocess
import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from .query_parser import QueryParser, ParsedQuery
from .reranker import CodeReranker, RerankerConfig

logger = logging.getLogger(__name__)


@dataclass
class HybridSearchConfig:
    """Configuration for hybrid search"""
    enable_vector_search: bool = True
    enable_keyword_search: bool = True

    vector_weight: float = 0.6
    keyword_weight: float = 0.4

    vector_top_k: int = 50
    keyword_top_k: int = 30

    final_top_k: int = 20

    enable_reranking: bool = True
    reranker_config: RerankerConfig = None

    keyword_search_extensions: List[str] = None
    use_ripgrep: bool = True

    max_keyword_file_size: int = 1024 * 1024

    def __post_init__(self):
        if self.keyword_search_extensions is None:
            self.keyword_search_extensions = [
                ".py", ".js", ".ts", ".jsx", ".tsx",
                ".java", ".go", ".rs", ".php", ".rb",
                ".c", ".cpp", ".h", ".hpp", ".cs",
            ]


@dataclass
class HybridSearchResult:
    """Single hybrid search result"""
    file_path: str
    start_line: int
    end_line: int
    content: str
    score: float
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def dedup_key(self) -> str:
        return f"{self.file_path}:{self.start_line}-{self.end_line}"

    def overlaps(self, other: "HybridSearchResult") -> bool:
        if self.file_path != other.file_path:
            return False
        return not (self.end_line < other.start_line or self.start_line > other.end_line)


class HybridSearcher:
    """Hybrid search orchestrator

    Combines vector search with keyword search for improved recall.
    """

    def __init__(
        self,
        vector_store: Any = None,
        embedding_client: Any = None,
        project_path: str = None,
        config: HybridSearchConfig = None
    ):
        self.vector_store = vector_store
        self.embedding_client = embedding_client
        self.project_path = Path(project_path) if project_path else None
        self.config = config or HybridSearchConfig()
        self.query_parser = QueryParser()
        self.reranker = CodeReranker(self.config.reranker_config)
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._ripgrep_available = self._check_ripgrep()

    def _check_ripgrep(self) -> bool:
        try:
            result = subprocess.run(
                ["rg", "--version"],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except Exception:
            return False

    async def search(
        self,
        query: str,
        top_k: int = None,
        filters: Dict[str, Any] = None
    ) -> List[HybridSearchResult]:
        """Execute hybrid search

        Args:
            query: Search query (may include modifiers)
            top_k: Number of results to return
            filters: Additional metadata filters

        Returns:
            List of HybridSearchResult
        """
        top_k = top_k or self.config.final_top_k
        parsed = self.query_parser.parse(query)

        if parsed.is_empty:
            return []

        combined_filters = {**(filters or {}), **(parsed.to_metadata_filter() or {})}
        file_filter = self.query_parser.build_file_filter(parsed)

        tasks = []

        if self.config.enable_vector_search and self.vector_store and self.embedding_client:
            tasks.append(self._vector_search(parsed.text, combined_filters))

        if self.config.enable_keyword_search and self.project_path:
            tasks.append(self._keyword_search(parsed.text, parsed.keywords, file_filter))

        if not tasks:
            return []

        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        all_results = []
        for i, results in enumerate(results_list):
            if isinstance(results, Exception):
                logger.warning(f"Search task {i} failed: {results}")
                continue
            all_results.extend(results)

        merged = self._merge_results(all_results)

        if self.config.enable_reranking and len(merged) > top_k:
            merged = self._rerank_results(merged, parsed.text, parsed.keywords)

        return merged[:top_k]

    async def _vector_search(
        self,
        query_text: str,
        filters: Dict[str, Any] = None
    ) -> List[HybridSearchResult]:
        """Execute vector similarity search"""
        if not self.embedding_client or not self.vector_store:
            return []

        try:
            if hasattr(self.embedding_client, 'embed_single'):
                embedding = await self.embedding_client.embed_single(query_text)
            elif hasattr(self.embedding_client, 'embed'):
                embedding = self.embedding_client.embed(query_text)
            else:
                logger.warning("Embedding client has no embed method")
                return []

            if hasattr(self.vector_store, 'search_async'):
                results = await self.vector_store.search_async(
                    embedding,
                    limit=self.config.vector_top_k,
                    file_filter=filters.get("file_path") if filters else None,
                    artifact_types=filters.get("artifact_type") if filters else None
                )
            else:
                results = self.vector_store.search(
                    embedding,
                    top_k=self.config.vector_top_k,
                    filters=filters
                )

            hybrid_results = []
            for r in results:
                unit = r.code_unit if hasattr(r, 'code_unit') else r
                hybrid_results.append(HybridSearchResult(
                    file_path=getattr(unit, 'file_path', ''),
                    start_line=getattr(unit, 'start_line', 0),
                    end_line=getattr(unit, 'end_line', 0),
                    content=getattr(unit, 'code', ''),
                    score=r.score * self.config.vector_weight,
                    source="vector",
                    metadata=r.metadata if hasattr(r, 'metadata') else {}
                ))

            return hybrid_results

        except Exception as e:
            logger.error(f"Vector search failed: {e}")
            return []

    async def _keyword_search(
        self,
        query_text: str,
        keywords: List[str],
        file_filter: callable = None
    ) -> List[HybridSearchResult]:
        """Execute keyword search using ripgrep or Python fallback"""
        if not self.project_path:
            return []

        search_terms = keywords if keywords else query_text.split()[:5]
        if not search_terms:
            return []

        loop = asyncio.get_event_loop()

        if self._ripgrep_available and self.config.use_ripgrep:
            results = await loop.run_in_executor(
                self._executor,
                self._ripgrep_search,
                search_terms,
                file_filter
            )
        else:
            results = await loop.run_in_executor(
                self._executor,
                self._python_grep_search,
                search_terms,
                file_filter
            )

        return results

    def _ripgrep_search(
        self,
        terms: List[str],
        file_filter: callable = None
    ) -> List[HybridSearchResult]:
        """Search using ripgrep"""
        results = []

        for term in terms[:5]:
            try:
                cmd = [
                    "rg",
                    "--json",
                    "-i",
                    "-C", "2",
                    "--max-filesize", f"{self.config.max_keyword_file_size}b",
                ]

                for ext in self.config.keyword_search_extensions:
                    cmd.extend(["-g", f"*{ext}"])

                cmd.append(term)
                cmd.append(str(self.project_path))

                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                for line in proc.stdout.splitlines():
                    if not line.strip():
                        continue
                    try:
                        import json
                        data = json.loads(line)
                        if data.get("type") == "match":
                            match_data = data.get("data", {})
                            file_path = match_data.get("path", {}).get("text", "")

                            if file_filter and not file_filter(file_path):
                                continue

                            line_num = match_data.get("line_number", 0)
                            content = match_data.get("lines", {}).get("text", "")

                            results.append(HybridSearchResult(
                                file_path=file_path,
                                start_line=max(1, line_num - 2),
                                end_line=line_num + 2,
                                content=content,
                                score=self.config.keyword_weight,
                                source="keyword",
                                metadata={"term": term}
                            ))
                    except (json.JSONDecodeError, KeyError):
                        continue

            except subprocess.TimeoutExpired:
                logger.warning(f"Ripgrep timeout for term: {term}")
            except Exception as e:
                logger.error(f"Ripgrep error: {e}")

        return results[:self.config.keyword_top_k]

    def _python_grep_search(
        self,
        terms: List[str],
        file_filter: callable = None
    ) -> List[HybridSearchResult]:
        """Fallback Python-based grep"""
        results = []
        pattern = re.compile("|".join(re.escape(t) for t in terms), re.IGNORECASE)

        for ext in self.config.keyword_search_extensions:
            for file_path in self.project_path.rglob(f"*{ext}"):
                if file_filter and not file_filter(str(file_path)):
                    continue

                try:
                    if file_path.stat().st_size > self.config.max_keyword_file_size:
                        continue

                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    lines = content.splitlines()

                    for i, line in enumerate(lines):
                        if pattern.search(line):
                            start = max(0, i - 2)
                            end = min(len(lines), i + 3)
                            context = "\n".join(lines[start:end])

                            results.append(HybridSearchResult(
                                file_path=str(file_path),
                                start_line=start + 1,
                                end_line=end,
                                content=context,
                                score=self.config.keyword_weight,
                                source="keyword",
                                metadata={"matched_line": i + 1}
                            ))

                            if len(results) >= self.config.keyword_top_k:
                                return results

                except Exception as e:
                    logger.debug(f"Error reading {file_path}: {e}")

        return results

    def _merge_results(
        self,
        results: List[HybridSearchResult]
    ) -> List[HybridSearchResult]:
        """Merge and deduplicate results"""
        dedup_map: Dict[str, HybridSearchResult] = {}

        for r in results:
            key = r.dedup_key

            if key in dedup_map:
                existing = dedup_map[key]
                combined_score = existing.score + r.score * 0.5
                if r.source != existing.source:
                    combined_score *= 1.2

                dedup_map[key] = HybridSearchResult(
                    file_path=existing.file_path,
                    start_line=existing.start_line,
                    end_line=existing.end_line,
                    content=existing.content if len(existing.content) >= len(r.content) else r.content,
                    score=combined_score,
                    source=f"{existing.source}+{r.source}" if r.source not in existing.source else existing.source,
                    metadata={**existing.metadata, **r.metadata}
                )
            else:
                overlapping = None
                for existing_key, existing in dedup_map.items():
                    if r.overlaps(existing):
                        overlapping = existing_key
                        break

                if overlapping:
                    existing = dedup_map[overlapping]
                    if r.score > existing.score:
                        dedup_map[overlapping] = r
                else:
                    dedup_map[key] = r

        merged = list(dedup_map.values())
        merged.sort(key=lambda x: x.score, reverse=True)

        return merged

    def _rerank_results(
        self,
        results: List[HybridSearchResult],
        query_text: str,
        keywords: List[str]
    ) -> List[HybridSearchResult]:
        """Rerank results using CodeReranker"""
        if not results:
            return []

        reranked = self.reranker.rerank(
            results,
            query_text,
            dangerous_keywords=keywords,
            score_extractor=lambda r: r.score,
            code_extractor=lambda r: r.content,
            symbol_extractor=lambda r: Path(r.file_path).stem if r.file_path else "",
        )

        for rr in reranked:
            rr.item.score = rr.final_score

        return [rr.item for rr in reranked]

    def search_sync(
        self,
        query: str,
        top_k: int = None,
        filters: Dict[str, Any] = None
    ) -> List[HybridSearchResult]:
        """Synchronous search wrapper"""
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.search(query, top_k, filters))
        finally:
            loop.close()


async def hybrid_search(
    query: str,
    vector_store: Any,
    embedding_client: Any,
    project_path: str,
    top_k: int = 20,
    config: HybridSearchConfig = None
) -> List[HybridSearchResult]:
    """Convenience function for hybrid search"""
    searcher = HybridSearcher(
        vector_store=vector_store,
        embedding_client=embedding_client,
        project_path=project_path,
        config=config
    )
    return await searcher.search(query, top_k)
