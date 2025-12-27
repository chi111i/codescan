"""Search module for CodeScan

Provides hybrid search capabilities combining vector similarity search
with keyword (grep) search for improved recall.

Components:
- QueryParser: Parse search queries with modifier syntax
- CodeReranker: Rerank results based on security relevance
- HybridSearcher: Orchestrate vector + keyword search
"""

from .query_parser import (
    QueryParser,
    ParsedQuery,
    ModifierType,
    parse_query,
)

from .reranker import (
    CodeReranker,
    RerankerConfig,
    RerankerResult,
    APIReranker,
)

from .hybrid_searcher import (
    HybridSearcher,
    HybridSearchConfig,
    HybridSearchResult,
    hybrid_search,
)

__all__ = [
    # Query Parser
    "QueryParser",
    "ParsedQuery",
    "ModifierType",
    "parse_query",
    # Reranker
    "CodeReranker",
    "RerankerConfig",
    "RerankerResult",
    "APIReranker",
    # Hybrid Searcher
    "HybridSearcher",
    "HybridSearchConfig",
    "HybridSearchResult",
    "hybrid_search",
]
