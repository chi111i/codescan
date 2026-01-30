"""Search module for CodeScan

Provides hybrid search capabilities combining vector similarity search
with keyword (grep) search for improved recall.

Components:
- QueryParser: Parse search queries with modifier syntax
- CodeReranker: Rerank results based on security relevance
- SecurityFirstReranker: CWE-aware security-first reranking
- HybridSearcher: Orchestrate vector + keyword search
- APIReranker: External API-based reranking (OpenAI compatible)
"""

from .query_parser import (
    QueryParser,
    ParsedQuery,
    ModifierType,
    parse_query,
)

from .reranker import (
    # Original reranker
    CodeReranker,
    RerankerConfig,
    RerankerResult,
    # Security-first reranker (new)
    SecurityFirstReranker,
    SecurityRerankerConfig,
    # API reranker (enhanced)
    APIReranker,
    # Hybrid reranker
    HybridReranker,
    # Factory functions
    create_security_reranker,
    create_api_reranker,
    create_hybrid_reranker,
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
    # Original Reranker
    "CodeReranker",
    "RerankerConfig",
    "RerankerResult",
    # Security-First Reranker (new)
    "SecurityFirstReranker",
    "SecurityRerankerConfig",
    # API Reranker
    "APIReranker",
    # Hybrid Reranker
    "HybridReranker",
    # Factory functions
    "create_security_reranker",
    "create_api_reranker",
    "create_hybrid_reranker",
    # Hybrid Searcher
    "HybridSearcher",
    "HybridSearchConfig",
    "HybridSearchResult",
    "hybrid_search",
]
