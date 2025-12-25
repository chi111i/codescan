"""Local / offline embedding generation.

This module provides a lightweight, dependency-free embedding fallback.
It is **not** intended to be a semantic embedding replacement for
production-grade vector retrieval, but it is good enough to:

1. Make the tool usable in offline environments.
2. Provide deterministic similarity based on token overlap.
3. Keep unit tests and small demo projects functional without calling
   external embedding services.

The approach is a classic *feature hashing* (a.k.a. hashing trick):
- tokenize input (works for natural language and code-ish text)
- hash tokens (and a few bigrams) into a fixed-size vector
- L2-normalize
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Iterable, List


_TOKEN_RE = re.compile(
    r"""
    # identifiers / keywords
    [A-Za-z_][A-Za-z0-9_]*
    |
    # numbers
    \d+(?:\.\d+)?
    |
    # some punctuations that are meaningful in code
    ==|!=|<=|>=|->|::|\.|/|\\
    """,
    re.VERBOSE,
)


def _iter_tokens(text: str) -> List[str]:
    """Tokenize input text into a list of simple tokens."""
    if not text:
        return []
    return [t.lower() for t in _TOKEN_RE.findall(text)]


def _hash_to_int(token: str) -> int:
    # 64-bit hash from blake2b for speed & stability
    h = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(h, "big", signed=False)


def embed_texts(texts: Iterable[str], dim: int = 1536) -> List[List[float]]:
    """Generate deterministic embeddings for a list of texts."""
    if dim <= 0:
        raise ValueError(f"dim must be > 0, got {dim}")

    vectors: List[List[float]] = []

    for text in texts:
        tokens = _iter_tokens(text)
        vec = [0.0] * dim

        # Unigrams
        for tok in tokens:
            h = _hash_to_int(tok)
            idx = h % dim
            sign = 1.0 if (h >> 1) & 1 else -1.0
            vec[idx] += sign

        # Bigrams (a small boost for code structure)
        for a, b in zip(tokens, tokens[1:]):
            bigram = f"{a}\u241f{b}"  # U+241F SYMBOL FOR UNIT SEPARATOR
            h = _hash_to_int(bigram)
            idx = h % dim
            sign = 1.0 if (h >> 1) & 1 else -1.0
            vec[idx] += 0.5 * sign

        # Normalize
        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0:
            vec = [x / norm for x in vec]

        vectors.append(vec)

    return vectors
