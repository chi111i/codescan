# Enhanced In-Memory Vector Store with NumPy acceleration
# Based on ACI (augmented-codebase-indexer) best practices

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set

from .interface import (
    VectorStoreInterface,
    SearchResult,
    UpsertResult,
    DeleteResult,
    HybridSearchConfig,
    ArtifactType,
    VectorStoreError,
    CodeReranker,
)

logger = logging.getLogger(__name__)

# Try to import NumPy for acceleration
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    logger.warning("NumPy not available, using pure Python implementation")

# Try to import faiss for even faster search (optional)
try:
    import faiss
    HAS_FAISS = True
except ImportError:
    HAS_FAISS = False


@dataclass
class MemoryStoreConfig:
    """Configuration for in-memory vector store"""
    use_numpy: bool = True
    use_faiss: bool = False  # Requires faiss-cpu
    embedding_dim: int = 1536
    normalize_vectors: bool = True  # L2 normalize for cosine similarity


class EnhancedInMemoryStore(VectorStoreInterface):
    """Enhanced in-memory vector store with NumPy/FAISS acceleration

    Features:
    - NumPy vectorized cosine similarity (10-50x faster than pure Python)
    - Optional FAISS index for very large datasets
    - Payload filtering support
    - Hybrid search with reranking

    Based on ACI best practices.
    """

    def __init__(
        self,
        config: Optional[MemoryStoreConfig] = None,
        embedding_dim: int = 1536,
    ):
        """Initialize enhanced in-memory store

        Args:
            config: Optional configuration
            embedding_dim: Vector dimension (default 1536 for text-embedding-3-small)
        """
        self.config = config or MemoryStoreConfig(embedding_dim=embedding_dim)
        self.embedding_dim = embedding_dim

        # Storage
        self._ids: List[str] = []
        self._payloads: Dict[str, Dict[str, Any]] = {}

        # Vector storage (NumPy or Python list)
        if HAS_NUMPY and self.config.use_numpy:
            self._vectors: Optional[np.ndarray] = None
            self._use_numpy = True
        else:
            self._vectors_list: List[List[float]] = []
            self._use_numpy = False

        # Optional FAISS index
        self._faiss_index = None
        if HAS_FAISS and self.config.use_faiss:
            self._init_faiss_index()

        self._reranker = CodeReranker()
        self._id_to_idx: Dict[str, int] = {}

    def _init_faiss_index(self) -> None:
        """Initialize FAISS index for fast similarity search"""
        if not HAS_FAISS:
            return

        # Use inner product index (for normalized vectors = cosine similarity)
        self._faiss_index = faiss.IndexFlatIP(self.embedding_dim)
        logger.info(f"FAISS index initialized (dim={self.embedding_dim})")

    def initialize(self) -> None:
        """Initialize store (no-op for memory store)"""
        pass

    def add(self, units: List[Any], embeddings: List[List[float]]) -> None:
        """Add code units with embeddings

        Args:
            units: CodeUnit objects
            embeddings: Corresponding embedding vectors
        """
        if len(units) != len(embeddings):
            raise ValueError("units and embeddings count mismatch")

        ids = [u.id for u in units]
        payloads = [self._unit_to_payload(u) for u in units]

        self._add_vectors(ids, embeddings, payloads)

    def _unit_to_payload(self, unit: Any) -> Dict[str, Any]:
        """Convert CodeUnit to payload dict"""
        payload = unit.to_dict()

        # Add artifact_type for filtering
        unit_type_str = unit.unit_type.value if hasattr(unit.unit_type, 'value') else str(unit.unit_type)
        if unit_type_str in ["function", "method", "class"]:
            payload["artifact_type"] = unit_type_str
        else:
            payload["artifact_type"] = ArtifactType.CHUNK.value

        return payload

    def _add_vectors(
        self,
        ids: List[str],
        vectors: List[List[float]],
        payloads: List[Dict[str, Any]],
    ) -> None:
        """Add vectors to storage

        Args:
            ids: Vector IDs
            vectors: Embedding vectors
            payloads: Metadata payloads
        """
        for i, (vid, vec, payload) in enumerate(zip(ids, vectors, payloads)):
            if vid in self._id_to_idx:
                # Update existing
                idx = self._id_to_idx[vid]
                self._payloads[vid] = payload
                if self._use_numpy:
                    vec_arr = np.array(vec, dtype=np.float32)
                    if self.config.normalize_vectors:
                        norm = np.linalg.norm(vec_arr)
                        if norm > 0:
                            vec_arr = vec_arr / norm
                    self._vectors[idx] = vec_arr
                else:
                    self._vectors_list[idx] = vec
            else:
                # Add new
                idx = len(self._ids)
                self._ids.append(vid)
                self._id_to_idx[vid] = idx
                self._payloads[vid] = payload

                if self._use_numpy:
                    vec_arr = np.array(vec, dtype=np.float32)
                    if self.config.normalize_vectors:
                        norm = np.linalg.norm(vec_arr)
                        if norm > 0:
                            vec_arr = vec_arr / norm

                    if self._vectors is None:
                        self._vectors = vec_arr.reshape(1, -1)
                    else:
                        self._vectors = np.vstack([self._vectors, vec_arr])
                else:
                    self._vectors_list.append(vec)

        # Update FAISS index if available
        if self._faiss_index is not None and self._use_numpy:
            self._rebuild_faiss_index()

    def _rebuild_faiss_index(self) -> None:
        """Rebuild FAISS index from current vectors"""
        if self._faiss_index is None or self._vectors is None:
            return

        self._faiss_index.reset()
        self._faiss_index.add(self._vectors.astype(np.float32))

    async def upsert_batch_async(
        self,
        ids: List[str],
        vectors: List[List[float]],
        payloads: List[Dict[str, Any]],
        batch_id: Optional[str] = None,
    ) -> UpsertResult:
        """Async batch upsert (synchronous for memory store)

        Args:
            ids: Point IDs
            vectors: Embedding vectors
            payloads: Metadata payloads
            batch_id: Optional batch ID (ignored for memory store)

        Returns:
            UpsertResult with counts
        """
        self._add_vectors(ids, vectors, payloads)
        return UpsertResult(
            inserted_count=len(ids),
            updated_count=0,
            failed_count=0,
            failed_ids=[],
        )

    def search(
        self,
        query_embedding: List[float],
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[SearchResult]:
        """Vector similarity search

        Args:
            query_embedding: Query vector
            top_k: Number of results to return
            filters: Optional metadata filters

        Returns:
            List of SearchResult
        """
        if not self._ids:
            return []

        # Get candidate indices (filtered if needed)
        if filters:
            candidate_indices = self._get_filtered_indices(filters)
            if not candidate_indices:
                return []
        else:
            candidate_indices = list(range(len(self._ids)))

        # Compute similarities
        if self._use_numpy:
            scores = self._numpy_search(query_embedding, candidate_indices)
        else:
            scores = self._python_search(query_embedding, candidate_indices)

        # Sort and get top_k
        scored = [(candidate_indices[i], scores[i]) for i in range(len(candidate_indices))]
        scored.sort(key=lambda x: x[1], reverse=True)
        top_results = scored[:top_k]

        # Convert to SearchResult
        results = []
        for idx, score in top_results:
            unit_id = self._ids[idx]
            payload = self._payloads[unit_id]
            results.append(self._payload_to_result(payload, score))

        return results

    def _get_filtered_indices(self, filters: Dict[str, Any]) -> List[int]:
        """Get indices matching filters

        Args:
            filters: Filter conditions

        Returns:
            List of matching indices
        """
        matching = []

        for idx, unit_id in enumerate(self._ids):
            payload = self._payloads[unit_id]
            match = True

            for key, value in filters.items():
                payload_value = payload.get(key)

                if isinstance(value, list):
                    if payload_value not in value:
                        match = False
                        break
                elif payload_value != value:
                    match = False
                    break

            if match:
                matching.append(idx)

        return matching

    def _numpy_search(
        self,
        query: List[float],
        candidate_indices: List[int],
    ) -> np.ndarray:
        """NumPy vectorized similarity search

        Args:
            query: Query vector
            candidate_indices: Indices to search

        Returns:
            Array of similarity scores
        """
        query_arr = np.array(query, dtype=np.float32)

        # Normalize query
        if self.config.normalize_vectors:
            norm = np.linalg.norm(query_arr)
            if norm > 0:
                query_arr = query_arr / norm

        # Get candidate vectors
        candidate_vectors = self._vectors[candidate_indices]

        # Compute cosine similarity (dot product for normalized vectors)
        if self.config.normalize_vectors:
            scores = np.dot(candidate_vectors, query_arr)
        else:
            # Full cosine similarity computation
            dot_products = np.dot(candidate_vectors, query_arr)
            query_norm = np.linalg.norm(query_arr)
            vec_norms = np.linalg.norm(candidate_vectors, axis=1)
            scores = dot_products / (query_norm * vec_norms + 1e-10)

        return scores

    def _python_search(
        self,
        query: List[float],
        candidate_indices: List[int],
    ) -> List[float]:
        """Pure Python similarity search (fallback)

        Args:
            query: Query vector
            candidate_indices: Indices to search

        Returns:
            List of similarity scores
        """
        scores = []

        for idx in candidate_indices:
            vec = self._vectors_list[idx]
            score = self._cosine_similarity(query, vec)
            scores.append(score)

        return scores

    @staticmethod
    def _cosine_similarity(a: List[float], b: List[float]) -> float:
        """Compute cosine similarity between two vectors"""
        dot_product = sum(x * y for x, y in zip(a, b))
        norm_a = sum(x * x for x in a) ** 0.5
        norm_b = sum(x * x for x in b) ** 0.5
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot_product / (norm_a * norm_b)

    def _payload_to_result(self, payload: Dict[str, Any], score: float) -> SearchResult:
        """Convert payload to SearchResult

        Args:
            payload: Metadata payload
            score: Similarity score

        Returns:
            SearchResult
        """
        from ..models import CodeUnit

        try:
            code_unit = CodeUnit.from_dict(payload)
            return SearchResult(
                code_unit=code_unit,
                score=score,
                metadata={"source": "memory"},
            )
        except Exception as e:
            logger.warning(f"Failed to convert payload to CodeUnit: {e}")
            # Return minimal result
            return SearchResult(
                code_unit=None,
                score=score,
                metadata=payload,
            )

    async def search_async(
        self,
        query_vector: List[float],
        limit: int = 10,
        file_filter: Optional[str] = None,
        artifact_types: Optional[List[str]] = None,
    ) -> List[SearchResult]:
        """Async search (synchronous for memory store)

        Args:
            query_vector: Query embedding
            limit: Max results
            file_filter: Optional file path filter
            artifact_types: Optional artifact type filter

        Returns:
            List of SearchResult
        """
        filters = {}
        if file_filter:
            filters["file_path"] = file_filter
        if artifact_types:
            filters["artifact_type"] = artifact_types

        return self.search(query_vector, limit, filters if filters else None)

    def hybrid_search(
        self,
        query_embedding: List[float],
        query_text: str,
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None,
        hybrid_config: Optional[HybridSearchConfig] = None,
    ) -> List[SearchResult]:
        """Hybrid search with reranking

        Args:
            query_embedding: Query vector
            query_text: Query text for keyword matching
            top_k: Number of results
            filters: Optional metadata filters
            hybrid_config: Hybrid search configuration

        Returns:
            Reranked search results
        """
        # Fetch more candidates for reranking
        fetch_k = min(top_k * 3, 100)
        results = self.search(query_embedding, fetch_k, filters)

        if not results:
            return results

        config = hybrid_config or HybridSearchConfig()

        if config.reranker_config:
            self._reranker.config = config.reranker_config

        return self._reranker.rerank(
            results,
            query_text,
            config.dangerous_keywords,
            top_k,
        )

    def get_by_id(self, unit_id: str) -> Optional[Any]:
        """Get code unit by ID

        Args:
            unit_id: Unit ID

        Returns:
            CodeUnit or None
        """
        from ..models import CodeUnit

        payload = self._payloads.get(unit_id)
        if payload:
            try:
                return CodeUnit.from_dict(payload)
            except Exception as e:
                logger.warning(f"Failed to convert payload: {e}")
        return None

    def delete(self, unit_ids: List[str]) -> None:
        """Delete units by ID

        Args:
            unit_ids: IDs to delete
        """
        for unit_id in unit_ids:
            if unit_id in self._id_to_idx:
                idx = self._id_to_idx[unit_id]
                # Mark as deleted (lazy deletion)
                del self._id_to_idx[unit_id]
                del self._payloads[unit_id]
                # Note: vectors not removed to avoid index shifting
                # Will be cleaned up on next rebuild

    async def delete_by_file_async(self, file_path: str) -> DeleteResult:
        """Delete all vectors for a file

        Args:
            file_path: File path to delete

        Returns:
            DeleteResult with count
        """
        to_delete = [
            uid for uid, payload in self._payloads.items()
            if payload.get("file_path") == file_path
        ]

        self.delete(to_delete)

        return DeleteResult(deleted_count=len(to_delete))

    def delete_by_file(self, file_path: str) -> DeleteResult:
        """Sync version of delete by file

        Args:
            file_path: File path to delete

        Returns:
            DeleteResult with count
        """
        to_delete = [
            uid for uid, payload in self._payloads.items()
            if payload.get("file_path") == file_path
        ]

        self.delete(to_delete)

        return DeleteResult(deleted_count=len(to_delete))

    def clear(self) -> None:
        """Clear all data"""
        self._ids.clear()
        self._payloads.clear()
        self._id_to_idx.clear()

        if self._use_numpy:
            self._vectors = None
        else:
            self._vectors_list.clear()

        if self._faiss_index is not None:
            self._faiss_index.reset()

    def count(self) -> int:
        """Get total vector count"""
        return len(self._id_to_idx)

    def get_all(self, limit: int = 10000) -> List[Any]:
        """Get all code units

        Args:
            limit: Max results

        Returns:
            List of CodeUnit
        """
        from ..models import CodeUnit

        results = []
        for unit_id in list(self._id_to_idx.keys())[:limit]:
            payload = self._payloads.get(unit_id)
            if payload:
                try:
                    results.append(CodeUnit.from_dict(payload))
                except Exception as e:
                    logger.warning(f"Failed to convert: {e}")

        return results

    def get_by_filter(self, filters: Dict[str, Any], limit: int = 1000) -> List[Any]:
        """Get code units by filter

        Args:
            filters: Filter conditions
            limit: Max results

        Returns:
            List of CodeUnit
        """
        from ..models import CodeUnit

        matching_indices = self._get_filtered_indices(filters)
        results = []

        for idx in matching_indices[:limit]:
            unit_id = self._ids[idx]
            payload = self._payloads.get(unit_id)
            if payload:
                try:
                    results.append(CodeUnit.from_dict(payload))
                except Exception as e:
                    logger.warning(f"Failed to convert: {e}")

        return results

    def get_files_in_index(self) -> List[str]:
        """Get all unique file paths in the index

        Returns:
            List of file paths
        """
        file_paths: Set[str] = set()
        for payload in self._payloads.values():
            fp = payload.get("file_path")
            if fp:
                file_paths.add(fp)
        return list(file_paths)

    async def close(self) -> None:
        """Close store (no-op for memory store)"""
        pass

    def compact(self) -> None:
        """Compact storage by removing deleted entries

        Rebuilds internal indices to reclaim memory from deleted entries.
        """
        if not self._id_to_idx:
            self.clear()
            return

        # Collect active entries
        active_ids = list(self._id_to_idx.keys())
        active_payloads = {uid: self._payloads[uid] for uid in active_ids}

        if self._use_numpy and self._vectors is not None:
            active_indices = [self._id_to_idx[uid] for uid in active_ids]
            active_vectors = self._vectors[active_indices]
        else:
            active_vectors = None

        # Reset and rebuild
        self._ids = active_ids
        self._payloads = active_payloads
        self._id_to_idx = {uid: i for i, uid in enumerate(active_ids)}

        if self._use_numpy:
            self._vectors = active_vectors

        # Rebuild FAISS if available
        if self._faiss_index is not None:
            self._rebuild_faiss_index()

        logger.info(f"Compacted store to {len(active_ids)} entries")


def create_enhanced_memory_store(
    embedding_dim: int = 1536,
    use_numpy: bool = True,
    use_faiss: bool = False,
) -> EnhancedInMemoryStore:
    """Factory function for EnhancedInMemoryStore

    Args:
        embedding_dim: Embedding vector dimension
        use_numpy: Whether to use NumPy acceleration
        use_faiss: Whether to use FAISS (requires faiss-cpu)

    Returns:
        Configured EnhancedInMemoryStore instance
    """
    config = MemoryStoreConfig(
        use_numpy=use_numpy and HAS_NUMPY,
        use_faiss=use_faiss and HAS_FAISS,
        embedding_dim=embedding_dim,
    )

    return EnhancedInMemoryStore(config=config, embedding_dim=embedding_dim)
