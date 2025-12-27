# Enhanced Qdrant Vector Store with async batch operations
# Based on ACI (augmented-codebase-indexer) best practices

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Callable

from .interface import (
    VectorStoreInterface,
    SearchResult,
    UpsertResult,
    DeleteResult,
    HybridSearchConfig,
    ArtifactType,
    VectorStoreError,
    VectorConnectionError,
    VectorIndexError,
    CodeReranker,
)
from .metadata_store import IndexMetadataStore, PendingBatch, BatchStatus

logger = logging.getLogger(__name__)


@dataclass
class QdrantConfig:
    """Qdrant connection configuration"""
    host: str = "localhost"
    port: int = 6333
    collection_name: str = "codescan"
    api_key: Optional[str] = None
    https: bool = False
    timeout: float = 30.0
    prefer_grpc: bool = False


class EnhancedQdrantStore(VectorStoreInterface):
    """Enhanced Qdrant vector store with:

    - Payload indexes for fast filtering (file_path, artifact_type, language, unit_type)
    - Async batch upsert for high-throughput indexing
    - Transaction support via IndexMetadataStore
    - Delete by file path for incremental re-indexing
    - Hybrid search with CodeReranker

    Based on ACI best practices.
    """

    # Payload fields to index for filtering
    INDEXED_FIELDS = [
        ("file_path", "keyword"),
        ("artifact_type", "keyword"),
        ("language", "keyword"),
        ("unit_type", "keyword"),
        ("symbol", "text"),  # Full-text search on symbol names
    ]

    def __init__(
        self,
        config: QdrantConfig,
        embedding_dim: int = 1536,
        metadata_store: Optional[IndexMetadataStore] = None,
    ):
        """Initialize enhanced Qdrant store

        Args:
            config: Qdrant connection configuration
            embedding_dim: Vector dimension (default 1536 for text-embedding-3-small)
            metadata_store: Optional metadata store for transaction support
        """
        self.config = config
        self.embedding_dim = embedding_dim
        self.metadata_store = metadata_store
        self._client = None
        self._async_client = None
        self._qmodels = None
        self._reranker = CodeReranker()

    def _get_client(self):
        """Lazy-load sync Qdrant client"""
        if self._client is None:
            try:
                from qdrant_client import QdrantClient
                from qdrant_client.http import models as qmodels

                if self.config.api_key:
                    url = f"{'https' if self.config.https else 'http'}://{self.config.host}:{self.config.port}"
                    self._client = QdrantClient(
                        url=url,
                        api_key=self.config.api_key,
                        timeout=self.config.timeout,
                    )
                else:
                    self._client = QdrantClient(
                        host=self.config.host,
                        port=self.config.port,
                        timeout=self.config.timeout,
                        prefer_grpc=self.config.prefer_grpc,
                    )

                self._qmodels = qmodels

            except ImportError:
                raise VectorConnectionError(
                    "qdrant-client not installed. Run: pip install qdrant-client"
                )

        return self._client

    async def _get_async_client(self):
        """Lazy-load async Qdrant client"""
        if self._async_client is None:
            try:
                from qdrant_client import AsyncQdrantClient
                from qdrant_client.http import models as qmodels

                if self.config.api_key:
                    url = f"{'https' if self.config.https else 'http'}://{self.config.host}:{self.config.port}"
                    self._async_client = AsyncQdrantClient(
                        url=url,
                        api_key=self.config.api_key,
                        timeout=self.config.timeout,
                    )
                else:
                    self._async_client = AsyncQdrantClient(
                        host=self.config.host,
                        port=self.config.port,
                        timeout=self.config.timeout,
                        prefer_grpc=self.config.prefer_grpc,
                    )

                self._qmodels = qmodels

            except ImportError:
                raise VectorConnectionError(
                    "qdrant-client not installed. Run: pip install qdrant-client"
                )

        return self._async_client

    @staticmethod
    def _str_to_int(str_id: str) -> int:
        """Convert string ID to deterministic integer for Qdrant point ID"""
        hash_bytes = hashlib.sha256(str_id.encode()).digest()
        return int.from_bytes(hash_bytes[:8], byteorder='big', signed=False)

    def initialize(self) -> None:
        """Initialize collection with optimized indexes"""
        client = self._get_client()
        qmodels = self._qmodels

        collections = client.get_collections().collections
        exists = any(c.name == self.config.collection_name for c in collections)

        if exists:
            try:
                info = client.get_collection(self.config.collection_name)
                existing_dim = info.config.params.vectors.size
                if existing_dim != self.embedding_dim:
                    logger.warning(
                        f"Collection dimension mismatch: {existing_dim} vs {self.embedding_dim}, rebuilding"
                    )
                    client.delete_collection(self.config.collection_name)
                    exists = False
                else:
                    logger.info(f"Collection {self.config.collection_name} exists, dim={existing_dim}")
                    self._ensure_indexes(client, qmodels)
                    return
            except Exception as e:
                logger.warning(f"Failed to check collection: {e}, rebuilding")
                try:
                    client.delete_collection(self.config.collection_name)
                except Exception:
                    pass
                exists = False

        if not exists:
            logger.info(f"Creating collection: {self.config.collection_name} (dim={self.embedding_dim})")
            client.create_collection(
                collection_name=self.config.collection_name,
                vectors_config=qmodels.VectorParams(
                    size=self.embedding_dim,
                    distance=qmodels.Distance.COSINE,
                ),
                # Optimize for filtered search
                optimizers_config=qmodels.OptimizersConfigDiff(
                    indexing_threshold=10000,  # Build HNSW after 10k points
                ),
            )
            self._create_indexes(client, qmodels)

    def _ensure_indexes(self, client, qmodels) -> None:
        """Ensure all payload indexes exist"""
        try:
            info = client.get_collection(self.config.collection_name)
            existing = set(info.payload_schema.keys()) if info.payload_schema else set()

            for field_name, _ in self.INDEXED_FIELDS:
                if field_name not in existing:
                    self._create_single_index(client, qmodels, field_name)
        except Exception as e:
            logger.warning(f"Failed to check indexes: {e}")

    def _create_indexes(self, client, qmodels) -> None:
        """Create all payload indexes"""
        for field_name, field_type in self.INDEXED_FIELDS:
            self._create_single_index(client, qmodels, field_name, field_type)

    def _create_single_index(self, client, qmodels, field_name: str, field_type: str = "keyword") -> None:
        """Create a single payload index"""
        try:
            if field_type == "keyword":
                schema = qmodels.PayloadSchemaType.KEYWORD
            elif field_type == "text":
                schema = qmodels.TextIndexParams(
                    type="text",
                    tokenizer=qmodels.TokenizerType.WORD,
                    min_token_len=2,
                    max_token_len=20,
                )
            else:
                schema = qmodels.PayloadSchemaType.KEYWORD

            client.create_payload_index(
                collection_name=self.config.collection_name,
                field_name=field_name,
                field_schema=schema,
            )
            logger.debug(f"Created index on {field_name}")
        except Exception as e:
            logger.debug(f"Index {field_name} may already exist: {e}")

    def add(self, units: List[Any], embeddings: List[List[float]]) -> None:
        """Add code units (sync)"""
        if len(units) != len(embeddings):
            raise ValueError("units and embeddings count mismatch")

        client = self._get_client()
        qmodels = self._qmodels

        points = []
        for unit, embedding in zip(units, embeddings):
            payload = self._unit_to_payload(unit)
            points.append(
                qmodels.PointStruct(
                    id=self._str_to_int(unit.id),
                    vector=embedding,
                    payload=payload,
                )
            )

        batch_size = 100
        for i in range(0, len(points), batch_size):
            batch = points[i:i + batch_size]
            client.upsert(
                collection_name=self.config.collection_name,
                points=batch,
            )

        logger.info(f"Added {len(units)} code units to Qdrant")

    def _unit_to_payload(self, unit: Any) -> Dict[str, Any]:
        """Convert CodeUnit to Qdrant payload with artifact_type"""
        payload = unit.to_dict()

        # Add artifact_type for filtering
        unit_type_str = unit.unit_type.value if hasattr(unit.unit_type, 'value') else str(unit.unit_type)
        if unit_type_str in ["function", "method", "class"]:
            payload["artifact_type"] = unit_type_str
        else:
            payload["artifact_type"] = ArtifactType.CHUNK.value

        return payload

    async def upsert_batch_async(
        self,
        ids: List[str],
        vectors: List[List[float]],
        payloads: List[Dict[str, Any]],
        batch_id: Optional[str] = None,
    ) -> UpsertResult:
        """Async batch upsert with optional transaction tracking

        Args:
            ids: Point IDs (strings, will be hashed)
            vectors: Embedding vectors
            payloads: Metadata payloads
            batch_id: Optional batch ID for transaction tracking

        Returns:
            UpsertResult with counts
        """
        if len(ids) != len(vectors) or len(ids) != len(payloads):
            raise ValueError("ids, vectors, and payloads must have same length")

        client = await self._get_async_client()
        qmodels = self._qmodels

        # Create pending batch if metadata store is available
        if batch_id and self.metadata_store:
            file_paths = list(set(p.get("file_path", "") for p in payloads if p.get("file_path")))
            self.metadata_store.add_to_batch(batch_id, file_paths, ids)

        points = [
            qmodels.PointStruct(
                id=self._str_to_int(pid),
                vector=vec,
                payload=payload,
            )
            for pid, vec, payload in zip(ids, vectors, payloads)
        ]

        inserted = 0
        failed = 0
        failed_ids = []
        batch_size = 100

        try:
            for i in range(0, len(points), batch_size):
                batch = points[i:i + batch_size]
                await client.upsert(
                    collection_name=self.config.collection_name,
                    points=batch,
                )
                inserted += len(batch)

            # Commit batch if tracking
            if batch_id and self.metadata_store:
                self.metadata_store.commit_batch(batch_id)

        except Exception as e:
            failed = len(points) - inserted
            failed_ids = ids[inserted:]
            logger.error(f"Batch upsert failed: {e}")

            if batch_id and self.metadata_store:
                self.metadata_store.fail_batch(batch_id, str(e))

            raise VectorIndexError(f"Batch upsert failed: {e}") from e

        return UpsertResult(
            inserted_count=inserted,
            updated_count=0,  # Qdrant upsert doesn't distinguish
            failed_count=failed,
            failed_ids=failed_ids,
        )

    def search(
        self,
        query_embedding: List[float],
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[SearchResult]:
        """Vector similarity search"""
        client = self._get_client()
        qmodels = self._qmodels

        query_filter = self._build_filter(filters, qmodels) if filters else None

        response = client.query_points(
            collection_name=self.config.collection_name,
            query=query_embedding,
            query_filter=query_filter,
            limit=top_k,
            with_payload=True,
        )

        return self._convert_results(response.points)

    async def search_async(
        self,
        query_vector: List[float],
        limit: int = 10,
        file_filter: Optional[str] = None,
        artifact_types: Optional[List[str]] = None
    ) -> List[SearchResult]:
        """Async vector search with optional filters"""
        client = await self._get_async_client()
        qmodels = self._qmodels

        filters = {}
        if file_filter:
            filters["file_path"] = file_filter
        if artifact_types:
            filters["artifact_type"] = artifact_types

        query_filter = self._build_filter(filters, qmodels) if filters else None

        response = await client.query_points(
            collection_name=self.config.collection_name,
            query=query_vector,
            query_filter=query_filter,
            limit=limit,
            with_payload=True,
        )

        return self._convert_results(response.points)

    def hybrid_search(
        self,
        query_embedding: List[float],
        query_text: str,
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None,
        hybrid_config: Optional[HybridSearchConfig] = None
    ) -> List[SearchResult]:
        """Hybrid search with reranking"""
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

    def _build_filter(self, filters: Dict[str, Any], qmodels) -> Any:
        """Build Qdrant filter from dict"""
        conditions = []
        for key, value in filters.items():
            if isinstance(value, list):
                conditions.append(
                    qmodels.FieldCondition(
                        key=key,
                        match=qmodels.MatchAny(any=value),
                    )
                )
            else:
                conditions.append(
                    qmodels.FieldCondition(
                        key=key,
                        match=qmodels.MatchValue(value=value),
                    )
                )
        return qmodels.Filter(must=conditions) if conditions else None

    def _convert_results(self, points: List[Any]) -> List[SearchResult]:
        """Convert Qdrant points to SearchResult"""
        from ..models import CodeUnit

        results = []
        for point in points:
            try:
                code_unit = CodeUnit.from_dict(point.payload)
                results.append(
                    SearchResult(
                        code_unit=code_unit,
                        score=point.score,
                        metadata={"id": point.id},
                    )
                )
            except Exception as e:
                logger.warning(f"Failed to convert point {point.id}: {e}")
        return results

    def get_by_id(self, unit_id: str) -> Optional[Any]:
        """Get code unit by ID"""
        from ..models import CodeUnit

        client = self._get_client()
        try:
            results = client.retrieve(
                collection_name=self.config.collection_name,
                ids=[self._str_to_int(unit_id)],
                with_payload=True,
            )
            if results:
                return CodeUnit.from_dict(results[0].payload)
        except Exception as e:
            logger.warning(f"Failed to get unit {unit_id}: {e}")
        return None

    def delete(self, unit_ids: List[str]) -> None:
        """Delete by IDs"""
        client = self._get_client()
        qmodels = self._qmodels

        int_ids = [self._str_to_int(uid) for uid in unit_ids]
        client.delete(
            collection_name=self.config.collection_name,
            points_selector=qmodels.PointIdsList(points=int_ids),
        )

    async def delete_by_file_async(self, file_path: str) -> DeleteResult:
        """Delete all vectors for a file (for incremental re-indexing)"""
        client = await self._get_async_client()
        qmodels = self._qmodels

        # Delete by file_path filter
        result = await client.delete(
            collection_name=self.config.collection_name,
            points_selector=qmodels.FilterSelector(
                filter=qmodels.Filter(
                    must=[
                        qmodels.FieldCondition(
                            key="file_path",
                            match=qmodels.MatchValue(value=file_path),
                        )
                    ]
                )
            ),
        )

        # Count is not directly returned, estimate from operation
        return DeleteResult(deleted_count=1)  # Approximate

    def delete_by_file(self, file_path: str) -> DeleteResult:
        """Sync version of delete by file"""
        client = self._get_client()
        qmodels = self._qmodels

        client.delete(
            collection_name=self.config.collection_name,
            points_selector=qmodels.FilterSelector(
                filter=qmodels.Filter(
                    must=[
                        qmodels.FieldCondition(
                            key="file_path",
                            match=qmodels.MatchValue(value=file_path),
                        )
                    ]
                )
            ),
        )
        return DeleteResult(deleted_count=1)

    def clear(self) -> None:
        """Clear all data"""
        client = self._get_client()
        try:
            client.delete_collection(self.config.collection_name)
        except Exception:
            pass
        self.initialize()

    def count(self) -> int:
        """Get total point count"""
        client = self._get_client()
        info = client.get_collection(self.config.collection_name)
        return info.points_count

    def get_all(self, limit: int = 10000) -> List[Any]:
        """Get all code units"""
        from ..models import CodeUnit

        client = self._get_client()
        results = []
        offset = None

        while len(results) < limit:
            response = client.scroll(
                collection_name=self.config.collection_name,
                limit=min(100, limit - len(results)),
                offset=offset,
                with_payload=True,
                with_vectors=False,
            )
            points, next_offset = response

            for point in points:
                try:
                    results.append(CodeUnit.from_dict(point.payload))
                except Exception as e:
                    logger.warning(f"Failed to convert point: {e}")

            if next_offset is None:
                break
            offset = next_offset

        return results[:limit]

    def get_by_filter(self, filters: Dict[str, Any], limit: int = 1000) -> List[Any]:
        """Get code units by filter"""
        from ..models import CodeUnit

        client = self._get_client()
        qmodels = self._qmodels
        query_filter = self._build_filter(filters, qmodels)

        results = []
        offset = None

        while len(results) < limit:
            response = client.scroll(
                collection_name=self.config.collection_name,
                scroll_filter=query_filter,
                limit=min(100, limit - len(results)),
                offset=offset,
                with_payload=True,
                with_vectors=False,
            )
            points, next_offset = response

            for point in points:
                try:
                    results.append(CodeUnit.from_dict(point.payload))
                except Exception as e:
                    logger.warning(f"Failed to convert point: {e}")

            if next_offset is None:
                break
            offset = next_offset

        return results[:limit]

    def get_files_in_index(self) -> List[str]:
        """Get all unique file paths in the index"""
        # Use scroll to collect all unique file_paths
        client = self._get_client()
        file_paths = set()
        offset = None

        while True:
            response = client.scroll(
                collection_name=self.config.collection_name,
                limit=1000,
                offset=offset,
                with_payload=["file_path"],
                with_vectors=False,
            )
            points, next_offset = response

            for point in points:
                fp = point.payload.get("file_path")
                if fp:
                    file_paths.add(fp)

            if next_offset is None:
                break
            offset = next_offset

        return list(file_paths)

    async def close(self) -> None:
        """Close async client connection"""
        if self._async_client:
            await self._async_client.close()
            self._async_client = None


def create_enhanced_qdrant_store(
    host: str = "localhost",
    port: int = 6333,
    collection_name: str = "codescan",
    embedding_dim: int = 1536,
    api_key: Optional[str] = None,
    metadata_db_path: Optional[str] = None,
) -> EnhancedQdrantStore:
    """Factory function for EnhancedQdrantStore

    Args:
        host: Qdrant host
        port: Qdrant port
        collection_name: Collection name
        embedding_dim: Embedding vector dimension
        api_key: Optional API key for Qdrant Cloud
        metadata_db_path: Optional path for metadata SQLite DB

    Returns:
        Configured EnhancedQdrantStore instance
    """
    config = QdrantConfig(
        host=host,
        port=port,
        collection_name=collection_name,
        api_key=api_key,
        https=bool(api_key),
    )

    metadata_store = None
    if metadata_db_path:
        metadata_store = IndexMetadataStore(metadata_db_path)

    return EnhancedQdrantStore(
        config=config,
        embedding_dim=embedding_dim,
        metadata_store=metadata_store,
    )
