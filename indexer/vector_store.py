"""
向量存储抽象层 - 支持多种向量数据库后端

支持:
- Qdrant 向量数据库
- 内存向量存储 (用于测试)
- Hybrid 混合检索 (元数据过滤 + 向量检索 + 关键词提升)
"""

import re
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from config import VectorStoreConfig
from .models import CodeUnit

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    """搜索结果"""
    code_unit: CodeUnit
    score: float
    metadata: Dict[str, Any]


@dataclass
class HybridSearchConfig:
    """混合检索配置"""
    enable_keyword_boost: bool = True      # 启用关键词提升
    keyword_boost_weight: float = 0.3      # 关键词匹配权重
    metadata_filter_first: bool = True     # 先元数据过滤
    dangerous_keywords: List[str] = None   # 危险关键词列表 (用于安全相关搜索)

    def __post_init__(self):
        if self.dangerous_keywords is None:
            self.dangerous_keywords = [
                # 认证相关
                "auth", "login", "password", "token", "session", "jwt", "oauth",
                # 授权相关
                "permission", "role", "admin", "privilege", "access",
                # 输入处理
                "input", "request", "param", "query", "body", "header", "cookie",
                # 危险函数
                "exec", "eval", "system", "shell", "cmd", "popen", "subprocess",
                "sql", "query", "execute", "cursor",
                "file", "open", "read", "write", "path", "upload", "download",
                "serialize", "deserialize", "pickle", "yaml", "json",
                # 业务关键词
                "payment", "money", "transfer", "balance", "order", "price",
                "delete", "remove", "update", "create", "modify",
            ]


class BaseVectorStore(ABC):
    """向量存储抽象基类"""

    @abstractmethod
    def initialize(self) -> None:
        """初始化存储（创建集合等）"""
        pass

    @abstractmethod
    def add(self, units: List[CodeUnit], embeddings: List[List[float]]) -> None:
        """添加代码单元及其嵌入向量"""
        pass

    @abstractmethod
    def search(
        self,
        query_embedding: List[float],
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[SearchResult]:
        """搜索相似代码"""
        pass

    @abstractmethod
    def get_by_id(self, unit_id: str) -> Optional[CodeUnit]:
        """根据 ID 获取代码单元"""
        pass

    @abstractmethod
    def delete(self, unit_ids: List[str]) -> None:
        """删除指定的代码单元"""
        pass

    @abstractmethod
    def clear(self) -> None:
        """清空所有数据"""
        pass

    @abstractmethod
    def count(self) -> int:
        """获取存储的代码单元数量"""
        pass

    @abstractmethod
    def get_all(self, limit: int = 10000) -> List[CodeUnit]:
        """获取所有代码单元"""
        pass

    @abstractmethod
    def get_by_filter(self, filters: Dict[str, Any], limit: int = 1000) -> List[CodeUnit]:
        """按过滤条件获取代码单元"""
        pass

    def hybrid_search(
        self,
        query_embedding: List[float],
        query_text: str,
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None,
        hybrid_config: Optional[HybridSearchConfig] = None
    ) -> List[SearchResult]:
        """混合检索 (向量 + 关键词)

        实现三明治检索策略:
        1. 先用元数据过滤 (language, file_path, category 等)
        2. 在候选集中做向量相似度检索
        3. 用关键词匹配对结果进行重排/提升

        Args:
            query_embedding: 查询向量
            query_text: 原始查询文本 (用于关键词匹配)
            top_k: 返回数量
            filters: 元数据过滤条件
            hybrid_config: 混合检索配置

        Returns:
            重排后的搜索结果列表
        """
        config = hybrid_config or HybridSearchConfig()

        # 第一步: 向量检索 (可能已包含元数据过滤)
        vector_results = self.search(
            query_embedding=query_embedding,
            top_k=top_k * 3 if config.enable_keyword_boost else top_k,  # 多取一些用于重排
            filters=filters
        )

        if not config.enable_keyword_boost:
            return vector_results[:top_k]

        # 第二步: 关键词匹配提升
        query_keywords = self._extract_keywords(query_text, config.dangerous_keywords)

        for result in vector_results:
            keyword_score = self._compute_keyword_score(
                result.code_unit,
                query_keywords,
                config.dangerous_keywords
            )
            # 混合分数 = 向量分数 * (1 - weight) + 关键词分数 * weight
            result.score = result.score * (1 - config.keyword_boost_weight) + \
                          keyword_score * config.keyword_boost_weight

        # 重新排序
        vector_results.sort(key=lambda x: x.score, reverse=True)
        return vector_results[:top_k]

    def _extract_keywords(self, text: str, dangerous_keywords: List[str]) -> List[str]:
        """从查询文本中提取关键词"""
        # 转小写并分词
        words = re.findall(r'\b\w+\b', text.lower())

        # 提取与危险关键词匹配的词
        keywords = []
        for word in words:
            if word in dangerous_keywords:
                keywords.append(word)
            # 检查部分匹配
            for dk in dangerous_keywords:
                if dk in word or word in dk:
                    keywords.append(dk)

        # 去重并返回
        return list(set(keywords)) or words[:5]  # 如果没有匹配，返回前5个词

    def _compute_keyword_score(
        self,
        code_unit: CodeUnit,
        query_keywords: List[str],
        dangerous_keywords: List[str]
    ) -> float:
        """计算关键词匹配分数"""
        if not query_keywords:
            return 0.0

        # 待匹配的文本
        search_text = f"{code_unit.symbol} {code_unit.code} {code_unit.signature or ''}"
        search_text = search_text.lower()

        matches = 0
        bonus = 0

        for keyword in query_keywords:
            if keyword in search_text:
                matches += 1
                # 危险关键词额外加分
                if keyword in dangerous_keywords:
                    bonus += 0.1

        # 基础分数 + 危险关键词奖励
        base_score = matches / len(query_keywords) if query_keywords else 0
        return min(1.0, base_score + bonus)


class QdrantVectorStore(BaseVectorStore):
    """Qdrant 向量数据库实现"""

    def __init__(self, config: VectorStoreConfig):
        self.config = config
        self.collection_name = config.collection_name
        self.embedding_dim = config.embedding_dim
        self._client = None

    def _get_client(self):
        """懒加载 Qdrant 客户端"""
        if self._client is None:
            try:
                from qdrant_client import QdrantClient
                from qdrant_client.http import models as qmodels

                if self.config.api_key:
                    # Qdrant Cloud
                    self._client = QdrantClient(
                        url=f"{'https' if self.config.https else 'http'}://{self.config.host}:{self.config.port}",
                        api_key=self.config.api_key,
                    )
                else:
                    # 本地 Qdrant
                    self._client = QdrantClient(
                        host=self.config.host,
                        port=self.config.port,
                    )

                self._qmodels = qmodels

            except ImportError:
                raise ImportError(
                    "qdrant-client 未安装。请运行: pip install qdrant-client"
                )

        return self._client

    def initialize(self) -> None:
        """初始化集合"""
        client = self._get_client()
        qmodels = self._qmodels

        # 检查集合是否存在
        collections = client.get_collections().collections
        exists = any(c.name == self.collection_name for c in collections)

        if not exists:
            logger.info(f"Creating Qdrant collection: {self.collection_name}")
            client.create_collection(
                collection_name=self.collection_name,
                vectors_config=qmodels.VectorParams(
                    size=self.embedding_dim,
                    distance=qmodels.Distance.COSINE,
                ),
            )

            # 创建索引用于过滤
            client.create_payload_index(
                collection_name=self.collection_name,
                field_name="language",
                field_schema=qmodels.PayloadSchemaType.KEYWORD,
            )
            client.create_payload_index(
                collection_name=self.collection_name,
                field_name="file_path",
                field_schema=qmodels.PayloadSchemaType.KEYWORD,
            )
            client.create_payload_index(
                collection_name=self.collection_name,
                field_name="unit_type",
                field_schema=qmodels.PayloadSchemaType.KEYWORD,
            )

    def add(self, units: List[CodeUnit], embeddings: List[List[float]]) -> None:
        """添加代码单元"""
        if len(units) != len(embeddings):
            raise ValueError("units 和 embeddings 数量不匹配")

        client = self._get_client()
        qmodels = self._qmodels

        points = []
        for unit, embedding in zip(units, embeddings):
            payload = unit.to_dict()
            points.append(
                qmodels.PointStruct(
                    id=unit.id,
                    vector=embedding,
                    payload=payload,
                )
            )

        # 批量上传
        batch_size = 100
        for i in range(0, len(points), batch_size):
            batch = points[i:i + batch_size]
            client.upsert(
                collection_name=self.collection_name,
                points=batch,
            )

        logger.info(f"Added {len(units)} code units to Qdrant")

    def search(
        self,
        query_embedding: List[float],
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[SearchResult]:
        """搜索相似代码"""
        client = self._get_client()
        qmodels = self._qmodels

        # 构建过滤条件
        query_filter = None
        if filters:
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

            if conditions:
                query_filter = qmodels.Filter(must=conditions)

        results = client.search(
            collection_name=self.collection_name,
            query_vector=query_embedding,
            query_filter=query_filter,
            limit=top_k,
            with_payload=True,
        )

        search_results = []
        for hit in results:
            code_unit = CodeUnit.from_dict(hit.payload)
            search_results.append(
                SearchResult(
                    code_unit=code_unit,
                    score=hit.score,
                    metadata={"id": hit.id},
                )
            )

        return search_results

    def get_by_id(self, unit_id: str) -> Optional[CodeUnit]:
        """根据 ID 获取代码单元"""
        client = self._get_client()

        try:
            results = client.retrieve(
                collection_name=self.collection_name,
                ids=[unit_id],
                with_payload=True,
            )
            if results:
                return CodeUnit.from_dict(results[0].payload)
        except Exception as e:
            logger.warning(f"Failed to get unit {unit_id}: {e}")

        return None

    def delete(self, unit_ids: List[str]) -> None:
        """删除指定的代码单元"""
        client = self._get_client()
        qmodels = self._qmodels

        client.delete(
            collection_name=self.collection_name,
            points_selector=qmodels.PointIdsList(points=unit_ids),
        )

    def clear(self) -> None:
        """清空所有数据"""
        client = self._get_client()

        # 删除并重建集合
        try:
            client.delete_collection(self.collection_name)
        except Exception:
            pass

        self.initialize()

    def count(self) -> int:
        """获取代码单元数量"""
        client = self._get_client()
        info = client.get_collection(self.collection_name)
        return info.points_count

    def get_all(self, limit: int = 10000) -> List[CodeUnit]:
        """获取所有代码单元"""
        client = self._get_client()

        results = []
        offset = None

        while True:
            response = client.scroll(
                collection_name=self.collection_name,
                limit=min(100, limit - len(results)),
                offset=offset,
                with_payload=True,
                with_vectors=False,
            )

            points, next_offset = response

            for point in points:
                code_unit = CodeUnit.from_dict(point.payload)
                results.append(code_unit)

            if next_offset is None or len(results) >= limit:
                break

            offset = next_offset

        return results[:limit]

    def get_by_filter(self, filters: Dict[str, Any], limit: int = 1000) -> List[CodeUnit]:
        """按过滤条件获取代码单元"""
        client = self._get_client()
        qmodels = self._qmodels

        # 构建过滤条件
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

        query_filter = qmodels.Filter(must=conditions) if conditions else None

        results = []
        offset = None

        while True:
            response = client.scroll(
                collection_name=self.collection_name,
                scroll_filter=query_filter,
                limit=min(100, limit - len(results)),
                offset=offset,
                with_payload=True,
                with_vectors=False,
            )

            points, next_offset = response

            for point in points:
                code_unit = CodeUnit.from_dict(point.payload)
                results.append(code_unit)

            if next_offset is None or len(results) >= limit:
                break

            offset = next_offset

        return results[:limit]


class InMemoryVectorStore(BaseVectorStore):
    """内存向量存储 - 用于测试和小型项目"""

    def __init__(self, config: VectorStoreConfig):
        self.config = config
        self._units: Dict[str, CodeUnit] = {}
        self._embeddings: Dict[str, List[float]] = {}

    def initialize(self) -> None:
        """初始化（内存存储无需特殊初始化）"""
        pass

    def add(self, units: List[CodeUnit], embeddings: List[List[float]]) -> None:
        """添加代码单元"""
        for unit, embedding in zip(units, embeddings):
            self._units[unit.id] = unit
            self._embeddings[unit.id] = embedding

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        """计算余弦相似度"""
        dot_product = sum(x * y for x, y in zip(a, b))
        norm_a = sum(x * x for x in a) ** 0.5
        norm_b = sum(x * x for x in b) ** 0.5
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot_product / (norm_a * norm_b)

    def search(
        self,
        query_embedding: List[float],
        top_k: int = 10,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[SearchResult]:
        """搜索相似代码"""
        results = []

        for unit_id, embedding in self._embeddings.items():
            unit = self._units[unit_id]

            # 应用过滤器
            if filters:
                skip = False
                for key, value in filters.items():
                    unit_value = getattr(unit, key, None)
                    if unit_value is None:
                        unit_value = unit.metadata.get(key)

                    if isinstance(value, list):
                        if unit_value not in value:
                            skip = True
                            break
                    elif unit_value != value:
                        skip = True
                        break

                if skip:
                    continue

            score = self._cosine_similarity(query_embedding, embedding)
            results.append(SearchResult(code_unit=unit, score=score, metadata={}))

        # 按分数排序
        results.sort(key=lambda x: x.score, reverse=True)
        return results[:top_k]

    def get_by_id(self, unit_id: str) -> Optional[CodeUnit]:
        """根据 ID 获取代码单元"""
        return self._units.get(unit_id)

    def delete(self, unit_ids: List[str]) -> None:
        """删除指定的代码单元"""
        for unit_id in unit_ids:
            self._units.pop(unit_id, None)
            self._embeddings.pop(unit_id, None)

    def clear(self) -> None:
        """清空所有数据"""
        self._units.clear()
        self._embeddings.clear()

    def count(self) -> int:
        """获取代码单元数量"""
        return len(self._units)

    def get_all(self, limit: int = 10000) -> List[CodeUnit]:
        """获取所有代码单元"""
        units = list(self._units.values())
        return units[:limit]

    def get_by_filter(self, filters: Dict[str, Any], limit: int = 1000) -> List[CodeUnit]:
        """按过滤条件获取代码单元"""
        results = []

        for unit in self._units.values():
            match = True
            for key, value in filters.items():
                unit_value = getattr(unit, key, None)
                if unit_value is None:
                    unit_value = unit.metadata.get(key)

                if isinstance(value, list):
                    if unit_value not in value:
                        match = False
                        break
                elif unit_value != value:
                    match = False
                    break

            if match:
                results.append(unit)
                if len(results) >= limit:
                    break

        return results


def create_vector_store(config: VectorStoreConfig) -> BaseVectorStore:
    """创建向量存储工厂函数"""
    provider = config.provider.lower()

    if provider == "qdrant":
        return QdrantVectorStore(config)
    elif provider in ("memory", "inmemory", "in-memory"):
        return InMemoryVectorStore(config)
    else:
        raise ValueError(f"不支持的向量存储提供者: {provider}")
