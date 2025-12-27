"""
向量存储抽象层 - 支持多种向量数据库后端

支持:
- Qdrant 向量数据库
- 内存向量存储 (用于测试)
- Hybrid 混合检索 (元数据过滤 + 向量检索 + 关键词提升)
"""

import re
import json
import hashlib
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
class RerankerConfig:
    """重排序配置"""
    enable_reranking: bool = True          # 启用重排序

    # 各因素权重 (总和应为 1.0)
    vector_weight: float = 0.4             # 向量相似度权重
    keyword_weight: float = 0.25           # 关键词匹配权重
    security_weight: float = 0.2           # 安全相关性权重
    context_weight: float = 0.15           # 上下文相关性权重

    # 安全优先模式 (强化安全相关结果)
    security_priority_mode: bool = True
    security_boost_factor: float = 1.5     # 安全相关代码的提升因子

    # 代码质量因素
    prefer_entry_points: bool = True       # 优先入口点 (handler, controller)
    prefer_smaller_units: bool = True      # 优先较小的代码单元 (更聚焦)
    max_preferred_lines: int = 100         # 偏好的最大行数


@dataclass
class HybridSearchConfig:
    """混合检索配置"""
    enable_keyword_boost: bool = True      # 启用关键词提升
    keyword_boost_weight: float = 0.3      # 关键词匹配权重
    metadata_filter_first: bool = True     # 先元数据过滤
    dangerous_keywords: List[str] = None   # 危险关键词列表 (用于安全相关搜索)
    reranker_config: RerankerConfig = None # 重排序配置

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


class CodeReranker:
    """代码搜索结果重排序器

    基于多种因素对搜索结果进行重排序:
    1. 向量相似度 (原始分数)
    2. 关键词匹配
    3. 安全相关性 (危险函数、敏感操作等)
    4. 代码上下文 (入口点优先、代码长度等)
    """

    # 入口点标识符
    ENTRY_POINT_PATTERNS = [
        # Web 框架
        "handler", "controller", "view", "endpoint", "route", "api",
        # 函数装饰器常见名
        "get", "post", "put", "delete", "patch",
        # RPC/消息处理
        "rpc", "grpc", "consumer", "subscriber", "listener",
        # 命令行/任务
        "command", "task", "job", "cron",
    ]

    # 高危模式 (额外加分)
    HIGH_RISK_PATTERNS = [
        # 命令执行
        r"exec\s*\(", r"eval\s*\(", r"system\s*\(", r"popen\s*\(",
        r"subprocess", r"shell\s*=\s*True",
        # SQL 操作
        r"execute\s*\(", r"raw\s*\(", r"cursor\.",
        r"SELECT.*FROM", r"INSERT.*INTO", r"UPDATE.*SET", r"DELETE.*FROM",
        # 文件操作
        r"open\s*\(", r"file\s*\(", r"read\s*\(", r"write\s*\(",
        # 反序列化
        r"pickle\.load", r"yaml\.load", r"unserialize",
        # 认证相关
        r"password", r"token", r"secret", r"credential",
        r"auth", r"login", r"session",
    ]

    def __init__(self, config: RerankerConfig = None):
        """初始化重排序器

        Args:
            config: 重排序配置
        """
        self.config = config or RerankerConfig()
        self._compile_patterns()

    def _compile_patterns(self):
        """预编译正则表达式"""
        self._high_risk_re = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.HIGH_RISK_PATTERNS
        ]

    def rerank(
        self,
        results: List[SearchResult],
        query_text: str,
        dangerous_keywords: List[str] = None,
        top_k: int = None
    ) -> List[SearchResult]:
        """重排序搜索结果

        Args:
            results: 原始搜索结果
            query_text: 查询文本
            dangerous_keywords: 危险关键词列表
            top_k: 返回数量 (None 表示返回全部)

        Returns:
            重排序后的结果列表
        """
        if not results or not self.config.enable_reranking:
            return results[:top_k] if top_k else results

        # 提取查询关键词
        query_keywords = self._extract_keywords(query_text, dangerous_keywords or [])

        # 计算每个结果的综合分数
        scored_results = []
        for result in results:
            scores = self._compute_all_scores(result, query_keywords, dangerous_keywords)
            final_score = self._combine_scores(scores, result.score)
            result.score = final_score
            result.metadata["rerank_scores"] = scores
            scored_results.append(result)

        # 按综合分数排序
        scored_results.sort(key=lambda x: x.score, reverse=True)

        return scored_results[:top_k] if top_k else scored_results

    def _extract_keywords(self, text: str, dangerous_keywords: List[str]) -> List[str]:
        """从查询文本中提取关键词"""
        words = re.findall(r'\b\w+\b', text.lower())
        keywords = []

        for word in words:
            if word in dangerous_keywords:
                keywords.append(word)
            for dk in dangerous_keywords:
                if dk in word or word in dk:
                    keywords.append(dk)

        return list(set(keywords)) or words[:5]

    def _compute_all_scores(
        self,
        result: SearchResult,
        query_keywords: List[str],
        dangerous_keywords: List[str] = None
    ) -> Dict[str, float]:
        """计算所有评分因素

        Returns:
            包含各项分数的字典
        """
        unit = result.code_unit
        code_text = f"{unit.symbol} {unit.code} {unit.signature or ''}"

        return {
            "keyword": self._compute_keyword_score(code_text, query_keywords, dangerous_keywords),
            "security": self._compute_security_score(unit),
            "context": self._compute_context_score(unit),
        }

    def _compute_keyword_score(
        self,
        code_text: str,
        query_keywords: List[str],
        dangerous_keywords: List[str] = None
    ) -> float:
        """计算关键词匹配分数"""
        if not query_keywords:
            return 0.0

        code_lower = code_text.lower()
        matches = 0
        bonus = 0

        for keyword in query_keywords:
            if keyword in code_lower:
                matches += 1
                if dangerous_keywords and keyword in dangerous_keywords:
                    bonus += 0.1

        base_score = matches / len(query_keywords)
        return min(1.0, base_score + bonus)

    def _compute_security_score(self, unit: CodeUnit) -> float:
        """计算安全相关性分数

        基于代码中危险模式的出现情况
        """
        code = unit.code.lower()
        score = 0.0
        matches = 0

        # 检查高危模式
        for pattern in self._high_risk_re:
            if pattern.search(code):
                matches += 1

        if matches > 0:
            # 基础分 + 额外匹配加分
            score = min(1.0, 0.3 + matches * 0.15)

        # 检查函数名/符号名是否包含敏感词
        symbol_lower = unit.symbol.lower()
        sensitive_in_name = any(
            kw in symbol_lower for kw in
            ["auth", "login", "password", "token", "admin", "delete", "payment", "transfer"]
        )
        if sensitive_in_name:
            score = min(1.0, score + 0.2)

        return score

    def _compute_context_score(self, unit: CodeUnit) -> float:
        """计算上下文相关性分数

        考虑:
        - 是否为入口点
        - 代码长度 (更短更聚焦)
        - 代码类型
        """
        score = 0.5  # 基础分

        # 入口点加分
        if self.config.prefer_entry_points:
            symbol_lower = unit.symbol.lower()
            for pattern in self.ENTRY_POINT_PATTERNS:
                if pattern in symbol_lower:
                    score += 0.2
                    break

            # 检查装饰器
            for decorator in (unit.decorators or []):
                dec_lower = decorator.lower()
                if any(p in dec_lower for p in ["route", "api", "get", "post", "put", "delete"]):
                    score += 0.15
                    break

        # 代码长度评估
        if self.config.prefer_smaller_units:
            lines = unit.code.count('\n') + 1
            if lines <= self.config.max_preferred_lines:
                # 较短代码加分
                score += 0.1 * (1 - lines / self.config.max_preferred_lines)
            else:
                # 过长代码轻微扣分
                score -= 0.1

        # 单元类型评估
        unit_type = unit.unit_type.value if hasattr(unit.unit_type, 'value') else str(unit.unit_type)
        if unit_type in ["function", "method"]:
            score += 0.1
        elif unit_type == "class":
            score += 0.05

        return min(1.0, max(0.0, score))

    def _combine_scores(self, scores: Dict[str, float], vector_score: float) -> float:
        """组合各项分数为最终分数

        Args:
            scores: 各项分数字典
            vector_score: 原始向量相似度分数

        Returns:
            综合分数
        """
        cfg = self.config

        # 加权求和
        final_score = (
            vector_score * cfg.vector_weight +
            scores.get("keyword", 0) * cfg.keyword_weight +
            scores.get("security", 0) * cfg.security_weight +
            scores.get("context", 0) * cfg.context_weight
        )

        # 安全优先模式: 对安全相关结果额外提升
        if cfg.security_priority_mode and scores.get("security", 0) > 0.5:
            final_score *= cfg.security_boost_factor

        return final_score


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
        """混合检索 (向量 + 关键词 + 重排序)

        实现多阶段检索策略:
        1. 先用元数据过滤 (language, file_path, category 等)
        2. 在候选集中做向量相似度检索
        3. 用关键词匹配对结果进行提升
        4. (可选) 使用 CodeReranker 进行高级重排序

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
        # 多取一些候选用于后续重排序
        expand_factor = 3 if config.enable_keyword_boost else 1
        if config.reranker_config and config.reranker_config.enable_reranking:
            expand_factor = max(expand_factor, 5)  # 重排序时取更多候选

        vector_results = self.search(
            query_embedding=query_embedding,
            top_k=top_k * expand_factor,
            filters=filters
        )

        if not vector_results:
            return []

        # 第二步: 基础关键词匹配提升
        if config.enable_keyword_boost:
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

        # 第三步: 高级重排序 (如果配置了)
        if config.reranker_config and config.reranker_config.enable_reranking:
            reranker = CodeReranker(config.reranker_config)
            vector_results = reranker.rerank(
                results=vector_results,
                query_text=query_text,
                dangerous_keywords=config.dangerous_keywords,
                top_k=top_k
            )
        else:
            # 基础排序
            vector_results.sort(key=lambda x: x.score, reverse=True)
            vector_results = vector_results[:top_k]

        return vector_results

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

    def __init__(self, config: VectorStoreConfig, embedding_dim: int = 1536):
        """初始化 Qdrant 向量存储

        Args:
            config: 向量存储配置
            embedding_dim: 嵌入向量维度，默认 1536
        """
        self.config = config
        self.collection_name = config.collection_name
        self.embedding_dim = embedding_dim
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

    @staticmethod
    def _str_to_int(str_id: str) -> int:
        """将任意字符串 ID 转换为整数（Qdrant 要求 point ID 必须是整数或 UUID）

        使用 SHA256 哈希生成确定性的整数 ID，支持任意格式的字符串：
        - 纯十六进制: '6eac13281cfe648a'
        - 带 chunk 后缀: '6eac13281cfe648a_chunk0'
        - 其他任意字符串
        """
        hash_bytes = hashlib.sha256(str_id.encode()).digest()
        # 取前 8 字节转换为无符号整数（64 位），确保唯一性
        return int.from_bytes(hash_bytes[:8], byteorder='big', signed=False)

    def initialize(self) -> None:
        """初始化集合"""
        client = self._get_client()
        qmodels = self._qmodels

        # 检查集合是否存在
        collections = client.get_collections().collections
        exists = any(c.name == self.collection_name for c in collections)

        if exists:
            # 检查现有集合的维度是否匹配
            try:
                collection_info = client.get_collection(self.collection_name)
                existing_dim = collection_info.config.params.vectors.size
                if existing_dim != self.embedding_dim:
                    logger.warning(
                        f"集合 {self.collection_name} 维度不匹配: "
                        f"现有={existing_dim}, 期望={self.embedding_dim}，将删除并重建"
                    )
                    client.delete_collection(self.collection_name)
                    exists = False
                else:
                    logger.info(f"集合 {self.collection_name} 已存在，维度匹配: {existing_dim}")
            except Exception as e:
                logger.warning(f"检查集合维度失败: {e}，将尝试重建")
                try:
                    client.delete_collection(self.collection_name)
                except Exception:
                    pass
                exists = False

        if not exists:
            logger.info(f"Creating Qdrant collection: {self.collection_name} (dim={self.embedding_dim})")
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
                    id=self._str_to_int(unit.id),  # 转换为整数 ID
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

        # qdrant-client 1.7+ 使用 query_points 替代 search
        response = client.query_points(
            collection_name=self.collection_name,
            query=query_embedding,
            query_filter=query_filter,
            limit=top_k,
            with_payload=True,
        )
        results = response.points

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
                ids=[self._str_to_int(unit_id)],  # 转换为整数 ID
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

        # 转换所有 ID 为整数
        int_ids = [self._str_to_int(uid) for uid in unit_ids]
        client.delete(
            collection_name=self.collection_name,
            points_selector=qmodels.PointIdsList(points=int_ids),
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

    def close(self) -> None:
        """关闭 Qdrant 客户端连接"""
        if self._client is not None:
            try:
                self._client.close()
            except Exception as e:
                logger.warning(f"关闭 Qdrant 客户端失败: {e}")
            finally:
                self._client = None

    def __del__(self) -> None:
        """析构函数，确保资源释放"""
        self.close()


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


def create_vector_store(
    config: VectorStoreConfig,
    embedding_dim: Optional[int] = None,
) -> BaseVectorStore:
    """创建向量存储工厂函数

    Args:
        config: 向量存储配置
        embedding_dim: 嵌入向量维度（可选）。
            - 若不传入，则优先使用 config.embedding_dim
            - 否则回退到 1536

    Returns:
        向量存储实例
    """
    provider = config.provider.lower()
    dim = embedding_dim or getattr(config, "embedding_dim", None) or 1536

    if provider == "qdrant":
        # Qdrant 依赖为可选项：未安装 qdrant-client 时自动回退到内存向量存储。
        try:
            from qdrant_client import QdrantClient  # noqa: F401
        except ImportError:
            logger.warning(
                "qdrant-client 未安装，但 provider=qdrant。将回退到 InMemoryVectorStore（memory）"
            )
            return InMemoryVectorStore(config)

        return QdrantVectorStore(config, embedding_dim=dim)
    elif provider in ("memory", "inmemory", "in-memory"):
        return InMemoryVectorStore(config)
    else:
        raise ValueError(f"不支持的向量存储提供者: {provider}")
