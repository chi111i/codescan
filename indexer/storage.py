"""
存储管理器 - 统一管理向量存储和 JSON 存储

功能：
1. 代码向量化存储到 Qdrant
2. 调用图和分析结果存储到 JSON
3. 提供统一的查询接口
4. 支持增量更新
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field, asdict
import hashlib

from config import AuditConfig
from .models import CodeUnit
from .vector_store_legacy import BaseVectorStore, SearchResult

# TYPE_CHECKING to avoid circular import with llm_client
if TYPE_CHECKING:
    from llm_client import BaseLLMClient

logger = logging.getLogger(__name__)


@dataclass
class ProjectIndex:
    """项目索引元数据"""
    project_path: str
    indexed_at: str
    total_files: int
    total_units: int
    languages: List[str]
    file_hashes: Dict[str, str] = field(default_factory=dict)  # 文件路径 -> hash
    index_version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProjectIndex":
        return cls(**data)


@dataclass
class StoredCodeUnit:
    """存储的代码单元（扩展 CodeUnit 用于存储）"""
    unit: CodeUnit
    embedding: List[float]
    file_hash: str
    indexed_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "unit": self.unit.to_dict(),
            "embedding_dim": len(self.embedding),
            "file_hash": self.file_hash,
            "indexed_at": self.indexed_at,
        }


class StorageManager:
    """存储管理器

    管理：
    1. 代码向量存储（Qdrant）- 用于语义搜索
    2. JSON 存储 - 用于调用图、分析结果等
    3. 索引元数据 - 用于增量更新
    """

    def __init__(
        self,
        config: AuditConfig,
        llm_client: "BaseLLMClient",
        vector_store: BaseVectorStore,
        storage_dir: str = ".audit_data",
    ):
        self.config = config
        self.llm_client = llm_client
        self.vector_store = vector_store
        self.storage_dir = Path(storage_dir)

        # 创建存储目录
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        (self.storage_dir / "indexes").mkdir(exist_ok=True)
        (self.storage_dir / "call_graphs").mkdir(exist_ok=True)
        (self.storage_dir / "analysis").mkdir(exist_ok=True)

        # 初始化向量存储
        self.vector_store.initialize()

        # 加载项目索引
        self.project_index: Optional[ProjectIndex] = None

    def _compute_file_hash(self, content: str) -> str:
        """计算文件内容哈希"""
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _get_index_path(self, project_path: str) -> Path:
        """获取索引文件路径"""
        project_hash = hashlib.md5(project_path.encode()).hexdigest()[:8]
        return self.storage_dir / "indexes" / f"index_{project_hash}.json"

    def load_project_index(self, project_path: str) -> Optional[ProjectIndex]:
        """加载项目索引"""
        index_path = self._get_index_path(project_path)
        if index_path.exists():
            try:
                with open(index_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.project_index = ProjectIndex.from_dict(data)
                    return self.project_index
            except Exception as e:
                logger.warning(f"Failed to load index: {e}")
        return None

    def save_project_index(self, index: ProjectIndex) -> None:
        """保存项目索引"""
        index_path = self._get_index_path(index.project_path)
        with open(index_path, "w", encoding="utf-8") as f:
            json.dump(index.to_dict(), f, ensure_ascii=False, indent=2)
        self.project_index = index

    def check_file_changed(self, file_path: str, content: str) -> bool:
        """检查文件是否变化"""
        if not self.project_index:
            return True

        current_hash = self._compute_file_hash(content)
        stored_hash = self.project_index.file_hashes.get(file_path)

        return stored_hash != current_hash

    def index_code_units(
        self,
        units: List[CodeUnit],
        file_contents: Dict[str, str],
        project_path: str,
        incremental: bool = True,
    ) -> int:
        """索引代码单元到向量存储

        Args:
            units: 代码单元列表
            file_contents: 文件路径 -> 内容映射
            project_path: 项目路径
            incremental: 是否增量更新

        Returns:
            实际索引的单元数量
        """
        logger.info(f"Indexing {len(units)} code units...")

        # 加载现有索引
        existing_index = self.load_project_index(project_path)

        # 计算文件哈希
        file_hashes = {
            path: self._compute_file_hash(content)
            for path, content in file_contents.items()
        }

        # 确定需要更新的单元
        if incremental and existing_index:
            units_to_index = []
            for unit in units:
                if self.check_file_changed(unit.file_path, file_contents.get(unit.file_path, "")):
                    units_to_index.append(unit)
            logger.info(f"Incremental update: {len(units_to_index)} units changed")
        else:
            units_to_index = units

        if not units_to_index:
            logger.info("No units to index")
            return 0

        # 生成嵌入向量
        logger.info("Generating embeddings...")
        embeddings = self._generate_embeddings(units_to_index)

        # 存储到向量数据库
        logger.info("Storing to vector database...")
        self.vector_store.add(units_to_index, embeddings)

        # 更新索引元数据
        languages = list(set(u.language for u in units))
        new_index = ProjectIndex(
            project_path=project_path,
            indexed_at=datetime.now().isoformat(),
            total_files=len(file_contents),
            total_units=len(units),
            languages=languages,
            file_hashes=file_hashes,
        )
        self.save_project_index(new_index)

        logger.info(f"Indexed {len(units_to_index)} code units")
        return len(units_to_index)

    def _generate_embeddings(self, units: List[CodeUnit]) -> List[List[float]]:
        """生成嵌入向量"""
        texts = [unit.to_embedding_text() for unit in units]

        # 批量处理
        batch_size = 50
        all_embeddings = []

        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i + batch_size]
            response = self.llm_client.embed(batch_texts)
            all_embeddings.extend(response.embeddings)
            logger.debug(f"Embedded batch {i//batch_size + 1}/{(len(texts) + batch_size - 1)//batch_size}")

        return all_embeddings

    def search_code(
        self,
        query: str,
        top_k: int = 10,
        language: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Tuple[CodeUnit, float]]:
        """语义搜索代码

        Args:
            query: 搜索查询（自然语言）
            top_k: 返回数量
            language: 语言过滤
            filters: 其他过滤条件

        Returns:
            (CodeUnit, 相似度分数) 列表
        """
        # 生成查询嵌入
        response = self.llm_client.embed([query])
        query_embedding = response.embeddings[0]

        # 构建过滤器
        search_filters = filters or {}
        if language:
            search_filters["language"] = language

        # 搜索
        results = self.vector_store.search(
            query_embedding=query_embedding,
            top_k=top_k,
            filters=search_filters if search_filters else None,
        )

        return [(r.code_unit, r.score) for r in results]

    def search_by_function_name(
        self,
        function_name: str,
        language: Optional[str] = None,
    ) -> List[CodeUnit]:
        """按函数名搜索"""
        # 构造更精确的查询
        query = f"function named {function_name}"
        results = self.search_code(query, top_k=20, language=language)

        # 过滤精确匹配
        matched = []
        for unit, score in results:
            if unit.symbol == function_name or function_name in unit.symbol:
                matched.append(unit)

        return matched

    def search_by_call(
        self,
        callee_name: str,
        language: Optional[str] = None,
    ) -> List[CodeUnit]:
        """搜索调用了指定函数的代码"""
        query = f"code that calls {callee_name}"
        results = self.search_code(query, top_k=30, language=language)

        # 过滤包含该调用的单元
        matched = []
        for unit, score in results:
            if callee_name in unit.calls:
                matched.append(unit)

        return matched

    def save_call_graph(
        self,
        call_graph_data: Dict[str, Any],
        project_path: str,
        filename: Optional[str] = None,
    ) -> str:
        """保存调用图到 JSON"""
        if filename is None:
            project_hash = hashlib.md5(project_path.encode()).hexdigest()[:8]
            filename = f"call_graph_{project_hash}.json"

        output_path = self.storage_dir / "call_graphs" / filename

        # 添加元数据
        call_graph_data["metadata"] = {
            "project_path": project_path,
            "generated_at": datetime.now().isoformat(),
            "tool_version": "0.1.0",
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(call_graph_data, f, ensure_ascii=False, indent=2)

        logger.info(f"Call graph saved to: {output_path}")
        return str(output_path)

    def load_call_graph(self, project_path: str) -> Optional[Dict[str, Any]]:
        """加载调用图"""
        project_hash = hashlib.md5(project_path.encode()).hexdigest()[:8]
        filename = f"call_graph_{project_hash}.json"
        graph_path = self.storage_dir / "call_graphs" / filename

        if graph_path.exists():
            with open(graph_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return None

    def save_analysis_result(
        self,
        result_data: Dict[str, Any],
        project_path: str,
        analysis_type: str = "security",
    ) -> str:
        """保存分析结果"""
        project_hash = hashlib.md5(project_path.encode()).hexdigest()[:8]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{analysis_type}_{project_hash}_{timestamp}.json"

        output_path = self.storage_dir / "analysis" / filename

        # 添加元数据
        result_data["metadata"] = {
            "project_path": project_path,
            "analysis_type": analysis_type,
            "generated_at": datetime.now().isoformat(),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result_data, f, ensure_ascii=False, indent=2)

        logger.info(f"Analysis result saved to: {output_path}")
        return str(output_path)

    def get_context_for_llm(
        self,
        query: str,
        max_units: int = 5,
        include_callers: bool = True,
        include_callees: bool = True,
    ) -> Dict[str, Any]:
        """获取 LLM 分析所需的上下文

        根据查询从向量数据库检索相关代码，并构建完整上下文

        Args:
            query: 查询描述
            max_units: 最大返回单元数
            include_callers: 是否包含调用者
            include_callees: 是否包含被调用者

        Returns:
            结构化的上下文信息
        """
        # 搜索相关代码
        results = self.search_code(query, top_k=max_units)

        context = {
            "query": query,
            "primary_units": [],
            "related_units": [],
        }

        seen_ids = set()

        for unit, score in results:
            unit_info = {
                "id": unit.id,
                "file": unit.file_path,
                "symbol": unit.symbol,
                "type": unit.unit_type.value,
                "code": unit.code,
                "signature": unit.signature,
                "relevance_score": score,
            }
            context["primary_units"].append(unit_info)
            seen_ids.add(unit.id)

            # 获取调用关系
            if include_callees:
                for called_name in unit.calls[:5]:
                    callee_units = self.search_by_function_name(called_name, unit.language)
                    for callee in callee_units[:2]:
                        if callee.id not in seen_ids:
                            seen_ids.add(callee.id)
                            context["related_units"].append({
                                "id": callee.id,
                                "file": callee.file_path,
                                "symbol": callee.symbol,
                                "relation": f"called by {unit.symbol}",
                                "code": callee.code[:500],
                            })

        return context

    def get_statistics(self) -> Dict[str, Any]:
        """获取存储统计信息"""
        stats = {
            "vector_store": {
                "total_units": self.vector_store.count(),
                "provider": self.config.vector_store.provider,
            },
            "storage_dir": str(self.storage_dir),
        }

        if self.project_index:
            stats["project_index"] = {
                "project_path": self.project_index.project_path,
                "indexed_at": self.project_index.indexed_at,
                "total_files": self.project_index.total_files,
                "total_units": self.project_index.total_units,
                "languages": self.project_index.languages,
            }

        # 统计 JSON 文件
        call_graphs = list((self.storage_dir / "call_graphs").glob("*.json"))
        analysis_files = list((self.storage_dir / "analysis").glob("*.json"))

        stats["json_storage"] = {
            "call_graphs": len(call_graphs),
            "analysis_results": len(analysis_files),
        }

        return stats

    def clear_all(self) -> None:
        """清空所有存储"""
        logger.warning("Clearing all storage...")

        # 清空向量存储
        self.vector_store.clear()

        # 清空 JSON 文件
        for json_file in self.storage_dir.rglob("*.json"):
            json_file.unlink()

        self.project_index = None
        logger.info("All storage cleared")
