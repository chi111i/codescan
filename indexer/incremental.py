"""
增量索引管理器 - 优化的索引更新策略

功能：
1. 基于文件hash和mtime的增量索引
2. 重复代码去重（相同hash的chunk只存一份向量）
3. 按语言/目录分片存储
4. 删除文件检测和清理
"""

import os
import json
import logging
import hashlib
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import CodeUnit

logger = logging.getLogger(__name__)


@dataclass
class FileIndexEntry:
    """文件索引条目"""
    file_path: str
    content_hash: str
    mtime: float
    size: int
    unit_ids: List[str] = field(default_factory=list)
    language: str = ""
    indexed_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileIndexEntry":
        return cls(**data)


@dataclass
class ChunkDeduplicationEntry:
    """代码块去重条目"""
    content_hash: str               # 代码内容hash
    embedding_hash: str             # 嵌入向量hash（用于快速查找）
    unit_ids: List[str]            # 引用此内容的所有unit ID
    locations: List[str]           # 文件位置列表
    language: str
    first_indexed_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChunkDeduplicationEntry":
        return cls(**data)


@dataclass
class IncrementalIndexStats:
    """增量索引统计"""
    total_files_scanned: int = 0
    files_added: int = 0
    files_modified: int = 0
    files_deleted: int = 0
    files_unchanged: int = 0
    units_indexed: int = 0
    units_deduplicated: int = 0
    embeddings_reused: int = 0
    embeddings_generated: int = 0
    time_elapsed_seconds: float = 0.0


@dataclass
class ShardInfo:
    """分片信息"""
    shard_id: str
    shard_type: str  # "language" or "directory"
    filter_value: str  # 语言名或目录路径
    unit_count: int
    file_count: int
    last_updated: str


class IncrementalIndexManager:
    """增量索引管理器"""

    def __init__(
        self,
        index_dir: str = ".audit_data/incremental_index",
        enable_deduplication: bool = True,
        enable_sharding: bool = True,
        shard_by: str = "language",  # "language" or "directory"
    ):
        self.index_dir = Path(index_dir)
        self.index_dir.mkdir(parents=True, exist_ok=True)

        self.enable_deduplication = enable_deduplication
        self.enable_sharding = enable_sharding
        self.shard_by = shard_by

        # 索引数据
        self.file_index: Dict[str, FileIndexEntry] = {}
        self.dedup_index: Dict[str, ChunkDeduplicationEntry] = {}
        self.shards: Dict[str, ShardInfo] = {}

        # 加载现有索引
        self._load_indexes()

    def _load_indexes(self) -> None:
        """加载索引文件"""
        # 加载文件索引
        file_index_path = self.index_dir / "file_index.json"
        if file_index_path.exists():
            try:
                with open(file_index_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.file_index = {
                        k: FileIndexEntry.from_dict(v)
                        for k, v in data.items()
                    }
                logger.info(f"Loaded file index with {len(self.file_index)} entries")
            except Exception as e:
                logger.warning(f"Failed to load file index: {e}")

        # 加载去重索引
        if self.enable_deduplication:
            dedup_index_path = self.index_dir / "dedup_index.json"
            if dedup_index_path.exists():
                try:
                    with open(dedup_index_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self.dedup_index = {
                            k: ChunkDeduplicationEntry.from_dict(v)
                            for k, v in data.items()
                        }
                    logger.info(f"Loaded dedup index with {len(self.dedup_index)} entries")
                except Exception as e:
                    logger.warning(f"Failed to load dedup index: {e}")

        # 加载分片信息
        if self.enable_sharding:
            shard_index_path = self.index_dir / "shard_index.json"
            if shard_index_path.exists():
                try:
                    with open(shard_index_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self.shards = {
                            k: ShardInfo(**v)
                            for k, v in data.items()
                        }
                    logger.info(f"Loaded {len(self.shards)} shards")
                except Exception as e:
                    logger.warning(f"Failed to load shard index: {e}")

    def _save_indexes(self) -> None:
        """保存索引文件"""
        # 保存文件索引
        file_index_path = self.index_dir / "file_index.json"
        with open(file_index_path, "w", encoding="utf-8") as f:
            json.dump(
                {k: v.to_dict() for k, v in self.file_index.items()},
                f, ensure_ascii=False, indent=2
            )

        # 保存去重索引
        if self.enable_deduplication:
            dedup_index_path = self.index_dir / "dedup_index.json"
            with open(dedup_index_path, "w", encoding="utf-8") as f:
                json.dump(
                    {k: v.to_dict() for k, v in self.dedup_index.items()},
                    f, ensure_ascii=False, indent=2
                )

        # 保存分片信息
        if self.enable_sharding:
            shard_index_path = self.index_dir / "shard_index.json"
            with open(shard_index_path, "w", encoding="utf-8") as f:
                json.dump(
                    {k: asdict(v) for k, v in self.shards.items()},
                    f, ensure_ascii=False, indent=2
                )

    def _compute_content_hash(self, content: str) -> str:
        """计算内容hash"""
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _compute_code_hash(self, code: str) -> str:
        """计算代码hash（忽略空白差异）"""
        # 标准化代码：去除多余空白
        normalized = " ".join(code.split())
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def check_file_status(
        self,
        file_path: str,
        content: str,
        mtime: float,
    ) -> Tuple[str, bool]:
        """检查文件状态

        Args:
            file_path: 文件路径
            content: 文件内容
            mtime: 修改时间

        Returns:
            (状态, 是否需要重新索引)
            状态: "new", "modified", "unchanged"
        """
        content_hash = self._compute_content_hash(content)

        if file_path not in self.file_index:
            return "new", True

        entry = self.file_index[file_path]

        # 先检查hash，再检查mtime
        if entry.content_hash != content_hash:
            return "modified", True

        # hash相同但mtime不同，不需要重新索引（内容没变）
        if entry.mtime != mtime:
            # 更新mtime但不重新索引
            entry.mtime = mtime
            return "unchanged", False

        return "unchanged", False

    def detect_deleted_files(self, current_files: Set[str]) -> List[str]:
        """检测已删除的文件

        Args:
            current_files: 当前存在的文件集合

        Returns:
            已删除的文件路径列表
        """
        indexed_files = set(self.file_index.keys())
        deleted = indexed_files - current_files
        return list(deleted)

    def check_duplicate_code(self, code: str) -> Optional[ChunkDeduplicationEntry]:
        """检查代码是否重复

        Args:
            code: 代码内容

        Returns:
            如果重复，返回去重条目；否则返回None
        """
        if not self.enable_deduplication:
            return None

        code_hash = self._compute_code_hash(code)
        return self.dedup_index.get(code_hash)

    def register_code_chunk(
        self,
        unit_id: str,
        code: str,
        file_path: str,
        language: str,
        embedding: Optional[List[float]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """注册代码块

        Args:
            unit_id: 代码单元ID
            code: 代码内容
            file_path: 文件路径
            language: 语言
            embedding: 嵌入向量（可选）

        Returns:
            (是否是新代码, 去重hash/None)
        """
        if not self.enable_deduplication:
            return True, None

        code_hash = self._compute_code_hash(code)

        if code_hash in self.dedup_index:
            # 代码重复，添加引用
            entry = self.dedup_index[code_hash]
            if unit_id not in entry.unit_ids:
                entry.unit_ids.append(unit_id)
            if file_path not in entry.locations:
                entry.locations.append(file_path)
            return False, code_hash

        # 新代码，创建条目
        embedding_hash = ""
        if embedding:
            # 计算嵌入向量的hash用于快速查找
            embedding_str = ",".join(f"{x:.6f}" for x in embedding[:10])
            embedding_hash = hashlib.md5(embedding_str.encode()).hexdigest()[:8]

        entry = ChunkDeduplicationEntry(
            content_hash=code_hash,
            embedding_hash=embedding_hash,
            unit_ids=[unit_id],
            locations=[file_path],
            language=language,
            first_indexed_at=datetime.now().isoformat(),
        )
        self.dedup_index[code_hash] = entry

        return True, code_hash

    def get_shard_id(self, unit: CodeUnit) -> str:
        """获取代码单元所属的分片ID

        Args:
            unit: 代码单元

        Returns:
            分片ID
        """
        if not self.enable_sharding:
            return "default"

        if self.shard_by == "language":
            return f"lang_{unit.language}"
        elif self.shard_by == "directory":
            # 使用顶级目录作为分片
            parts = unit.file_path.split("/")
            if len(parts) > 1:
                return f"dir_{parts[0]}"
            return "dir_root"
        else:
            return "default"

    def update_shard(
        self,
        shard_id: str,
        units: List[CodeUnit],
        files: Set[str],
    ) -> None:
        """更新分片信息

        Args:
            shard_id: 分片ID
            units: 该分片的代码单元列表
            files: 该分片的文件集合
        """
        if not self.enable_sharding:
            return

        shard_type = self.shard_by
        filter_value = shard_id.split("_", 1)[1] if "_" in shard_id else shard_id

        self.shards[shard_id] = ShardInfo(
            shard_id=shard_id,
            shard_type=shard_type,
            filter_value=filter_value,
            unit_count=len(units),
            file_count=len(files),
            last_updated=datetime.now().isoformat(),
        )

    def update_file_index(
        self,
        file_path: str,
        content: str,
        mtime: float,
        unit_ids: List[str],
        language: str,
    ) -> None:
        """更新文件索引

        Args:
            file_path: 文件路径
            content: 文件内容
            mtime: 修改时间
            unit_ids: 该文件的代码单元ID列表
            language: 语言
        """
        self.file_index[file_path] = FileIndexEntry(
            file_path=file_path,
            content_hash=self._compute_content_hash(content),
            mtime=mtime,
            size=len(content),
            unit_ids=unit_ids,
            language=language,
            indexed_at=datetime.now().isoformat(),
        )

    def remove_file_from_index(self, file_path: str) -> List[str]:
        """从索引中移除文件

        Args:
            file_path: 文件路径

        Returns:
            被移除的unit ID列表
        """
        if file_path not in self.file_index:
            return []

        entry = self.file_index[file_path]
        removed_unit_ids = entry.unit_ids.copy()

        # 从去重索引中移除引用
        if self.enable_deduplication:
            for hash_key, dedup_entry in list(self.dedup_index.items()):
                # 移除unit_ids中的引用
                dedup_entry.unit_ids = [
                    uid for uid in dedup_entry.unit_ids
                    if uid not in removed_unit_ids
                ]
                # 移除locations中的引用
                dedup_entry.locations = [
                    loc for loc in dedup_entry.locations
                    if loc != file_path
                ]
                # 如果没有引用了，删除条目
                if not dedup_entry.unit_ids:
                    del self.dedup_index[hash_key]

        # 从文件索引中移除
        del self.file_index[file_path]

        return removed_unit_ids

    def get_units_to_remove(self, deleted_files: List[str]) -> List[str]:
        """获取需要从向量库中移除的unit ID列表

        Args:
            deleted_files: 已删除的文件路径列表

        Returns:
            需要移除的unit ID列表
        """
        unit_ids = []
        for file_path in deleted_files:
            if file_path in self.file_index:
                unit_ids.extend(self.file_index[file_path].unit_ids)
        return unit_ids

    def compute_incremental_update(
        self,
        files_info: List[Tuple[str, str, float]],  # [(path, content, mtime), ...]
    ) -> Dict[str, Any]:
        """计算增量更新计划

        Args:
            files_info: 文件信息列表

        Returns:
            增量更新计划
        """
        plan = {
            "files_to_add": [],
            "files_to_update": [],
            "files_unchanged": [],
            "files_to_delete": [],
            "units_to_remove": [],
        }

        current_files = set()

        for file_path, content, mtime in files_info:
            current_files.add(file_path)
            status, needs_index = self.check_file_status(file_path, content, mtime)

            if status == "new":
                plan["files_to_add"].append((file_path, content, mtime))
            elif status == "modified":
                plan["files_to_update"].append((file_path, content, mtime))
                # 标记旧的units需要删除
                if file_path in self.file_index:
                    plan["units_to_remove"].extend(self.file_index[file_path].unit_ids)
            else:
                plan["files_unchanged"].append(file_path)

        # 检测删除的文件
        deleted = self.detect_deleted_files(current_files)
        plan["files_to_delete"] = deleted
        plan["units_to_remove"].extend(self.get_units_to_remove(deleted))

        return plan

    def save(self) -> None:
        """保存索引到磁盘"""
        self._save_indexes()
        logger.info("Incremental index saved")

    def clear(self) -> None:
        """清空所有索引"""
        self.file_index.clear()
        self.dedup_index.clear()
        self.shards.clear()

        # 删除索引文件
        for f in self.index_dir.glob("*.json"):
            f.unlink()

        logger.info("Incremental index cleared")

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {
            "total_files": len(self.file_index),
            "total_units": sum(len(e.unit_ids) for e in self.file_index.values()),
            "deduplication_enabled": self.enable_deduplication,
            "sharding_enabled": self.enable_sharding,
        }

        if self.enable_deduplication:
            total_refs = sum(len(e.unit_ids) for e in self.dedup_index.values())
            unique_chunks = len(self.dedup_index)
            stats["dedup_stats"] = {
                "unique_chunks": unique_chunks,
                "total_references": total_refs,
                "dedup_ratio": 1 - (unique_chunks / max(total_refs, 1)),
            }

        if self.enable_sharding:
            stats["shards"] = {
                sid: {
                    "type": s.shard_type,
                    "filter": s.filter_value,
                    "units": s.unit_count,
                    "files": s.file_count,
                }
                for sid, s in self.shards.items()
            }

        # 按语言统计
        by_language = {}
        for entry in self.file_index.values():
            lang = entry.language
            if lang not in by_language:
                by_language[lang] = {"files": 0, "units": 0}
            by_language[lang]["files"] += 1
            by_language[lang]["units"] += len(entry.unit_ids)

        stats["by_language"] = by_language

        return stats

    def get_reusable_embeddings(
        self,
        units: List[CodeUnit],
    ) -> Tuple[List[CodeUnit], List[CodeUnit], Dict[str, List[float]]]:
        """获取可重用的嵌入

        将代码单元分为需要生成新嵌入的和可以重用的

        Args:
            units: 代码单元列表

        Returns:
            (需要生成嵌入的units, 可重用嵌入的units, {unit_id: 重用的embedding})
        """
        if not self.enable_deduplication:
            return units, [], {}

        new_units = []
        reusable_units = []
        reusable_embeddings = {}

        for unit in units:
            dedup_entry = self.check_duplicate_code(unit.code)
            if dedup_entry and dedup_entry.embedding_hash:
                # 可以重用
                reusable_units.append(unit)
                # 注意：这里只是标记可重用，实际embedding需要从向量库获取
            else:
                new_units.append(unit)

        return new_units, reusable_units, reusable_embeddings
