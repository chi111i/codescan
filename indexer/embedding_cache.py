"""
嵌入缓存模块 - 基于内容哈希避免重复计算

功能:
- 基于文件/代码内容的 SHA256 哈希作为缓存键
- 支持本地文件缓存和 SQLite 缓存
- 自动过期清理 (TTL)
- LRU 淘汰策略 (基于访问时间)
- 压缩存储 (减少磁盘占用)
- 持久化统计信息
- 相似代码去重 (可选)
"""

import hashlib
import json
import logging
import sqlite3
import struct
import threading
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from serialization import safe_json_dumps

logger = logging.getLogger(__name__)

# 全局单例和锁
_cache_instances: Dict[str, "EmbeddingCache"] = {}
_cache_lock = threading.Lock()


@dataclass
class CacheEntry:
    """缓存条目"""
    content_hash: str
    embedding: List[float]
    created_at: float
    accessed_at: float  # LRU 追踪
    metadata: Dict[str, Any]


class EmbeddingCache:
    """嵌入缓存 - 基于内容哈希

    特点:
    - 内容不变则不重算 embedding
    - 支持批量查询和存储
    - TTL 过期清理
    - LRU 淘汰策略
    - 压缩存储 (可选)
    - 持久化统计信息
    """

    def __init__(
        self,
        cache_dir: str = ".audit_cache",
        ttl_days: int = 30,
        use_sqlite: bool = True,
        max_entries: int = 100000,
        use_compression: bool = True
    ):
        """初始化缓存

        Args:
            cache_dir: 缓存目录
            ttl_days: 缓存过期天数
            use_sqlite: 使用 SQLite (推荐) 还是 JSON 文件
            max_entries: 最大缓存条目数 (用于 LRU 淘汰)
            use_compression: 是否压缩嵌入向量
        """
        self.cache_dir = Path(cache_dir)
        self.ttl_days = ttl_days
        self.use_sqlite = use_sqlite
        self.max_entries = max_entries
        self.use_compression = use_compression
        self._db_conn = None

        # 确保缓存目录存在
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        if use_sqlite:
            self._init_sqlite()

    def _init_sqlite(self, max_retries: int = 3) -> None:
        """初始化 SQLite 数据库

        Args:
            max_retries: 最大重试次数
        """
        db_path = self.cache_dir / "embeddings.db"

        for attempt in range(max_retries):
            try:
                # 添加 timeout 避免数据库锁定问题
                self._db_conn = sqlite3.connect(
                    str(db_path),
                    check_same_thread=False,
                    timeout=30.0  # 30 秒超时
                )
                # 设置 WAL 模式以减少锁定问题
                self._db_conn.execute("PRAGMA journal_mode=WAL")
                self._db_conn.execute("PRAGMA busy_timeout=30000")  # 30 秒忙等待

                # 初始化表结构
                self._init_tables(db_path)
                break
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    logger.warning(f"数据库锁定，重试中 ({attempt + 1}/{max_retries})...")
                    time.sleep(1)  # 等待 1 秒后重试
                    # 尝试清理 WAL 文件
                    self._cleanup_wal_files(db_path)
                else:
                    raise

    def _cleanup_wal_files(self, db_path: Path) -> None:
        """清理 WAL 相关文件"""
        wal_file = db_path.parent / f"{db_path.name}-wal"
        shm_file = db_path.parent / f"{db_path.name}-shm"
        journal_file = db_path.parent / f"{db_path.name}-journal"

        for f in [wal_file, shm_file, journal_file]:
            if f.exists():
                try:
                    f.unlink()
                    logger.info(f"清理 WAL 文件: {f}")
                except Exception as e:
                    logger.warning(f"无法清理 {f}: {e}")

    def _init_tables(self, db_path: Path) -> None:
        """初始化数据库表"""
        # 主缓存表 (增加 accessed_at 列用于 LRU)
        self._db_conn.execute("""
            CREATE TABLE IF NOT EXISTS embeddings (
                content_hash TEXT PRIMARY KEY,
                embedding BLOB,
                created_at REAL,
                accessed_at REAL,
                metadata TEXT,
                compressed INTEGER DEFAULT 0
            )
        """)

        # 统计信息表 (持久化)
        self._db_conn.execute("""
            CREATE TABLE IF NOT EXISTS cache_stats (
                key TEXT PRIMARY KEY,
                value INTEGER DEFAULT 0
            )
        """)

        # 初始化统计计数器
        for key in ['total_hits', 'total_misses', 'total_evictions']:
            self._db_conn.execute("""
                INSERT OR IGNORE INTO cache_stats (key, value) VALUES (?, 0)
            """, (key,))

        self._db_conn.commit()
        logger.info(f"Initialized embedding cache: {db_path}")

        # 迁移旧数据库 (添加新列如果不存在)
        self._migrate_schema()

        # 在迁移完成后创建索引（确保列存在）
        self._create_indexes()

    def _migrate_schema(self) -> None:
        """迁移数据库 schema

        添加新版本需要的列，确保向后兼容
        """
        if not self._db_conn:
            return

        # 检查并添加 accessed_at 列
        try:
            self._db_conn.execute("SELECT accessed_at FROM embeddings LIMIT 1")
        except sqlite3.OperationalError:
            logger.info("Migrating schema: adding accessed_at column")
            self._db_conn.execute("""
                ALTER TABLE embeddings ADD COLUMN accessed_at REAL
            """)
            # 用 created_at 初始化 accessed_at
            self._db_conn.execute("""
                UPDATE embeddings SET accessed_at = created_at WHERE accessed_at IS NULL
            """)
            self._db_conn.commit()

        # 检查并添加 compressed 列
        try:
            self._db_conn.execute("SELECT compressed FROM embeddings LIMIT 1")
        except sqlite3.OperationalError:
            logger.info("Migrating schema: adding compressed column")
            self._db_conn.execute("""
                ALTER TABLE embeddings ADD COLUMN compressed INTEGER DEFAULT 0
            """)
            self._db_conn.commit()

    def _create_indexes(self) -> None:
        """创建数据库索引（在迁移完成后调用）"""
        if not self._db_conn:
            return

        try:
            self._db_conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_created_at ON embeddings(created_at)
            """)
            self._db_conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_accessed_at ON embeddings(accessed_at)
            """)
            self._db_conn.commit()
        except sqlite3.OperationalError as e:
            logger.warning(f"创建索引失败: {e}")

    @staticmethod
    def compute_hash(content: str) -> str:
        """计算内容哈希"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def _compress_embedding(self, embedding: List[float]) -> bytes:
        """压缩嵌入向量

        使用 struct 打包为 float32 数组，然后 zlib 压缩
        """
        # 打包为二进制 float32 数组
        packed = struct.pack(f'{len(embedding)}f', *embedding)
        # zlib 压缩
        return zlib.compress(packed, level=6)

    def _decompress_embedding(self, data: bytes, is_compressed: bool) -> List[float]:
        """解压嵌入向量"""
        if is_compressed:
            # zlib 解压
            packed = zlib.decompress(data)
            # 解包 float32 数组
            count = len(packed) // 4  # float32 = 4 bytes
            return list(struct.unpack(f'{count}f', packed))
        else:
            # 兼容旧格式 (JSON)
            return json.loads(data)

    def _increment_stat(self, key: str, count: int = 1) -> None:
        """增加统计计数"""
        if self.use_sqlite and self._db_conn:
            self._db_conn.execute("""
                UPDATE cache_stats SET value = value + ? WHERE key = ?
            """, (count, key))

    def _get_stat(self, key: str) -> int:
        """获取统计值"""
        if self.use_sqlite and self._db_conn:
            cursor = self._db_conn.execute(
                "SELECT value FROM cache_stats WHERE key = ?", (key,)
            )
            row = cursor.fetchone()
            return row[0] if row else 0
        return 0

    def get(self, content_hash: str) -> Optional[List[float]]:
        """获取缓存的嵌入

        Args:
            content_hash: 内容哈希

        Returns:
            嵌入向量，如果缓存未命中则返回 None
        """
        if self.use_sqlite:
            return self._get_sqlite(content_hash)
        else:
            return self._get_file(content_hash)

    def _get_sqlite(self, content_hash: str) -> Optional[List[float]]:
        """从 SQLite 获取"""
        cursor = self._db_conn.execute(
            "SELECT embedding, created_at, compressed FROM embeddings WHERE content_hash = ?",
            (content_hash,)
        )
        row = cursor.fetchone()

        if not row:
            self._increment_stat('total_misses')
            return None

        embedding_bytes, created_at, is_compressed = row

        # 检查是否过期
        if self._is_expired(created_at):
            self._delete_sqlite(content_hash)
            self._increment_stat('total_misses')
            return None

        # 更新访问时间 (LRU)
        self._db_conn.execute(
            "UPDATE embeddings SET accessed_at = ? WHERE content_hash = ?",
            (time.time(), content_hash)
        )
        self._db_conn.commit()

        # 统计命中
        self._increment_stat('total_hits')

        # 解压/解析嵌入
        return self._decompress_embedding(embedding_bytes, bool(is_compressed))

    def _get_file(self, content_hash: str) -> Optional[List[float]]:
        """从文件获取"""
        cache_file = self.cache_dir / f"{content_hash[:2]}" / f"{content_hash}.json"

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, "r") as f:
                data = json.load(f)

            if self._is_expired(data.get("created_at", 0)):
                cache_file.unlink()
                return None

            return data.get("embedding")
        except Exception as e:
            logger.warning(f"Failed to read cache file: {e}")
            return None

    def set(
        self,
        content_hash: str,
        embedding: List[float],
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """存储嵌入到缓存

        Args:
            content_hash: 内容哈希
            embedding: 嵌入向量
            metadata: 额外元数据
        """
        if self.use_sqlite:
            self._set_sqlite(content_hash, embedding, metadata)
        else:
            self._set_file(content_hash, embedding, metadata)

    def _set_sqlite(
        self,
        content_hash: str,
        embedding: List[float],
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """存储到 SQLite"""
        now = time.time()

        # 压缩嵌入向量
        if self.use_compression:
            embedding_data = self._compress_embedding(embedding)
            compressed = 1
        else:
            embedding_data = json.dumps(embedding)
            compressed = 0

        self._db_conn.execute(
            """
            INSERT OR REPLACE INTO embeddings
            (content_hash, embedding, created_at, accessed_at, metadata, compressed)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                content_hash,
                embedding_data,
                now,
                now,  # 初始访问时间
                safe_json_dumps(metadata or {}, ensure_ascii=False),
                compressed
            )
        )
        self._db_conn.commit()

        # 检查是否需要 LRU 淘汰
        self._maybe_evict_lru()

    def _set_file(
        self,
        content_hash: str,
        embedding: List[float],
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """存储到文件"""
        # 使用哈希前两位作为子目录
        subdir = self.cache_dir / content_hash[:2]
        subdir.mkdir(exist_ok=True)

        cache_file = subdir / f"{content_hash}.json"
        data = {
            "embedding": embedding,
            "created_at": time.time(),
            "metadata": metadata or {}
        }

        with open(cache_file, "w") as f:
            json.dump(data, f)

    def get_batch(self, content_hashes: List[str]) -> Dict[str, Optional[List[float]]]:
        """批量获取缓存 (优化: 使用 SQL IN 查询)

        Args:
            content_hashes: 内容哈希列表

        Returns:
            哈希到嵌入的映射
        """
        if not content_hashes:
            return {}

        if self.use_sqlite:
            return self._get_batch_sqlite(content_hashes)
        else:
            # 文件模式仍使用逐个查询
            results = {}
            for h in content_hashes:
                results[h] = self.get(h)
            return results

    def _get_batch_sqlite(self, content_hashes: List[str]) -> Dict[str, Optional[List[float]]]:
        """从 SQLite 批量获取 (使用 IN 查询)

        性能优化: O(1) 次 SQL 查询代替 O(n) 次
        """
        results: Dict[str, Optional[List[float]]] = {h: None for h in content_hashes}
        expiry_threshold = time.time() - (self.ttl_days * 24 * 60 * 60)
        now = time.time()

        # 分块处理以避免 SQL 变量过多 (SQLite 限制约 999 个变量)
        chunk_size = 500
        hits = 0
        expired_hashes = []
        hashes_to_update = []

        for i in range(0, len(content_hashes), chunk_size):
            chunk = content_hashes[i:i + chunk_size]
            placeholders = ",".join("?" * len(chunk))

            query = f"""
                SELECT content_hash, embedding, created_at, compressed
                FROM embeddings
                WHERE content_hash IN ({placeholders})
            """

            cursor = self._db_conn.execute(query, chunk)
            rows = cursor.fetchall()

            for row in rows:
                content_hash, embedding_bytes, created_at, is_compressed = row

                # 检查是否过期
                if created_at < expiry_threshold:
                    expired_hashes.append(content_hash)
                    continue

                # 解压/解析嵌入
                try:
                    embedding = self._decompress_embedding(embedding_bytes, bool(is_compressed))
                    results[content_hash] = embedding
                    hashes_to_update.append(content_hash)
                    hits += 1
                except Exception as e:
                    logger.warning(f"解压嵌入失败: {content_hash[:8]}... - {e}")
                    continue

        # 批量更新访问时间 (LRU)
        if hashes_to_update:
            for i in range(0, len(hashes_to_update), chunk_size):
                chunk = hashes_to_update[i:i + chunk_size]
                placeholders = ",".join("?" * len(chunk))
                self._db_conn.execute(
                    f"UPDATE embeddings SET accessed_at = ? WHERE content_hash IN ({placeholders})",
                    [now] + chunk
                )
            self._db_conn.commit()

        # 批量删除过期条目
        if expired_hashes:
            for i in range(0, len(expired_hashes), chunk_size):
                chunk = expired_hashes[i:i + chunk_size]
                placeholders = ",".join("?" * len(chunk))
                self._db_conn.execute(
                    f"DELETE FROM embeddings WHERE content_hash IN ({placeholders})",
                    chunk
                )
            self._db_conn.commit()
            logger.debug(f"批量删除 {len(expired_hashes)} 个过期缓存条目")

        # 更新统计
        misses = len(content_hashes) - hits
        self._increment_stat('total_hits', hits)
        self._increment_stat('total_misses', misses)

        return results

    def set_batch(
        self,
        items: List[Tuple[str, List[float], Optional[Dict[str, Any]]]]
    ) -> None:
        """批量存储缓存

        Args:
            items: [(content_hash, embedding, metadata), ...]
        """
        if self.use_sqlite:
            now = time.time()
            for content_hash, embedding, metadata in items:
                # 压缩嵌入向量
                if self.use_compression:
                    embedding_data = self._compress_embedding(embedding)
                    compressed = 1
                else:
                    embedding_data = json.dumps(embedding)
                    compressed = 0

                self._db_conn.execute(
                    """
                    INSERT OR REPLACE INTO embeddings
                    (content_hash, embedding, created_at, accessed_at, metadata, compressed)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        content_hash,
                        embedding_data,
                        now,
                        now,
                        safe_json_dumps(metadata or {}, ensure_ascii=False),
                        compressed
                    )
                )
            self._db_conn.commit()

            # 批量插入后检查 LRU 淘汰
            self._maybe_evict_lru()
        else:
            for content_hash, embedding, metadata in items:
                self._set_file(content_hash, embedding, metadata)

    def _is_expired(self, created_at: float) -> bool:
        """检查是否过期"""
        expiry_time = created_at + (self.ttl_days * 24 * 60 * 60)
        return time.time() > expiry_time

    def _delete_sqlite(self, content_hash: str) -> None:
        """从 SQLite 删除"""
        self._db_conn.execute(
            "DELETE FROM embeddings WHERE content_hash = ?",
            (content_hash,)
        )
        self._db_conn.commit()

    def _maybe_evict_lru(self) -> None:
        """检查并执行 LRU 淘汰

        当缓存条目数超过 max_entries 时，删除最久未访问的 10% 条目
        """
        if not self.use_sqlite or not self._db_conn:
            return

        cursor = self._db_conn.execute("SELECT COUNT(*) FROM embeddings")
        current_count = cursor.fetchone()[0]

        if current_count <= self.max_entries:
            return

        # 计算需要删除的数量 (超出部分 + 10% 缓冲)
        excess = current_count - self.max_entries
        to_evict = max(excess, int(self.max_entries * 0.1))

        # 删除访问时间最早的条目
        self._db_conn.execute("""
            DELETE FROM embeddings
            WHERE content_hash IN (
                SELECT content_hash FROM embeddings
                ORDER BY accessed_at ASC
                LIMIT ?
            )
        """, (to_evict,))
        self._db_conn.commit()

        self._increment_stat('total_evictions', to_evict)
        logger.info(f"LRU eviction: removed {to_evict} entries, cache now at {current_count - to_evict}")

    def cleanup_expired(self) -> int:
        """清理过期缓存

        Returns:
            清理的条目数
        """
        expiry_threshold = time.time() - (self.ttl_days * 24 * 60 * 60)

        if self.use_sqlite:
            cursor = self._db_conn.execute(
                "DELETE FROM embeddings WHERE created_at < ?",
                (expiry_threshold,)
            )
            self._db_conn.commit()
            count = cursor.rowcount
        else:
            count = 0
            for subdir in self.cache_dir.iterdir():
                if subdir.is_dir() and len(subdir.name) == 2:
                    for cache_file in subdir.glob("*.json"):
                        try:
                            with open(cache_file, "r") as f:
                                data = json.load(f)
                            if self._is_expired(data.get("created_at", 0)):
                                cache_file.unlink()
                                count += 1
                        except Exception:
                            pass

        logger.info(f"Cleaned up {count} expired cache entries")
        return count

    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计信息

        Returns:
            包含以下字段的字典:
            - total_entries: 总条目数
            - expired_entries: 过期条目数
            - cache_size_mb: 缓存大小 (MB)
            - ttl_days: TTL 天数
            - max_entries: 最大条目限制
            - total_hits: 总命中次数 (持久化)
            - total_misses: 总未命中次数 (持久化)
            - total_evictions: 总淘汰次数 (持久化)
            - hit_rate: 总命中率
            - compression_enabled: 是否启用压缩
        """
        if self.use_sqlite:
            cursor = self._db_conn.execute("SELECT COUNT(*) FROM embeddings")
            total = cursor.fetchone()[0]

            expiry_threshold = time.time() - (self.ttl_days * 24 * 60 * 60)
            cursor = self._db_conn.execute(
                "SELECT COUNT(*) FROM embeddings WHERE created_at < ?",
                (expiry_threshold,)
            )
            expired = cursor.fetchone()[0]

            # 计算压缩条目数
            cursor = self._db_conn.execute(
                "SELECT COUNT(*) FROM embeddings WHERE compressed = 1"
            )
            compressed_count = cursor.fetchone()[0]

            # 计算缓存大小
            db_path = self.cache_dir / "embeddings.db"
            size_mb = db_path.stat().st_size / (1024 * 1024) if db_path.exists() else 0

            # 获取持久化统计
            total_hits = self._get_stat('total_hits')
            total_misses = self._get_stat('total_misses')
            total_evictions = self._get_stat('total_evictions')

            # 计算命中率
            total_requests = total_hits + total_misses
            hit_rate = total_hits / max(1, total_requests)

            return {
                "total_entries": total,
                "expired_entries": expired,
                "compressed_entries": compressed_count,
                "cache_size_mb": round(size_mb, 2),
                "ttl_days": self.ttl_days,
                "max_entries": self.max_entries,
                "total_hits": total_hits,
                "total_misses": total_misses,
                "total_evictions": total_evictions,
                "hit_rate": round(hit_rate, 4),
                "compression_enabled": self.use_compression,
                "cache_enabled": True,
            }
        else:
            total = 0
            for subdir in self.cache_dir.iterdir():
                if subdir.is_dir() and len(subdir.name) == 2:
                    total += len(list(subdir.glob("*.json")))

            return {
                "total_entries": total,
                "ttl_days": self.ttl_days
            }

    def clear(self) -> None:
        """清空所有缓存"""
        if self.use_sqlite:
            self._db_conn.execute("DELETE FROM embeddings")
            self._db_conn.commit()
        else:
            import shutil
            for subdir in self.cache_dir.iterdir():
                if subdir.is_dir() and len(subdir.name) == 2:
                    shutil.rmtree(subdir)

        logger.info("Embedding cache cleared")

    def close(self) -> None:
        """关闭缓存连接"""
        if self._db_conn:
            self._db_conn.close()
            self._db_conn = None


class CachedEmbeddingGenerator:
    """带缓存的嵌入生成器

    用于包装 LLM 客户端的 embed 方法，自动处理缓存
    """

    def __init__(
        self,
        llm_client,
        cache: Optional[EmbeddingCache] = None,
        cache_dir: str = ".audit_cache",
        ttl_days: int = 30
    ):
        """初始化

        Args:
            llm_client: LLM 客户端 (需要有 embed 方法)
            cache: 可选的缓存实例
            cache_dir: 缓存目录 (如果 cache 为 None)
            ttl_days: 缓存过期天数 (如果 cache 为 None)
        """
        self.llm_client = llm_client
        self.cache = cache or EmbeddingCache(cache_dir=cache_dir, ttl_days=ttl_days)
        self._cache_hits = 0
        self._cache_misses = 0

    def generate_embeddings(
        self,
        texts: List[str],
        batch_size: int = 50,
        max_concurrent: int = 5
    ) -> List[List[float]]:
        """生成嵌入 (带缓存 + 并行请求)

        Args:
            texts: 文本列表
            batch_size: 每批文本数量 (默认50)
            max_concurrent: 最大并发请求数 (默认5，适配 SiliconFlow 3000 RPM)

        Returns:
            嵌入向量列表
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # 计算所有文本的哈希
        hashes = [EmbeddingCache.compute_hash(t) for t in texts]

        # 批量查询缓存
        cached = self.cache.get_batch(hashes)

        # 找出需要计算的文本
        embeddings = [None] * len(texts)
        texts_to_compute = []
        indices_to_compute = []

        for i, (text, h) in enumerate(zip(texts, hashes)):
            if cached[h] is not None:
                embeddings[i] = cached[h]
                self._cache_hits += 1
            else:
                texts_to_compute.append(text)
                indices_to_compute.append(i)
                self._cache_misses += 1

        logger.debug(f"Cache hits: {self._cache_hits}, misses: {self._cache_misses}")

        # 批量计算新的嵌入（并行请求）
        if texts_to_compute:
            # 准备所有批次
            batches = []
            for i in range(0, len(texts_to_compute), batch_size):
                batch_texts = texts_to_compute[i:i + batch_size]
                batch_indices = list(range(i, min(i + batch_size, len(texts_to_compute))))
                batches.append((batch_texts, batch_indices))

            logger.info(f"[Embedding] 并行处理 {len(batches)} 批次，每批 {batch_size} 个，并发数 {max_concurrent}")

            # 并行执行嵌入请求
            new_embeddings = [None] * len(texts_to_compute)

            def process_batch(batch_data):
                batch_texts, batch_indices = batch_data
                response = self.llm_client.embed(batch_texts)
                return batch_indices, response.embeddings

            with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
                futures = {executor.submit(process_batch, batch): batch for batch in batches}
                completed = 0
                for future in as_completed(futures):
                    try:
                        batch_indices, batch_embeddings = future.result()
                        for idx, emb in zip(batch_indices, batch_embeddings):
                            new_embeddings[idx] = emb
                        completed += 1
                        if completed % 5 == 0 or completed == len(batches):
                            logger.info(f"[Embedding] 进度: {completed}/{len(batches)} 批次完成")
                    except Exception as e:
                        logger.error(f"[Embedding] 批次处理失败: {e}")
                        # 填充空向量
                        batch_texts, batch_indices = futures[future]
                        for idx in batch_indices:
                            new_embeddings[idx] = [0.0] * 4096

            # 填充结果并缓存
            cache_items = []
            for idx, emb, text in zip(indices_to_compute, new_embeddings, texts_to_compute):
                if emb is not None:
                    embeddings[idx] = emb
                    h = hashes[idx]
                    cache_items.append((h, emb, {"text_length": len(text)}))

            self.cache.set_batch(cache_items)

        return embeddings

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        cache_stats = self.cache.get_stats()
        hit_rate = self._cache_hits / max(1, self._cache_hits + self._cache_misses)

        return {
            **cache_stats,
            "session_hits": self._cache_hits,
            "session_misses": self._cache_misses,
            "session_hit_rate": round(hit_rate, 3)
        }

    def reset_stats(self) -> None:
        """重置会话统计"""
        self._cache_hits = 0
        self._cache_misses = 0


def get_embedding_cache(
    cache_dir: str = ".audit_cache",
    ttl_days: int = 30,
    use_sqlite: bool = True,
    max_entries: int = 100000,
    use_compression: bool = True
) -> EmbeddingCache:
    """获取单例嵌入缓存实例（线程安全）

    Args:
        cache_dir: 缓存目录
        ttl_days: 缓存过期天数
        use_sqlite: 使用 SQLite 还是 JSON 文件
        max_entries: 最大缓存条目数
        use_compression: 是否压缩嵌入向量

    Returns:
        EmbeddingCache 单例实例
    """
    global _cache_instances, _cache_lock

    cache_key = str(Path(cache_dir).resolve())

    with _cache_lock:
        if cache_key not in _cache_instances:
            logger.info(f"创建嵌入缓存单例实例: {cache_key}")
            _cache_instances[cache_key] = EmbeddingCache(
                cache_dir=cache_dir,
                ttl_days=ttl_days,
                use_sqlite=use_sqlite,
                max_entries=max_entries,
                use_compression=use_compression
            )
        return _cache_instances[cache_key]


def close_all_caches() -> None:
    """关闭所有缓存连接（应用关闭时调用）"""
    global _cache_instances, _cache_lock

    with _cache_lock:
        for cache_key, cache in list(_cache_instances.items()):
            try:
                cache.close()
                logger.info(f"关闭缓存实例: {cache_key}")
            except Exception as e:
                logger.warning(f"关闭缓存实例失败: {cache_key}, {e}")
        _cache_instances.clear()
