"""
代码索引器 - 遍历、解析、向量化代码

支持:
- 多语言代码解析
- 嵌入缓存 (基于内容哈希)
- Hybrid 混合检索
- 增量索引 (仅处理变更文件)
"""

import fnmatch
import hashlib
import logging
import sqlite3
import time
from pathlib import Path
from typing import List, Optional, Set, Iterator, Callable, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import AuditConfig, ScanConfig
from llm_client import BaseLLMClient

from .models import CodeUnit
from .parser import get_parser_for_file, BaseLanguageParser
from .vector_store import BaseVectorStore, SearchResult, HybridSearchConfig, create_vector_store
from .embedding_cache import EmbeddingCache, CachedEmbeddingGenerator

logger = logging.getLogger(__name__)


class GitIgnoreParser:
    """解析 .gitignore 文件"""

    def __init__(self, root_path: Path):
        self.root_path = root_path
        self.patterns: List[str] = []
        self._load_gitignore()

    def _load_gitignore(self) -> None:
        """加载 .gitignore 规则"""
        gitignore_path = self.root_path / ".gitignore"
        if gitignore_path.exists():
            with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.patterns.append(line)

        # 添加默认忽略
        default_ignores = [".git", "__pycache__", "*.pyc", ".DS_Store"]
        self.patterns.extend(default_ignores)

    def is_ignored(self, path: Path) -> bool:
        """检查路径是否应该被忽略"""
        rel_path = path.relative_to(self.root_path)
        path_str = str(rel_path).replace("\\", "/")

        for pattern in self.patterns:
            # 处理目录模式
            if pattern.endswith("/"):
                if fnmatch.fnmatch(path_str + "/", pattern) or \
                   fnmatch.fnmatch(path_str, pattern[:-1]):
                    return True
            # 处理 ** 模式
            elif "**" in pattern:
                if fnmatch.fnmatch(path_str, pattern):
                    return True
            else:
                # 检查路径的每个部分
                parts = path_str.split("/")
                for part in parts:
                    if fnmatch.fnmatch(part, pattern):
                        return True
                # 也检查完整路径
                if fnmatch.fnmatch(path_str, pattern):
                    return True

        return False


class FileTracker:
    """文件变更追踪器

    用于增量索引，追踪文件的修改时间和内容哈希
    """

    def __init__(self, db_path: str = ".audit_cache/file_tracker.db"):
        """初始化追踪器

        Args:
            db_path: SQLite 数据库路径
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        """初始化数据库 schema"""
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS file_index (
                file_path TEXT PRIMARY KEY,
                mtime REAL,
                content_hash TEXT,
                unit_ids TEXT,
                indexed_at REAL
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_mtime ON file_index(mtime)
        """)
        self._conn.commit()

    @staticmethod
    def compute_file_hash(file_path: Path) -> str:
        """计算文件内容哈希"""
        content = file_path.read_bytes()
        return hashlib.sha256(content).hexdigest()

    def get_file_state(self, file_path: str) -> Optional[Tuple[float, str]]:
        """获取文件的已记录状态

        Returns:
            (mtime, content_hash) 或 None
        """
        cursor = self._conn.execute(
            "SELECT mtime, content_hash FROM file_index WHERE file_path = ?",
            (file_path,)
        )
        row = cursor.fetchone()
        return (row[0], row[1]) if row else None

    def update_file_state(
        self,
        file_path: str,
        mtime: float,
        content_hash: str,
        unit_ids: List[str]
    ) -> None:
        """更新文件状态"""
        self._conn.execute("""
            INSERT OR REPLACE INTO file_index
            (file_path, mtime, content_hash, unit_ids, indexed_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            file_path,
            mtime,
            content_hash,
            ",".join(unit_ids),
            time.time()
        ))
        self._conn.commit()

    def get_unit_ids(self, file_path: str) -> List[str]:
        """获取文件关联的代码单元 ID 列表"""
        cursor = self._conn.execute(
            "SELECT unit_ids FROM file_index WHERE file_path = ?",
            (file_path,)
        )
        row = cursor.fetchone()
        if row and row[0]:
            return row[0].split(",")
        return []

    def remove_file(self, file_path: str) -> List[str]:
        """移除文件记录，返回其关联的代码单元 ID"""
        unit_ids = self.get_unit_ids(file_path)
        self._conn.execute(
            "DELETE FROM file_index WHERE file_path = ?",
            (file_path,)
        )
        self._conn.commit()
        return unit_ids

    def get_all_tracked_files(self) -> Set[str]:
        """获取所有已追踪的文件路径"""
        cursor = self._conn.execute("SELECT file_path FROM file_index")
        return {row[0] for row in cursor.fetchall()}

    def check_file_changed(self, file_path: Path) -> bool:
        """检查文件是否已变更

        Args:
            file_path: 文件路径

        Returns:
            True 如果文件是新的或已修改
        """
        if not file_path.exists():
            return False

        path_str = str(file_path)
        current_mtime = file_path.stat().st_mtime

        state = self.get_file_state(path_str)
        if state is None:
            # 新文件
            return True

        old_mtime, old_hash = state
        if current_mtime != old_mtime:
            # mtime 变了，检查内容是否真的变了
            current_hash = self.compute_file_hash(file_path)
            return current_hash != old_hash

        return False

    def get_stats(self) -> Dict[str, Any]:
        """获取追踪统计"""
        cursor = self._conn.execute("SELECT COUNT(*) FROM file_index")
        total = cursor.fetchone()[0]

        return {
            "tracked_files": total,
            "db_path": str(self.db_path),
        }

    def clear(self) -> None:
        """清空所有追踪记录"""
        self._conn.execute("DELETE FROM file_index")
        self._conn.commit()

    def close(self) -> None:
        """关闭数据库连接"""
        if self._conn:
            self._conn.close()
            self._conn = None


class CodeIndexer:
    """代码索引器

    负责：
    1. 遍历目标目录
    2. 解析代码文件
    3. 生成嵌入向量 (带缓存)
    4. 存储到向量数据库
    5. 支持 Hybrid 混合检索
    6. 增量索引 (仅处理变更文件)
    """

    def __init__(
        self,
        config: AuditConfig,
        llm_client: BaseLLMClient,
        vector_store: Optional[BaseVectorStore] = None,
        embedding_cache: Optional[EmbeddingCache] = None,
        file_tracker: Optional[FileTracker] = None
    ):
        self.config = config
        self.scan_config = config.scan
        self.llm_client = llm_client
        self.vector_store = vector_store or create_vector_store(
            config.vector_store,
            embedding_dim=config.llm.embedding_dim
        )
        # 当前索引的目标路径（在 index_directory 时更新）
        self._current_target_path: Optional[Path] = None

        # 初始化嵌入缓存
        if config.vector_store.enable_cache:
            self.embedding_cache = embedding_cache or EmbeddingCache(
                cache_dir=config.vector_store.cache_dir,
                ttl_days=config.vector_store.cache_ttl_days
            )
            self.cached_generator = CachedEmbeddingGenerator(
                llm_client=llm_client,
                cache=self.embedding_cache
            )
        else:
            self.embedding_cache = None
            self.cached_generator = None

        # 初始化文件追踪器 (增量索引)
        tracker_path = f"{config.vector_store.cache_dir}/file_tracker.db"
        self.file_tracker = file_tracker or FileTracker(db_path=tracker_path)

        # Hybrid 检索配置 (包含重排序)
        from .vector_store import RerankerConfig
        reranker_config = None
        if getattr(config.scan, 'enable_reranking', True):
            reranker_config = RerankerConfig(
                enable_reranking=True,
                security_priority_mode=getattr(config.scan, 'rerank_security_priority', True),
                security_boost_factor=getattr(config.scan, 'rerank_security_boost', 1.5),
                prefer_entry_points=getattr(config.scan, 'rerank_prefer_entry_points', True),
            )

        self.hybrid_config = HybridSearchConfig(
            enable_keyword_boost=config.scan.enable_hybrid_search,
            keyword_boost_weight=config.scan.keyword_boost,
            metadata_filter_first=config.scan.metadata_filter_first,
            reranker_config=reranker_config
        )

        # 初始化向量存储
        self.vector_store.initialize()

    @property
    def code_units(self) -> Dict[str, 'CodeUnit']:
        """获取所有已索引的代码单元（字典格式）

        Returns:
            Dict[str, CodeUnit]: 以 unit.id 为键的代码单元字典
        """
        all_units = self.vector_store.get_all(limit=100000)
        return {unit.id: unit for unit in all_units}

    def _should_include(self, file_path: Path, gitignore: GitIgnoreParser) -> bool:
        """检查文件是否应该被索引"""
        # 检查 gitignore
        if gitignore.is_ignored(file_path):
            return False

        # 检查排除模式
        rel_path = str(file_path).replace("\\", "/")
        for pattern in self.scan_config.exclude_patterns:
            # 支持 ** 模式
            if "**" in pattern:
                # 对于 **/ 开头的模式，匹配任何目录
                if pattern.startswith("**/"):
                    # 检查文件名或路径的任意后缀是否匹配
                    suffix_pattern = pattern[3:]  # 去掉 **/
                    if fnmatch.fnmatch(file_path.name, suffix_pattern):
                        return False
                    # 也检查完整路径的各个部分
                    parts = rel_path.split("/")
                    for i in range(len(parts)):
                        sub_path = "/".join(parts[i:])
                        if fnmatch.fnmatch(sub_path, suffix_pattern):
                            return False
                elif fnmatch.fnmatch(rel_path, pattern.replace("**", "*")):
                    return False
            elif fnmatch.fnmatch(rel_path, pattern):
                return False

        # 检查包含模式
        for pattern in self.scan_config.include_patterns:
            # 支持 ** 模式
            if "**" in pattern:
                if pattern.startswith("**/"):
                    suffix_pattern = pattern[3:]  # 去掉 **/
                    # 检查文件名是否匹配
                    if fnmatch.fnmatch(file_path.name, suffix_pattern):
                        return True
                    # 也检查完整路径的各个部分
                    parts = rel_path.split("/")
                    for i in range(len(parts)):
                        sub_path = "/".join(parts[i:])
                        if fnmatch.fnmatch(sub_path, suffix_pattern):
                            return True
                elif fnmatch.fnmatch(rel_path, pattern.replace("**", "*")):
                    return True
            elif fnmatch.fnmatch(rel_path, pattern):
                return True
            # 也直接检查文件扩展名（作为后备）
            elif pattern.startswith("*.") or pattern.startswith("**/*."):
                ext_pattern = pattern.split("*")[-1]  # 获取 .php 这样的扩展名
                if file_path.suffix == ext_pattern:
                    return True

        return False

    def _scan_files(self, root_path: Path) -> Iterator[Path]:
        """扫描目录，返回需要索引的文件"""
        gitignore = GitIgnoreParser(root_path)
        total_files = 0
        included_files = 0
        excluded_files = 0
        excluded_examples = []

        for path in root_path.rglob("*"):
            if path.is_file():
                total_files += 1
                if self._should_include(path, gitignore):
                    # 检查文件大小
                    size_kb = path.stat().st_size / 1024
                    if size_kb <= self.scan_config.max_file_size_kb:
                        included_files += 1
                        yield path
                    else:
                        logger.debug(f"Skipping large file: {path} ({size_kb:.1f}KB)")
                        excluded_files += 1
                else:
                    excluded_files += 1
                    if len(excluded_examples) < 5:
                        excluded_examples.append(str(path))
                    logger.debug(f"Excluded file: {path}")

        logger.info(
            "[SCAN] 文件扫描完成: 总计 %s, 包含 %s, 排除 %s",
            total_files,
            included_files,
            excluded_files,
        )
        if excluded_examples:
            logger.debug("[SCAN] 排除示例: %s", excluded_examples)

    def _parse_file(self, file_path: Path, root_path: Path) -> List[CodeUnit]:
        """解析单个文件"""
        parser = get_parser_for_file(str(file_path))
        if not parser:
            logger.debug("[PARSE] 没有找到解析器: %s", file_path)
            return []

        logger.debug(
            "[PARSE] 使用解析器 %s 解析: %s",
            parser.__class__.__name__,
            file_path,
        )

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            logger.debug("[PARSE] 文件内容长度: %s 字符", len(content))

            rel_path = str(file_path.relative_to(root_path)).replace("\\", "/")
            units = parser.parse_file(rel_path, content)
            logger.debug("[PARSE] 解析结果: %s 个代码单元", len(units))

            if units and logger.isEnabledFor(logging.DEBUG):
                for u in units[:3]:
                    logger.debug("[PARSE]   - %s: %s", u.unit_type.value, u.symbol)

            return units
        except Exception:
            logger.exception("[PARSE] 解析失败: %s", file_path)
            return []

    def _chunk_units(self, units: List[CodeUnit], max_tokens: int = 2000) -> List[CodeUnit]:
        """将大代码单元分块

        估算：平均每个字符约 0.25 token（英文），中文约 0.5 token
        """
        result = []

        for unit in units:
            # 估算 token 数
            estimated_tokens = len(unit.code) * 0.3

            if estimated_tokens <= max_tokens:
                result.append(unit)
            else:
                # 需要分块
                chunk_size = int(max_tokens / 0.3)  # 字符数
                code = unit.code
                chunks = []

                # 尝试按行分割
                lines = code.split("\n")
                current_chunk = []
                current_size = 0

                for line in lines:
                    line_size = len(line) + 1  # +1 for newline
                    if current_size + line_size > chunk_size and current_chunk:
                        chunks.append("\n".join(current_chunk))
                        current_chunk = [line]
                        current_size = line_size
                    else:
                        current_chunk.append(line)
                        current_size += line_size

                if current_chunk:
                    chunks.append("\n".join(current_chunk))

                # 创建分块的 CodeUnit
                for i, chunk_code in enumerate(chunks):
                    chunked_unit = CodeUnit(
                        id=f"{unit.id}_chunk{i}",
                        language=unit.language,
                        file_path=unit.file_path,
                        symbol=unit.symbol,
                        unit_type=unit.unit_type,
                        signature=unit.signature,
                        span=unit.span,
                        code=chunk_code,
                        docstring=unit.docstring if i == 0 else None,
                        calls=unit.calls if i == 0 else [],
                        parent_class=unit.parent_class,
                        decorators=unit.decorators if i == 0 else [],
                        imports=unit.imports if i == 0 else [],
                        metadata=unit.metadata,
                        chunk_index=i,
                        total_chunks=len(chunks),
                    )
                    result.append(chunked_unit)

        return result

    def _generate_embeddings(
        self,
        units: List[CodeUnit],
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> List[List[float]]:
        """生成嵌入向量 (带缓存支持)

        Args:
            units: 代码单元列表
            progress_callback: 进度回调 (current, total, message)

        Returns:
            嵌入向量列表
        """
        texts = [unit.to_embedding_text() for unit in units]
        total = len(texts)

        if progress_callback:
            progress_callback(0, total, "准备生成嵌入向量...")

        # 使用缓存生成器
        if self.cached_generator:
            logger.info("Using cached embedding generator...")
            embeddings = self.cached_generator.generate_embeddings(texts)
            if progress_callback:
                progress_callback(total, total, "嵌入向量生成完成")
            return embeddings

        # 无缓存时直接计算（带进度）
        batch_size = 50
        all_embeddings = []

        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i + batch_size]
            response = self.llm_client.embed(batch_texts)
            all_embeddings.extend(response.embeddings)

            if progress_callback:
                processed = min(i + batch_size, total)
                progress_callback(processed, total, f"生成嵌入: {processed}/{total}")

        return all_embeddings

    def index_directory(
        self,
        target_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> int:
        """索引目录

        Args:
            target_path: 目标路径，默认使用配置中的路径
            progress_callback: 进度回调函数 (current, total)

        Returns:
            索引的代码单元数量
        """
        path = Path(target_path or self.scan_config.target_path).resolve()

        if not path.exists():
            raise FileNotFoundError(f"目标路径不存在: {path}")

        # 更新当前目标路径
        self._current_target_path = path

        logger.info(f"Starting index of: {path}")

        # 收集所有文件
        files = list(self._scan_files(path))
        logger.info(f"Found {len(files)} files to index")

        if not files:
            return 0

        # 解析所有文件
        all_units: List[CodeUnit] = []
        total_files = len(files)

        # 使用线程池并行解析
        with ThreadPoolExecutor(max_workers=self.scan_config.max_concurrent) as executor:
            futures = {
                executor.submit(self._parse_file, f, path): f
                for f in files
            }

            for i, future in enumerate(as_completed(futures)):
                units = future.result()
                all_units.extend(units)

                if progress_callback:
                    progress_callback(i + 1, total_files)

        logger.info(f"Parsed {len(all_units)} code units")

        if not all_units:
            return 0

        # 分块处理大代码单元
        chunked_units = self._chunk_units(all_units, self.scan_config.chunk_size)
        logger.info(f"After chunking: {len(chunked_units)} units")

        # 生成嵌入并存储
        logger.info("Generating embeddings...")
        embeddings = self._generate_embeddings(chunked_units)

        logger.info("Storing to vector database...")
        self.vector_store.add(chunked_units, embeddings)

        total_count = self.vector_store.count()
        logger.info(f"Index complete. Total units in store: {total_count}")

        return len(chunked_units)

    def index_directory_incremental(
        self,
        target_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, int]:
        """增量索引目录

        仅处理新增或修改的文件，删除已移除文件的索引。

        Args:
            target_path: 目标路径，默认使用配置中的路径
            progress_callback: 进度回调函数 (current, total)

        Returns:
            包含索引统计的字典:
            - added: 新增的代码单元数
            - updated: 更新的代码单元数
            - deleted: 删除的代码单元数
            - unchanged: 未变更的文件数
        """
        path = Path(target_path or self.scan_config.target_path).resolve()

        if not path.exists():
            raise FileNotFoundError(f"目标路径不存在: {path}")

        # 更新当前目标路径
        self._current_target_path = path

        logger.info(f"Starting incremental index of: {path}")

        stats = {
            "added": 0,
            "updated": 0,
            "deleted": 0,
            "unchanged": 0,
        }

        # 收集当前所有文件
        current_files = list(self._scan_files(path))
        current_file_paths = {str(f) for f in current_files}
        logger.info(f"Found {len(current_files)} files in directory")

        # 获取已追踪的文件
        tracked_files = self.file_tracker.get_all_tracked_files()

        # 1. 找出已删除的文件
        deleted_files = tracked_files - current_file_paths
        for deleted_file in deleted_files:
            unit_ids = self.file_tracker.remove_file(deleted_file)
            if unit_ids:
                # 从向量存储中删除
                for unit_id in unit_ids:
                    try:
                        self.vector_store.delete(unit_id)
                        stats["deleted"] += 1
                    except Exception as e:
                        logger.warning(f"Failed to delete unit {unit_id}: {e}")
            logger.debug(f"Removed deleted file from index: {deleted_file}")

        # 2. 找出新增或修改的文件
        files_to_process = []
        for file_path in current_files:
            if self.file_tracker.check_file_changed(file_path):
                files_to_process.append(file_path)
            else:
                stats["unchanged"] += 1

        logger.info(f"Files to process: {len(files_to_process)} (unchanged: {stats['unchanged']})")

        if not files_to_process:
            logger.info("No files changed, index is up to date")
            return stats

        # 3. 处理变更的文件
        total_files = len(files_to_process)

        with ThreadPoolExecutor(max_workers=self.scan_config.max_concurrent) as executor:
            futures = {
                executor.submit(self._process_file_incremental, f, path): f
                for f in files_to_process
            }

            for i, future in enumerate(as_completed(futures)):
                file_path = futures[future]
                try:
                    result = future.result()
                    if result["is_new"]:
                        stats["added"] += result["units_count"]
                    else:
                        stats["updated"] += result["units_count"]
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")

                if progress_callback:
                    progress_callback(i + 1, total_files)

        total_count = self.vector_store.count()
        logger.info(f"Incremental index complete. Total units: {total_count}, Stats: {stats}")

        return stats

    def _process_file_incremental(self, file_path: Path, root_path: Path) -> Dict[str, Any]:
        """增量处理单个文件

        Args:
            file_path: 文件路径
            root_path: 根目录路径

        Returns:
            处理结果字典
        """
        path_str = str(file_path)
        is_new = self.file_tracker.get_file_state(path_str) is None

        # 如果文件已存在，先删除旧的代码单元
        if not is_new:
            old_unit_ids = self.file_tracker.get_unit_ids(path_str)
            for unit_id in old_unit_ids:
                try:
                    self.vector_store.delete(unit_id)
                except Exception as e:
                    logger.warning(f"Failed to delete old unit {unit_id}: {e}")

        # 解析文件
        units = self._parse_file(file_path, root_path)

        if not units:
            # 如果解析结果为空，清除追踪记录
            self.file_tracker.remove_file(path_str)
            return {"is_new": is_new, "units_count": 0}

        # 分块处理
        chunked_units = self._chunk_units(units, self.scan_config.chunk_size)

        # 生成嵌入并存储
        embeddings = self._generate_embeddings(chunked_units)
        self.vector_store.add(chunked_units, embeddings)

        # 更新文件追踪
        unit_ids = [u.id for u in chunked_units]
        mtime = file_path.stat().st_mtime
        content_hash = FileTracker.compute_file_hash(file_path)
        self.file_tracker.update_file_state(path_str, mtime, content_hash, unit_ids)

        return {"is_new": is_new, "units_count": len(chunked_units)}

    def search(
        self,
        query: str,
        top_k: int = 10,
        language: Optional[str] = None,
        file_pattern: Optional[str] = None,
        use_hybrid: Optional[bool] = None,
    ) -> List[CodeUnit]:
        """搜索相关代码

        Args:
            query: 搜索查询
            top_k: 返回数量
            language: 过滤语言
            file_pattern: 文件路径模式
            use_hybrid: 是否使用混合检索 (默认根据配置)

        Returns:
            相关的 CodeUnit 列表
        """
        # 生成查询嵌入
        response = self.llm_client.embed([query])
        query_embedding = response.embeddings[0]

        # 构建过滤器
        filters = {}
        if language:
            filters["language"] = language

        # 决定是否使用混合检索
        enable_hybrid = use_hybrid if use_hybrid is not None else self.hybrid_config.enable_keyword_boost

        if enable_hybrid:
            # 使用混合检索
            results = self.vector_store.hybrid_search(
                query_embedding=query_embedding,
                query_text=query,
                top_k=top_k,
                filters=filters if filters else None,
                hybrid_config=self.hybrid_config
            )
        else:
            # 仅向量检索
            results = self.vector_store.search(
                query_embedding=query_embedding,
                top_k=top_k,
                filters=filters if filters else None,
            )

        # 应用文件模式过滤
        if file_pattern:
            results = [
                r for r in results
                if fnmatch.fnmatch(r.code_unit.file_path, file_pattern)
            ]

        return [r.code_unit for r in results]

    def search_with_scores(
        self,
        query: str,
        top_k: int = 10,
        language: Optional[str] = None,
        use_hybrid: Optional[bool] = None,
    ) -> List[SearchResult]:
        """搜索相关代码并返回分数

        Args:
            query: 搜索查询
            top_k: 返回数量
            language: 过滤语言
            use_hybrid: 是否使用混合检索

        Returns:
            SearchResult 列表 (包含分数)
        """
        response = self.llm_client.embed([query])
        query_embedding = response.embeddings[0]

        filters = {}
        if language:
            filters["language"] = language

        enable_hybrid = use_hybrid if use_hybrid is not None else self.hybrid_config.enable_keyword_boost

        if enable_hybrid:
            return self.vector_store.hybrid_search(
                query_embedding=query_embedding,
                query_text=query,
                top_k=top_k,
                filters=filters if filters else None,
                hybrid_config=self.hybrid_config
            )
        else:
            return self.vector_store.search(
                query_embedding=query_embedding,
                top_k=top_k,
                filters=filters if filters else None,
            )

    def get_unit(self, unit_id: str) -> Optional[CodeUnit]:
        """获取指定的代码单元"""
        return self.vector_store.get_by_id(unit_id)

    def clear_index(self) -> None:
        """清空索引"""
        self.vector_store.clear()
        logger.info("Index cleared")

    def get_stats(self) -> dict:
        """获取索引统计信息"""
        stats = {
            "total_units": self.vector_store.count(),
            "collection_name": self.config.vector_store.collection_name,
            "hybrid_search_enabled": self.hybrid_config.enable_keyword_boost,
        }

        # 添加缓存统计
        if self.cached_generator:
            stats["cache"] = self.cached_generator.get_stats()

        return stats

    def cleanup_cache(self) -> int:
        """清理过期的嵌入缓存

        Returns:
            清理的条目数
        """
        if self.embedding_cache:
            return self.embedding_cache.cleanup_expired()
        return 0

    def get_current_target_path(self) -> Optional[Path]:
        """获取当前索引的目标路径

        Returns:
            当前索引路径，如果未索引则返回 None
        """
        return self._current_target_path

    def set_target_path(self, target_path: str) -> None:
        """设置当前目标路径（不执行索引）

        用于在不重新索引的情况下更新目标路径。

        Args:
            target_path: 目标路径
        """
        path = Path(target_path).resolve()
        if path.exists():
            self._current_target_path = path
            logger.info(f"已设置目标路径: {path}")
        else:
            logger.warning(f"目标路径不存在: {path}")

    def get_all_units(self, limit: int = 10000) -> List[CodeUnit]:
        """获取所有代码单元

        Args:
            limit: 最大返回数量

        Returns:
            CodeUnit 列表
        """
        return self.vector_store.get_all(limit=limit)

    def get_units_by_language(self, language: str, limit: int = 1000) -> List[CodeUnit]:
        """按语言获取代码单元

        Args:
            language: 语言类型 (python, javascript, php 等)
            limit: 最大返回数量

        Returns:
            CodeUnit 列表
        """
        return self.vector_store.get_by_filter({"language": language}, limit=limit)

    def get_units_by_file(self, file_path: str) -> List[CodeUnit]:
        """按文件路径获取代码单元

        Args:
            file_path: 文件路径（支持部分匹配）

        Returns:
            CodeUnit 列表
        """
        all_units = self.get_all_units()
        return [u for u in all_units if file_path in u.file_path]

    def read_file(
        self,
        file_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None
    ) -> Optional[str]:
        """读取文件内容（支持行号范围）

        Args:
            file_path: 文件路径（相对或绝对）
            start_line: 起始行号（从1开始，可选）
            end_line: 结束行号（包含，可选）

        Returns:
            文件内容字符串，如果文件不存在返回 None
        """
        try:
            # 优先使用当前索引路径，其次使用配置路径
            base_path = self._current_target_path or Path(self.scan_config.target_path)

            # 尝试作为相对路径处理
            target_path = base_path / file_path
            if not target_path.exists():
                # 尝试作为绝对路径
                target_path = Path(file_path)
                if not target_path.exists():
                    return None

            content = target_path.read_text(encoding='utf-8', errors='ignore')

            # 如果指定了行号范围，提取对应行
            if start_line is not None or end_line is not None:
                lines = content.splitlines()
                start = (start_line - 1) if start_line else 0
                end = end_line if end_line else len(lines)
                content = '\n'.join(lines[start:end])

            return content

        except Exception as e:
            logger.error(f"读取文件失败 {file_path}: {e}")
            return None

    def list_files(
        self,
        pattern: str = "**/*",
        max_results: int = 100
    ) -> List[str]:
        """列出匹配模式的文件

        Args:
            pattern: Glob 模式（如 "**/*.py", "src/**/*"）
            max_results: 最大返回数量

        Returns:
            文件路径列表（相对于 target_path）
        """
        try:
            # 优先使用当前索引路径，其次使用配置路径
            root_path = self._current_target_path or Path(self.scan_config.target_path).resolve()
            if not root_path.exists():
                return []

            files = []
            gitignore = GitIgnoreParser(root_path)

            # 使用 glob 查找匹配的文件
            for file_path in root_path.glob(pattern):
                if not file_path.is_file():
                    continue

                # 应用 include/exclude 过滤
                if not self._should_include(file_path, gitignore):
                    continue

                # 转换为相对路径
                rel_path = str(file_path.relative_to(root_path)).replace("\\", "/")
                files.append(rel_path)

                if len(files) >= max_results:
                    break

            return files

        except Exception as e:
            logger.error(f"列出文件失败 (pattern={pattern}): {e}")
            return []

    def parse_directory_without_index(self, directory: str, languages: Optional[List[str]] = None) -> List[CodeUnit]:
        """直接解析目录中的代码文件，不使用向量索引

        适用于小项目，跳过嵌入向量的生成和存储。

        Args:
            directory: 目标目录路径
            languages: 限定的语言列表（可选）

        Returns:
            CodeUnit 列表
        """
        root_path = Path(directory).resolve()
        if not root_path.exists():
            raise ValueError(f"目录不存在: {directory}")

        logger.info(f"直接解析目录（跳过索引）: {root_path}")
        logger.info(f"包含模式: {self.scan_config.include_patterns}")
        logger.info(f"排除模式: {self.scan_config.exclude_patterns}")
        logger.info(f"语言过滤: {languages}")

        all_units = []
        file_count = 0
        scanned_files = []

        for file_path in self._scan_files(root_path):
            scanned_files.append(str(file_path))
            units = self._parse_file(file_path, root_path)
            if units:
                # 如果指定了语言，过滤
                if languages:
                    units = [u for u in units if u.language in languages]
                all_units.extend(units)
                file_count += 1

        logger.info(f"扫描到的文件: {scanned_files[:10]}{'...' if len(scanned_files) > 10 else ''}")
        logger.info(f"扫描文件总数: {len(scanned_files)}")

        # 分块处理
        all_units = self._chunk_units(all_units, self.scan_config.chunk_size)

        logger.info(f"直接解析完成: {file_count} 个文件, {len(all_units)} 个代码单元")
        return all_units
