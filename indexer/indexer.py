"""
代码索引器 - 遍历、解析、向量化代码

支持:
- 多语言代码解析
- 嵌入缓存 (基于内容哈希)
- Hybrid 混合检索
- 增量索引
"""

import fnmatch
import logging
from pathlib import Path
from typing import List, Optional, Set, Iterator, Callable, Dict, Any
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


class CodeIndexer:
    """代码索引器

    负责：
    1. 遍历目标目录
    2. 解析代码文件
    3. 生成嵌入向量 (带缓存)
    4. 存储到向量数据库
    5. 支持 Hybrid 混合检索
    """

    def __init__(
        self,
        config: AuditConfig,
        llm_client: BaseLLMClient,
        vector_store: Optional[BaseVectorStore] = None,
        embedding_cache: Optional[EmbeddingCache] = None
    ):
        self.config = config
        self.scan_config = config.scan
        self.llm_client = llm_client
        self.vector_store = vector_store or create_vector_store(config.vector_store)

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

        # Hybrid 检索配置
        self.hybrid_config = HybridSearchConfig(
            enable_keyword_boost=config.scan.enable_hybrid_search,
            keyword_boost_weight=config.scan.keyword_boost,
            metadata_filter_first=config.scan.metadata_filter_first
        )

        # 初始化向量存储
        self.vector_store.initialize()

    def _should_include(self, file_path: Path, gitignore: GitIgnoreParser) -> bool:
        """检查文件是否应该被索引"""
        # 检查 gitignore
        if gitignore.is_ignored(file_path):
            return False

        # 检查排除模式
        rel_path = str(file_path).replace("\\", "/")
        for pattern in self.scan_config.exclude_patterns:
            if fnmatch.fnmatch(rel_path, pattern):
                return False

        # 检查包含模式
        for pattern in self.scan_config.include_patterns:
            if fnmatch.fnmatch(rel_path, pattern):
                return True

        return False

    def _scan_files(self, root_path: Path) -> Iterator[Path]:
        """扫描目录，返回需要索引的文件"""
        gitignore = GitIgnoreParser(root_path)

        for path in root_path.rglob("*"):
            if path.is_file():
                if self._should_include(path, gitignore):
                    # 检查文件大小
                    size_kb = path.stat().st_size / 1024
                    if size_kb <= self.scan_config.max_file_size_kb:
                        yield path
                    else:
                        logger.debug(f"Skipping large file: {path} ({size_kb:.1f}KB)")

    def _parse_file(self, file_path: Path, root_path: Path) -> List[CodeUnit]:
        """解析单个文件"""
        parser = get_parser_for_file(str(file_path))
        if not parser:
            logger.debug(f"No parser for: {file_path}")
            return []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            rel_path = str(file_path.relative_to(root_path)).replace("\\", "/")
            units = parser.parse_file(rel_path, content)
            logger.debug(f"Parsed {len(units)} units from {rel_path}")
            return units
        except Exception as e:
            logger.warning(f"Failed to parse {file_path}: {e}")
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

    def _generate_embeddings(self, units: List[CodeUnit]) -> List[List[float]]:
        """生成嵌入向量 (带缓存支持)"""
        texts = [unit.to_embedding_text() for unit in units]

        # 使用缓存生成器
        if self.cached_generator:
            logger.info("Using cached embedding generator...")
            return self.cached_generator.generate_embeddings(texts)

        # 无缓存时直接计算
        batch_size = 50
        all_embeddings = []

        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i + batch_size]
            response = self.llm_client.embed(batch_texts)
            all_embeddings.extend(response.embeddings)

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
