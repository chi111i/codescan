"""
Tree-sitter 解析性能优化模块

提供：
- 解析器实例池化
- 增量解析支持
- 并行解析
- 解析结果缓存
- 性能监控
"""

import logging
import time
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable, Tuple
from collections import OrderedDict

logger = logging.getLogger(__name__)

try:
    from tree_sitter import Parser, Language, Tree
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Parser = None
    Language = None
    Tree = None


@dataclass
class ParseStats:
    """解析统计信息"""
    total_files: int = 0
    total_time_ms: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    parse_errors: int = 0
    incremental_parses: int = 0

    @property
    def avg_time_ms(self) -> float:
        return self.total_time_ms / self.total_files if self.total_files > 0 else 0.0

    @property
    def cache_hit_rate(self) -> float:
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_files": self.total_files,
            "total_time_ms": round(self.total_time_ms, 2),
            "avg_time_ms": round(self.avg_time_ms, 2),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": round(self.cache_hit_rate * 100, 1),
            "parse_errors": self.parse_errors,
            "incremental_parses": self.incremental_parses,
        }


class ParserPool:
    """解析器实例池

    为每种语言维护解析器实例池，避免重复创建。
    线程安全。
    """

    def __init__(self, pool_size: int = 4):
        self.pool_size = pool_size
        self._pools: Dict[str, List['Parser']] = {}
        self._locks: Dict[str, threading.Lock] = {}
        self._global_lock = threading.Lock()

    def get_parser(self, language: str, language_obj: 'Language') -> 'Parser':
        """获取解析器实例"""
        if not TREE_SITTER_AVAILABLE:
            raise RuntimeError("tree-sitter not available")

        with self._global_lock:
            if language not in self._pools:
                self._pools[language] = []
                self._locks[language] = threading.Lock()

        with self._locks[language]:
            pool = self._pools[language]
            if pool:
                return pool.pop()
            else:
                parser = Parser()
                parser.language = language_obj
                return parser

    def return_parser(self, language: str, parser: 'Parser'):
        """归还解析器实例"""
        with self._locks.get(language, self._global_lock):
            pool = self._pools.get(language, [])
            if len(pool) < self.pool_size:
                pool.append(parser)
                self._pools[language] = pool

    def clear(self):
        """清空所有池"""
        with self._global_lock:
            self._pools.clear()


class ParseCache:
    """解析结果缓存

    基于文件内容哈希的 LRU 缓存。
    """

    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._cache: OrderedDict[str, Tuple['Tree', float]] = OrderedDict()
        self._lock = threading.Lock()

    def _compute_key(self, content: bytes, language: str) -> str:
        """计算缓存键"""
        content_hash = hashlib.md5(content).hexdigest()
        return f"{language}:{content_hash}"

    def get(self, content: bytes, language: str) -> Optional['Tree']:
        """获取缓存的解析树"""
        key = self._compute_key(content, language)
        with self._lock:
            if key in self._cache:
                tree, _ = self._cache[key]
                # 移动到末尾（最近使用）
                self._cache.move_to_end(key)
                return tree
        return None

    def put(self, content: bytes, language: str, tree: 'Tree'):
        """缓存解析树"""
        key = self._compute_key(content, language)
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            else:
                self._cache[key] = (tree, time.time())
                # LRU 淘汰
                while len(self._cache) > self.max_size:
                    self._cache.popitem(last=False)

    def invalidate(self, content: bytes, language: str):
        """使缓存失效"""
        key = self._compute_key(content, language)
        with self._lock:
            self._cache.pop(key, None)

    def clear(self):
        """清空缓存"""
        with self._lock:
            self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)


class IncrementalParser:
    """增量解析器

    支持对文件的增量修改进行高效解析。
    """

    def __init__(self):
        self._trees: Dict[str, 'Tree'] = {}
        self._contents: Dict[str, bytes] = {}
        self._lock = threading.Lock()

    def parse(
        self,
        parser: 'Parser',
        content: bytes,
        file_path: str,
    ) -> Tuple['Tree', bool]:
        """解析文件，支持增量更新

        Returns:
            (tree, is_incremental): 解析树和是否使用了增量解析
        """
        with self._lock:
            old_tree = self._trees.get(file_path)
            old_content = self._contents.get(file_path)

        is_incremental = False

        if old_tree and old_content:
            # 计算编辑差异
            edits = self._compute_edits(old_content, content)
            if edits:
                # 应用编辑到旧树
                for edit in edits:
                    old_tree.edit(
                        start_byte=edit["start_byte"],
                        old_end_byte=edit["old_end_byte"],
                        new_end_byte=edit["new_end_byte"],
                        start_point=edit["start_point"],
                        old_end_point=edit["old_end_point"],
                        new_end_point=edit["new_end_point"],
                    )
                is_incremental = True

        # 解析（增量或全量）
        tree = parser.parse(content, old_tree if is_incremental else None)

        # 更新缓存
        with self._lock:
            self._trees[file_path] = tree
            self._contents[file_path] = content

        return tree, is_incremental

    def _compute_edits(
        self,
        old_content: bytes,
        new_content: bytes,
    ) -> List[Dict[str, Any]]:
        """计算内容差异

        简化实现：只处理追加和替换的情况
        """
        if old_content == new_content:
            return []

        # 找到第一个不同的位置
        min_len = min(len(old_content), len(new_content))
        start_byte = 0
        for i in range(min_len):
            if old_content[i] != new_content[i]:
                start_byte = i
                break
        else:
            start_byte = min_len

        # 计算行列位置
        start_point = self._byte_to_point(old_content, start_byte)
        old_end_point = self._byte_to_point(old_content, len(old_content))
        new_end_point = self._byte_to_point(new_content, len(new_content))

        return [{
            "start_byte": start_byte,
            "old_end_byte": len(old_content),
            "new_end_byte": len(new_content),
            "start_point": start_point,
            "old_end_point": old_end_point,
            "new_end_point": new_end_point,
        }]

    def _byte_to_point(self, content: bytes, byte_offset: int) -> Tuple[int, int]:
        """将字节偏移转换为 (行, 列)"""
        text = content[:byte_offset].decode("utf-8", errors="replace")
        lines = text.split("\n")
        row = len(lines) - 1
        col = len(lines[-1]) if lines else 0
        return (row, col)

    def invalidate(self, file_path: str):
        """使文件缓存失效"""
        with self._lock:
            self._trees.pop(file_path, None)
            self._contents.pop(file_path, None)

    def clear(self):
        """清空所有缓存"""
        with self._lock:
            self._trees.clear()
            self._contents.clear()


class ParallelParser:
    """并行解析器

    使用线程池并行解析多个文件。
    """

    def __init__(
        self,
        max_workers: int = 4,
        parser_pool: Optional[ParserPool] = None,
        cache: Optional[ParseCache] = None,
    ):
        self.max_workers = max_workers
        self.parser_pool = parser_pool or ParserPool()
        self.cache = cache or ParseCache()
        self.stats = ParseStats()

    def parse_files(
        self,
        files: List[Tuple[str, bytes, str]],  # (path, content, language)
        language_loader: Callable[[str], Optional['Language']],
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, 'Tree']:
        """并行解析多个文件

        Args:
            files: 文件列表 [(路径, 内容, 语言), ...]
            language_loader: 语言加载函数
            progress_callback: 进度回调 (completed, total)

        Returns:
            {路径: 解析树} 字典
        """
        results: Dict[str, 'Tree'] = {}
        total = len(files)
        completed = 0
        lock = threading.Lock()

        def parse_one(file_info: Tuple[str, bytes, str]) -> Tuple[str, Optional['Tree']]:
            nonlocal completed
            path, content, language = file_info

            start_time = time.time()
            tree = None

            try:
                # 检查缓存
                tree = self.cache.get(content, language)
                if tree:
                    with lock:
                        self.stats.cache_hits += 1
                    return path, tree

                with lock:
                    self.stats.cache_misses += 1

                # 加载语言
                lang_obj = language_loader(language)
                if not lang_obj:
                    return path, None

                # 获取解析器
                parser = self.parser_pool.get_parser(language, lang_obj)

                try:
                    tree = parser.parse(content)
                    self.cache.put(content, language, tree)
                finally:
                    self.parser_pool.return_parser(language, parser)

            except Exception as e:
                logger.warning(f"Failed to parse {path}: {e}")
                with lock:
                    self.stats.parse_errors += 1

            finally:
                elapsed = (time.time() - start_time) * 1000
                with lock:
                    self.stats.total_files += 1
                    self.stats.total_time_ms += elapsed
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total)

            return path, tree

        # 并行执行
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(parse_one, f): f for f in files}
            for future in as_completed(futures):
                path, tree = future.result()
                if tree:
                    results[path] = tree

        return results

    def reset_stats(self):
        """重置统计信息"""
        self.stats = ParseStats()


class OptimizedTreeSitterParser:
    """优化后的 Tree-sitter 解析器

    整合所有优化特性。
    """

    def __init__(
        self,
        pool_size: int = 4,
        cache_size: int = 1000,
        max_workers: int = 4,
        enable_incremental: bool = True,
    ):
        self.parser_pool = ParserPool(pool_size)
        self.cache = ParseCache(cache_size)
        self.parallel_parser = ParallelParser(
            max_workers=max_workers,
            parser_pool=self.parser_pool,
            cache=self.cache,
        )
        self.incremental_parser = IncrementalParser() if enable_incremental else None
        self._language_cache: Dict[str, 'Language'] = {}

    def parse(
        self,
        content: bytes,
        language: str,
        file_path: Optional[str] = None,
        language_loader: Optional[Callable[[str], Optional['Language']]] = None,
    ) -> Optional['Tree']:
        """解析单个文件"""
        # 检查缓存
        tree = self.cache.get(content, language)
        if tree:
            return tree

        # 加载语言
        if language not in self._language_cache:
            if language_loader:
                lang_obj = language_loader(language)
            else:
                from .loader import LanguageLoader
                lang_obj = LanguageLoader.load(language)

            if lang_obj:
                self._language_cache[language] = lang_obj

        lang_obj = self._language_cache.get(language)
        if not lang_obj:
            return None

        # 获取解析器
        parser = self.parser_pool.get_parser(language, lang_obj)

        try:
            # 增量解析
            if self.incremental_parser and file_path:
                tree, is_incremental = self.incremental_parser.parse(
                    parser, content, file_path
                )
                if is_incremental:
                    self.parallel_parser.stats.incremental_parses += 1
            else:
                tree = parser.parse(content)

            # 缓存结果
            self.cache.put(content, language, tree)
            return tree

        finally:
            self.parser_pool.return_parser(language, parser)

    def parse_batch(
        self,
        files: List[Tuple[str, bytes, str]],
        language_loader: Optional[Callable[[str], Optional['Language']]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, 'Tree']:
        """批量并行解析"""
        def loader(lang: str) -> Optional['Language']:
            if lang in self._language_cache:
                return self._language_cache[lang]

            if language_loader:
                lang_obj = language_loader(lang)
            else:
                from .loader import LanguageLoader
                lang_obj = LanguageLoader.load(lang)

            if lang_obj:
                self._language_cache[lang] = lang_obj
            return lang_obj

        return self.parallel_parser.parse_files(files, loader, progress_callback)

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = self.parallel_parser.stats.to_dict()
        stats["cache_size"] = self.cache.size
        return stats

    def clear_cache(self):
        """清空所有缓存"""
        self.cache.clear()
        if self.incremental_parser:
            self.incremental_parser.clear()
        self.parallel_parser.reset_stats()


# 全局优化解析器实例
_optimized_parser: Optional[OptimizedTreeSitterParser] = None


def get_optimized_parser() -> OptimizedTreeSitterParser:
    """获取全局优化解析器实例"""
    global _optimized_parser
    if _optimized_parser is None:
        _optimized_parser = OptimizedTreeSitterParser()
    return _optimized_parser


def reset_optimized_parser():
    """重置全局优化解析器"""
    global _optimized_parser
    if _optimized_parser:
        _optimized_parser.clear_cache()
    _optimized_parser = None
