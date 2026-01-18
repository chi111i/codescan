"""
测试 P0-1: 按需加载 chunk 机制
"""

import pytest
import sys
import os
from collections import OrderedDict

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from indexer.models import CodeUnit, CodeUnitType


class MockVectorStore:
    """模拟向量存储"""

    def __init__(self):
        self._units = {}

    def initialize(self):
        pass

    def add(self, units, embeddings):
        for unit in units:
            self._units[unit.id] = unit

    def get_by_id(self, unit_id):
        return self._units.get(unit_id)

    def get_all(self, limit=10000):
        return list(self._units.values())[:limit]

    def count(self):
        return len(self._units)

    def clear(self):
        self._units.clear()

    def delete(self, unit_id):
        if unit_id in self._units:
            del self._units[unit_id]


class TestChunkMechanism:
    """测试 chunk 机制"""

    def setup_method(self):
        """初始化测试环境"""
        from unittest.mock import MagicMock, patch

        # 创建 mock 配置
        self.mock_config = MagicMock()
        self.mock_config.scan.chunk_size = 2000
        self.mock_config.scan.include_patterns = ["**/*.py"]
        self.mock_config.scan.exclude_patterns = []
        self.mock_config.scan.max_file_size_kb = 1024
        self.mock_config.scan.max_concurrent = 4
        self.mock_config.scan.enable_hybrid_search = False
        self.mock_config.scan.keyword_boost = 0.3
        self.mock_config.scan.metadata_filter_first = True
        self.mock_config.scan.enable_reranking = False
        self.mock_config.vector_store.enable_cache = False
        self.mock_config.vector_store.collection_name = "test"
        self.mock_config.vector_store.cache_dir = ".test_cache"
        self.mock_config.llm.embedding_dim = 1536

        # 创建 mock LLM client
        self.mock_llm_client = MagicMock()

        # 创建 mock 向量存储
        self.mock_vector_store = MockVectorStore()

    def test_chunk_mapping_creation(self):
        """测试 chunk 映射创建"""
        from indexer.indexer import CodeIndexer
        from unittest.mock import patch, MagicMock

        # 创建一个大的代码单元（超过 chunk_size）
        large_code = "\n".join([f"line_{i} = {i}" for i in range(500)])  # 约 5000 字符

        large_unit = CodeUnit(
            id="test_large_func",
            language="python",
            file_path="test.py",
            symbol="large_function",
            unit_type=CodeUnitType.FUNCTION,
            signature="def large_function():",
            span=(1, 500),
            code=large_code,
            docstring="A large function",
            calls=["helper_func"],
            parent_class=None,
            decorators=[],
            imports=[],
        )

        small_unit = CodeUnit(
            id="test_small_func",
            language="python",
            file_path="test.py",
            symbol="small_function",
            unit_type=CodeUnitType.FUNCTION,
            signature="def small_function():",
            span=(501, 510),
            code="def small_function():\n    return 42",
            docstring="A small function",
            calls=[],
            parent_class=None,
            decorators=[],
            imports=[],
        )

        # 使用 patch 来避免实际初始化
        with patch.object(CodeIndexer, '__init__', lambda self, *args, **kwargs: None):
            indexer = CodeIndexer.__new__(CodeIndexer)
            # 手动初始化必要的属性
            indexer._chunk_parent_map = {}
            indexer._chunk_siblings = {}
            indexer._raw_unit_cache = OrderedDict()
            indexer._raw_unit_cache_max_size = 500
            indexer.scan_config = self.mock_config.scan
            indexer.vector_store = self.mock_vector_store

            # 调用 _chunk_units
            result = indexer._chunk_units([large_unit, small_unit], max_tokens=500)

            # 验证小单元未被分块
            small_results = [u for u in result if u.symbol == "small_function"]
            assert len(small_results) == 1
            assert small_results[0].id == "test_small_func"

            # 验证大单元被分块
            large_results = [u for u in result if u.symbol == "large_function"]
            assert len(large_results) > 1  # 应该有多个 chunk

            # 验证 chunk 映射
            assert "test_large_func" in indexer._chunk_siblings
            chunk_ids = indexer._chunk_siblings["test_large_func"]
            assert len(chunk_ids) == len(large_results)

            for chunk_id in chunk_ids:
                assert chunk_id in indexer._chunk_parent_map
                assert indexer._chunk_parent_map[chunk_id] == "test_large_func"

            # 验证原始单元被缓存
            assert "test_large_func" in indexer._raw_unit_cache

    def test_get_raw_unit_from_chunk(self):
        """测试从 chunk 获取原始单元"""
        from indexer.indexer import CodeIndexer
        from unittest.mock import patch

        # 准备测试数据
        original_code = "\n".join([f"line_{i} = {i}" for i in range(100)])

        with patch.object(CodeIndexer, '__init__', lambda self, *args, **kwargs: None):
            indexer = CodeIndexer.__new__(CodeIndexer)
            indexer._chunk_parent_map = {
                "parent_1_chunk0": "parent_1",
                "parent_1_chunk1": "parent_1",
            }
            indexer._chunk_siblings = {
                "parent_1": ["parent_1_chunk0", "parent_1_chunk1"],
            }
            indexer._raw_unit_cache = OrderedDict()
            indexer._raw_unit_cache_max_size = 500
            indexer.vector_store = self.mock_vector_store

            # 添加 chunk 到 mock store
            chunk0 = CodeUnit(
                id="parent_1_chunk0",
                language="python",
                file_path="test.py",
                symbol="large_func",
                unit_type=CodeUnitType.FUNCTION,
                signature="def large_func():",
                span=(1, 100),
                code="# Part 1\nline_0 = 0\nline_1 = 1",
                docstring="Large function",
                calls=["helper"],
                chunk_index=0,
                total_chunks=2,
            )
            chunk1 = CodeUnit(
                id="parent_1_chunk1",
                language="python",
                file_path="test.py",
                symbol="large_func",
                unit_type=CodeUnitType.FUNCTION,
                signature="def large_func():",
                span=(1, 100),
                code="line_2 = 2\nline_3 = 3",
                docstring=None,
                calls=[],
                chunk_index=1,
                total_chunks=2,
            )
            indexer.vector_store.add([chunk0, chunk1], [])

            # 测试通过 chunk_id 获取原始单元
            raw_unit = indexer.get_raw_unit("parent_1_chunk0")
            assert raw_unit is not None
            assert raw_unit.id == "parent_1"
            assert "line_0 = 0" in raw_unit.code
            assert "line_2 = 2" in raw_unit.code
            assert raw_unit.chunk_index is None  # 完整单元

            # 验证缓存
            assert "parent_1" in indexer._raw_unit_cache

    def test_get_raw_unit_non_chunked(self):
        """测试获取非分块单元"""
        from indexer.indexer import CodeIndexer
        from unittest.mock import patch

        with patch.object(CodeIndexer, '__init__', lambda self, *args, **kwargs: None):
            indexer = CodeIndexer.__new__(CodeIndexer)
            indexer._chunk_parent_map = {}
            indexer._chunk_siblings = {}
            indexer._raw_unit_cache = OrderedDict()
            indexer._raw_unit_cache_max_size = 500
            indexer.vector_store = self.mock_vector_store

            # 添加非分块单元
            normal_unit = CodeUnit(
                id="normal_func",
                language="python",
                file_path="test.py",
                symbol="normal_func",
                unit_type=CodeUnitType.FUNCTION,
                signature="def normal_func():",
                span=(1, 10),
                code="def normal_func():\n    return 42",
            )
            indexer.vector_store.add([normal_unit], [])

            # 测试获取非分块单元
            result = indexer.get_raw_unit("normal_func")
            assert result is not None
            assert result.id == "normal_func"
            assert result.code == "def normal_func():\n    return 42"

    def test_batch_get_raw_units(self):
        """测试批量获取原始单元"""
        from indexer.indexer import CodeIndexer
        from unittest.mock import patch

        with patch.object(CodeIndexer, '__init__', lambda self, *args, **kwargs: None):
            indexer = CodeIndexer.__new__(CodeIndexer)
            indexer._chunk_parent_map = {
                "parent_1_chunk0": "parent_1",
                "parent_1_chunk1": "parent_1",
            }
            indexer._chunk_siblings = {
                "parent_1": ["parent_1_chunk0", "parent_1_chunk1"],
            }
            indexer._raw_unit_cache = OrderedDict()
            indexer._raw_unit_cache_max_size = 500
            indexer.vector_store = self.mock_vector_store

            # 添加 chunks
            chunk0 = CodeUnit(
                id="parent_1_chunk0",
                language="python",
                file_path="test.py",
                symbol="func1",
                unit_type=CodeUnitType.FUNCTION,
                signature="def func1():",
                span=(1, 10),
                code="# Part 1",
                chunk_index=0,
                total_chunks=2,
            )
            chunk1 = CodeUnit(
                id="parent_1_chunk1",
                language="python",
                file_path="test.py",
                symbol="func1",
                unit_type=CodeUnitType.FUNCTION,
                signature="def func1():",
                span=(1, 10),
                code="# Part 2",
                chunk_index=1,
                total_chunks=2,
            )
            normal_unit = CodeUnit(
                id="normal_func",
                language="python",
                file_path="test.py",
                symbol="normal_func",
                unit_type=CodeUnitType.FUNCTION,
                signature="def normal_func():",
                span=(1, 5),
                code="def normal_func(): pass",
            )
            indexer.vector_store.add([chunk0, chunk1, normal_unit], [])

            # 批量获取，包括重复的 chunk
            result = indexer.get_raw_units_batch([
                "parent_1_chunk0",
                "parent_1_chunk1",  # 同一个 parent 的另一个 chunk
                "normal_func",
            ])

            # 应该只返回 2 个单元（parent_1 和 normal_func）
            assert len(result) == 2
            ids = [u.id for u in result]
            assert "parent_1" in ids
            assert "normal_func" in ids

    def test_is_chunked(self):
        """测试 is_chunked 方法"""
        from indexer.indexer import CodeIndexer
        from unittest.mock import patch

        with patch.object(CodeIndexer, '__init__', lambda self, *args, **kwargs: None):
            indexer = CodeIndexer.__new__(CodeIndexer)
            indexer._chunk_parent_map = {
                "parent_1_chunk0": "parent_1",
            }
            indexer._chunk_siblings = {
                "parent_1": ["parent_1_chunk0"],
            }

            assert indexer.is_chunked("parent_1_chunk0") is True
            assert indexer.is_chunked("parent_1") is True
            assert indexer.is_chunked("not_chunked") is False

    def test_get_chunk_info(self):
        """测试获取 chunk 信息"""
        from indexer.indexer import CodeIndexer
        from unittest.mock import patch

        with patch.object(CodeIndexer, '__init__', lambda self, *args, **kwargs: None):
            indexer = CodeIndexer.__new__(CodeIndexer)
            indexer._chunk_parent_map = {
                "parent_1_chunk0": "parent_1",
                "parent_1_chunk1": "parent_1",
            }
            indexer._chunk_siblings = {
                "parent_1": ["parent_1_chunk0", "parent_1_chunk1"],
            }

            # 测试 chunk
            info = indexer.get_chunk_info("parent_1_chunk0")
            assert info is not None
            assert info["is_chunk"] is True
            assert info["parent_id"] == "parent_1"
            assert info["chunk_count"] == 2

            # 测试 parent
            info = indexer.get_chunk_info("parent_1")
            assert info is not None
            assert info["is_chunk"] is False
            assert info["is_parent"] is True
            assert info["chunk_count"] == 2

            # 测试非 chunk
            info = indexer.get_chunk_info("random_id")
            assert info is None

    def test_clear_index_clears_chunk_data(self):
        """测试清空索引时同时清空 chunk 数据"""
        from indexer.indexer import CodeIndexer
        from unittest.mock import patch

        with patch.object(CodeIndexer, '__init__', lambda self, *args, **kwargs: None):
            indexer = CodeIndexer.__new__(CodeIndexer)
            indexer._chunk_parent_map = {"chunk1": "parent1"}
            indexer._chunk_siblings = {"parent1": ["chunk1"]}
            indexer._raw_unit_cache = OrderedDict({"parent1": "some_unit"})
            indexer.vector_store = self.mock_vector_store

            indexer.clear_index()

            assert len(indexer._chunk_parent_map) == 0
            assert len(indexer._chunk_siblings) == 0
            assert len(indexer._raw_unit_cache) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
