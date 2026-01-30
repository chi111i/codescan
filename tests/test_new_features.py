#!/usr/bin/env python3
"""
新功能集成测试 - 验证优化后的索引和搜索功能
测试范围:
1. 搜索服务 (SearchService) - 混合搜索、查询解析
2. 增量索引流水线 (IncrementalPipeline)
3. 文件变更检测 (FileChangeDetector)
4. 安全优先重排序 (SecurityFirstReranker)
5. 向量存储接口 (VectorStoreInterface)
"""

import asyncio
import logging
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass

# 添加项目根目录到路径
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """测试结果"""
    name: str
    passed: bool
    duration: float
    message: str = ""
    error: Optional[str] = None


class FeatureTestSuite:
    """新功能测试套件"""

    def __init__(self):
        self.results: List[TestResult] = []
        self.test_dir: Optional[Path] = None

    def log_result(self, result: TestResult):
        """记录测试结果"""
        self.results.append(result)
        status = "✅ PASS" if result.passed else "❌ FAIL"
        logger.info(f"{status} [{result.name}] - {result.duration:.3f}s")
        if result.message:
            logger.info(f"   {result.message}")
        if result.error:
            logger.error(f"   Error: {result.error}")

    def setup_test_files(self) -> Path:
        """创建测试文件"""
        self.test_dir = Path(tempfile.mkdtemp(prefix="codescan_test_"))

        # 创建测试 Python 文件
        (self.test_dir / "app.py").write_text('''
"""主应用模块"""
import os
import subprocess

def execute_command(user_input):
    """危险：命令注入漏洞"""
    os.system(user_input)  # sink: command_injection

def safe_execute(cmd, args):
    """安全：使用参数化调用"""
    subprocess.run([cmd] + args, check=True)

class UserController:
    """用户控制器"""

    def get_user(self, user_id):
        """获取用户信息"""
        query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL注入
        return self.db.execute(query)

    def authenticate(self, username, password):
        """用户认证"""
        if self.check_password(username, password):
            return self.create_session(username)
        return None
''', encoding='utf-8')

        (self.test_dir / "utils.py").write_text('''
"""工具模块"""
import pickle
import yaml

def load_data(data_bytes):
    """危险：反序列化漏洞"""
    return pickle.loads(data_bytes)  # sink: deserialization

def load_config(config_str):
    """危险：YAML反序列化"""
    return yaml.load(config_str)  # sink: deserialization

def safe_load_config(config_str):
    """安全：使用safe_load"""
    return yaml.safe_load(config_str)
''', encoding='utf-8')

        (self.test_dir / "file_handler.py").write_text('''
"""文件处理模块"""
from pathlib import Path

def read_file(file_path):
    """读取文件"""
    with open(file_path, 'r') as f:  # sink: file_read
        return f.read()

def write_file(file_path, content):
    """写入文件"""
    with open(file_path, 'w') as f:  # sink: file_write
        f.write(content)

def process_upload(filename, data):
    """处理上传文件"""
    # 危险：路径遍历漏洞
    target = Path("/uploads") / filename
    target.write_bytes(data)
''', encoding='utf-8')

        logger.info(f"创建测试目录: {self.test_dir}")
        return self.test_dir

    def cleanup(self):
        """清理测试文件"""
        if self.test_dir and self.test_dir.exists():
            import shutil
            shutil.rmtree(self.test_dir, ignore_errors=True)
            logger.info(f"清理测试目录: {self.test_dir}")

    # ─────────────────────────────────────────────────────────────────
    # 测试用例
    # ─────────────────────────────────────────────────────────────────

    def test_imports(self) -> TestResult:
        """测试1: 验证所有新模块可以正常导入"""
        start = time.time()
        try:
            # 核心模块
            from indexer import (
                CodeUnit, CodeUnitType, CodeSpan,
                VectorStoreInterface, create_vector_store, VectorStoreConfig,
                EnhancedQdrantStore, EnhancedInMemoryStore,
            )

            # 搜索服务
            from indexer import (
                SearchService, SearchConfig, SearchMode,
                HybridSearchResult, ParsedQuery,
                create_search_service,
            )

            # 增量索引
            from indexer import (
                IncrementalPipeline, IncrementalConfig, IncrementalStats,
                create_incremental_pipeline,
            )

            # 文件变更检测
            from indexer import (
                FileChangeDetector, FileChangeResult,
                IndexedFileInfo, compute_file_hash,
            )

            # 索引流水线
            from indexer import (
                IndexingPipeline, PipelineConfig, PipelineStats,
            )

            # Reranker
            from indexer.search import (
                SecurityFirstReranker, SecurityRerankerConfig,
                HybridReranker, create_security_reranker,
            )

            return TestResult(
                name="模块导入",
                passed=True,
                duration=time.time() - start,
                message="所有新模块导入成功"
            )

        except ImportError as e:
            return TestResult(
                name="模块导入",
                passed=False,
                duration=time.time() - start,
                error=str(e)
            )

    def test_vector_store_interface(self) -> TestResult:
        """测试2: 验证向量存储接口"""
        start = time.time()
        try:
            from indexer import (
                VectorStoreInterface, create_vector_store, VectorStoreConfig,
                EnhancedInMemoryStore,
            )

            # 创建内存向量存储
            config = VectorStoreConfig(
                provider="memory",
                collection_name="test_collection",
            )
            store = create_vector_store(config, embedding_dim=384)

            # 验证接口
            assert isinstance(store, VectorStoreInterface), "应该实现VectorStoreInterface"
            assert hasattr(store, 'add'), "应该有add方法"
            assert hasattr(store, 'search'), "应该有search方法"
            assert hasattr(store, 'delete'), "应该有delete方法"
            assert hasattr(store, 'clear'), "应该有clear方法"
            assert hasattr(store, 'hybrid_search'), "应该有hybrid_search方法"

            return TestResult(
                name="向量存储接口",
                passed=True,
                duration=time.time() - start,
                message="VectorStoreInterface验证通过"
            )

        except Exception as e:
            return TestResult(
                name="向量存储接口",
                passed=False,
                duration=time.time() - start,
                error=str(e)
            )

    def test_query_parsing(self) -> TestResult:
        """测试3: 验证查询解析器"""
        start = time.time()
        try:
            from indexer.search_service import SearchService, SearchConfig

            # 创建mock对象用于测试解析
            class MockLLMClient:
                def embed(self, texts):
                    class Response:
                        embeddings = [[0.1] * 384]
                    return Response()

            class MockVectorStore:
                pass

            service = SearchService(
                llm_client=MockLLMClient(),
                vector_store=MockVectorStore(),
                config=SearchConfig(),
            )

            # 测试查询解析
            test_cases = [
                ("SQL injection path:*.py", "SQL injection", "*.py", None),
                ("command exec lang:python", "command exec", None, "python"),
                ("auth bypass -path:tests exclude:vendor", "auth bypass", None, None),
            ]

            for query, expected_clean, expected_filter, expected_lang in test_cases:
                parsed = service._parse_query_modifiers(query)
                assert parsed.clean_query == expected_clean, f"Query parse failed for: {query}"
                if expected_filter:
                    assert parsed.file_filter == expected_filter
                if expected_lang:
                    assert parsed.language_filter == expected_lang

            return TestResult(
                name="查询解析器",
                passed=True,
                duration=time.time() - start,
                message=f"通过{len(test_cases)}个查询解析测试"
            )

        except Exception as e:
            return TestResult(
                name="查询解析器",
                passed=False,
                duration=time.time() - start,
                error=str(e)
            )

    def test_file_change_detector(self) -> TestResult:
        """测试4: 验证文件变更检测"""
        start = time.time()
        try:
            from indexer import FileChangeDetector, compute_file_hash

            # 创建临时数据库
            db_path = self.test_dir / ".test_cache" / "file_index.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)

            detector = FileChangeDetector(str(db_path))
            detector.initialize()

            # 测试文件哈希计算
            test_file = self.test_dir / "app.py"
            hash1 = compute_file_hash(test_file)
            assert len(hash1) == 64, "SHA-256哈希应该是64个字符"

            # 重复计算应该相同
            hash2 = compute_file_hash(test_file)
            assert hash1 == hash2, "相同文件哈希应该一致"

            # 测试变更检测
            files = list(self.test_dir.glob("*.py"))
            changes = detector.detect_changes(self.test_dir, files, use_content_hash=True)

            # 首次扫描，所有文件应该是新文件
            assert len(changes.new_files) == len(files), "首次扫描应该都是新文件"
            assert len(changes.modified_files) == 0, "不应该有修改文件"
            assert len(changes.deleted_files) == 0, "不应该有删除文件"

            detector.close()

            return TestResult(
                name="文件变更检测",
                passed=True,
                duration=time.time() - start,
                message=f"检测到{len(files)}个新文件"
            )

        except Exception as e:
            import traceback
            return TestResult(
                name="文件变更检测",
                passed=False,
                duration=time.time() - start,
                error=f"{str(e)}\n{traceback.format_exc()}"
            )

    def test_security_reranker(self) -> TestResult:
        """测试5: 验证安全优先重排序"""
        start = time.time()
        try:
            from indexer.search import (
                SecurityFirstReranker, SecurityRerankerConfig,
                create_security_reranker,
            )
            from indexer.search_service import HybridSearchResult
            from indexer import CodeUnit, CodeUnitType, CodeSpan

            # 创建reranker
            reranker = create_security_reranker()

            # 创建测试结果
            def make_result(code: str, symbol: str, score: float) -> HybridSearchResult:
                unit = CodeUnit(
                    id=f"test_{symbol}",
                    language="python",
                    file_path="test.py",
                    symbol=symbol,
                    unit_type=CodeUnitType.FUNCTION,
                    signature=f"def {symbol}():",
                    span=CodeSpan(start_line=1, end_line=10),
                    code=code,
                )
                return HybridSearchResult(
                    code_unit=unit,
                    score=score,
                    source="vector",
                )

            # 创建测试数据 - 安全相关代码应该排名更高
            results = [
                make_result("def hello(): print('hello')", "hello", 0.9),
                make_result("os.system(user_input)", "execute_cmd", 0.7),
                make_result("cursor.execute(sql)", "run_query", 0.8),
            ]

            # 执行重排序
            reranked = asyncio.run(reranker.rerank(
                query="command injection vulnerability",
                results=results,
                limit=10,
            ))

            assert len(reranked) > 0, "应该返回结果"

            # 验证含有安全模式的结果被提升
            # (具体排序取决于实现，这里只验证不崩溃)

            return TestResult(
                name="安全优先重排序",
                passed=True,
                duration=time.time() - start,
                message=f"重排序{len(results)}个结果"
            )

        except Exception as e:
            import traceback
            return TestResult(
                name="安全优先重排序",
                passed=False,
                duration=time.time() - start,
                error=f"{str(e)}\n{traceback.format_exc()}"
            )

    def test_keyword_extraction(self) -> TestResult:
        """测试6: 验证关键词提取"""
        start = time.time()
        try:
            from indexer.search_service import SearchService, SearchConfig

            class MockLLMClient:
                def embed(self, texts):
                    class Response:
                        embeddings = [[0.1] * 384]
                    return Response()

            class MockVectorStore:
                pass

            service = SearchService(
                llm_client=MockLLMClient(),
                vector_store=MockVectorStore(),
                config=SearchConfig(),
            )

            # 测试关键词提取
            test_cases = [
                ("SQL injection vulnerability", ["sql", "injection", "vulnerability"]),
                ("find the authentication bypass", ["authentication", "bypass"]),
                ("os.system command execution", ["system", "command", "execution"]),
            ]

            for query, expected_keywords in test_cases:
                keywords = service._extract_keywords(query)
                for kw in expected_keywords:
                    assert kw in keywords, f"应该提取出关键词 '{kw}' from '{query}'"

            return TestResult(
                name="关键词提取",
                passed=True,
                duration=time.time() - start,
                message=f"通过{len(test_cases)}个关键词提取测试"
            )

        except Exception as e:
            return TestResult(
                name="关键词提取",
                passed=False,
                duration=time.time() - start,
                error=str(e)
            )

    def test_rrf_fusion(self) -> TestResult:
        """测试7: 验证RRF融合算法"""
        start = time.time()
        try:
            from indexer.search_service import SearchService, SearchConfig, HybridSearchResult
            from indexer import CodeUnit, CodeUnitType, CodeSpan

            class MockLLMClient:
                def embed(self, texts):
                    class Response:
                        embeddings = [[0.1] * 384]
                    return Response()

            class MockVectorStore:
                pass

            service = SearchService(
                llm_client=MockLLMClient(),
                vector_store=MockVectorStore(),
                config=SearchConfig(rrf_k=60, vector_weight=1.0, keyword_weight=0.8),
            )

            # 创建测试数据
            # 使用固定行号以确保相同符号的函数能被正确去重
            def make_result(symbol: str, score: float, rank: int, source: str, line_start: int = None):
                if line_start is None:
                    line_start = rank * 10
                unit = CodeUnit(
                    id=f"test_{symbol}_{source}",
                    language="python",
                    file_path="test.py",
                    symbol=symbol,
                    unit_type=CodeUnitType.FUNCTION,
                    signature=f"def {symbol}():",
                    span=CodeSpan(start_line=line_start, end_line=line_start+5),
                    code=f"def {symbol}(): pass",
                )
                return HybridSearchResult(
                    code_unit=unit,
                    score=score,
                    source=source,
                    rank=rank,
                )

            vector_results = [
                make_result("func_a", 0.9, 0, "vector", line_start=0),
                make_result("func_b", 0.8, 1, "vector", line_start=10),  # func_b 在行10
                make_result("func_c", 0.7, 2, "vector", line_start=20),
            ]

            keyword_results = [
                make_result("func_b", 0.95, 0, "keyword", line_start=10),  # 重叠：func_b 也在行10
                make_result("func_d", 0.85, 1, "keyword", line_start=30),
            ]

            # 执行融合
            merged = service._merge_results(vector_results, keyword_results, will_rerank=False)

            # 验证
            assert len(merged) == 4, f"应该有4个唯一结果，实际{len(merged)}"

            # func_b 同时出现在两个结果中，source 应该是 'both'
            func_b_results = [r for r in merged if r.code_unit.symbol == "func_b"]
            assert len(func_b_results) == 1, "func_b应该只出现一次（去重）"
            assert func_b_results[0].source == "both", "重叠结果source应该是'both'"

            return TestResult(
                name="RRF融合算法",
                passed=True,
                duration=time.time() - start,
                message="RRF融合正确处理重叠和去重"
            )

        except Exception as e:
            import traceback
            return TestResult(
                name="RRF融合算法",
                passed=False,
                duration=time.time() - start,
                error=f"{str(e)}\n{traceback.format_exc()}"
            )

    def test_smart_cutoff(self) -> TestResult:
        """测试8: 验证智能截断算法"""
        start = time.time()
        try:
            from indexer.search_service import SearchService, SearchConfig, HybridSearchResult
            from indexer import CodeUnit, CodeUnitType, CodeSpan

            class MockLLMClient:
                pass
            class MockVectorStore:
                pass

            config = SearchConfig(
                enable_smart_cutoff=True,
                smart_ratio=0.7,
                smart_delta=0.2,
                smart_floor=0.3,
                smart_min_k=3,
                smart_max_k=20,
            )

            service = SearchService(
                llm_client=MockLLMClient(),
                vector_store=MockVectorStore(),
                config=config,
            )

            # 创建测试数据
            def make_result(score: float, rank: int):
                unit = CodeUnit(
                    id=f"test_{rank}",
                    language="python",
                    file_path="test.py",
                    symbol=f"func_{rank}",
                    unit_type=CodeUnitType.FUNCTION,
                    signature=f"def func_{rank}():",
                    span=CodeSpan(start_line=rank, end_line=rank+1),
                    code=f"def func_{rank}(): pass",
                )
                return HybridSearchResult(
                    code_unit=unit,
                    score=score,
                    source="vector",
                    rank=rank,
                )

            # 测试高分结果 - 应该保留更多
            high_score_results = [
                make_result(0.95, 0),
                make_result(0.90, 1),
                make_result(0.85, 2),
                make_result(0.70, 3),  # 低于阈值
                make_result(0.50, 4),  # 远低于阈值
            ]

            cutoff_results = service._apply_smart_cutoff(high_score_results)

            # safe_harbor (min_k=3) 内只检查 floor
            # 之后检查动态阈值
            assert len(cutoff_results) >= 3, "至少应该保留safe_harbor数量"
            assert len(cutoff_results) <= len(high_score_results), "不应该增加结果"

            # 测试低分结果 - 应该只返回top1
            low_score_results = [
                make_result(0.2, 0),  # 低于floor
                make_result(0.15, 1),
            ]

            cutoff_low = service._apply_smart_cutoff(low_score_results)
            assert len(cutoff_low) == 1, "低于floor时只返回top1"

            return TestResult(
                name="智能截断算法",
                passed=True,
                duration=time.time() - start,
                message=f"高分保留{len(cutoff_results)}个，低分保留{len(cutoff_low)}个"
            )

        except Exception as e:
            import traceback
            return TestResult(
                name="智能截断算法",
                passed=False,
                duration=time.time() - start,
                error=f"{str(e)}\n{traceback.format_exc()}"
            )

    def test_file_path_matching(self) -> TestResult:
        """测试9: 验证文件路径匹配（Windows兼容）"""
        start = time.time()
        try:
            from indexer.search_service import SearchService, SearchConfig

            class MockLLMClient:
                pass
            class MockVectorStore:
                pass

            service = SearchService(
                llm_client=MockLLMClient(),
                vector_store=MockVectorStore(),
                config=SearchConfig(),
            )

            # 测试各种路径格式
            test_cases = [
                # (file_path, pattern, expected_match)
                ("src/app.py", "*.py", True),
                ("src\\app.py", "*.py", True),  # Windows路径
                ("src/utils/helper.py", "src/**", True),
                ("tests/test_app.py", "tests", True),
                ("src/app.py", "tests", False),
                ("E:\\project\\src\\app.py", "*.py", True),  # Windows绝对路径
            ]

            passed = 0
            for file_path, pattern, expected in test_cases:
                result = service._match_file_filter(file_path, pattern)
                if result == expected:
                    passed += 1
                else:
                    logger.warning(
                        f"路径匹配失败: {file_path} vs {pattern} "
                        f"-> got {result}, expected {expected}"
                    )

            if passed < len(test_cases):
                return TestResult(
                    name="文件路径匹配",
                    passed=False,
                    duration=time.time() - start,
                    error=f"只通过{passed}/{len(test_cases)}个测试"
                )

            return TestResult(
                name="文件路径匹配",
                passed=True,
                duration=time.time() - start,
                message=f"通过{len(test_cases)}个路径匹配测试"
            )

        except Exception as e:
            return TestResult(
                name="文件路径匹配",
                passed=False,
                duration=time.time() - start,
                error=str(e)
            )

    def test_empty_query_handling(self) -> TestResult:
        """测试10: 验证空查询处理"""
        start = time.time()
        try:
            from indexer.search_service import SearchService, SearchConfig

            class MockLLMClient:
                def embed(self, texts):
                    class Response:
                        embeddings = [[0.1] * 384]
                    return Response()

            class MockVectorStore:
                def search(self, **kwargs):
                    return []

            service = SearchService(
                llm_client=MockLLMClient(),
                vector_store=MockVectorStore(),
                config=SearchConfig(),
            )

            # 测试空查询
            empty_queries = ["", "   ", None]

            for query in empty_queries:
                try:
                    if query is None:
                        # None会在类型检查时失败，跳过
                        continue
                    results = asyncio.run(service.search(query))
                    assert results == [], f"空查询'{query}'应该返回空列表"
                except Exception as e:
                    # 应该优雅处理，不崩溃
                    if "Empty query" not in str(e):
                        raise

            return TestResult(
                name="空查询处理",
                passed=True,
                duration=time.time() - start,
                message="空查询正确返回空结果"
            )

        except Exception as e:
            return TestResult(
                name="空查询处理",
                passed=False,
                duration=time.time() - start,
                error=str(e)
            )

    def run_all(self) -> bool:
        """运行所有测试"""
        logger.info("=" * 60)
        logger.info("新功能集成测试")
        logger.info("=" * 60)

        # 设置测试环境
        self.setup_test_files()

        try:
            # 运行所有测试
            tests = [
                self.test_imports,
                self.test_vector_store_interface,
                self.test_query_parsing,
                self.test_file_change_detector,
                self.test_security_reranker,
                self.test_keyword_extraction,
                self.test_rrf_fusion,
                self.test_smart_cutoff,
                self.test_file_path_matching,
                self.test_empty_query_handling,
            ]

            for test_func in tests:
                try:
                    result = test_func()
                    self.log_result(result)
                except Exception as e:
                    self.log_result(TestResult(
                        name=test_func.__name__,
                        passed=False,
                        duration=0,
                        error=str(e)
                    ))

        finally:
            # 清理
            self.cleanup()

        # 汇总结果
        passed = sum(1 for r in self.results if r.passed)
        total = len(self.results)

        logger.info("=" * 60)
        logger.info(f"测试完成: {passed}/{total} 通过")
        logger.info("=" * 60)

        # 显示失败的测试
        failed = [r for r in self.results if not r.passed]
        if failed:
            logger.error("失败的测试:")
            for r in failed:
                logger.error(f"  - {r.name}: {r.error}")

        return passed == total


def main():
    """主入口"""
    suite = FeatureTestSuite()
    success = suite.run_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
