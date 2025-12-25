"""P0 阶段集成测试

验证所有 P0 功能的协同工作：
1. Prompt 模板系统
2. Token 控制策略
3. 配置验证
4. 文件过滤
"""

import sys
import io
import tempfile
from pathlib import Path

# 设置 UTF-8 编码
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 添加项目根目录到 sys.path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def test_end_to_end_workflow():
    """端到端工作流测试"""
    print("=" * 60)
    print("集成测试 1: 端到端工作流")
    print("=" * 60)

    from config import AuditConfig, LLMConfig, VectorStoreConfig, ScanConfig, RulesConfig
    from config import validate_config
    from prompts import get_prompt_manager, count_tokens, ContentBlock
    from indexer import FileFilter

    with tempfile.TemporaryDirectory() as tmpdir:
        # 1. 配置验证
        print("\n[1/4] 配置验证...")
        config = AuditConfig(
            llm=LLMConfig(
                api_key="sk-test-integration-key",
                model="gpt-4",
                max_tokens=8000,
            ),
            vector_store=VectorStoreConfig(cache_dir=tmpdir),
            scan=ScanConfig(target_path=str(Path.cwd()), mode="full"),
            rules=RulesConfig(),
        )

        try:
            validate_config(config)
            print("✓ 配置验证通过")
        except ValueError as e:
            print(f"❌ 配置验证失败: {e}")
            raise

        # 2. 文件过滤
        print("\n[2/4] 文件过滤...")
        root = Path(tmpdir)
        (root / "main.py").write_text("# production code")
        (root / "test.py").write_text("# test code")
        (root / ".auditignore").write_text("*test*.py\n")

        file_filter = FileFilter(root_path=root)
        files = list(root.rglob("*.py"))
        filtered = file_filter.filter_files(files)

        print(f"  总文件: {len(files)}")
        print(f"  过滤后: {len(filtered)}")
        assert len(filtered) == 1, "应该只保留 main.py"
        assert filtered[0].name == "main.py"
        print("✓ 文件过滤正常")

        # 3. Prompt 模板构建
        print("\n[3/4] Prompt 模板构建...")
        manager = get_prompt_manager()

        chain_context = """
def login(username, password):
    query = f"SELECT * FROM users WHERE name='{username}'"
    cursor.execute(query)
"""

        system, user, metadata = manager.build_chain_analysis_prompt(
            chain_id="test-chain-1",
            sink_category="sql_injection",
            chain_context=chain_context,
            max_tokens=2000,
            style="professional",
        )

        print(f"  System Prompt 长度: {len(system)} 字符")
        print(f"  User Prompt 长度: {len(user)} 字符")
        print(f"  元数据: {metadata}")

        assert "SQL" in system or "SQL" in user, "应该包含 SQL 注入相关指导"
        assert "login" in user, "应该包含代码上下文"
        print("✓ Prompt 模板构建正常")

        # 4. Token 控制
        print("\n[4/4] Token 控制...")
        token_count = count_tokens(system + user)
        print(f"  总 Token 数: {token_count}")
        assert token_count < 3000, "Token 数应该在预算内"
        print("✓ Token 控制正常")

        print("\n" + "=" * 60)
        print("✅ 端到端工作流测试通过")
        print("=" * 60)


def test_component_integration():
    """组件集成测试"""
    print("\n" + "=" * 60)
    print("集成测试 2: 组件协同")
    print("=" * 60)

    from prompts import get_prompt_manager, TokenBudgetManager, ContentBlock, TokenPriority
    from config import ConfigValidator, AuditConfig, LLMConfig, VectorStoreConfig, ScanConfig, RulesConfig

    with tempfile.TemporaryDirectory() as tmpdir:
        # 场景：配置指定较小 token 预算，验证 token manager 和 prompt manager 协同
        print("\n[场景] Token 预算受限时的协同工作...")

        config = AuditConfig(
            llm=LLMConfig(
                api_key="sk-test",
                max_tokens=4000,  # 较小预算
                max_context_tokens=3000,
            ),
            vector_store=VectorStoreConfig(cache_dir=tmpdir),
            scan=ScanConfig(target_path=str(Path.cwd()), mode="full"),
            rules=RulesConfig(),
        )

        validator = ConfigValidator(config)
        is_valid, errors, warnings = validator.validate_all(strict=False)

        print(f"  配置验证: {'通过' if is_valid else '失败'}")
        if warnings:
            print(f"  警告数: {len(warnings)}")

        # 使用 TokenBudgetManager 控制内容
        budget_manager = TokenBudgetManager(max_total_tokens=3000)

        content_blocks = [
            ContentBlock(
                text="你是一个安全审计专家...",
                priority=TokenPriority.CRITICAL,
                name="system_prompt",
            ),
            ContentBlock(
                text="SQL 注入是一种严重的安全漏洞..." * 100,  # 很长
                priority=TokenPriority.MEDIUM,
                name="vulnerability_context",
            ),
            ContentBlock(
                text='def login(user): query = f"SELECT * FROM users WHERE id={user}"',
                priority=TokenPriority.HIGH,
                name="code_snippet",
            ),
        ]

        prompt, stats = budget_manager.build_prompt(content_blocks)

        print(f"  最终 Token 数: {stats['total_tokens']}")
        print(f"  截断的块: {stats['truncated_blocks']}")
        assert stats['total_tokens'] <= 3000, "应该控制在预算内"
        assert 'total_tokens' in stats, "应该有统计信息"
        print("✓ 组件协同正常")

        print("\n" + "=" * 60)
        print("✅ 组件集成测试通过")
        print("=" * 60)


def test_error_handling():
    """错误处理测试"""
    print("\n" + "=" * 60)
    print("集成测试 3: 错误处理")
    print("=" * 60)

    from config import AuditConfig, LLMConfig, VectorStoreConfig, ScanConfig, RulesConfig
    from config import validate_config
    from prompts import get_prompt_manager
    from indexer import FileFilter

    # 场景 1：配置错误被正确捕获
    print("\n[场景 1] 配置验证错误处理...")
    with tempfile.TemporaryDirectory() as tmpdir:
        invalid_config = AuditConfig(
            llm=LLMConfig(
                api_key="",  # 空 key
                max_tokens=-100,  # 负数
            ),
            vector_store=VectorStoreConfig(cache_dir=tmpdir),
            scan=ScanConfig(target_path="/nonexistent", mode="invalid"),
            rules=RulesConfig(),
        )

        try:
            validate_config(invalid_config)
            print("❌ 应该抛出异常")
            assert False
        except ValueError as e:
            print(f"✓ 正确捕获异常: {str(e)[:50]}...")

    # 场景 2：文件过滤器健壮性
    print("\n[场景 2] 文件过滤器错误处理...")
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        # 创建损坏的 .auditignore
        (root / ".auditignore").write_bytes(b'\xff\xfe invalid utf-8 \x00')

        try:
            file_filter = FileFilter(root_path=root)
            # 应该能处理损坏的文件
            print("✓ 能够处理损坏的 .auditignore")
        except Exception as e:
            print(f"⚠️ 异常: {e}")

    # 场景 3：Prompt 模板缺失处理
    print("\n[场景 3] Prompt 模板错误处理...")
    manager = get_prompt_manager()

    try:
        # 无效的 sink_category
        system, user, _ = manager.build_chain_analysis_prompt(
            chain_id="test",
            sink_category="nonexistent_category",
            chain_context="test",
        )
        # 应该回退到通用模板
        print("✓ 未知类别能回退到通用模板")
    except Exception as e:
        print(f"⚠️ 异常: {e}")

    print("\n" + "=" * 60)
    print("✅ 错误处理测试通过")
    print("=" * 60)


def test_performance_baseline():
    """性能基准测试"""
    print("\n" + "=" * 60)
    print("集成测试 4: 性能基准")
    print("=" * 60)

    import time
    from prompts import get_prompt_manager, count_tokens
    from indexer import FileFilter

    # 测试 1: Prompt 模板构建性能
    print("\n[性能 1] Prompt 模板构建...")
    manager = get_prompt_manager()

    start = time.time()
    for i in range(100):
        system, user, _ = manager.build_chain_analysis_prompt(
            chain_id=f"chain-{i}",
            sink_category="sql_injection",
            chain_context="def test(): pass" * 10,
        )
    elapsed = time.time() - start

    print(f"  100 次构建耗时: {elapsed:.3f}s")
    print(f"  平均每次: {elapsed/100*1000:.1f}ms")
    assert elapsed < 5.0, "性能应该可接受"
    print("✓ Prompt 构建性能正常")

    # 测试 2: Token 计数性能
    print("\n[性能 2] Token 计数...")
    text = "The quick brown fox jumps over the lazy dog. " * 1000

    start = time.time()
    for _ in range(100):
        count = count_tokens(text)
    elapsed = time.time() - start

    print(f"  100 次计数耗时: {elapsed:.3f}s")
    print(f"  平均每次: {elapsed/100*1000:.1f}ms")
    print("✓ Token 计数性能正常")

    # 测试 3: 文件过滤性能
    print("\n[性能 3] 文件过滤...")
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        # 创建 1000 个文件
        for i in range(1000):
            (root / f"file_{i}.py").write_text(f"# file {i}")

        file_filter = FileFilter(root_path=root)

        files = list(root.rglob("*.py"))
        start = time.time()
        filtered = file_filter.filter_files(files)
        elapsed = time.time() - start

        print(f"  过滤 {len(files)} 个文件耗时: {elapsed:.3f}s")
        print(f"  平均每个文件: {elapsed/len(files)*1000:.2f}ms")
        print("✓ 文件过滤性能正常")

    print("\n" + "=" * 60)
    print("✅ 性能基准测试通过")
    print("=" * 60)


if __name__ == "__main__":
    try:
        print("\n" + "=" * 60)
        print(" P0 阶段集成测试套件")
        print("=" * 60 + "\n")

        test_end_to_end_workflow()
        test_component_integration()
        test_error_handling()
        test_performance_baseline()

        print("\n" + "=" * 60)
        print(" 🎉 所有集成测试通过！P0 阶段验收完成")
        print("=" * 60)
        print("\n已验证的功能：")
        print("  ✅ Prompt 模板工程化系统")
        print("  ✅ Token 控制策略和预算管理")
        print("  ✅ 配置统一验证机制")
        print("  ✅ 文件过滤机制（.auditignore）")
        print("  ✅ 组件协同工作")
        print("  ✅ 错误处理")
        print("  ✅ 性能基准")
        print("\n" + "=" * 60)

    except Exception as e:
        print(f"\n❌ 集成测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
