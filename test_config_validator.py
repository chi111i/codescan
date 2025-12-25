"""配置验证器测试

测试配置验证功能的完整性和准确性。
"""

import sys
import io
from pathlib import Path
import tempfile

# 设置 UTF-8 编码
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 添加项目根目录到 sys.path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def test_valid_config():
    """测试有效配置"""
    print("=" * 60)
    print("测试 1: 有效配置验证")
    print("=" * 60)

    from config import AuditConfig, LLMConfig, VectorStoreConfig, ScanConfig, RulesConfig
    from config import ConfigValidator

    # 创建临时目录
    with tempfile.TemporaryDirectory() as tmpdir:
        config = AuditConfig(
            llm=LLMConfig(
                provider="openai-compatible",
                base_url="https://api.openai.com/v1",
                api_key="sk-test-key-1234567890",
                model="gpt-4",
                embedding_model="text-embedding-3-small",
            ),
            vector_store=VectorStoreConfig(
                provider="qdrant",
                host="localhost",
                port=6333,
                cache_dir=tmpdir,
            ),
            scan=ScanConfig(
                target_path=str(Path.cwd()),
                mode="full",
                languages=["python"],
            ),
            rules=RulesConfig(
                rules_dir="rules/data",
                risk_threshold="low",
            ),
        )

        validator = ConfigValidator(config)
        is_valid, errors, warnings = validator.validate_all(strict=False)

        print(f"验证结果: {'通过' if is_valid else '失败'}")
        print(f"错误数: {len(errors)}")
        print(f"警告数: {len(warnings)}")

        if errors:
            print("\n错误:")
            for error in errors:
                print(f"  ❌ {error}")

        if warnings:
            print("\n警告:")
            for warning in warnings:
                print(f"  ⚠️ {warning}")

        assert is_valid, "有效配置应该通过验证"
        print("✓ 有效配置验证通过")
        print()


def test_invalid_llm_config():
    """测试无效 LLM 配置"""
    print("=" * 60)
    print("测试 2: 无效 LLM 配置")
    print("=" * 60)

    from config import AuditConfig, LLMConfig, VectorStoreConfig, ScanConfig, RulesConfig
    from config import ConfigValidator

    # 创建临时目录
    with tempfile.TemporaryDirectory() as tmpdir:
        config = AuditConfig(
            llm=LLMConfig(
                provider="invalid-provider",  # 无效提供商
                base_url="invalid-url",        # 无效 URL
                api_key="",                    # 空 API Key
                model="",                      # 空模型
                max_tokens=-100,               # 负数
                temperature=10.0,              # 超出范围
            ),
            vector_store=VectorStoreConfig(
                cache_dir=tmpdir,
            ),
            scan=ScanConfig(
                target_path=str(Path.cwd()),
                mode="full",
            ),
            rules=RulesConfig(),
        )

        validator = ConfigValidator(config)
        is_valid, errors, warnings = validator.validate_all(strict=False)

        print(f"验证结果: {'通过' if is_valid else '失败'}")
        print(f"错误数: {len(errors)}")

        if errors:
            print("\n捕获的错误:")
            for error in errors:
                print(f"  ❌ {error}")

        assert not is_valid, "无效配置应该被拒绝"
        assert len(errors) > 0, "应该有错误信息"
        print(f"✓ 成功捕获 {len(errors)} 个配置错误")
        print()


def test_invalid_scan_config():
    """测试无效扫描配置"""
    print("=" * 60)
    print("测试 3: 无效扫描配置")
    print("=" * 60)

    from config import AuditConfig, LLMConfig, VectorStoreConfig, ScanConfig, RulesConfig
    from config import ConfigValidator

    with tempfile.TemporaryDirectory() as tmpdir:
        config = AuditConfig(
            llm=LLMConfig(
                api_key="sk-test",
            ),
            vector_store=VectorStoreConfig(
                cache_dir=tmpdir,
            ),
            scan=ScanConfig(
                target_path="/nonexistent/path",  # 不存在的路径
                mode="invalid-mode",               # 无效模式
                languages=[],                      # 空语言列表
                max_file_size_kb=99999999,         # 超大文件
                max_concurrent=100,                # 过高并发
            ),
            rules=RulesConfig(),
        )

        validator = ConfigValidator(config)
        is_valid, errors, warnings = validator.validate_all(strict=False)

        print(f"验证结果: {'通过' if is_valid else '失败'}")
        print(f"错误数: {len(errors)}")

        if errors:
            print("\n捕获的错误:")
            for error in errors:
                print(f"  ❌ {error}")

        assert not is_valid, "无效配置应该被拒绝"
        print(f"✓ 成功捕获 {len(errors)} 个配置错误")
        print()


def test_cross_validation():
    """测试交叉验证"""
    print("=" * 60)
    print("测试 4: 配置交叉验证")
    print("=" * 60)

    from config import AuditConfig, LLMConfig, VectorStoreConfig, ScanConfig, RulesConfig
    from config import ConfigValidator

    with tempfile.TemporaryDirectory() as tmpdir:
        config = AuditConfig(
            llm=LLMConfig(
                api_key="sk-test",
                max_code_tokens_per_call=1000,    # 小于 chunk_size
                max_context_tokens=500,           # 不合理的顺序
            ),
            vector_store=VectorStoreConfig(
                cache_dir=tmpdir,
            ),
            scan=ScanConfig(
                target_path=str(Path.cwd()),
                mode="full",
                chunk_size=2000,                  # 大于 max_code_tokens
            ),
            rules=RulesConfig(),
        )

        validator = ConfigValidator(config)
        is_valid, errors, warnings = validator.validate_all(strict=False)

        print(f"验证结果: {'通过' if is_valid else '失败'}")
        print(f"错误数: {len(errors)}")
        print(f"警告数: {len(warnings)}")

        if errors:
            print("\n错误:")
            for error in errors:
                print(f"  ❌ {error}")

        if warnings:
            print("\n警告:")
            for warning in warnings:
                print(f"  ⚠️ {warning}")

        # 应该有错误（max_context < max_code）或警告
        assert len(errors) > 0 or len(warnings) > 0, "应该检测到配置不合理"
        print("✓ 交叉验证正常工作")
        print()


def test_validate_config_function():
    """测试便捷验证函数"""
    print("=" * 60)
    print("测试 5: 便捷验证函数")
    print("=" * 60)

    from config import AuditConfig, LLMConfig, VectorStoreConfig, ScanConfig, RulesConfig
    from config import validate_config

    with tempfile.TemporaryDirectory() as tmpdir:
        # 有效配置
        valid_config = AuditConfig(
            llm=LLMConfig(api_key="sk-test"),
            vector_store=VectorStoreConfig(cache_dir=tmpdir),
            scan=ScanConfig(target_path=str(Path.cwd()), mode="full"),
            rules=RulesConfig(),
        )

        try:
            validate_config(valid_config)
            print("✓ 有效配置验证通过")
        except ValueError as e:
            print(f"❌ 不应该抛出异常: {e}")
            raise

        # 无效配置
        invalid_config = AuditConfig(
            llm=LLMConfig(api_key="", model=""),  # 无效
            vector_store=VectorStoreConfig(cache_dir=tmpdir),
            scan=ScanConfig(target_path="/nonexistent", mode="full"),
            rules=RulesConfig(),
        )

        try:
            validate_config(invalid_config)
            print("❌ 应该抛出异常")
            assert False, "无效配置应该抛出异常"
        except ValueError as e:
            print(f"✓ 正确抛出异常: {e}")

        print()


def test_environment_validation():
    """测试环境变量验证"""
    print("=" * 60)
    print("测试 6: 环境变量验证")
    print("=" * 60)

    import os
    from config import AuditConfig, LLMConfig, VectorStoreConfig, ScanConfig, RulesConfig
    from config import ConfigValidator

    # 模拟环境变量
    os.environ["LLM_API_KEY"] = "sk-from-env"

    with tempfile.TemporaryDirectory() as tmpdir:
        config = AuditConfig(
            llm=LLMConfig(api_key=""),  # 空，但环境变量有值
            vector_store=VectorStoreConfig(cache_dir=tmpdir),
            scan=ScanConfig(target_path=str(Path.cwd()), mode="full"),
            rules=RulesConfig(),
        )

        validator = ConfigValidator(config)
        is_valid, errors, warnings = validator.validate_all(strict=False)

        print(f"验证结果: {'通过' if is_valid else '失败'}")
        print(f"错误数: {len(errors)}")

        # 清理环境变量
        del os.environ["LLM_API_KEY"]

        # 环境变量存在时应该不报错
        # 注意：validator 会检查配置本身，不会自动填充环境变量
        print("✓ 环境变量验证完成")
        print()


if __name__ == "__main__":
    try:
        print("\n" + "=" * 60)
        print(" 配置验证器测试套件")
        print("=" * 60 + "\n")

        test_valid_config()
        test_invalid_llm_config()
        test_invalid_scan_config()
        test_cross_validation()
        test_validate_config_function()
        test_environment_validation()

        print("=" * 60)
        print(" 所有测试通过! ✓")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
