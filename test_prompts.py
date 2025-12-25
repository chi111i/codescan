"""Prompt 工程化系统测试

测试 Prompt 模板管理器和 Token 预算管理器的核心功能。
"""

import sys
import io
from pathlib import Path

# 设置 UTF-8 编码
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 添加项目根目录到 sys.path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_prompt_manager():
    """测试 Prompt 管理器"""
    print("=" * 60)
    print("测试 1: Prompt 管理器加载")
    print("=" * 60)

    from prompts import get_prompt_manager

    manager = get_prompt_manager()
    print(f"✓ Prompt 管理器初始化成功")
    print(f"  配置路径: {manager.config_path}")
    print(f"  模板目录: {manager.base_dir / 'templates'}")
    print(f"  可用风格: {manager.get_available_styles()}")
    print(f"  支持类别: {manager.get_available_categories()}")
    print()


def test_chain_prompt_build():
    """测试链级 Prompt 构建"""
    print("=" * 60)
    print("测试 2: 链级 Prompt 构建")
    print("=" * 60)

    from prompts import get_prompt_manager

    manager = get_prompt_manager()

    # 构建测试数据
    chain_context = """
    【入口点】
    def upload_file(request):
        filename = request.POST['filename']
        content = request.FILES['file'].read()
        return save_file(filename, content)

    【调用链】
    upload_file -> save_file -> open(path, 'wb')

    【Sink 触发点】
    def save_file(filename, content):
        path = f"/uploads/{filename}"
        with open(path, 'wb') as f:
            f.write(content)
    """

    system, user, metadata = manager.build_chain_analysis_prompt(
        chain_id="test-001",
        sink_category="file_write",
        chain_context=chain_context,
        max_tokens=8000,
    )

    print(f"✓ Prompt 构建成功")
    print(f"  System Prompt 长度: {len(system)} 字符")
    print(f"  User Prompt 长度: {len(user)} 字符")
    print(f"  Token 使用: {metadata['token_usage']}")
    print(f"  是否截断: {metadata['truncated']}")
    print()

    # 验证包含高危类别提示词
    assert "任意文件写入" in system, "应包含 file_write 专项提示词"
    print("✓ 包含高危类别专项提示词")
    print()


def test_token_counter():
    """测试 Token 计数器"""
    print("=" * 60)
    print("测试 3: Token 计数器")
    print("=" * 60)

    from prompts import TokenCounter, count_tokens

    counter = TokenCounter()

    test_texts = [
        "Hello, world!",
        "你好，世界！这是一个测试。",
        "def hello():\n    print('Hello, world!')",
    ]

    for text in test_texts:
        tokens = counter.count(text)
        simple_count = count_tokens(text)
        print(f"文本: {text[:30]}...")
        print(f"  Token 数: {tokens}")
        print(f"  简便函数: {simple_count}")
        assert tokens == simple_count, "两种计数方式应一致"

    print("✓ Token 计数正常")
    print()


def test_token_truncation():
    """测试 Token 截断"""
    print("=" * 60)
    print("测试 4: Token 截断")
    print("=" * 60)

    from prompts import truncate_text_by_tokens, count_tokens

    long_text = "这是一个很长的文本。" * 100
    original_tokens = count_tokens(long_text)

    truncated = truncate_text_by_tokens(long_text, max_tokens=50)
    truncated_tokens = count_tokens(truncated)

    print(f"原始文本: {original_tokens} tokens")
    print(f"截断后: {truncated_tokens} tokens")
    print(f"截断比例: {truncated_tokens / original_tokens:.1%}")

    assert truncated_tokens <= 50, "截断后应不超过限制"
    print("✓ Token 截断正常")
    print()


def test_budget_manager():
    """测试预算管理器"""
    print("=" * 60)
    print("测试 5: Token 预算管理器")
    print("=" * 60)

    from prompts import TokenBudgetManager, ContentBlock, TokenPriority

    manager = TokenBudgetManager(max_total_tokens=200)

    blocks = [
        ContentBlock(
            text="这是系统提示词" * 10,
            priority=TokenPriority.CRITICAL,
            name="system_prompt"
        ),
        ContentBlock(
            text="这是高优先级代码" * 20,
            priority=TokenPriority.HIGH,
            name="sink_code"
        ),
        ContentBlock(
            text="这是中优先级内容" * 30,
            priority=TokenPriority.MEDIUM,
            name="chain_nodes"
        ),
        ContentBlock(
            text="这是低优先级元数据" * 40,
            priority=TokenPriority.LOW,
            name="metadata"
        ),
    ]

    final_prompt, budget_info = manager.build_prompt(blocks)

    print(f"✓ 预算管理完成")
    print(f"  最终 Token 数: {budget_info['total_tokens']}")
    print(f"  预算利用率: {budget_info['utilization']:.1%}")
    print(f"  截断块数: {budget_info['truncated_count']}")
    if budget_info['truncated_count'] > 0:
        print(f"  截断的块: {budget_info['truncated_blocks']}")
        print(f"  节省 Token: {budget_info.get('tokens_saved', 0)}")
    print()


def test_full_integration():
    """完整集成测试"""
    print("=" * 60)
    print("测试 6: 完整集成测试")
    print("=" * 60)

    from prompts import get_prompt_manager, TokenBudgetManager, ContentBlock, TokenPriority

    manager = get_prompt_manager()

    # 模拟构建一个完整的 Prompt
    system, user, metadata = manager.build_chain_analysis_prompt(
        chain_id="integration-test",
        sink_category="command_exec",
        chain_context="测试上下文" * 100,  # 故意制造较长上下文
    )

    print(f"✓ 完整集成测试通过")
    print(f"  System Prompt: {len(system)} 字符")
    print(f"  User Prompt: {len(user)} 字符")
    print(f"  Token 统计: {metadata['token_usage']}")
    print()


if __name__ == "__main__":
    try:
        print("\n" + "=" * 60)
        print(" Prompt 工程化系统测试套件")
        print("=" * 60 + "\n")

        test_prompt_manager()
        test_chain_prompt_build()
        test_token_counter()
        test_token_truncation()
        test_budget_manager()
        test_full_integration()

        print("=" * 60)
        print(" 所有测试通过! ✓")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
