"""验证 CodeIndexer 修复的测试脚本"""

import sys
import io
from pathlib import Path

# Windows 编码修复
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 添加项目根目录到路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_code_units_property():
    """测试 code_units 属性"""
    from config import AuditConfig
    from llm_client import create_llm_client
    from indexer.indexer import CodeIndexer

    print("=" * 60)
    print("测试 CodeIndexer.code_units 属性")
    print("=" * 60)

    # 加载配置
    config = AuditConfig.from_yaml("audit.config.yaml")
    llm_client = create_llm_client(config.llm)

    # 创建 indexer
    indexer = CodeIndexer(config, llm_client)

    # 测试 code_units 属性访问
    print("\n✅ 测试 1: 访问 code_units 属性")
    try:
        units = indexer.code_units
        print(f"   成功! 类型: {type(units)}")
        print(f"   code_units 数量: {len(units)}")
    except AttributeError as e:
        print(f"   ❌ 失败: {e}")
        return False

    # 测试 len() 操作
    print("\n✅ 测试 2: len(indexer.code_units)")
    try:
        count = len(indexer.code_units) if indexer.code_units else 0
        print(f"   成功! 数量: {count}")
    except Exception as e:
        print(f"   ❌ 失败: {e}")
        return False

    # 测试 .values() 迭代
    print("\n✅ 测试 3: 迭代 code_units.values()")
    try:
        for unit in (indexer.code_units or {}).values():
            print(f"   找到单元: {unit.symbol}")
            break  # 只测试第一个
        print(f"   成功!")
    except Exception as e:
        print(f"   ❌ 失败: {e}")
        return False

    return True


def test_missing_methods():
    """测试新添加的方法"""
    from config import AuditConfig
    from llm_client import create_llm_client
    from indexer.indexer import CodeIndexer

    print("\n" + "=" * 60)
    print("测试新添加的方法")
    print("=" * 60)

    # 加载配置
    config = AuditConfig.from_yaml("audit.config.yaml")
    llm_client = create_llm_client(config.llm)
    indexer = CodeIndexer(config, llm_client)

    # 测试 read_file
    print("\n✅ 测试 4: read_file() 方法")
    try:
        has_method = hasattr(indexer, 'read_file')
        print(f"   方法存在: {has_method}")
        if has_method:
            # 测试读取自身
            content = indexer.read_file(__file__, start_line=1, end_line=5)
            if content:
                print(f"   成功读取 {len(content)} 字符")
            else:
                print(f"   返回 None (文件可能不存在)")
    except Exception as e:
        print(f"   ❌ 失败: {e}")
        return False

    # 测试 list_files
    print("\n✅ 测试 5: list_files() 方法")
    try:
        has_method = hasattr(indexer, 'list_files')
        print(f"   方法存在: {has_method}")
        if has_method:
            files = indexer.list_files(pattern="**/*.py", max_results=5)
            print(f"   成功! 找到 {len(files)} 个文件")
            for f in files[:3]:
                print(f"     - {f}")
    except Exception as e:
        print(f"   ❌ 失败: {e}")
        return False

    return True


def test_required_methods():
    """测试所有必需的方法存在"""
    from config import AuditConfig
    from llm_client import create_llm_client
    from indexer.indexer import CodeIndexer

    print("\n" + "=" * 60)
    print("测试所有必需方法存在")
    print("=" * 60)

    # 加载配置
    config = AuditConfig.from_yaml("audit.config.yaml")
    llm_client = create_llm_client(config.llm)
    indexer = CodeIndexer(config, llm_client)

    required_methods = [
        'get_all_units',
        'get_unit',
        'index_directory',
        'list_files',
        'read_file',
        'search',
    ]

    all_exist = True
    for method_name in required_methods:
        exists = hasattr(indexer, method_name)
        status = "✅" if exists else "❌"
        print(f"   {status} {method_name}: {'存在' if exists else '缺失'}")
        if not exists:
            all_exist = False

    return all_exist


def main():
    """运行所有测试"""
    print("\n" + "🔍" * 30)
    print("CodeIndexer BUG 修复验证")
    print("🔍" * 30)

    results = []

    # 测试 1: code_units 属性
    try:
        result = test_code_units_property()
        results.append(("code_units 属性", result))
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        results.append(("code_units 属性", False))

    # 测试 2: 新方法
    try:
        result = test_missing_methods()
        results.append(("新添加方法", result))
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        results.append(("新添加方法", False))

    # 测试 3: 必需方法
    try:
        result = test_required_methods()
        results.append(("必需方法检查", result))
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        results.append(("必需方法检查", False))

    # 总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)

    for name, result in results:
        status = "✅ 通过" if result else "❌ 失败"
        print(f"   {status}: {name}")

    all_passed = all(r for _, r in results)

    if all_passed:
        print("\n🎉 所有测试通过! BUG 已修复!")
        return 0
    else:
        print("\n⚠️ 部分测试失败，请检查错误信息")
        return 1


if __name__ == "__main__":
    sys.exit(main())
