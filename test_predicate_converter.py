"""测试 Predicate 转换器"""

import sys
import io
from pathlib import Path

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from scripts.fortify_migration.predicate_converter import PredicateConverter

def test_predicate_converter():
    """测试 Predicate 转换"""
    print("=" * 60)
    print("测试：Predicate 转换器")
    print("=" * 60)

    converter = PredicateConverter()

    test_cases = [
        # Level 1: 直接转换
        (
            'FunctionCall fc: fc.name == "eval"',
            ['eval'],
            'direct'
        ),
        (
            'FunctionPointerCall fpc: fpc.name == "system"',
            ['system'],
            'direct'
        ),

        # Level 2: 模块调用
        (
            'instance is [FieldAccess: name == "os~module"] and fc.name == "system"',
            ['os.system'],
            'heuristic'
        ),

        # Level 2: 正则匹配
        (
            'fc.name matches "exec.*"',
            ['regex:exec.*'],
            'heuristic'
        ),

        # Level 2: 字符串常量
        (
            'StringLiteral: constantValue matches ".*password.*"',
            ['contains:password'],
            'heuristic'
        ),
    ]

    passed = 0
    failed = 0

    for i, (predicate, expected_patterns, expected_method) in enumerate(test_cases, 1):
        patterns, method, confidence = converter.convert(predicate)

        print(f"\n测试 {i}:")
        print(f"  Predicate: {predicate[:60]}...")
        print(f"  预期: {expected_patterns} ({expected_method})")
        print(f"  实际: {patterns} ({method}, 置信度={confidence:.2f})")

        if patterns == expected_patterns and method == expected_method:
            print(f"  ✓ 通过")
            passed += 1
        else:
            print(f"  ✗ 失败")
            failed += 1

    print(f"\n" + "=" * 60)
    print(f"测试结果: {passed}/{len(test_cases)} 通过")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = test_predicate_converter()
    sys.exit(0 if success else 1)
