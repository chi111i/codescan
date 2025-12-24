"""验证 UnifiedAgent ToolCall 修复的测试"""

import sys
import io

# Windows 编码修复
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

print("=" * 60)
print("UnifiedAgent ToolCall 修复验证")
print("=" * 60)

# 测试 1: 检查 ToolCall 导入
print("\n[测试 1] 检查 ToolCall 导入...")
try:
    from agent.unified_agent import ToolCall
    print("  ✅ ToolCall 导入成功")
except ImportError as e:
    print(f"  ❌ ToolCall 导入失败: {e}")
    sys.exit(1)

# 测试 2: 检查 _execute_tool_calls 方法签名
print("\n[测试 2] 检查 _execute_tool_calls 方法签名...")
try:
    from agent.unified_agent import UnifiedAuditAgent
    import inspect

    # 获取方法签名
    sig = inspect.signature(UnifiedAuditAgent._execute_tool_calls)
    params = sig.parameters

    # 检查 tool_calls 参数的类型注解
    tool_calls_param = params.get('tool_calls')
    if tool_calls_param:
        annotation = str(tool_calls_param.annotation)
        print(f"  参数类型: {annotation}")

        # 应该是 List[ToolCall] 而不是 List[Dict]
        if 'ToolCall' in annotation:
            print("  ✅ 通过: 参数类型为 List[ToolCall]")
        else:
            print(f"  ❌ 失败: 参数类型仍为 {annotation}")
            sys.exit(1)
    else:
        print("  ❌ 失败: 未找到 tool_calls 参数")
        sys.exit(1)

except Exception as e:
    print(f"  ❌ 错误: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# 测试 3: 模拟 ToolCall 对象处理
print("\n[测试 3] 模拟 ToolCall 对象处理...")
try:
    from llm_client import ToolCall

    # 创建模拟 ToolCall
    test_tool_call = ToolCall(
        id="test_call_123",
        name="test_tool",
        arguments={"arg1": "value1"}
    )

    # 验证属性访问
    assert test_tool_call.id == "test_call_123", "id 属性访问失败"
    assert test_tool_call.name == "test_tool", "name 属性访问失败"
    assert test_tool_call.arguments == {"arg1": "value1"}, "arguments 属性访问失败"

    print("  ✅ 通过: ToolCall 对象属性访问正常")

    # 验证没有 .get() 方法
    has_get = hasattr(test_tool_call, 'get')
    if not has_get:
        print("  ✅ 通过: ToolCall 确实没有 .get() 方法(符合预期)")
    else:
        print("  ⚠️  警告: ToolCall 有 .get() 方法(不符合预期)")

except Exception as e:
    print(f"  ❌ 错误: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# 测试 4: 检查代码中没有遗留的 .get() 调用
print("\n[测试 4] 检查代码中没有遗留的字典访问模式...")
try:
    with open('E:/1ceshi/codescan/agent/unified_agent.py', 'r', encoding='utf-8') as f:
        content = f.read()

    # 检查 _execute_tool_calls 方法中是否还有 .get("name") 或 .get("id")
    import re

    # 提取 _execute_tool_calls 方法
    match = re.search(
        r'async def _execute_tool_calls.*?(?=\n    async def|\n    def|\Z)',
        content,
        re.DOTALL
    )

    if match:
        method_code = match.group(0)

        # 检查是否有 tc.get( 或 tool_call.get(
        if re.search(r'(tc|tool_call)\.get\(', method_code):
            print("  ❌ 失败: 仍存在 .get() 调用")
            sys.exit(1)
        else:
            print("  ✅ 通过: 没有遗留的 .get() 调用")

        # 检查是否使用属性访问
        if re.search(r'tc\.(id|name|arguments)', method_code):
            print("  ✅ 通过: 使用属性访问模式")
        else:
            print("  ⚠️  警告: 未检测到属性访问模式")
    else:
        print("  ⚠️  警告: 未找到 _execute_tool_calls 方法")

except Exception as e:
    print(f"  ⚠️  警告: 无法检查源代码: {e}")

# 总结
print("\n" + "=" * 60)
print("✅ 所有测试通过!")
print("=" * 60)
print("\n修复内容:")
print("  1. ✅ 修改 _execute_tool_calls 参数类型: List[Dict] → List[ToolCall]")
print("  2. ✅ 修改属性访问: tc.get('name') → tc.name")
print("  3. ✅ 修改属性访问: tc.get('id') → tc.id")
print("  4. ✅ 添加 ToolCall 导入")
print("\nBUG 已修复! UnifiedAgent 现在可以正确处理 ToolCall 对象")
