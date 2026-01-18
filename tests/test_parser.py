"""
测试代码解析器
"""

import pytest
import sys
import os

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from indexer.parser import PythonParser, JavaScriptParser, PHPParser
from indexer.models import CodeUnitType


class TestPythonParser:
    """测试 Python 解析器"""

    def setup_method(self):
        self.parser = PythonParser()

    def test_sync_function_parsing(self):
        """测试同步函数解析"""
        code = '''
def hello_world(name: str) -> str:
    """Say hello to someone."""
    return f"Hello, {name}!"
'''
        units = self.parser.parse_file("test.py", code)
        assert len(units) == 1
        unit = units[0]
        assert unit.symbol == "hello_world"
        assert unit.unit_type == CodeUnitType.FUNCTION
        assert "def hello_world" in unit.signature
        assert "async" not in unit.signature

    def test_async_function_parsing(self):
        """测试异步函数解析 - P0-2 验证"""
        code = '''
async def fetch_data(url: str) -> dict:
    """Fetch data from URL asynchronously."""
    async with aiohttp.ClientSession() as session:
        response = await session.get(url)
        return await response.json()
'''
        units = self.parser.parse_file("test.py", code)
        assert len(units) == 1
        unit = units[0]
        assert unit.symbol == "fetch_data"
        assert unit.unit_type == CodeUnitType.FUNCTION
        # 验证签名包含 async def
        assert "async def" in unit.signature
        assert "fetch_data(url: str)" in unit.signature
        assert "-> dict" in unit.signature

    def test_async_function_calls_extraction(self):
        """测试异步函数中的调用提取"""
        code = '''
async def process_request(request):
    data = await request.json()
    result = await database.query("SELECT * FROM users")
    await cache.set("key", result)
    return result
'''
        units = self.parser.parse_file("test.py", code)
        assert len(units) == 1
        unit = units[0]
        calls = unit.calls
        # 验证调用被正确提取
        assert "request.json" in calls or "json" in calls
        assert "database.query" in calls or "query" in calls
        assert "cache.set" in calls or "set" in calls

    def test_async_class_method_parsing(self):
        """测试异步类方法解析"""
        code = '''
class DataService:
    """Data service class."""

    async def get_user(self, user_id: int) -> dict:
        """Get user by ID."""
        return await self.db.fetch_one(user_id)

    async def create_user(self, data: dict) -> int:
        """Create a new user."""
        return await self.db.insert(data)

    def sync_method(self) -> None:
        """A sync method."""
        pass
'''
        units = self.parser.parse_file("test.py", code)

        # 应该有 1 个类 + 3 个方法 = 4 个单元
        assert len(units) == 4

        # 找到方法
        methods = [u for u in units if u.unit_type == CodeUnitType.METHOD]
        assert len(methods) == 3

        # 验证异步方法
        get_user = next((u for u in methods if u.symbol == "get_user"), None)
        assert get_user is not None
        assert "async def" in get_user.signature

        create_user = next((u for u in methods if u.symbol == "create_user"), None)
        assert create_user is not None
        assert "async def" in create_user.signature

        # 验证同步方法
        sync_method = next((u for u in methods if u.symbol == "sync_method"), None)
        assert sync_method is not None
        assert "async def" not in sync_method.signature
        assert "def sync_method" in sync_method.signature

    def test_async_handler_detection(self):
        """测试异步 Web 处理器检测"""
        code = '''
@route("/users")
async def get_users(request):
    """Get all users endpoint."""
    return await User.all()

@post("/users")
async def create_user(request):
    """Create user endpoint."""
    data = await request.json()
    return await User.create(**data)
'''
        units = self.parser.parse_file("test.py", code)
        assert len(units) == 2

        # 两个都应该被标记为 HANDLER（因为有 route/post 装饰器）
        for unit in units:
            assert unit.unit_type == CodeUnitType.HANDLER
            assert "async def" in unit.signature

    def test_mixed_async_sync_functions(self):
        """测试混合异步和同步函数"""
        code = '''
def sync_helper(data):
    return data.strip()

async def async_process(data):
    cleaned = sync_helper(data)
    return await api.send(cleaned)

def another_sync():
    pass

async def another_async():
    pass
'''
        units = self.parser.parse_file("test.py", code)
        assert len(units) == 4

        sync_funcs = [u for u in units if "async def" not in u.signature]
        async_funcs = [u for u in units if "async def" in u.signature]

        assert len(sync_funcs) == 2
        assert len(async_funcs) == 2

        # 验证同步函数签名
        for unit in sync_funcs:
            assert unit.signature.startswith("def ")

        # 验证异步函数签名
        for unit in async_funcs:
            assert unit.signature.startswith("async def ")

    def test_async_with_complex_signature(self):
        """测试复杂签名的异步函数"""
        code = '''
async def complex_func(
    arg1: str,
    arg2: int = 10,
    *args,
    **kwargs
) -> Optional[Dict[str, Any]]:
    """Complex async function."""
    pass
'''
        units = self.parser.parse_file("test.py", code)
        assert len(units) == 1
        unit = units[0]

        assert "async def" in unit.signature
        assert "complex_func" in unit.signature
        assert "arg1: str" in unit.signature
        assert "*args" in unit.signature
        assert "**kwargs" in unit.signature


class TestJavaScriptParser:
    """测试 JavaScript 解析器"""

    def setup_method(self):
        self.parser = JavaScriptParser()

    def test_async_function_parsing(self):
        """测试 JS 异步函数解析"""
        code = '''
async function fetchData(url) {
    const response = await fetch(url);
    return await response.json();
}
'''
        units = self.parser.parse_file("test.js", code)
        assert len(units) >= 1

        func = units[0]
        assert func.symbol == "fetchData"
        assert "async" in func.signature

    def test_async_arrow_function_parsing(self):
        """测试 JS 异步箭头函数解析"""
        code = '''
const processData = async (data) => {
    const result = await transform(data);
    return result;
};
'''
        units = self.parser.parse_file("test.js", code)
        assert len(units) >= 1

        func = units[0]
        assert func.symbol == "processData"
        assert "async" in func.signature


class TestPHPParser:
    """测试 PHP 解析器"""

    def setup_method(self):
        self.parser = PHPParser()

    def test_function_parsing(self):
        """测试 PHP 函数解析"""
        code = '''<?php
function hello($name) {
    return "Hello, $name!";
}
?>'''
        units = self.parser.parse_file("test.php", code)
        assert len(units) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
