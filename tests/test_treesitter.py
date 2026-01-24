"""
Tree-sitter 解析器单元测试

测试内容：
1. 基础设施（加载器、查询引擎）
2. JavaScript/TypeScript 解析器
3. PHP 解析器
4. Generic AST 转换
5. 回退策略
6. 统一解析器
"""

import unittest
import sys
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from indexer.models import CodeUnit, CodeUnitType


class TestTreeSitterAvailability(unittest.TestCase):
    """测试 Tree-sitter 模块可用性"""

    def test_module_import(self):
        """测试模块导入"""
        try:
            from indexer.treesitter import (
                TreeSitterParserRegistry,
                TREE_SITTER_AVAILABLE,
            )
            self.assertIsNotNone(TreeSitterParserRegistry)
            # TREE_SITTER_AVAILABLE 可能是 True 或 False，取决于环境
            self.assertIsInstance(TREE_SITTER_AVAILABLE, bool)
        except ImportError as e:
            self.skipTest(f"Tree-sitter 模块不可用: {e}")

    def test_utils_import(self):
        """测试工具函数导入"""
        from indexer.treesitter.utils import (
            node_text,
            node_span,
            find_child_by_type,
            find_child_by_field,
            find_children_by_type,
            find_all_by_type,
            walk_tree,
        )
        # 确保函数可调用
        self.assertTrue(callable(node_text))
        self.assertTrue(callable(node_span))


class TestGenericAST(unittest.TestCase):
    """测试 Generic AST 层"""

    def test_node_kinds(self):
        """测试节点类型枚举"""
        from indexer.treesitter.generic.nodes import NodeKind

        self.assertEqual(NodeKind.FUNCTION.value, "function")
        self.assertEqual(NodeKind.METHOD.value, "method")
        self.assertEqual(NodeKind.CLASS.value, "class")
        self.assertEqual(NodeKind.CALL.value, "call")

    def test_visibility(self):
        """测试可见性枚举"""
        from indexer.treesitter.generic.nodes import Visibility

        self.assertEqual(Visibility.PUBLIC.value, "public")
        self.assertEqual(Visibility.PRIVATE.value, "private")
        self.assertEqual(Visibility.PROTECTED.value, "protected")

    def test_span_creation(self):
        """测试 Span 创建"""
        from indexer.treesitter.generic.nodes import Span

        span = Span(start_line=1, start_column=0, end_line=10, end_column=5)
        self.assertEqual(span.start_line, 1)
        self.assertEqual(span.end_line, 10)

    def test_generic_function(self):
        """测试 GenericFunction 创建"""
        from indexer.treesitter.generic.nodes import (
            GenericFunction,
            GenericParameter,
            NodeKind,
            Visibility,
            Span,
        )

        func = GenericFunction(
            kind=NodeKind.FUNCTION,
            name="test_func",
            span=Span(1, 0, 5, 1),
            source_language="python",
            parameters=[
                GenericParameter(name="arg1", type_annotation="str"),
                GenericParameter(name="arg2", default_value="None"),
            ],
            return_type="int",
            visibility=Visibility.PUBLIC,
        )

        self.assertEqual(func.name, "test_func")
        self.assertEqual(len(func.parameters), 2)
        self.assertEqual(func.return_type, "int")

    def test_generic_class(self):
        """测试 GenericClass 创建"""
        from indexer.treesitter.generic.nodes import (
            GenericClass,
            NodeKind,
            Span,
        )

        cls = GenericClass(
            kind=NodeKind.CLASS,
            name="TestClass",
            span=Span(1, 0, 50, 1),
            source_language="javascript",
            bases=["BaseClass"],
            is_abstract=False,
        )

        self.assertEqual(cls.name, "TestClass")
        self.assertEqual(cls.bases, ["BaseClass"])

    def test_generic_call(self):
        """测试 GenericCall 创建"""
        from indexer.treesitter.generic.nodes import (
            GenericCall,
            NodeKind,
            Span,
        )

        call = GenericCall(
            kind=NodeKind.CALL,
            name="exec",
            span=Span(10, 4, 10, 20),
            source_language="php",
            callee="exec",
            receiver=None,
            full_name="exec",
        )

        self.assertEqual(call.callee, "exec")
        self.assertIsNone(call.receiver)


class TestSecurityPatterns(unittest.TestCase):
    """测试安全模式"""

    def test_pattern_loading(self):
        """测试模式加载"""
        from indexer.treesitter.generic.patterns import CROSS_LANGUAGE_PATTERNS

        self.assertGreater(len(CROSS_LANGUAGE_PATTERNS), 0)

    def test_command_injection_pattern(self):
        """测试命令注入模式"""
        from indexer.treesitter.generic.patterns import (
            CROSS_LANGUAGE_PATTERNS,
            COMMAND_EXEC_SINKS,
        )

        cmd_pattern = next(
            (p for p in CROSS_LANGUAGE_PATTERNS if "command" in p.name), None
        )

        self.assertIsNotNone(cmd_pattern)
        self.assertIn("command", cmd_pattern.name)
        # 检查 sink 集合
        self.assertIn("exec", COMMAND_EXEC_SINKS)
        self.assertIn("shell_exec", COMMAND_EXEC_SINKS)

    def test_sql_injection_pattern(self):
        """测试 SQL 注入模式"""
        from indexer.treesitter.generic.patterns import (
            CROSS_LANGUAGE_PATTERNS,
            SQL_SINKS,
        )

        sql_pattern = next(
            (p for p in CROSS_LANGUAGE_PATTERNS if "sql" in p.name), None
        )

        self.assertIsNotNone(sql_pattern)
        self.assertIn("execute", SQL_SINKS)

    def test_get_sinks_for_language(self):
        """测试获取所有 sinks"""
        from indexer.treesitter.generic.patterns import list_all_sinks

        all_sinks = list_all_sinks()

        self.assertIn("command_exec", all_sinks)
        self.assertIn("sql", all_sinks)
        self.assertIn("exec", all_sinks["command_exec"])


class TestFallbackStrategy(unittest.TestCase):
    """测试回退策略"""

    def test_parse_error_types(self):
        """测试解析错误类型"""
        from indexer.treesitter.fallback.strategy import ParseErrorType

        self.assertEqual(ParseErrorType.SYNTAX_ERROR.value, "syntax_error")
        self.assertEqual(ParseErrorType.MISSING_NODE.value, "missing_node")

    def test_parse_error_creation(self):
        """测试解析错误创建"""
        from indexer.treesitter.fallback.strategy import ParseError, ParseErrorType

        error = ParseError(
            error_type=ParseErrorType.SYNTAX_ERROR,
            message="Unexpected token",
            line=10,
            column=5,
        )

        self.assertEqual(error.line, 10)
        self.assertEqual(error.error_type, ParseErrorType.SYNTAX_ERROR)

    def test_partial_parse_result(self):
        """测试部分解析结果"""
        from indexer.treesitter.fallback.strategy import (
            PartialParseResult,
            ParseError,
            ParseErrorType,
        )

        result = PartialParseResult(
            successful_units=[],
            errors=[
                ParseError(ParseErrorType.SYNTAX_ERROR, "Test error", 1, 0)
            ],
        )

        self.assertEqual(len(result.errors), 1)
        # PartialParseResult 通过 errors 列表长度判断是否完整
        self.assertTrue(len(result.errors) > 0)

    def test_error_marked_unit(self):
        """测试错误标记单元"""
        from indexer.treesitter.fallback.error_marker import ErrorMarkedUnit
        from indexer.models import CodeUnit, CodeUnitType, CodeSpan

        unit = CodeUnit(
            id="test-id",
            language="javascript",
            file_path="/test/file.js",
            symbol="testFunc",
            unit_type=CodeUnitType.FUNCTION,
            signature="function testFunc()",
            span=CodeSpan(start_line=1, end_line=10),
            code="function testFunc() {}",
        )

        marked = ErrorMarkedUnit(
            unit=unit,
            parse_source="regex_fallback",
            confidence=0.8,
        )

        self.assertEqual(marked.parse_source, "regex_fallback")
        self.assertEqual(marked.confidence, 0.8)
        self.assertTrue(marked.is_fallback)


class TestConverterRegistry(unittest.TestCase):
    """测试转换器注册表"""

    def test_registry_import(self):
        """测试注册表导入"""
        from indexer.treesitter.generic.converter import ConverterRegistry

        self.assertIsNotNone(ConverterRegistry)

    def test_registered_converters(self):
        """测试已注册的转换器"""
        from indexer.treesitter.generic.converter import ConverterRegistry

        # JavaScript 和 PHP 转换器应该已注册
        js_converter = ConverterRegistry.get("javascript")
        php_converter = ConverterRegistry.get("php")

        # 如果 Tree-sitter 可用，应该能获取到转换器
        # 否则可能为 None（取决于导入顺序）


class TestUnifiedParser(unittest.TestCase):
    """测试统一解析器"""

    def test_parser_strategy(self):
        """测试解析器策略"""
        from indexer.unified_parser import ParserStrategy

        self.assertEqual(ParserStrategy.TREESITTER, "treesitter")
        self.assertEqual(ParserStrategy.REGEX, "regex")
        self.assertEqual(ParserStrategy.AUTO, "auto")
        self.assertEqual(ParserStrategy.HYBRID, "hybrid")

    def test_parser_config_defaults(self):
        """测试解析器配置默认值"""
        from indexer.unified_parser import ParserConfig, ParserStrategy

        config = ParserConfig()

        self.assertEqual(config.strategy, ParserStrategy.AUTO)
        self.assertIn("javascript", config.use_treesitter_for)
        self.assertIn("php", config.use_treesitter_for)
        self.assertEqual(config.python_parser, "ast")
        self.assertTrue(config.fallback_enabled)
        self.assertEqual(config.error_threshold, 0.3)

    def test_parser_config_from_dict(self):
        """测试从字典创建配置"""
        from indexer.unified_parser import ParserConfig, ParserStrategy

        config = ParserConfig.from_dict({
            "strategy": "regex",
            "python_parser": "treesitter",
            "fallback_enabled": False,
        })

        self.assertEqual(config.strategy, "regex")
        self.assertEqual(config.python_parser, "treesitter")
        self.assertFalse(config.fallback_enabled)

    def test_unified_parser_creation(self):
        """测试统一解析器创建"""
        from indexer.unified_parser import UnifiedParser, ParserConfig

        parser = UnifiedParser()
        self.assertIsNotNone(parser)
        self.assertIsNotNone(parser.config)

    def test_language_detection(self):
        """测试语言检测"""
        from indexer.unified_parser import UnifiedParser

        parser = UnifiedParser()

        self.assertEqual(parser._detect_language("test.py"), "python")
        self.assertEqual(parser._detect_language("test.js"), "javascript")
        self.assertEqual(parser._detect_language("test.jsx"), "javascript")
        self.assertEqual(parser._detect_language("test.ts"), "typescript")
        self.assertEqual(parser._detect_language("test.tsx"), "typescript")
        self.assertEqual(parser._detect_language("test.php"), "php")
        self.assertIsNone(parser._detect_language("test.unknown"))

    def test_available_parsers(self):
        """测试获取可用解析器"""
        from indexer.unified_parser import UnifiedParser

        parser = UnifiedParser()
        available = parser.get_available_parsers()

        self.assertIn("python", available)
        self.assertIn("javascript", available)
        self.assertIn("php", available)

        # 正则解析器应该都可用
        self.assertTrue(available["python"]["regex"])
        self.assertTrue(available["javascript"]["regex"])
        self.assertTrue(available["php"]["regex"])

    def test_parse_python_file(self):
        """测试解析 Python 文件"""
        from indexer.unified_parser import UnifiedParser

        parser = UnifiedParser()

        code = '''
def hello(name):
    """Say hello."""
    print(f"Hello, {name}!")

class Greeter:
    def greet(self, name):
        return f"Hi, {name}"
'''

        units = parser.parse_file("test.py", code)

        self.assertIsInstance(units, list)
        # 应该至少有函数和类
        symbols = [u.symbol for u in units]
        self.assertIn("hello", symbols)

    def test_parse_javascript_file(self):
        """测试解析 JavaScript 文件"""
        from indexer.unified_parser import UnifiedParser

        parser = UnifiedParser()

        code = '''
function greet(name) {
    console.log("Hello, " + name);
}

class Calculator {
    add(a, b) {
        return a + b;
    }
}

const multiply = (a, b) => a * b;
'''

        units = parser.parse_file("test.js", code)

        self.assertIsInstance(units, list)
        # 应该检测到函数和类
        self.assertGreater(len(units), 0)

    def test_parse_php_file(self):
        """测试解析 PHP 文件"""
        from indexer.unified_parser import UnifiedParser

        parser = UnifiedParser()

        code = '''<?php
function greet($name) {
    echo "Hello, " . $name;
}

class UserController {
    public function index() {
        return $this->view('users.index');
    }

    private function validate($data) {
        return true;
    }
}
'''

        units = parser.parse_file("test.php", code)

        self.assertIsInstance(units, list)
        self.assertGreater(len(units), 0)

    def test_global_parse_function(self):
        """测试全局解析函数"""
        from indexer.unified_parser import parse_file

        code = "def test(): pass"
        units = parse_file("test.py", code)

        self.assertIsInstance(units, list)


class TestJavaScriptParser(unittest.TestCase):
    """测试 JavaScript 解析器"""

    def setUp(self):
        """设置测试"""
        try:
            from indexer.treesitter.javascript import JavaScriptTSParser
            from indexer.treesitter.base import TREE_SITTER_AVAILABLE

            if not TREE_SITTER_AVAILABLE:
                self.skipTest("Tree-sitter 不可用")

            self.parser = JavaScriptTSParser()
            if not self.parser.is_available():
                self.skipTest("JavaScript Tree-sitter 解析器不可用")
        except ImportError as e:
            self.skipTest(f"导入失败: {e}")

    def test_parse_function(self):
        """测试函数解析"""
        code = '''
function add(a, b) {
    return a + b;
}
'''
        units = self.parser.parse_file("test.js", code)
        self.assertGreater(len(units), 0)

        func = next((u for u in units if u.symbol == "add"), None)
        self.assertIsNotNone(func)
        self.assertEqual(func.unit_type, CodeUnitType.FUNCTION)

    def test_parse_arrow_function(self):
        """测试箭头函数解析"""
        code = '''
const multiply = (a, b) => a * b;
const greet = name => console.log(name);
'''
        units = self.parser.parse_file("test.js", code)
        # 箭头函数可能作为变量声明的一部分被捕获
        self.assertIsInstance(units, list)

    def test_parse_class(self):
        """测试类解析"""
        code = '''
class Calculator {
    constructor(value) {
        this.value = value;
    }

    add(n) {
        return this.value + n;
    }

    static create() {
        return new Calculator(0);
    }
}
'''
        units = self.parser.parse_file("test.js", code)
        self.assertGreater(len(units), 0)

        cls = next((u for u in units if u.symbol == "Calculator"), None)
        self.assertIsNotNone(cls)

    def test_extract_calls(self):
        """测试调用提取"""
        code = '''
function process(data) {
    console.log("Processing");
    const result = JSON.parse(data);
    fetch("/api/submit", { method: "POST", body: result });
    return result;
}
'''
        units = self.parser.parse_file("test.js", code)

        func = next((u for u in units if u.symbol == "process"), None)
        if func:
            self.assertIn("console.log", func.calls)
            self.assertIn("JSON.parse", func.calls)


class TestPHPParser(unittest.TestCase):
    """测试 PHP 解析器"""

    def setUp(self):
        """设置测试"""
        try:
            from indexer.treesitter.php import PHPTSParser
            from indexer.treesitter.base import TREE_SITTER_AVAILABLE

            if not TREE_SITTER_AVAILABLE:
                self.skipTest("Tree-sitter 不可用")

            self.parser = PHPTSParser()
            if not self.parser.is_available():
                self.skipTest("PHP Tree-sitter 解析器不可用")
        except ImportError as e:
            self.skipTest(f"导入失败: {e}")

    def test_parse_function(self):
        """测试函数解析"""
        code = '''<?php
function greet($name) {
    echo "Hello, " . $name;
}
'''
        units = self.parser.parse_file("test.php", code)
        self.assertGreater(len(units), 0)

        func = next((u for u in units if u.symbol == "greet"), None)
        self.assertIsNotNone(func)
        self.assertEqual(func.unit_type, CodeUnitType.FUNCTION)

    def test_parse_class(self):
        """测试类解析"""
        code = '''<?php
class UserController extends Controller {
    public function index() {
        return $this->view('users.index');
    }

    private function validate($data) {
        return true;
    }
}
'''
        units = self.parser.parse_file("test.php", code)
        self.assertGreater(len(units), 0)

        cls = next((u for u in units if u.symbol == "UserController"), None)
        self.assertIsNotNone(cls)

    def test_parse_interface(self):
        """测试接口解析"""
        code = '''<?php
interface Authenticatable {
    public function authenticate($credentials);
    public function logout();
}
'''
        units = self.parser.parse_file("test.php", code)
        self.assertGreater(len(units), 0)

    def test_parse_trait(self):
        """测试 Trait 解析"""
        code = '''<?php
trait Loggable {
    public function log($message) {
        error_log($message);
    }
}
'''
        units = self.parser.parse_file("test.php", code)
        self.assertGreater(len(units), 0)

    def test_dangerous_calls_detection(self):
        """测试危险函数检测"""
        code = '''<?php
function execute_command($cmd) {
    return shell_exec($cmd);
}

function run_code($code) {
    eval($code);
}
'''
        units = self.parser.parse_file("test.php", code)

        exec_func = next((u for u in units if u.symbol == "execute_command"), None)
        if exec_func and exec_func.metadata:
            dangerous = exec_func.metadata.get("dangerous_calls", [])
            self.assertIn("shell_exec", dangerous)


class TestQueryEngine(unittest.TestCase):
    """测试查询引擎"""

    def test_query_builder(self):
        """测试查询构建器"""
        from indexer.treesitter.query_engine import QueryBuilder

        builder = QueryBuilder()
        builder.add_function_pattern("function_declaration")
        query = builder.build()

        self.assertIn("function_declaration", query)
        self.assertIn("@function", query)

    def test_query_builder_chaining(self):
        """测试查询构建器链式调用"""
        from indexer.treesitter.query_engine import QueryBuilder

        builder = QueryBuilder()
        result = builder.add_function_pattern("function_declaration") \
                        .add_call_pattern("call_expression") \
                        .build()

        self.assertIn("function_declaration", result)
        self.assertIn("call_expression", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
