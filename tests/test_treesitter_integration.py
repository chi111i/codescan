"""
Tree-sitter 集成测试

测试所有语言解析器的端到端功能。
"""

import unittest
import tempfile
import os
from pathlib import Path


class TestTreeSitterIntegration(unittest.TestCase):
    """Tree-sitter 集成测试"""

    @classmethod
    def setUpClass(cls):
        """设置测试环境"""
        cls.test_dir = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        """清理测试环境"""
        import shutil
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def _create_test_file(self, filename: str, content: str) -> str:
        """创建测试文件"""
        path = os.path.join(self.test_dir, filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path


class TestUnifiedParserIntegration(TestTreeSitterIntegration):
    """统一解析器集成测试"""

    def test_unified_parser_import(self):
        """测试统一解析器导入"""
        from indexer.treesitter.unified_parser import UnifiedParser
        parser = UnifiedParser()
        self.assertIsNotNone(parser)

    def test_parse_javascript_file(self):
        """测试解析 JavaScript 文件"""
        from indexer.treesitter.unified_parser import UnifiedParser

        js_code = """
function greet(name) {
    console.log("Hello, " + name);
}

class UserService {
    constructor(db) {
        this.db = db;
    }

    async getUser(id) {
        return await this.db.query("SELECT * FROM users WHERE id = " + id);
    }
}

module.exports = { greet, UserService };
"""
        path = self._create_test_file("test.js", js_code)
        parser = UnifiedParser()
        result = parser.parse_file(path)

        self.assertIsNotNone(result)
        # 检查是否提取了函数和类
        functions = [u for u in result if u.unit_type.value in ("function", "method")]
        classes = [u for u in result if u.unit_type.value == "class"]

        self.assertGreater(len(functions), 0, "Should find functions")
        self.assertGreater(len(classes), 0, "Should find classes")

    def test_parse_php_file(self):
        """测试解析 PHP 文件"""
        from indexer.treesitter.unified_parser import UnifiedParser

        php_code = """<?php
namespace App\\Controllers;

class UserController {
    private $userService;

    public function __construct($userService) {
        $this->userService = $userService;
    }

    public function index() {
        return $this->userService->getAllUsers();
    }

    public function show($id) {
        $user = $this->userService->find($id);
        return response()->json($user);
    }
}
"""
        path = self._create_test_file("UserController.php", php_code)
        parser = UnifiedParser()
        result = parser.parse_file(path)

        self.assertIsNotNone(result)
        # 检查类和方法
        self.assertTrue(any("UserController" in str(u.symbol) for u in result))

    def test_parse_java_file(self):
        """测试解析 Java 文件"""
        from indexer.treesitter.unified_parser import UnifiedParser

        java_code = """
package com.example.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/{id}")
    public User getUser(@PathVariable Long id) {
        return userService.findById(id);
    }

    @PostMapping
    public User createUser(@RequestBody User user) {
        return userService.save(user);
    }
}
"""
        path = self._create_test_file("UserController.java", java_code)
        parser = UnifiedParser()
        result = parser.parse_file(path)

        self.assertIsNotNone(result)
        self.assertTrue(any("UserController" in str(u.symbol) for u in result))

    def test_parse_go_file(self):
        """测试解析 Go 文件"""
        from indexer.treesitter.unified_parser import UnifiedParser

        go_code = """
package main

import (
    "fmt"
    "net/http"
    "github.com/gin-gonic/gin"
)

type UserHandler struct {
    service *UserService
}

func NewUserHandler(s *UserService) *UserHandler {
    return &UserHandler{service: s}
}

func (h *UserHandler) GetUser(c *gin.Context) {
    id := c.Param("id")
    user, err := h.service.FindByID(id)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
        return
    }
    c.JSON(http.StatusOK, user)
}
"""
        path = self._create_test_file("handler.go", go_code)
        parser = UnifiedParser()
        result = parser.parse_file(path)

        self.assertIsNotNone(result)
        # 检查结构体和方法
        self.assertTrue(any("UserHandler" in str(u.symbol) for u in result))

    def test_parse_rust_file(self):
        """测试解析 Rust 文件"""
        from indexer.treesitter.unified_parser import UnifiedParser

        rust_code = """
use std::io::Read;

pub struct Config {
    pub host: String,
    pub port: u16,
}

impl Config {
    pub fn new(host: String, port: u16) -> Self {
        Config { host, port }
    }

    pub fn load_from_file(path: &str) -> Result<Config, std::io::Error> {
        let mut file = std::fs::File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(Config::new(contents, 8080))
    }
}

pub async fn handle_request(req: Request) -> Response {
    // Process request
    Response::ok()
}
"""
        path = self._create_test_file("config.rs", rust_code)
        parser = UnifiedParser()
        result = parser.parse_file(path)

        self.assertIsNotNone(result)
        self.assertTrue(any("Config" in str(u.symbol) for u in result))

    def test_parse_csharp_file(self):
        """测试解析 C# 文件"""
        from indexer.treesitter.unified_parser import UnifiedParser

        csharp_code = """
using System;
using Microsoft.AspNetCore.Mvc;

namespace MyApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<User>> GetUser(int id)
        {
            var user = await _userService.GetByIdAsync(id);
            if (user == null)
                return NotFound();
            return Ok(user);
        }
    }
}
"""
        path = self._create_test_file("UsersController.cs", csharp_code)
        parser = UnifiedParser()
        result = parser.parse_file(path)

        self.assertIsNotNone(result)
        self.assertTrue(any("UsersController" in str(u.symbol) for u in result))

    def test_parse_ruby_file(self):
        """测试解析 Ruby 文件"""
        from indexer.treesitter.unified_parser import UnifiedParser

        ruby_code = """
class UsersController < ApplicationController
  before_action :authenticate_user!

  def index
    @users = User.all
    render json: @users
  end

  def show
    @user = User.find(params[:id])
    render json: @user
  end

  def create
    @user = User.new(user_params)
    if @user.save
      render json: @user, status: :created
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end

  private

  def user_params
    params.require(:user).permit(:name, :email)
  end
end
"""
        path = self._create_test_file("users_controller.rb", ruby_code)
        parser = UnifiedParser()
        result = parser.parse_file(path)

        self.assertIsNotNone(result)
        self.assertTrue(any("UsersController" in str(u.symbol) for u in result))

    def test_parse_kotlin_file(self):
        """测试解析 Kotlin 文件"""
        from indexer.treesitter.unified_parser import UnifiedParser

        kotlin_code = """
package com.example.api

import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/users")
class UserController(private val userService: UserService) {

    @GetMapping("/{id}")
    suspend fun getUser(@PathVariable id: Long): User {
        return userService.findById(id)
    }

    @PostMapping
    suspend fun createUser(@RequestBody user: User): User {
        return userService.save(user)
    }
}

data class User(
    val id: Long,
    val name: String,
    val email: String
)
"""
        path = self._create_test_file("UserController.kt", kotlin_code)
        parser = UnifiedParser()
        result = parser.parse_file(path)

        self.assertIsNotNone(result)
        self.assertTrue(any("UserController" in str(u.symbol) for u in result))

    def test_parse_cpp_file(self):
        """测试解析 C++ 文件"""
        from indexer.treesitter.unified_parser import UnifiedParser

        cpp_code = """
#include <iostream>
#include <string>
#include <vector>

class UserRepository {
private:
    std::vector<User> users;

public:
    UserRepository() {}

    User* findById(int id) {
        for (auto& user : users) {
            if (user.id == id) {
                return &user;
            }
        }
        return nullptr;
    }

    void save(const User& user) {
        users.push_back(user);
    }
};

int main() {
    UserRepository repo;
    return 0;
}
"""
        path = self._create_test_file("repository.cpp", cpp_code)
        parser = UnifiedParser()
        result = parser.parse_file(path)

        self.assertIsNotNone(result)
        self.assertTrue(any("UserRepository" in str(u.symbol) for u in result))


class TestFrameworkDetection(TestTreeSitterIntegration):
    """框架检测集成测试"""

    def test_detect_flask(self):
        """测试检测 Flask 框架"""
        from indexer.treesitter.frameworks import FrameworkDetector, FrameworkType

        code = """
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/users', methods=['GET'])
def get_users():
    return jsonify(users)
"""
        detector = FrameworkDetector()
        frameworks = detector.detect_from_code(code)
        self.assertIn(FrameworkType.FLASK, frameworks)

    def test_detect_express(self):
        """测试检测 Express 框架"""
        from indexer.treesitter.frameworks import FrameworkDetector, FrameworkType

        code = """
const express = require('express');
const app = express();

app.get('/api/users', (req, res) => {
    res.json(users);
});
"""
        detector = FrameworkDetector()
        frameworks = detector.detect_from_code(code)
        self.assertIn(FrameworkType.EXPRESS, frameworks)

    def test_detect_spring(self):
        """测试检测 Spring 框架"""
        from indexer.treesitter.frameworks import FrameworkDetector, FrameworkType

        code = """
@RestController
@RequestMapping("/api")
public class ApiController {
    @GetMapping("/users")
    public List<User> getUsers() {
        return userService.findAll();
    }
}
"""
        detector = FrameworkDetector()
        frameworks = detector.detect_from_code(code)
        self.assertIn(FrameworkType.SPRING, frameworks)

    def test_detect_gin(self):
        """测试检测 Gin 框架"""
        from indexer.treesitter.frameworks import FrameworkDetector, FrameworkType

        imports = ["github.com/gin-gonic/gin"]
        detector = FrameworkDetector()
        frameworks = detector.detect_from_imports(imports)
        self.assertIn(FrameworkType.GIN, frameworks)


class TestOptimization(TestTreeSitterIntegration):
    """性能优化集成测试"""

    def test_parse_cache(self):
        """测试解析缓存"""
        from indexer.treesitter.optimization import ParseCache

        cache = ParseCache(max_size=10)
        content = b"function test() { return 1; }"

        # 缓存未命中
        result = cache.get(content, "javascript")
        self.assertIsNone(result)

        # 模拟缓存存储（需要真实的 Tree 对象，这里简化测试）
        self.assertEqual(cache.size, 0)

    def test_parser_pool(self):
        """测试解析器池"""
        from indexer.treesitter.optimization import ParserPool

        pool = ParserPool(pool_size=2)
        # 测试池创建
        self.assertIsNotNone(pool)
        self.assertEqual(pool.pool_size, 2)

    def test_parse_stats(self):
        """测试解析统计"""
        from indexer.treesitter.optimization import ParseStats

        stats = ParseStats()
        stats.total_files = 100
        stats.total_time_ms = 5000
        stats.cache_hits = 30
        stats.cache_misses = 70

        self.assertEqual(stats.avg_time_ms, 50.0)
        self.assertEqual(stats.cache_hit_rate, 0.3)

        stats_dict = stats.to_dict()
        self.assertEqual(stats_dict["total_files"], 100)
        self.assertEqual(stats_dict["cache_hit_rate"], 30.0)


class TestGenericASTConversion(TestTreeSitterIntegration):
    """Generic AST 转换集成测试"""

    def test_generic_nodes_creation(self):
        """测试 Generic AST 节点创建"""
        from indexer.treesitter.generic.nodes import (
            GenericFunction, GenericClass, GenericCall,
            Span, NodeKind, Visibility
        )

        span = Span(start_line=1, end_line=10, start_column=0, end_column=1)

        func = GenericFunction(
            kind=NodeKind.FUNCTION,
            name="test_func",
            span=span,
            source_language="python",
        )
        self.assertEqual(func.name, "test_func")
        self.assertEqual(func.kind, NodeKind.FUNCTION)

        cls = GenericClass(
            kind=NodeKind.CLASS,
            name="TestClass",
            span=span,
            source_language="java",
        )
        self.assertEqual(cls.name, "TestClass")

        call = GenericCall(
            kind=NodeKind.CALL,
            name="some_func",
            span=span,
            source_language="go",
            callee="some_func",
            full_name="pkg.some_func",
        )
        self.assertEqual(call.full_name, "pkg.some_func")

    def test_cross_language_patterns(self):
        """测试跨语言安全模式"""
        from indexer.treesitter.generic.patterns import (
            CROSS_LANGUAGE_PATTERNS,
            list_all_sinks,
        )

        self.assertIsInstance(CROSS_LANGUAGE_PATTERNS, list)
        self.assertGreater(len(CROSS_LANGUAGE_PATTERNS), 0)

        sinks = list_all_sinks()
        self.assertIn("command_injection", sinks)
        self.assertIn("sql_injection", sinks)


class TestFallbackStrategy(TestTreeSitterIntegration):
    """回退策略集成测试"""

    def test_fallback_result_creation(self):
        """测试回退结果创建"""
        from indexer.treesitter.fallback import (
            PartialParseResult, ErrorMarkedUnit, FallbackChain
        )
        from indexer.models import CodeUnit, CodeUnitType, CodeSpan

        # 创建部分解析结果
        span = CodeSpan(start_line=1, end_line=5)
        unit = CodeUnit(
            id="test-1",
            language="javascript",
            file_path="test.js",
            symbol="testFunc",
            unit_type=CodeUnitType.FUNCTION,
            signature="function testFunc()",
            span=span,
            code="function testFunc() {}",
            calls=[],
            imports=[],
        )

        result = PartialParseResult(
            units=[unit],
            errors=["Syntax error at line 10"],
            warnings=["Deprecated syntax"],
        )

        self.assertEqual(len(result.units), 1)
        self.assertEqual(len(result.errors), 1)

    def test_fallback_chain_creation(self):
        """测试回退链创建"""
        from indexer.treesitter.fallback import FallbackChain

        chain = FallbackChain()
        self.assertIsNotNone(chain)


if __name__ == "__main__":
    unittest.main(verbosity=2)
