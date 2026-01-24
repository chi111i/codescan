# Tree-sitter 多语言解析器模块

## 概述

本模块为 CodeScan 提供基于 Tree-sitter 的多语言代码解析能力，支持 11 种编程语言的统一解析接口。

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                     UnifiedParser                            │
│  统一解析入口，自动选择最佳解析器                            │
└─────────────────────────────────────────────────────────────┘
                              │
           ┌──────────────────┼──────────────────┐
           ▼                  ▼                  ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Tree-sitter     │ │ Generic AST     │ │ Fallback        │
│ Parser Registry │ │ Converter       │ │ Chain           │
└─────────────────┘ └─────────────────┘ └─────────────────┘
           │                  │                  │
           ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    Language Parsers                          │
│  JS/TS | PHP | Java | Go | Rust | C/C++ | C# | Ruby | Kotlin │
└─────────────────────────────────────────────────────────────┘
```

## 支持的语言

| 语言 | 文件扩展名 | 解析器模块 | 框架支持 |
|------|-----------|-----------|---------|
| JavaScript | .js, .jsx, .mjs | `javascript.py` | Express, Koa, Fastify |
| TypeScript | .ts, .tsx | `javascript.py` | NestJS |
| PHP | .php | `php.py` | Laravel, Symfony |
| Java | .java | `java.py` | Spring Boot/MVC |
| Go | .go | `go.py` | Gin, Echo, Fiber, Chi |
| Rust | .rs | `rust.py` | - |
| C | .c, .h | `cpp.py` | - |
| C++ | .cpp, .cxx, .cc, .hpp | `cpp.py` | - |
| C# | .cs | `csharp.py` | ASP.NET |
| Ruby | .rb, .rake | `ruby.py` | Rails |
| Kotlin | .kt, .kts | `kotlin.py` | Spring, Ktor |
| Python | .py | `python_parser.py` | Flask, Django, FastAPI |

## 核心组件

### 1. TreeSitterParser (base.py)

所有语言解析器的基类。

```python
from indexer.treesitter import TreeSitterParserRegistry

# 获取特定语言的解析器
parser = TreeSitterParserRegistry.get_parser("javascript")
units = parser.parse_file("app.js")
```

### 2. UnifiedParser (unified_parser.py)

统一解析入口，自动检测语言并选择最佳解析器。

```python
from indexer.treesitter.unified_parser import UnifiedParser

parser = UnifiedParser()

# 解析单个文件
units = parser.parse_file("src/app.js")

# 解析目录
all_units = parser.parse_directory("src/", recursive=True)
```

### 3. Generic AST (generic/)

跨语言的中间表示层，类似 Semgrep 的设计。

```python
from indexer.treesitter.generic.nodes import (
    GenericFunction, GenericClass, GenericCall,
    NodeKind, Visibility
)

# 通用节点可以来自任何语言
func = GenericFunction(
    kind=NodeKind.FUNCTION,
    name="process_data",
    source_language="python",
)
```

### 4. FallbackChain (fallback.py)

解析失败时的回退策略，确保部分结果可用。

```python
from indexer.treesitter.fallback import FallbackChain

chain = FallbackChain()
result = chain.parse_with_fallback(content, "javascript", "app.js")

# result.units: 成功解析的单元
# result.errors: 解析错误
# result.warnings: 警告信息
```

### 5. FrameworkAnalyzer (frameworks.py)

Web 框架检测和路由提取。

```python
from indexer.treesitter.frameworks import FrameworkAnalyzer, FrameworkType

analyzer = FrameworkAnalyzer()
info = analyzer.analyze_file(code, "app.py", "python")

print(info.type)    # FrameworkType.FLASK
print(info.routes)  # [RouteInfo(path="/api/users", methods=["GET"], ...)]
```

## 性能优化

### 优化解析器 (optimization.py)

```python
from indexer.treesitter.optimization import (
    OptimizedTreeSitterParser,
    get_optimized_parser,
)

# 使用全局优化解析器
parser = get_optimized_parser()

# 批量并行解析
files = [
    ("app.js", content1, "javascript"),
    ("main.go", content2, "go"),
    ("App.java", content3, "java"),
]
results = parser.parse_batch(files)

# 查看统计信息
stats = parser.get_stats()
print(f"Cache hit rate: {stats['cache_hit_rate']}%")
```

### 优化特性

1. **解析器池化**: 复用解析器实例，减少创建开销
2. **结果缓存**: LRU 缓存避免重复解析
3. **增量解析**: 仅重新解析修改的部分
4. **并行解析**: 多线程批量处理

## 查询文件 (.scm)

每种语言的查询按功能分类：

```
queries/
├── javascript/
│   ├── functions.scm    # 函数/方法提取
│   ├── classes.scm      # 类/接口提取
│   └── calls.scm        # 函数调用提取
├── java/
│   └── ...
└── go/
    └── ...
```

### 查询示例

```scheme
; Go 危险调用检测 (queries/go/calls.scm)
(call_expression
  function: (selector_expression
    operand: (identifier) @danger.exec
    (#eq? @danger.exec "exec")
    field: (field_identifier) @danger.command
    (#eq? @danger.command "Command"))) @danger.rce
```

## 安全模式检测

### 跨语言模式 (generic/patterns.py)

```python
from indexer.treesitter.generic.patterns import (
    CROSS_LANGUAGE_PATTERNS,
    list_all_sinks,
    get_patterns_for_category,
)

# 获取所有 sink 类别
sinks = list_all_sinks()
# ['command_injection', 'sql_injection', 'ssrf', ...]

# 获取特定类别的模式
rce_patterns = get_patterns_for_category("command_injection")
```

### 语言特定危险函数

每个解析器定义了该语言的危险函数列表：

| 语言 | 危险函数示例 |
|------|-------------|
| Python | `os.system`, `eval`, `pickle.loads` |
| Java | `Runtime.exec`, `ProcessBuilder`, JNDI |
| Go | `exec.Command`, `os.StartProcess` |
| PHP | `exec`, `system`, `unserialize` |
| JavaScript | `eval`, `child_process.exec` |
| C/C++ | `system`, `strcpy`, `gets` |

## Python Tree-sitter（可选模式）

Python 默认使用原生 AST 解析器，Tree-sitter 版本作为可选：

```python
from indexer.treesitter.python_parser import (
    enable_python_treesitter,
    disable_python_treesitter,
)

# 启用 Tree-sitter 解析 Python
enable_python_treesitter()

# 恢复原生 AST
disable_python_treesitter()
```

## 安装依赖

```bash
# 基础 tree-sitter 库
pip install tree-sitter

# 各语言绑定（按需安装）
pip install tree-sitter-javascript
pip install tree-sitter-typescript
pip install tree-sitter-php
pip install tree-sitter-java
pip install tree-sitter-go
pip install tree-sitter-rust
pip install tree-sitter-c
pip install tree-sitter-cpp
pip install tree-sitter-c-sharp
pip install tree-sitter-ruby
pip install tree-sitter-kotlin
pip install tree-sitter-python
```

## 测试

```bash
# 单元测试
python -m pytest tests/test_treesitter.py -v

# 集成测试
python -m pytest tests/test_treesitter_integration.py -v
```

## 扩展新语言

1. 创建解析器文件 `indexer/treesitter/{language}.py`
2. 继承 `TreeSitterParser` 基类
3. 实现 `_extract_functions` 和 `_extract_classes` 方法
4. 使用 `@TreeSitterParserRegistry.register` 注册
5. 创建查询文件 `queries/{language}/*.scm`
6. 实现 Generic AST 转换器（可选）

```python
@TreeSitterParserRegistry.register
class MyLanguageParser(TreeSitterParser):
    language_name = "mylang"
    extensions = [".ml"]

    def _load_language(self):
        return LanguageLoader.load("mylang")

    def _extract_functions(self, tree, source, file_path):
        # 实现函数提取逻辑
        pass

    def _extract_classes(self, tree, source, file_path):
        # 实现类提取逻辑
        pass
```

## 文件结构

```
indexer/treesitter/
├── __init__.py              # 模块入口
├── base.py                  # 基类和注册表
├── loader.py                # 语言加载器
├── query_engine.py          # 查询引擎
├── utils.py                 # 工具函数
├── unified_parser.py        # 统一解析器
├── fallback.py              # 回退策略
├── frameworks.py            # 框架检测
├── optimization.py          # 性能优化
│
├── javascript.py            # JS/TS 解析器
├── php.py                   # PHP 解析器
├── java.py                  # Java 解析器
├── go.py                    # Go 解析器
├── rust.py                  # Rust 解析器
├── cpp.py                   # C/C++ 解析器
├── csharp.py                # C# 解析器
├── ruby.py                  # Ruby 解析器
├── kotlin.py                # Kotlin 解析器
├── python_parser.py         # Python 解析器（可选）
│
├── generic/                 # Generic AST 层
│   ├── nodes.py             # 通用节点定义
│   ├── converter.py         # AST 转换器
│   └── patterns.py          # 跨语言安全模式
│
└── queries/                 # .scm 查询文件
    ├── javascript/
    ├── java/
    └── go/
```
