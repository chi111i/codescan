"""
语言解析器 - 将源代码解析为 CodeUnit
"""

import ast
import re
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Dict, Any, Type, Union, Tuple

from .models import CodeUnit, CodeUnitType, CodeSpan

logger = logging.getLogger(__name__)


class BaseLanguageParser(ABC):
    """语言解析器抽象基类"""

    # 子类需要设置支持的语言和文件扩展名
    language: str = ""
    extensions: List[str] = []

    @abstractmethod
    def parse_file(self, file_path: str, content: str) -> List[CodeUnit]:
        """解析文件内容，返回 CodeUnit 列表

        Args:
            file_path: 文件路径（相对于项目根目录）
            content: 文件内容

        Returns:
            CodeUnit 列表
        """
        pass

    def supports_file(self, file_path: str) -> bool:
        """检查是否支持该文件"""
        return any(file_path.endswith(ext) for ext in self.extensions)


class PythonParser(BaseLanguageParser):
    """Python 代码解析器"""

    language = "python"
    extensions = [".py"]

    def parse_file(self, file_path: str, content: str) -> List[CodeUnit]:
        """解析 Python 文件"""
        units: List[CodeUnit] = []

        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            logger.warning(f"Syntax error in {file_path}: {e}")
            return units

        lines = content.split("\n")

        # 收集导入
        imports = self._extract_imports(tree)

        # 解析顶层定义
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                unit = self._parse_function(node, file_path, lines, imports)
                if unit:
                    units.append(unit)

            elif isinstance(node, ast.ClassDef):
                # 解析类本身
                class_unit = self._parse_class(node, file_path, lines, imports)
                if class_unit:
                    units.append(class_unit)

                # 解析类中的方法
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_unit = self._parse_function(
                            item, file_path, lines, imports,
                            parent_class=node.name
                        )
                        if method_unit:
                            units.append(method_unit)

        return units

    def _extract_imports(self, tree: ast.AST) -> List[str]:
        """提取导入语句"""
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}")
        return imports

    def _get_decorators(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef]
    ) -> List[str]:
        """提取装饰器"""
        decorators = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                decorators.append(ast.unparse(dec))
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    decorators.append(dec.func.id)
                elif isinstance(dec.func, ast.Attribute):
                    decorators.append(ast.unparse(dec.func))
        return decorators

    def _get_function_signature(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> str:
        """获取函数签名，支持同步和异步函数"""
        args = []
        for arg in node.args.args:
            arg_str = arg.arg
            if arg.annotation:
                arg_str += f": {ast.unparse(arg.annotation)}"
            args.append(arg_str)

        # 处理 *args
        if node.args.vararg:
            args.append(f"*{node.args.vararg.arg}")

        # 处理 **kwargs
        if node.args.kwarg:
            args.append(f"**{node.args.kwarg.arg}")

        # 判断是否为异步函数
        is_async = isinstance(node, ast.AsyncFunctionDef)
        prefix = "async def" if is_async else "def"
        signature = f"{prefix} {node.name}({', '.join(args)})"

        # 返回值注解
        if node.returns:
            signature += f" -> {ast.unparse(node.returns)}"

        return signature

    def _get_full_attr_name(self, node: ast.AST) -> str:
        """递归获取完整的属性链名称

        例如:
        - ast.Name('os') -> 'os'
        - ast.Attribute(ast.Name('os'), 'system') -> 'os.system'
        - ast.Attribute(ast.Attribute(ast.Name('subprocess'), 'run'), 'call') -> 'subprocess.run'
        """
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value_name = self._get_full_attr_name(node.value)
            if value_name:
                return f"{value_name}.{node.attr}"
            return node.attr
        elif isinstance(node, ast.Call):
            # 处理链式调用如 foo().bar()
            return self._get_full_attr_name(node.func)
        elif isinstance(node, ast.Subscript):
            # 处理下标访问如 foo[0].bar()
            return self._get_full_attr_name(node.value)
        return ""

    def _extract_calls(self, node: ast.AST) -> List[str]:
        """提取函数调用，包含完整限定名和短名

        返回列表中包含:
        - 完整限定名 (如 os.system, subprocess.Popen)
        - 短名 (如 system, Popen) 用于兼容匹配
        """
        calls = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    # 简单函数调用: func()
                    calls.add(child.func.id)
                elif isinstance(child.func, ast.Attribute):
                    # 属性调用: obj.method() 或 module.func()
                    # 获取完整限定名
                    full_name = self._get_full_attr_name(child.func)
                    if full_name:
                        calls.add(full_name)
                    # 同时保留短名用于兼容
                    calls.add(child.func.attr)
        return list(calls)

    def _get_docstring(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef]
    ) -> Optional[str]:
        """提取文档字符串"""
        return ast.get_docstring(node)

    def _get_code_span(self, node: ast.AST, lines: List[str]) -> Tuple[CodeSpan, str]:
        """获取代码范围和内容"""
        start_line = node.lineno
        end_line = node.end_lineno or node.lineno

        # 获取代码内容
        code_lines = lines[start_line - 1:end_line]
        code = "\n".join(code_lines)

        span = CodeSpan(
            start_line=start_line,
            end_line=end_line,
            start_col=node.col_offset,
            end_col=node.end_col_offset or 0,
        )

        return span, code

    def _parse_function(
        self,
        node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        file_path: str,
        lines: List[str],
        imports: List[str],
        parent_class: Optional[str] = None
    ) -> Optional[CodeUnit]:
        """解析函数/方法"""
        span, code = self._get_code_span(node, lines)

        # 确定单元类型
        decorators = self._get_decorators(node)
        unit_type = CodeUnitType.METHOD if parent_class else CodeUnitType.FUNCTION

        # 检查是否是 Web 处理器
        handler_decorators = {"route", "get", "post", "put", "delete", "patch", "api_view", "action"}
        if any(d.lower() in handler_decorators for d in decorators):
            unit_type = CodeUnitType.HANDLER

        unit_id = CodeUnit.generate_id(file_path, node.name, span)

        return CodeUnit(
            id=unit_id,
            language=self.language,
            file_path=file_path,
            symbol=node.name,
            unit_type=unit_type,
            signature=self._get_function_signature(node),
            span=span,
            code=code,
            docstring=self._get_docstring(node),
            calls=self._extract_calls(node),
            parent_class=parent_class,
            decorators=decorators,
            imports=imports,
        )

    def _parse_class(
        self,
        node: ast.ClassDef,
        file_path: str,
        lines: List[str],
        imports: List[str]
    ) -> Optional[CodeUnit]:
        """解析类"""
        span, code = self._get_code_span(node, lines)
        decorators = self._get_decorators(node)

        # 获取基类
        bases = [ast.unparse(base) for base in node.bases]
        signature = f"class {node.name}"
        if bases:
            signature += f"({', '.join(bases)})"

        unit_id = CodeUnit.generate_id(file_path, node.name, span)

        # 检查是否是中间件
        unit_type = CodeUnitType.CLASS
        middleware_indicators = {"middleware", "Middleware"}
        if any(ind in node.name for ind in middleware_indicators):
            unit_type = CodeUnitType.MIDDLEWARE

        return CodeUnit(
            id=unit_id,
            language=self.language,
            file_path=file_path,
            symbol=node.name,
            unit_type=unit_type,
            signature=signature,
            span=span,
            code=code,
            docstring=self._get_docstring(node),
            calls=self._extract_calls(node),
            decorators=decorators,
            imports=imports,
            metadata={"bases": bases},
        )


class JavaScriptParser(BaseLanguageParser):
    """JavaScript/TypeScript 代码解析器

    使用正则表达式进行基础解析（不依赖 tree-sitter）
    生产环境建议使用 tree-sitter-javascript
    """

    language = "javascript"
    extensions = [".js", ".jsx", ".ts", ".tsx", ".mjs"]

    # 函数匹配模式
    FUNCTION_PATTERNS = [
        # 普通函数: function name(args) { }
        r'(?P<async>async\s+)?function\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)',
        # 箭头函数: const name = (args) => { }
        r'(?:const|let|var)\s+(?P<name>\w+)\s*=\s*(?P<async>async\s+)?\((?P<args>[^)]*)\)\s*=>',
        # 方法简写: name(args) { } 在类/对象中
        r'^\s*(?P<async>async\s+)?(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*{',
    ]

    # 类匹配模式
    CLASS_PATTERN = r'class\s+(?P<name>\w+)(?:\s+extends\s+(?P<base>\w+))?'

    # 导出匹配
    EXPORT_PATTERN = r'export\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var)\s+(\w+)'

    def parse_file(self, file_path: str, content: str) -> List[CodeUnit]:
        """解析 JavaScript/TypeScript 文件"""
        units: List[CodeUnit] = []
        lines = content.split("\n")

        # 确定语言
        lang = "typescript" if file_path.endswith((".ts", ".tsx")) else "javascript"

        # 提取导入
        imports = self._extract_imports(content)

        # 解析类
        units.extend(self._parse_classes(content, file_path, lines, imports, lang))

        # 解析顶层函数
        units.extend(self._parse_functions(content, file_path, lines, imports, lang))

        return units

    def _extract_imports(self, content: str) -> List[str]:
        """提取导入"""
        imports = []
        # import ... from '...'
        pattern = r"import\s+(?:{[^}]+}|\w+|\*\s+as\s+\w+)\s+from\s+['\"]([^'\"]+)['\"]"
        imports.extend(re.findall(pattern, content))
        # require('...')
        pattern = r"require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"
        imports.extend(re.findall(pattern, content))
        return imports

    def _find_block_end(self, content: str, start_pos: int) -> int:
        """找到代码块结束位置（匹配大括号）"""
        brace_count = 0
        in_string = False
        string_char = None
        i = start_pos

        while i < len(content):
            char = content[i]

            # 处理字符串
            if char in ('"', "'", "`") and (i == 0 or content[i-1] != "\\"):
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False

            if not in_string:
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        return i

            i += 1

        return len(content) - 1

    def _get_line_number(self, content: str, pos: int) -> int:
        """获取位置对应的行号"""
        return content[:pos].count("\n") + 1

    def _parse_classes(
        self,
        content: str,
        file_path: str,
        lines: List[str],
        imports: List[str],
        lang: str
    ) -> List[CodeUnit]:
        """解析类"""
        units = []

        for match in re.finditer(self.CLASS_PATTERN, content):
            class_name = match.group("name")
            base_class = match.group("base")

            # 找到类的代码块
            block_start = content.find("{", match.end())
            if block_start == -1:
                continue

            block_end = self._find_block_end(content, block_start)
            class_code = content[match.start():block_end + 1]

            start_line = self._get_line_number(content, match.start())
            end_line = self._get_line_number(content, block_end)

            span = CodeSpan(start_line=start_line, end_line=end_line)
            unit_id = CodeUnit.generate_id(file_path, class_name, span)

            signature = f"class {class_name}"
            if base_class:
                signature += f" extends {base_class}"

            # 提取类内的方法调用
            calls = self._extract_calls(class_code)

            units.append(CodeUnit(
                id=unit_id,
                language=lang,
                file_path=file_path,
                symbol=class_name,
                unit_type=CodeUnitType.CLASS,
                signature=signature,
                span=span,
                code=class_code,
                calls=calls,
                imports=imports,
                metadata={"base": base_class} if base_class else {},
            ))

            # 解析类中的方法
            method_pattern = r'(?P<async>async\s+)?(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*{'
            class_body = content[block_start:block_end]

            for method_match in re.finditer(method_pattern, class_body):
                method_name = method_match.group("name")
                if method_name in ("if", "for", "while", "switch", "catch"):
                    continue

                method_start = block_start + method_match.start()
                method_block_start = content.find("{", method_start)
                method_block_end = self._find_block_end(content, method_block_start)

                method_code = content[method_start:method_block_end + 1]
                method_start_line = self._get_line_number(content, method_start)
                method_end_line = self._get_line_number(content, method_block_end)

                method_span = CodeSpan(start_line=method_start_line, end_line=method_end_line)
                method_id = CodeUnit.generate_id(file_path, f"{class_name}.{method_name}", method_span)

                is_async = bool(method_match.group("async"))
                args = method_match.group("args")
                signature = f"{'async ' if is_async else ''}{method_name}({args})"

                units.append(CodeUnit(
                    id=method_id,
                    language=lang,
                    file_path=file_path,
                    symbol=method_name,
                    unit_type=CodeUnitType.METHOD,
                    signature=signature,
                    span=method_span,
                    code=method_code,
                    calls=self._extract_calls(method_code),
                    parent_class=class_name,
                    imports=imports,
                ))

        return units

    def _parse_functions(
        self,
        content: str,
        file_path: str,
        lines: List[str],
        imports: List[str],
        lang: str
    ) -> List[CodeUnit]:
        """解析顶层函数"""
        units = []

        # 函数声明
        func_pattern = r'(?:export\s+)?(?:default\s+)?(?P<async>async\s+)?function\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)'

        for match in re.finditer(func_pattern, content):
            func_name = match.group("name")

            block_start = content.find("{", match.end())
            if block_start == -1:
                continue

            block_end = self._find_block_end(content, block_start)
            func_code = content[match.start():block_end + 1]

            start_line = self._get_line_number(content, match.start())
            end_line = self._get_line_number(content, block_end)

            span = CodeSpan(start_line=start_line, end_line=end_line)
            unit_id = CodeUnit.generate_id(file_path, func_name, span)

            is_async = bool(match.group("async"))
            args = match.group("args")
            signature = f"{'async ' if is_async else ''}function {func_name}({args})"

            # 检查是否是路由处理器
            unit_type = CodeUnitType.FUNCTION
            handler_indicators = ["req", "res", "request", "response", "ctx", "context"]
            if any(ind in args.lower() for ind in handler_indicators):
                unit_type = CodeUnitType.HANDLER

            units.append(CodeUnit(
                id=unit_id,
                language=lang,
                file_path=file_path,
                symbol=func_name,
                unit_type=unit_type,
                signature=signature,
                span=span,
                code=func_code,
                calls=self._extract_calls(func_code),
                imports=imports,
            ))

        # 箭头函数
        arrow_pattern = r'(?:export\s+)?(?:const|let|var)\s+(?P<name>\w+)\s*=\s*(?P<async>async\s+)?\((?P<args>[^)]*)\)\s*=>'

        for match in re.finditer(arrow_pattern, content):
            func_name = match.group("name")

            # 找函数体
            arrow_pos = content.find("=>", match.end() - 10)
            body_start = arrow_pos + 2

            # 跳过空白
            while body_start < len(content) and content[body_start] in " \t\n":
                body_start += 1

            if body_start >= len(content):
                continue

            if content[body_start] == "{":
                block_end = self._find_block_end(content, body_start)
            else:
                # 单表达式箭头函数，找到语句结束
                block_end = content.find(";", body_start)
                if block_end == -1:
                    block_end = content.find("\n", body_start)
                if block_end == -1:
                    block_end = len(content) - 1

            func_code = content[match.start():block_end + 1]

            start_line = self._get_line_number(content, match.start())
            end_line = self._get_line_number(content, block_end)

            span = CodeSpan(start_line=start_line, end_line=end_line)
            unit_id = CodeUnit.generate_id(file_path, func_name, span)

            is_async = bool(match.group("async"))
            args = match.group("args")
            signature = f"const {func_name} = {'async ' if is_async else ''}({args}) =>"

            units.append(CodeUnit(
                id=unit_id,
                language=lang,
                file_path=file_path,
                symbol=func_name,
                unit_type=CodeUnitType.FUNCTION,
                signature=signature,
                span=span,
                code=func_code,
                calls=self._extract_calls(func_code),
                imports=imports,
            ))

        return units

    def _extract_calls(self, code: str) -> List[str]:
        """提取函数调用，包含完整限定名和短名

        支持:
        - 简单调用: func()
        - 方法调用: obj.method()
        - 链式调用: fs.readFile(), child_process.exec()
        """
        calls = set()

        # 匹配完整的属性链调用: obj.method() 或 obj.prop.method()
        # 例如: fs.readFile, child_process.exec, process.env.get
        chain_pattern = r'((?:\w+\.)+\w+)\s*\('
        for match in re.finditer(chain_pattern, code):
            full_name = match.group(1)
            calls.add(full_name)
            # 同时添加最后一个方法名作为短名
            parts = full_name.split('.')
            if parts:
                calls.add(parts[-1])

        # 匹配简单函数调用: name(...)
        simple_pattern = r'(?:^|[^\w.])(\w+)\s*\('
        for match in re.finditer(simple_pattern, code):
            name = match.group(1)
            # 排除关键字
            if name not in ("if", "for", "while", "switch", "catch", "function", "return", "new", "typeof", "async", "await"):
                calls.add(name)

        return list(calls)


class PHPParser(BaseLanguageParser):
    """PHP 代码解析器

    使用正则表达式进行基础解析
    """

    language = "php"
    extensions = [".php", ".phtml", ".php5", ".php7"]

    # 函数匹配模式
    FUNCTION_PATTERN = r'(?P<visibility>public\s+|private\s+|protected\s+)?(?P<static>static\s+)?function\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)'

    # 类匹配模式
    CLASS_PATTERN = r'(?P<abstract>abstract\s+)?class\s+(?P<name>\w+)(?:\s+extends\s+(?P<base>\w+))?(?:\s+implements\s+(?P<interfaces>[\w,\s]+))?'

    # 危险函数列表（用于安全审计）
    DANGEROUS_FUNCTIONS = [
        # RCE
        "eval", "assert", "create_function", "call_user_func", "call_user_func_array",
        "preg_replace",  # with /e modifier
        # 命令执行
        "exec", "shell_exec", "system", "passthru", "popen", "proc_open", "pcntl_exec",
        "backticks",
        # 文件操作
        "file_get_contents", "file_put_contents", "fopen", "fread", "fwrite",
        "readfile", "file", "include", "include_once", "require", "require_once",
        "copy", "unlink", "rename", "move_uploaded_file",
        # SQL
        "mysql_query", "mysqli_query", "pg_query", "sqlite_query",
        # 反序列化
        "unserialize",
        # SSRF
        "curl_exec", "curl_init", "fsockopen", "pfsockopen",
        # XSS
        "echo", "print", "printf",
    ]

    def parse_file(self, file_path: str, content: str) -> List[CodeUnit]:
        """解析 PHP 文件"""
        units: List[CodeUnit] = []
        lines = content.split("\n")

        # 提取导入/use
        imports = self._extract_imports(content)

        # 解析类
        units.extend(self._parse_classes(content, file_path, lines, imports))

        # 解析顶层函数
        units.extend(self._parse_functions(content, file_path, lines, imports))

        # 如果没有找到函数/类，尝试解析内联 PHP 代码块
        if not units:
            units.extend(self._parse_inline_php(content, file_path, lines, imports))

        return units

    def _parse_inline_php(
        self,
        content: str,
        file_path: str,
        lines: List[str],
        imports: List[str]
    ) -> List[CodeUnit]:
        """解析内联 PHP 代码块（用于处理没有函数/类定义的 PHP 文件）"""
        logger.debug("[PHP_PARSER] 开始解析内联 PHP: %s", file_path)
        logger.debug("[PHP_PARSER] 原始内容长度: %s 字符", len(content))
        units = []

        # 提取所有 PHP 代码块: <?php ... ?> 或 <? ... ?> 或 <?= ... ?>
        php_block_pattern = r'<\?(?:php)?\s*([\s\S]*?)(?:\?>|$)'
        php_blocks = []

        for match in re.finditer(php_block_pattern, content, re.IGNORECASE):
            php_code = match.group(1).strip()
            if php_code:
                start_pos = match.start()
                end_pos = match.end()
                start_line = self._get_line_number(content, start_pos)
                end_line = self._get_line_number(content, end_pos)
                logger.debug(
                    "[PHP_PARSER] 找到 PHP 块: 行 %s-%s, 长度: %s 字符",
                    start_line,
                    end_line,
                    len(php_code),
                )
                logger.debug("[PHP_PARSER] PHP 代码预览: %s...", php_code[:500])
                php_blocks.append({
                    'code': php_code,
                    'full_match': match.group(0),
                    'start_line': start_line,
                    'end_line': end_line,
                    'start_pos': start_pos,
                    'end_pos': end_pos,
                })

        if not php_blocks:
            logger.debug("[PHP_PARSER] 未找到任何 PHP 代码块")
            return units

        logger.debug("[PHP_PARSER] 共找到 %s 个 PHP 代码块", len(php_blocks))

        # 如果只有一个或几个小的 PHP 块，合并为一个代码单元
        # 如果有多个较大的块，分别创建
        total_php_code = "\n".join([b['code'] for b in php_blocks])
        calls = self._extract_calls(total_php_code)

        # 检查是否包含危险函数调用
        dangerous_calls = [c for c in calls if c in self.DANGEROUS_FUNCTIONS]

        # 创建一个代表整个文件的代码单元
        file_name = file_path.split('/')[-1].split('\\')[-1]
        symbol_name = f"<script:{file_name}>"

        span = CodeSpan(
            start_line=php_blocks[0]['start_line'],
            end_line=php_blocks[-1]['end_line']
        )
        unit_id = CodeUnit.generate_id(file_path, symbol_name, span)

        # 构建代码内容：提取所有 PHP 代码
        code_content = "\n// === PHP Code Blocks ===\n"
        for i, block in enumerate(php_blocks):
            code_content += f"\n// Block {i+1} (line {block['start_line']}-{block['end_line']}):\n"
            code_content += block['code'] + "\n"

        logger.debug("[PHP_PARSER] 最终代码内容长度: %s 字符", len(code_content))
        logger.debug("[PHP_PARSER] 提取的函数调用: %s", calls)
        logger.debug("[PHP_PARSER] 危险函数调用: %s", dangerous_calls)

        # 确定代码单元类型
        unit_type = CodeUnitType.FUNCTION  # 默认为脚本类型
        # 如果包含 $_GET, $_POST, $_REQUEST 等，标记为处理器
        if any(var in total_php_code for var in ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES']):
            unit_type = CodeUnitType.HANDLER

        units.append(CodeUnit(
            id=unit_id,
            language=self.language,
            file_path=file_path,
            symbol=symbol_name,
            unit_type=unit_type,
            signature=f"inline PHP script: {file_name}",
            span=span,
            code=code_content,
            calls=calls,
            imports=imports,
            metadata={
                "is_inline": True,
                "block_count": len(php_blocks),
                "dangerous_calls": dangerous_calls,
                "has_user_input": any(var in total_php_code for var in ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES']),
            },
        ))

        return units

    def _extract_imports(self, content: str) -> List[str]:
        """提取 use 语句"""
        imports = []
        # use Namespace\Class;
        pattern = r'use\s+([\w\\]+)(?:\s+as\s+\w+)?;'
        imports.extend(re.findall(pattern, content))
        # require/include
        pattern = r'(?:require|include)(?:_once)?\s*\(?[\'"]([^\'"]+)[\'"]\)?;'
        imports.extend(re.findall(pattern, content))
        return imports

    def _find_block_end(self, content: str, start_pos: int) -> int:
        """找到代码块结束位置"""
        brace_count = 0
        in_string = False
        string_char = None
        i = start_pos

        while i < len(content):
            char = content[i]

            # 处理字符串
            if char in ('"', "'") and (i == 0 or content[i-1] != "\\"):
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False

            if not in_string:
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        return i

            i += 1

        return len(content) - 1

    def _get_line_number(self, content: str, pos: int) -> int:
        """获取位置对应的行号"""
        return content[:pos].count("\n") + 1

    def _parse_classes(
        self,
        content: str,
        file_path: str,
        lines: List[str],
        imports: List[str]
    ) -> List[CodeUnit]:
        """解析 PHP 类"""
        units = []

        for match in re.finditer(self.CLASS_PATTERN, content):
            class_name = match.group("name")
            base_class = match.group("base")
            interfaces = match.group("interfaces")
            is_abstract = bool(match.group("abstract"))

            # 找到类的代码块
            block_start = content.find("{", match.end())
            if block_start == -1:
                continue

            block_end = self._find_block_end(content, block_start)
            class_code = content[match.start():block_end + 1]

            start_line = self._get_line_number(content, match.start())
            end_line = self._get_line_number(content, block_end)

            span = CodeSpan(start_line=start_line, end_line=end_line)
            unit_id = CodeUnit.generate_id(file_path, class_name, span)

            signature = f"{'abstract ' if is_abstract else ''}class {class_name}"
            if base_class:
                signature += f" extends {base_class}"
            if interfaces:
                signature += f" implements {interfaces.strip()}"

            # 检查是否是控制器
            unit_type = CodeUnitType.CLASS
            if "Controller" in class_name or "controller" in file_path.lower():
                unit_type = CodeUnitType.HANDLER

            calls = self._extract_calls(class_code)

            units.append(CodeUnit(
                id=unit_id,
                language=self.language,
                file_path=file_path,
                symbol=class_name,
                unit_type=unit_type,
                signature=signature,
                span=span,
                code=class_code,
                calls=calls,
                imports=imports,
                metadata={
                    "base": base_class,
                    "interfaces": interfaces.split(",") if interfaces else [],
                    "is_abstract": is_abstract,
                },
            ))

            # 解析类中的方法
            class_body = content[block_start:block_end]

            for method_match in re.finditer(self.FUNCTION_PATTERN, class_body):
                method_name = method_match.group("name")
                visibility = (method_match.group("visibility") or "public").strip()
                is_static = bool(method_match.group("static"))
                args = method_match.group("args")

                method_start = block_start + method_match.start()
                method_block_start = content.find("{", method_start)
                if method_block_start == -1:
                    continue

                method_block_end = self._find_block_end(content, method_block_start)
                method_code = content[method_start:method_block_end + 1]

                method_start_line = self._get_line_number(content, method_start)
                method_end_line = self._get_line_number(content, method_block_end)

                method_span = CodeSpan(start_line=method_start_line, end_line=method_end_line)
                method_id = CodeUnit.generate_id(file_path, f"{class_name}::{method_name}", method_span)

                signature = f"{visibility} {'static ' if is_static else ''}function {method_name}({args})"

                # 检查是否是路由处理器/动作
                method_type = CodeUnitType.METHOD
                action_suffixes = ["Action", "action"]
                if any(method_name.endswith(suffix) for suffix in action_suffixes):
                    method_type = CodeUnitType.HANDLER

                units.append(CodeUnit(
                    id=method_id,
                    language=self.language,
                    file_path=file_path,
                    symbol=method_name,
                    unit_type=method_type,
                    signature=signature,
                    span=method_span,
                    code=method_code,
                    calls=self._extract_calls(method_code),
                    parent_class=class_name,
                    imports=imports,
                    metadata={
                        "visibility": visibility,
                        "is_static": is_static,
                    },
                ))

        return units

    def _parse_functions(
        self,
        content: str,
        file_path: str,
        lines: List[str],
        imports: List[str]
    ) -> List[CodeUnit]:
        """解析顶层函数"""
        units = []

        # 简单匹配顶层函数（不在类内部的）
        # 先找出所有类的范围
        class_ranges = []
        for match in re.finditer(self.CLASS_PATTERN, content):
            block_start = content.find("{", match.end())
            if block_start != -1:
                block_end = self._find_block_end(content, block_start)
                class_ranges.append((match.start(), block_end))

        # 查找函数
        func_pattern = r'function\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)'

        for match in re.finditer(func_pattern, content):
            func_name = match.group("name")
            pos = match.start()

            # 检查是否在类内部
            in_class = any(start <= pos <= end for start, end in class_ranges)
            if in_class:
                continue

            block_start = content.find("{", match.end())
            if block_start == -1:
                continue

            block_end = self._find_block_end(content, block_start)
            func_code = content[match.start():block_end + 1]

            start_line = self._get_line_number(content, match.start())
            end_line = self._get_line_number(content, block_end)

            span = CodeSpan(start_line=start_line, end_line=end_line)
            unit_id = CodeUnit.generate_id(file_path, func_name, span)

            args = match.group("args")
            signature = f"function {func_name}({args})"

            units.append(CodeUnit(
                id=unit_id,
                language=self.language,
                file_path=file_path,
                symbol=func_name,
                unit_type=CodeUnitType.FUNCTION,
                signature=signature,
                span=span,
                code=func_code,
                calls=self._extract_calls(func_code),
                imports=imports,
            ))

        return units

    def _extract_calls(self, code: str) -> List[str]:
        """提取函数调用，包含完整限定名和短名

        支持:
        - 普通函数: func_name()
        - 方法调用: $obj->method()
        - 静态调用: Class::method()
        - 命名空间调用: Namespace\\Class::method()
        """
        calls = set()

        # 普通函数调用: func_name(...)
        pattern = r'(?:^|[^\w$>\\])(\w+)\s*\('
        for match in re.finditer(pattern, code):
            name = match.group(1)
            if name not in ("if", "for", "foreach", "while", "switch", "catch", "function", "return", "new", "array", "list", "isset", "empty", "unset"):
                calls.add(name)

        # 方法调用: $obj->method(...) - 提取完整链
        # 例如: $this->db->query, $request->input
        obj_method_pattern = r'(\$\w+(?:->\w+)*)\s*\('
        for match in re.finditer(obj_method_pattern, code):
            full_call = match.group(1)
            calls.add(full_call)
            # 提取最后的方法名
            parts = full_call.replace('$', '').split('->')
            if len(parts) > 1:
                calls.add(parts[-1])

        # 静态调用: Class::method(...) 或 \Namespace\Class::method(...)
        static_pattern = r'((?:\\?[\w\\]+)?::?\w+)\s*\('
        for match in re.finditer(static_pattern, code):
            full_call = match.group(1)
            if '::' in full_call:
                calls.add(full_call)
                # 提取方法名
                parts = full_call.split('::')
                if len(parts) == 2:
                    calls.add(parts[1])

        return list(calls)


# 解析器注册表
_PARSERS: Dict[str, Type[BaseLanguageParser]] = {}


def register_parser(parser_class: Type[BaseLanguageParser]) -> Type[BaseLanguageParser]:
    """注册解析器"""
    _PARSERS[parser_class.language] = parser_class
    return parser_class


def get_parser(language: str) -> Optional[BaseLanguageParser]:
    """获取指定语言的解析器"""
    parser_class = _PARSERS.get(language)
    if parser_class:
        return parser_class()
    return None


def get_parser_for_file(file_path: str) -> Optional[BaseLanguageParser]:
    """根据文件扩展名获取解析器"""
    for parser_class in _PARSERS.values():
        parser = parser_class()
        if parser.supports_file(file_path):
            return parser
    return None


# 注册内置解析器
register_parser(PythonParser)
register_parser(JavaScriptParser)
register_parser(PHPParser)
