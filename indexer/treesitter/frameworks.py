"""
框架特定支持模块

提供对常见 Web 框架的特定支持，包括：
- 路由/端点提取
- 中间件识别
- 框架特定的安全模式
- 入口点自动识别

支持的框架：
- Python: Flask, Django, FastAPI
- JavaScript: Express, Koa, Fastify, NestJS
- PHP: Laravel, Symfony, CodeIgniter
- Java: Spring Boot, Spring MVC
- Go: Gin, Echo, Fiber, Chi
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class FrameworkType(Enum):
    """框架类型"""
    # Python
    FLASK = "flask"
    DJANGO = "django"
    FASTAPI = "fastapi"
    # JavaScript
    EXPRESS = "express"
    KOA = "koa"
    FASTIFY = "fastify"
    NESTJS = "nestjs"
    # PHP
    LARAVEL = "laravel"
    SYMFONY = "symfony"
    CODEIGNITER = "codeigniter"
    # Java
    SPRING = "spring"
    # Go
    GIN = "gin"
    ECHO = "echo"
    FIBER = "fiber"
    CHI = "chi"
    # Generic
    UNKNOWN = "unknown"


@dataclass
class RouteInfo:
    """路由信息"""
    path: str
    methods: List[str]
    handler: str
    file_path: str
    line: int
    middleware: List[str] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    framework: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def full_path(self) -> str:
        """获取完整路径（包含参数占位符）"""
        return self.path

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "path": self.path,
            "methods": self.methods,
            "handler": self.handler,
            "file_path": self.file_path,
            "line": self.line,
            "middleware": self.middleware,
            "params": self.params,
            "framework": self.framework,
            "metadata": self.metadata,
        }


@dataclass
class FrameworkInfo:
    """框架信息"""
    name: str
    type: FrameworkType
    version: Optional[str] = None
    config_files: List[str] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    routes: List[RouteInfo] = field(default_factory=list)


# ============================================================
# 框架检测器
# ============================================================

class FrameworkDetector:
    """框架检测器

    通过分析导入、文件结构和代码模式来检测使用的框架。
    """

    # 框架特征
    FRAMEWORK_SIGNATURES: Dict[FrameworkType, Dict[str, Any]] = {
        # Python
        FrameworkType.FLASK: {
            "imports": ["flask", "Flask"],
            "patterns": [r"@app\.route", r"Flask\(__name__\)"],
            "files": ["app.py", "wsgi.py"],
        },
        FrameworkType.DJANGO: {
            "imports": ["django"],
            "patterns": [r"urlpatterns", r"path\(", r"re_path\("],
            "files": ["urls.py", "views.py", "settings.py", "manage.py"],
        },
        FrameworkType.FASTAPI: {
            "imports": ["fastapi", "FastAPI"],
            "patterns": [r"@app\.(get|post|put|delete|patch)", r"FastAPI\(\)"],
            "files": ["main.py"],
        },
        # JavaScript
        FrameworkType.EXPRESS: {
            "imports": ["express"],
            "patterns": [r"express\(\)", r"app\.(get|post|put|delete|patch|use)"],
            "files": ["app.js", "server.js", "index.js"],
        },
        FrameworkType.KOA: {
            "imports": ["koa", "Koa"],
            "patterns": [r"new Koa\(\)", r"router\.(get|post|put|delete)"],
            "files": ["app.js", "server.js"],
        },
        FrameworkType.FASTIFY: {
            "imports": ["fastify"],
            "patterns": [r"fastify\(\)", r"fastify\.(get|post|put|delete)"],
            "files": ["app.js", "server.js"],
        },
        FrameworkType.NESTJS: {
            "imports": ["@nestjs/core", "@nestjs/common"],
            "patterns": [r"@Controller", r"@Get\(", r"@Post\(", r"@Injectable"],
            "files": ["main.ts", "app.module.ts"],
        },
        # PHP
        FrameworkType.LARAVEL: {
            "imports": ["Illuminate"],
            "patterns": [r"Route::(get|post|put|delete)", r"extends Controller"],
            "files": ["routes/web.php", "routes/api.php", "artisan"],
        },
        FrameworkType.SYMFONY: {
            "imports": ["Symfony"],
            "patterns": [r"#\[Route\(", r"@Route\("],
            "files": ["config/routes.yaml", "bin/console"],
        },
        # Java
        FrameworkType.SPRING: {
            "imports": ["org.springframework"],
            "patterns": [
                r"@RestController", r"@Controller", r"@RequestMapping",
                r"@GetMapping", r"@PostMapping", r"@SpringBootApplication",
            ],
            "files": ["pom.xml", "build.gradle", "Application.java"],
        },
        # Go
        FrameworkType.GIN: {
            "imports": ["github.com/gin-gonic/gin"],
            "patterns": [r"gin\.Default\(\)", r"gin\.New\(\)", r"\.(GET|POST|PUT|DELETE)\("],
            "files": ["main.go"],
        },
        FrameworkType.ECHO: {
            "imports": ["github.com/labstack/echo"],
            "patterns": [r"echo\.New\(\)", r"e\.(GET|POST|PUT|DELETE)\("],
            "files": ["main.go"],
        },
        FrameworkType.FIBER: {
            "imports": ["github.com/gofiber/fiber"],
            "patterns": [r"fiber\.New\(\)", r"app\.(Get|Post|Put|Delete)\("],
            "files": ["main.go"],
        },
        FrameworkType.CHI: {
            "imports": ["github.com/go-chi/chi"],
            "patterns": [r"chi\.NewRouter\(\)", r"r\.(Get|Post|Put|Delete)\("],
            "files": ["main.go"],
        },
    }

    def detect_from_imports(self, imports: List[str]) -> List[FrameworkType]:
        """从导入语句检测框架"""
        detected = []
        for fw_type, signatures in self.FRAMEWORK_SIGNATURES.items():
            for imp in signatures.get("imports", []):
                if any(imp in i for i in imports):
                    detected.append(fw_type)
                    break
        return detected

    def detect_from_code(self, code: str) -> List[FrameworkType]:
        """从代码内容检测框架"""
        detected = []
        for fw_type, signatures in self.FRAMEWORK_SIGNATURES.items():
            for pattern in signatures.get("patterns", []):
                if re.search(pattern, code):
                    detected.append(fw_type)
                    break
        return detected

    def detect_from_files(self, file_names: List[str]) -> List[FrameworkType]:
        """从文件名检测框架"""
        detected = []
        file_set = set(file_names)
        for fw_type, signatures in self.FRAMEWORK_SIGNATURES.items():
            for sig_file in signatures.get("files", []):
                if sig_file in file_set or any(f.endswith(sig_file) for f in file_names):
                    detected.append(fw_type)
                    break
        return detected


# ============================================================
# 路由提取器
# ============================================================

class RouteExtractor:
    """路由提取器基类"""

    def extract_routes(
        self,
        code: str,
        file_path: str,
        framework: FrameworkType
    ) -> List[RouteInfo]:
        """提取路由信息"""
        raise NotImplementedError


class PythonRouteExtractor(RouteExtractor):
    """Python 路由提取器"""

    # Flask 路由模式
    FLASK_PATTERNS = [
        # @app.route('/path', methods=['GET', 'POST'])
        r"@(?:app|blueprint|bp)\.route\(['\"]([^'\"]+)['\"](?:,\s*methods=\[([^\]]+)\])?\)",
        # @app.get('/path'), @app.post('/path')
        r"@(?:app|blueprint|bp)\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]\)",
    ]

    # FastAPI 路由模式
    FASTAPI_PATTERNS = [
        # @app.get('/path'), @router.post('/path')
        r"@(?:app|router)\.(get|post|put|delete|patch|options|head)\(['\"]([^'\"]+)['\"]\)",
        # @app.api_route('/path', methods=['GET'])
        r"@(?:app|router)\.api_route\(['\"]([^'\"]+)['\"](?:,\s*methods=\[([^\]]+)\])?\)",
    ]

    # Django URL 模式
    DJANGO_PATTERNS = [
        # path('url/', view, name='name')
        r"path\(['\"]([^'\"]+)['\"],\s*(\w+)",
        # re_path(r'^url/$', view)
        r"re_path\(r?['\"]([^'\"]+)['\"],\s*(\w+)",
    ]

    def extract_routes(
        self,
        code: str,
        file_path: str,
        framework: FrameworkType
    ) -> List[RouteInfo]:
        routes = []

        if framework == FrameworkType.FLASK:
            routes.extend(self._extract_flask_routes(code, file_path))
        elif framework == FrameworkType.FASTAPI:
            routes.extend(self._extract_fastapi_routes(code, file_path))
        elif framework == FrameworkType.DJANGO:
            routes.extend(self._extract_django_routes(code, file_path))

        return routes

    def _extract_flask_routes(self, code: str, file_path: str) -> List[RouteInfo]:
        routes = []
        lines = code.split('\n')

        for i, line in enumerate(lines):
            # 检查 @app.route 模式
            match = re.search(
                r"@(?:app|blueprint|bp)\.route\(['\"]([^'\"]+)['\"](?:,\s*methods=\[([^\]]+)\])?",
                line
            )
            if match:
                path = match.group(1)
                methods_str = match.group(2)
                methods = self._parse_methods(methods_str) if methods_str else ["GET"]

                # 查找处理函数名
                handler = self._find_next_function(lines, i + 1)

                routes.append(RouteInfo(
                    path=path,
                    methods=methods,
                    handler=handler,
                    file_path=file_path,
                    line=i + 1,
                    framework="flask",
                    params=self._extract_path_params(path),
                ))

            # 检查 @app.get/@app.post 模式
            match = re.search(
                r"@(?:app|blueprint|bp)\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]\)",
                line
            )
            if match:
                method = match.group(1).upper()
                path = match.group(2)
                handler = self._find_next_function(lines, i + 1)

                routes.append(RouteInfo(
                    path=path,
                    methods=[method],
                    handler=handler,
                    file_path=file_path,
                    line=i + 1,
                    framework="flask",
                    params=self._extract_path_params(path),
                ))

        return routes

    def _extract_fastapi_routes(self, code: str, file_path: str) -> List[RouteInfo]:
        routes = []
        lines = code.split('\n')

        for i, line in enumerate(lines):
            match = re.search(
                r"@(?:app|router)\.(get|post|put|delete|patch|options|head)\(['\"]([^'\"]+)['\"]\)",
                line
            )
            if match:
                method = match.group(1).upper()
                path = match.group(2)
                handler = self._find_next_function(lines, i + 1)

                routes.append(RouteInfo(
                    path=path,
                    methods=[method],
                    handler=handler,
                    file_path=file_path,
                    line=i + 1,
                    framework="fastapi",
                    params=self._extract_path_params(path),
                ))

        return routes

    def _extract_django_routes(self, code: str, file_path: str) -> List[RouteInfo]:
        routes = []
        lines = code.split('\n')

        for i, line in enumerate(lines):
            # path('url/', view)
            match = re.search(r"path\(['\"]([^'\"]+)['\"],\s*(\w+)", line)
            if match:
                path = "/" + match.group(1).strip("/")
                handler = match.group(2)

                routes.append(RouteInfo(
                    path=path,
                    methods=["GET", "POST"],  # Django 默认支持所有方法
                    handler=handler,
                    file_path=file_path,
                    line=i + 1,
                    framework="django",
                    params=self._extract_django_params(match.group(1)),
                ))

        return routes

    def _parse_methods(self, methods_str: str) -> List[str]:
        """解析方法列表字符串"""
        methods = re.findall(r"['\"](\w+)['\"]", methods_str)
        return [m.upper() for m in methods]

    def _find_next_function(self, lines: List[str], start: int) -> str:
        """查找下一个函数定义"""
        for i in range(start, min(start + 5, len(lines))):
            match = re.search(r"(?:async\s+)?def\s+(\w+)", lines[i])
            if match:
                return match.group(1)
        return "unknown"

    def _extract_path_params(self, path: str) -> List[str]:
        """提取路径参数"""
        # Flask/FastAPI: <param> 或 {param}
        params = re.findall(r"<(\w+)(?::\w+)?>|{(\w+)}", path)
        return [p[0] or p[1] for p in params]

    def _extract_django_params(self, path: str) -> List[str]:
        """提取 Django URL 参数"""
        # <type:name> 格式
        return re.findall(r"<\w+:(\w+)>", path)


class JavaScriptRouteExtractor(RouteExtractor):
    """JavaScript 路由提取器"""

    def extract_routes(
        self,
        code: str,
        file_path: str,
        framework: FrameworkType
    ) -> List[RouteInfo]:
        routes = []
        lines = code.split('\n')

        if framework == FrameworkType.EXPRESS:
            routes.extend(self._extract_express_routes(code, file_path, lines))
        elif framework == FrameworkType.NESTJS:
            routes.extend(self._extract_nestjs_routes(code, file_path, lines))

        return routes

    def _extract_express_routes(
        self, code: str, file_path: str, lines: List[str]
    ) -> List[RouteInfo]:
        routes = []

        for i, line in enumerate(lines):
            # app.get('/path', handler) 或 router.post('/path', handler)
            match = re.search(
                r"(?:app|router)\.(get|post|put|delete|patch|all)\(['\"]([^'\"]+)['\"]",
                line
            )
            if match:
                method = match.group(1).upper()
                if method == "ALL":
                    method = "*"
                path = match.group(2)

                # 尝试提取处理函数
                handler = self._extract_handler(line)

                routes.append(RouteInfo(
                    path=path,
                    methods=[method] if method != "*" else ["GET", "POST", "PUT", "DELETE", "PATCH"],
                    handler=handler,
                    file_path=file_path,
                    line=i + 1,
                    framework="express",
                    params=self._extract_express_params(path),
                ))

        return routes

    def _extract_nestjs_routes(
        self, code: str, file_path: str, lines: List[str]
    ) -> List[RouteInfo]:
        routes = []
        controller_path = ""

        for i, line in enumerate(lines):
            # @Controller('path')
            match = re.search(r"@Controller\(['\"]?([^'\")\s]*)['\"]?\)", line)
            if match:
                controller_path = "/" + match.group(1).strip("/")

            # @Get('path'), @Post('path')
            match = re.search(
                r"@(Get|Post|Put|Delete|Patch)\(['\"]?([^'\")\s]*)?['\"]?\)",
                line
            )
            if match:
                method = match.group(1).upper()
                path = match.group(2) or ""
                full_path = controller_path + "/" + path.strip("/")

                # 查找方法名
                handler = self._find_next_method(lines, i + 1)

                routes.append(RouteInfo(
                    path=full_path,
                    methods=[method],
                    handler=handler,
                    file_path=file_path,
                    line=i + 1,
                    framework="nestjs",
                    params=self._extract_express_params(full_path),
                ))

        return routes

    def _extract_handler(self, line: str) -> str:
        """从行中提取处理函数名"""
        # 尝试匹配函数名
        match = re.search(r",\s*(\w+)\s*[,)]", line)
        if match:
            return match.group(1)
        return "anonymous"

    def _find_next_method(self, lines: List[str], start: int) -> str:
        """查找下一个方法定义"""
        for i in range(start, min(start + 3, len(lines))):
            match = re.search(r"(?:async\s+)?(\w+)\s*\(", lines[i])
            if match and match.group(1) not in ("if", "for", "while", "function"):
                return match.group(1)
        return "unknown"

    def _extract_express_params(self, path: str) -> List[str]:
        """提取 Express 路径参数 :param"""
        return re.findall(r":(\w+)", path)


class JavaRouteExtractor(RouteExtractor):
    """Java 路由提取器（Spring）"""

    def extract_routes(
        self,
        code: str,
        file_path: str,
        framework: FrameworkType
    ) -> List[RouteInfo]:
        if framework != FrameworkType.SPRING:
            return []

        routes = []
        lines = code.split('\n')
        class_path = ""

        for i, line in enumerate(lines):
            # @RequestMapping 在类上
            match = re.search(r"@RequestMapping\(['\"]?([^'\")\s]*)['\"]?\)", line)
            if match:
                class_path = "/" + match.group(1).strip("/")

            # @GetMapping, @PostMapping 等
            match = re.search(
                r"@(Get|Post|Put|Delete|Patch|Request)Mapping\(['\"]?([^'\")\s]*)?['\"]?\)",
                line
            )
            if match:
                mapping_type = match.group(1)
                path = match.group(2) or ""
                full_path = class_path + "/" + path.strip("/")

                methods = ["GET"] if mapping_type == "Get" else \
                         ["POST"] if mapping_type == "Post" else \
                         ["PUT"] if mapping_type == "Put" else \
                         ["DELETE"] if mapping_type == "Delete" else \
                         ["PATCH"] if mapping_type == "Patch" else \
                         ["GET", "POST"]

                # 查找方法名
                handler = self._find_next_method(lines, i + 1)

                routes.append(RouteInfo(
                    path=full_path.replace("//", "/"),
                    methods=methods,
                    handler=handler,
                    file_path=file_path,
                    line=i + 1,
                    framework="spring",
                    params=self._extract_spring_params(full_path),
                ))

        return routes

    def _find_next_method(self, lines: List[str], start: int) -> str:
        """查找下一个方法定义"""
        for i in range(start, min(start + 5, len(lines))):
            match = re.search(r"(?:public|private|protected)?\s*\w+\s+(\w+)\s*\(", lines[i])
            if match:
                return match.group(1)
        return "unknown"

    def _extract_spring_params(self, path: str) -> List[str]:
        """提取 Spring 路径参数 {param}"""
        return re.findall(r"\{(\w+)\}", path)


class GoRouteExtractor(RouteExtractor):
    """Go 路由提取器"""

    def extract_routes(
        self,
        code: str,
        file_path: str,
        framework: FrameworkType
    ) -> List[RouteInfo]:
        routes = []
        lines = code.split('\n')

        if framework == FrameworkType.GIN:
            routes.extend(self._extract_gin_routes(code, file_path, lines))
        elif framework == FrameworkType.ECHO:
            routes.extend(self._extract_echo_routes(code, file_path, lines))
        elif framework == FrameworkType.FIBER:
            routes.extend(self._extract_fiber_routes(code, file_path, lines))
        elif framework == FrameworkType.CHI:
            routes.extend(self._extract_chi_routes(code, file_path, lines))

        return routes

    def _extract_gin_routes(
        self, code: str, file_path: str, lines: List[str]
    ) -> List[RouteInfo]:
        routes = []

        for i, line in enumerate(lines):
            # r.GET("/path", handler)
            match = re.search(
                r"(?:\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\(['\"]([^'\"]+)['\"]",
                line
            )
            if match:
                method = match.group(1)
                path = match.group(2)
                handler = self._extract_go_handler(line)

                routes.append(RouteInfo(
                    path=path,
                    methods=[method],
                    handler=handler,
                    file_path=file_path,
                    line=i + 1,
                    framework="gin",
                    params=self._extract_gin_params(path),
                ))

        return routes

    def _extract_echo_routes(
        self, code: str, file_path: str, lines: List[str]
    ) -> List[RouteInfo]:
        routes = []

        for i, line in enumerate(lines):
            match = re.search(
                r"(?:\w+)\.(GET|POST|PUT|DELETE|PATCH)\(['\"]([^'\"]+)['\"]",
                line
            )
            if match:
                method = match.group(1)
                path = match.group(2)
                handler = self._extract_go_handler(line)

                routes.append(RouteInfo(
                    path=path,
                    methods=[method],
                    handler=handler,
                    file_path=file_path,
                    line=i + 1,
                    framework="echo",
                    params=self._extract_echo_params(path),
                ))

        return routes

    def _extract_fiber_routes(
        self, code: str, file_path: str, lines: List[str]
    ) -> List[RouteInfo]:
        routes = []

        for i, line in enumerate(lines):
            match = re.search(
                r"(?:\w+)\.(Get|Post|Put|Delete|Patch)\(['\"]([^'\"]+)['\"]",
                line
            )
            if match:
                method = match.group(1).upper()
                path = match.group(2)
                handler = self._extract_go_handler(line)

                routes.append(RouteInfo(
                    path=path,
                    methods=[method],
                    handler=handler,
                    file_path=file_path,
                    line=i + 1,
                    framework="fiber",
                    params=self._extract_fiber_params(path),
                ))

        return routes

    def _extract_chi_routes(
        self, code: str, file_path: str, lines: List[str]
    ) -> List[RouteInfo]:
        routes = []

        for i, line in enumerate(lines):
            match = re.search(
                r"(?:\w+)\.(Get|Post|Put|Delete|Patch)\(['\"]([^'\"]+)['\"]",
                line
            )
            if match:
                method = match.group(1).upper()
                path = match.group(2)
                handler = self._extract_go_handler(line)

                routes.append(RouteInfo(
                    path=path,
                    methods=[method],
                    handler=handler,
                    file_path=file_path,
                    line=i + 1,
                    framework="chi",
                    params=self._extract_chi_params(path),
                ))

        return routes

    def _extract_go_handler(self, line: str) -> str:
        """提取 Go 处理函数名"""
        match = re.search(r",\s*(\w+)\s*\)", line)
        if match:
            return match.group(1)
        return "anonymous"

    def _extract_gin_params(self, path: str) -> List[str]:
        """Gin: :param 或 *param"""
        return re.findall(r"[:*](\w+)", path)

    def _extract_echo_params(self, path: str) -> List[str]:
        """Echo: :param"""
        return re.findall(r":(\w+)", path)

    def _extract_fiber_params(self, path: str) -> List[str]:
        """Fiber: :param 或 *"""
        return re.findall(r":(\w+)", path)

    def _extract_chi_params(self, path: str) -> List[str]:
        """Chi: {param}"""
        return re.findall(r"\{(\w+)\}", path)


class PHPRouteExtractor(RouteExtractor):
    """PHP 路由提取器"""

    def extract_routes(
        self,
        code: str,
        file_path: str,
        framework: FrameworkType
    ) -> List[RouteInfo]:
        routes = []
        lines = code.split('\n')

        if framework == FrameworkType.LARAVEL:
            routes.extend(self._extract_laravel_routes(code, file_path, lines))
        elif framework == FrameworkType.SYMFONY:
            routes.extend(self._extract_symfony_routes(code, file_path, lines))

        return routes

    def _extract_laravel_routes(
        self, code: str, file_path: str, lines: List[str]
    ) -> List[RouteInfo]:
        routes = []

        for i, line in enumerate(lines):
            # Route::get('/path', [Controller::class, 'method'])
            match = re.search(
                r"Route::(get|post|put|delete|patch|any)\(['\"]([^'\"]+)['\"]",
                line
            )
            if match:
                method = match.group(1).upper()
                if method == "ANY":
                    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
                else:
                    methods = [method]
                path = match.group(2)

                # 提取控制器和方法
                handler = self._extract_laravel_handler(line)

                routes.append(RouteInfo(
                    path=path,
                    methods=methods,
                    handler=handler,
                    file_path=file_path,
                    line=i + 1,
                    framework="laravel",
                    params=self._extract_laravel_params(path),
                ))

        return routes

    def _extract_symfony_routes(
        self, code: str, file_path: str, lines: List[str]
    ) -> List[RouteInfo]:
        routes = []

        for i, line in enumerate(lines):
            # #[Route('/path', methods: ['GET'])] 或 @Route("/path")
            match = re.search(
                r"(?:#\[|@)Route\(['\"]([^'\"]+)['\"](?:.*?methods:\s*\[([^\]]+)\])?",
                line
            )
            if match:
                path = match.group(1)
                methods_str = match.group(2)
                methods = self._parse_php_methods(methods_str) if methods_str else ["GET", "POST"]

                # 查找方法名
                handler = self._find_next_php_method(lines, i + 1)

                routes.append(RouteInfo(
                    path=path,
                    methods=methods,
                    handler=handler,
                    file_path=file_path,
                    line=i + 1,
                    framework="symfony",
                    params=self._extract_symfony_params(path),
                ))

        return routes

    def _extract_laravel_handler(self, line: str) -> str:
        """提取 Laravel 控制器处理方法"""
        # [Controller::class, 'method']
        match = re.search(r"(\w+)::class,\s*['\"](\w+)['\"]", line)
        if match:
            return f"{match.group(1)}@{match.group(2)}"
        # 'Controller@method'
        match = re.search(r"['\"](\w+@\w+)['\"]", line)
        if match:
            return match.group(1)
        return "anonymous"

    def _find_next_php_method(self, lines: List[str], start: int) -> str:
        """查找下一个 PHP 方法"""
        for i in range(start, min(start + 5, len(lines))):
            match = re.search(r"(?:public|private|protected)\s+function\s+(\w+)", lines[i])
            if match:
                return match.group(1)
        return "unknown"

    def _parse_php_methods(self, methods_str: str) -> List[str]:
        """解析 PHP 方法数组"""
        return re.findall(r"['\"](\w+)['\"]", methods_str)

    def _extract_laravel_params(self, path: str) -> List[str]:
        """Laravel: {param} 或 {param?}"""
        return re.findall(r"\{(\w+)\??}", path)

    def _extract_symfony_params(self, path: str) -> List[str]:
        """Symfony: {param}"""
        return re.findall(r"\{(\w+)\}", path)


# ============================================================
# 统一框架分析器
# ============================================================

class FrameworkAnalyzer:
    """统一框架分析器

    整合框架检测和路由提取功能。
    """

    def __init__(self):
        self.detector = FrameworkDetector()
        self.extractors: Dict[str, RouteExtractor] = {
            "python": PythonRouteExtractor(),
            "javascript": JavaScriptRouteExtractor(),
            "typescript": JavaScriptRouteExtractor(),
            "java": JavaRouteExtractor(),
            "go": GoRouteExtractor(),
            "php": PHPRouteExtractor(),
        }

    def analyze_file(
        self,
        code: str,
        file_path: str,
        language: str,
        imports: Optional[List[str]] = None,
    ) -> FrameworkInfo:
        """分析单个文件的框架信息"""
        # 检测框架
        frameworks = []
        if imports:
            frameworks.extend(self.detector.detect_from_imports(imports))
        frameworks.extend(self.detector.detect_from_code(code))

        if not frameworks:
            return FrameworkInfo(
                name="unknown",
                type=FrameworkType.UNKNOWN,
            )

        # 使用第一个检测到的框架
        framework = frameworks[0]

        # 提取路由
        extractor = self.extractors.get(language)
        routes = []
        if extractor:
            routes = extractor.extract_routes(code, file_path, framework)

        return FrameworkInfo(
            name=framework.value,
            type=framework,
            routes=routes,
        )

    def extract_all_routes(
        self,
        files: List[Dict[str, Any]],
    ) -> List[RouteInfo]:
        """从多个文件中提取所有路由

        Args:
            files: 文件列表，每个元素包含:
                - code: 文件内容
                - file_path: 文件路径
                - language: 语言
                - imports: 导入列表（可选）

        Returns:
            所有路由信息
        """
        all_routes = []
        for file_info in files:
            info = self.analyze_file(
                code=file_info.get("code", ""),
                file_path=file_info.get("file_path", ""),
                language=file_info.get("language", ""),
                imports=file_info.get("imports"),
            )
            all_routes.extend(info.routes)
        return all_routes


# 导出
__all__ = [
    "FrameworkType",
    "RouteInfo",
    "FrameworkInfo",
    "FrameworkDetector",
    "FrameworkAnalyzer",
    "RouteExtractor",
    "PythonRouteExtractor",
    "JavaScriptRouteExtractor",
    "JavaRouteExtractor",
    "GoRouteExtractor",
    "PHPRouteExtractor",
]
