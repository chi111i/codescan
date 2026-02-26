"""
轻量级污点分析模块 - Source → Sink 数据流追踪

功能：
1. 识别污点源（用户输入）
2. 追踪污点传播
3. 检测污点进入危险函数（sink）
4. 识别消毒函数（sanitizer）

设计原则：
- 基于 AST 的浅层数据流追踪
- 不依赖完整的数据流框架
- 为 LLM 分析提供精准的候选点
"""

import re
import ast
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any
from enum import Enum

from indexer import CodeUnit, CodeUnitType
from rules import RuleManager, RuleType, RiskLevel

logger = logging.getLogger(__name__)


class TaintType(Enum):
    """污点类型"""
    HTTP_PARAM = "http_param"      # HTTP 请求参数
    HTTP_BODY = "http_body"        # HTTP 请求体
    HTTP_HEADER = "http_header"    # HTTP 头
    COOKIE = "cookie"              # Cookie
    FILE_INPUT = "file_input"      # 文件输入
    DB_INPUT = "db_input"          # 数据库输入
    ENV_VAR = "env_var"            # 环境变量
    COMMAND_LINE = "command_line"  # 命令行参数
    USER_INPUT = "user_input"      # 其他用户输入


class SinkCategory(Enum):
    """危险函数类别"""
    COMMAND_EXEC = "command_exec"          # 命令执行
    CODE_EXEC = "code_exec"                # 代码执行
    FILE_READ = "file_read"                # 文件读取
    FILE_WRITE = "file_write"              # 文件写入
    SQL_QUERY = "sql_query"                # SQL 查询
    NOSQL_QUERY = "nosql_query"            # NoSQL 查询
    HTTP_REQUEST = "http_request"          # HTTP 请求
    TEMPLATE_RENDER = "template_render"    # 模板渲染
    DESERIALIZE = "deserialize"            # 反序列化
    REDIRECT = "redirect"                  # 重定向
    LOGGING = "logging"                    # 日志输出（信息泄露）


@dataclass
class TaintSource:
    """污点源定义"""
    taint_type: TaintType
    patterns: List[str]
    languages: List[str]
    description: str


@dataclass
class TaintSink:
    """危险函数定义"""
    category: SinkCategory
    patterns: List[str]
    languages: List[str]
    risk_level: RiskLevel
    description: str
    cwe_ids: List[str] = field(default_factory=list)


@dataclass
class Sanitizer:
    """消毒函数定义"""
    patterns: List[str]
    sanitizes: List[SinkCategory]  # 能防护的 sink 类型
    languages: List[str]
    description: str


@dataclass
class TaintFlow:
    """污点流"""
    source: str               # 污点源变量/表达式
    source_type: TaintType
    source_location: str      # file:line

    sink: str                 # sink 函数调用
    sink_category: SinkCategory
    sink_location: str        # file:line

    path: List[str]           # 传播路径
    is_sanitized: bool        # 是否被消毒
    sanitizers: List[str]     # 途经的消毒函数

    confidence: float         # 置信度
    risk_level: RiskLevel
    description: str


# ============ 污点源定义 ============
TAINT_SOURCES: List[TaintSource] = [
    # Python - Flask/Django
    TaintSource(
        taint_type=TaintType.HTTP_PARAM,
        patterns=[
            r"request\.args\[",
            r"request\.args\.get\(",
            r"request\.form\[",
            r"request\.form\.get\(",
            r"request\.GET\[",
            r"request\.GET\.get\(",
            r"request\.POST\[",
            r"request\.POST\.get\(",
            r"request\.values\[",
            r"request\.params",
        ],
        languages=["python"],
        description="HTTP 请求参数"
    ),
    TaintSource(
        taint_type=TaintType.HTTP_BODY,
        patterns=[
            r"request\.json",
            r"request\.data",
            r"request\.get_json\(",
            r"request\.body",
        ],
        languages=["python"],
        description="HTTP 请求体"
    ),
    TaintSource(
        taint_type=TaintType.HTTP_HEADER,
        patterns=[
            r"request\.headers\[",
            r"request\.headers\.get\(",
            r"request\.META\[",
        ],
        languages=["python"],
        description="HTTP 请求头"
    ),
    TaintSource(
        taint_type=TaintType.COOKIE,
        patterns=[
            r"request\.cookies\[",
            r"request\.cookies\.get\(",
            r"request\.COOKIES\[",
        ],
        languages=["python"],
        description="Cookie"
    ),
    TaintSource(
        taint_type=TaintType.FILE_INPUT,
        patterns=[
            r"request\.files\[",
            r"request\.FILES\[",
            r"\.filename",
        ],
        languages=["python"],
        description="文件上传"
    ),
    TaintSource(
        taint_type=TaintType.USER_INPUT,
        patterns=[
            r"input\s*\(",
            r"sys\.stdin",
        ],
        languages=["python"],
        description="用户输入"
    ),
    TaintSource(
        taint_type=TaintType.COMMAND_LINE,
        patterns=[
            r"sys\.argv",
            r"argparse",
        ],
        languages=["python"],
        description="命令行参数"
    ),
    TaintSource(
        taint_type=TaintType.ENV_VAR,
        patterns=[
            r"os\.environ\[",
            r"os\.environ\.get\(",
            r"os\.getenv\(",
        ],
        languages=["python"],
        description="环境变量"
    ),

    # JavaScript/TypeScript - Express/Node.js
    TaintSource(
        taint_type=TaintType.HTTP_PARAM,
        patterns=[
            r"req\.query\.",
            r"req\.query\[",
            r"req\.params\.",
            r"req\.params\[",
        ],
        languages=["javascript", "typescript"],
        description="HTTP 请求参数"
    ),
    TaintSource(
        taint_type=TaintType.HTTP_BODY,
        patterns=[
            r"req\.body\.",
            r"req\.body\[",
        ],
        languages=["javascript", "typescript"],
        description="HTTP 请求体"
    ),
    TaintSource(
        taint_type=TaintType.HTTP_HEADER,
        patterns=[
            r"req\.headers\[",
            r"req\.get\(",
        ],
        languages=["javascript", "typescript"],
        description="HTTP 请求头"
    ),
    TaintSource(
        taint_type=TaintType.COOKIE,
        patterns=[
            r"req\.cookies\.",
            r"req\.cookies\[",
        ],
        languages=["javascript", "typescript"],
        description="Cookie"
    ),
    TaintSource(
        taint_type=TaintType.FILE_INPUT,
        patterns=[
            r"req\.file\.",
            r"req\.files\[",
            r"\.originalname",
        ],
        languages=["javascript", "typescript"],
        description="文件上传"
    ),
    TaintSource(
        taint_type=TaintType.ENV_VAR,
        patterns=[
            r"process\.env\.",
            r"process\.env\[",
        ],
        languages=["javascript", "typescript"],
        description="环境变量"
    ),
]

# ============ 危险函数定义 ============
TAINT_SINKS: List[TaintSink] = [
    # 命令执行
    TaintSink(
        category=SinkCategory.COMMAND_EXEC,
        patterns=[
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
            r"subprocess\.(call|run|Popen|check_output|check_call)\s*\(",
            r"commands\.(getoutput|getstatusoutput)\s*\(",
            r"child_process\.(exec|execSync|spawn|spawnSync|execFile)\s*\(",
            r"shell_exec\s*\(",
            r"`[^`]*\$\{",
        ],
        languages=["python", "javascript", "typescript", "php"],
        risk_level=RiskLevel.CRITICAL,
        description="系统命令执行",
        cwe_ids=["CWE-78", "CWE-77"]
    ),
    # 代码执行
    TaintSink(
        category=SinkCategory.CODE_EXEC,
        patterns=[
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"\bcompile\s*\(",
            r"new\s+Function\s*\(",
            r"vm\.runInContext\s*\(",
            r"vm\.runInNewContext\s*\(",
        ],
        languages=["python", "javascript", "typescript"],
        risk_level=RiskLevel.CRITICAL,
        description="动态代码执行",
        cwe_ids=["CWE-94", "CWE-95"]
    ),
    # 文件读取
    TaintSink(
        category=SinkCategory.FILE_READ,
        patterns=[
            r"\bopen\s*\([^)]*,\s*['\"]r",
            r"\.read\s*\(",
            r"\.readlines\s*\(",
            r"\.readline\s*\(",
            r"Path\([^)]*\)\.read_",
            r"fs\.readFile(Sync)?\s*\(",
            r"fs\.createReadStream\s*\(",
            r"file_get_contents\s*\(",
        ],
        languages=["python", "javascript", "typescript", "php"],
        risk_level=RiskLevel.HIGH,
        description="文件读取",
        cwe_ids=["CWE-22", "CWE-73"]
    ),
    # 文件写入
    TaintSink(
        category=SinkCategory.FILE_WRITE,
        patterns=[
            r"\bopen\s*\([^)]*,\s*['\"]w",
            r"\.write\s*\(",
            r"\.writelines\s*\(",
            r"Path\([^)]*\)\.write_",
            r"fs\.writeFile(Sync)?\s*\(",
            r"fs\.createWriteStream\s*\(",
            r"file_put_contents\s*\(",
            r"move_uploaded_file\s*\(",
        ],
        languages=["python", "javascript", "typescript", "php"],
        risk_level=RiskLevel.CRITICAL,
        description="文件写入",
        cwe_ids=["CWE-22", "CWE-73", "CWE-434"]
    ),
    # SQL 查询
    TaintSink(
        category=SinkCategory.SQL_QUERY,
        patterns=[
            r"cursor\.execute\s*\(",
            r"\.raw\s*\(",
            r"\.extra\s*\(",
            r"connection\.query\s*\(",
            r"pool\.query\s*\(",
            r"sequelize\.query\s*\(",
            r"mysql_query\s*\(",
        ],
        languages=["python", "javascript", "typescript", "php"],
        risk_level=RiskLevel.CRITICAL,
        description="SQL 查询执行",
        cwe_ids=["CWE-89"]
    ),
    # HTTP 请求
    TaintSink(
        category=SinkCategory.HTTP_REQUEST,
        patterns=[
            r"requests\.(get|post|put|delete|patch|head|options)\s*\(",
            r"urllib\.request\.urlopen\s*\(",
            r"http\.request\s*\(",
            r"axios\.(get|post|put|delete|patch)\s*\(",
            r"fetch\s*\(",
            r"curl_exec\s*\(",
        ],
        languages=["python", "javascript", "typescript", "php"],
        risk_level=RiskLevel.HIGH,
        description="HTTP 请求",
        cwe_ids=["CWE-918"]
    ),
    # 模板渲染
    TaintSink(
        category=SinkCategory.TEMPLATE_RENDER,
        patterns=[
            r"Template\s*\(",
            r"render_template_string\s*\(",
            r"Jinja2\.from_string\s*\(",
            r"\.substitute\s*\(",
            r"format_map\s*\(",
            r"ejs\.render\s*\(",
        ],
        languages=["python", "javascript", "typescript"],
        risk_level=RiskLevel.CRITICAL,
        description="模板渲染",
        cwe_ids=["CWE-94", "CWE-1336"]
    ),
    # 反序列化
    TaintSink(
        category=SinkCategory.DESERIALIZE,
        patterns=[
            r"pickle\.loads?\s*\(",
            r"yaml\.load\s*\(",
            r"yaml\.unsafe_load\s*\(",
            r"marshal\.loads?\s*\(",
            r"jsonpickle\.decode\s*\(",
            r"unserialize\s*\(",
        ],
        languages=["python", "php"],
        risk_level=RiskLevel.CRITICAL,
        description="反序列化",
        cwe_ids=["CWE-502"]
    ),
    # 重定向
    TaintSink(
        category=SinkCategory.REDIRECT,
        patterns=[
            r"redirect\s*\(",
            r"HttpResponseRedirect\s*\(",
            r"res\.redirect\s*\(",
            r"header\s*\(\s*['\"]Location",
        ],
        languages=["python", "javascript", "typescript", "php"],
        risk_level=RiskLevel.MEDIUM,
        description="URL 重定向",
        cwe_ids=["CWE-601"]
    ),
]

# ============ 消毒函数定义 ============
SANITIZERS: List[Sanitizer] = [
    # SQL 注入防护
    Sanitizer(
        patterns=[
            r"\.execute\s*\([^,]+,\s*\(",  # 参数化查询
            r"\.execute\s*\([^,]+,\s*\[",  # 参数化查询
            r"escape_string\s*\(",
            r"quote\s*\(",
            r"parameterized",
        ],
        sanitizes=[SinkCategory.SQL_QUERY],
        languages=["python", "javascript", "php"],
        description="SQL 参数化/转义"
    ),
    # 命令注入防护
    Sanitizer(
        patterns=[
            r"shlex\.quote\s*\(",
            r"shlex\.split\s*\(",
            r"shell\s*=\s*False",
            r"escapeshellarg\s*\(",
            r"escapeshellcmd\s*\(",
        ],
        sanitizes=[SinkCategory.COMMAND_EXEC],
        languages=["python", "php"],
        description="命令行参数转义"
    ),
    # 路径遍历防护
    Sanitizer(
        patterns=[
            r"os\.path\.realpath\s*\(",
            r"os\.path\.abspath\s*\(",
            r"path\.resolve\s*\(",
            r"\.startswith\s*\([^)]*base",
            r"secure_filename\s*\(",
            r"basename\s*\(",
        ],
        sanitizes=[SinkCategory.FILE_READ, SinkCategory.FILE_WRITE],
        languages=["python", "javascript", "typescript"],
        description="路径规范化"
    ),
    # SSRF 防护
    Sanitizer(
        patterns=[
            r"urlparse\s*\(",
            r"\.hostname\s*==",
            r"\.netloc\s*in",
            r"whitelist",
            r"allowlist",
        ],
        sanitizes=[SinkCategory.HTTP_REQUEST],
        languages=["python", "javascript", "typescript"],
        description="URL 白名单验证"
    ),
    # XSS 防护（模板自动转义）
    Sanitizer(
        patterns=[
            r"autoescape\s*=\s*True",
            r"escape\s*\(",
            r"html\.escape\s*\(",
            r"markupsafe\.escape\s*\(",
        ],
        sanitizes=[SinkCategory.TEMPLATE_RENDER],
        languages=["python"],
        description="HTML 转义"
    ),
]


@dataclass
class TaintedVariable:
    """被污染的变量"""
    name: str
    source_type: TaintType
    source_location: str
    propagation_path: List[str] = field(default_factory=list)
    # === 新增：跨函数追踪字段 ===
    origin_function: Optional[str] = None  # 污点起源函数
    parameter_index: Optional[int] = None  # 如果是参数，记录参数位置


@dataclass
class InterproceduralTaint:
    """跨函数污点信息"""
    tainted_var: TaintedVariable
    function_id: str           # 当前函数 ID
    function_name: str         # 当前函数名
    is_parameter: bool         # 是否是函数参数
    parameter_index: int       # 参数位置（如果是参数）
    is_return_value: bool      # 是否是返回值
    callers: List[str] = field(default_factory=list)  # 调用该函数的函数列表
    callees: List[str] = field(default_factory=list)  # 被调用的函数列表


@dataclass
class CrossFunctionFlow:
    """跨函数污点流"""
    source_function: str       # 源函数
    source_var: str            # 源变量
    source_type: TaintType
    source_location: str

    target_function: str       # 目标函数
    target_var: str            # 目标变量（参数名）
    target_location: str

    sink_function: Optional[str] = None   # 最终的 sink 函数
    sink_call: Optional[str] = None       # sink 调用
    sink_category: Optional[SinkCategory] = None

    call_chain: List[str] = field(default_factory=list)  # 完整调用链
    is_sanitized: bool = False
    sanitizers: List[str] = field(default_factory=list)

    confidence: float = 0.5
    risk_level: RiskLevel = RiskLevel.MEDIUM
    description: str = ""


# ============ 框架污点传播规则 ============
@dataclass
class FrameworkPropagationRule:
    """框架特定的污点传播规则"""
    framework: str
    languages: List[str]
    description: str
    # 传播模式：哪些对象/属性会传递污点
    propagation_patterns: List[str]
    # 自动标记为污点的对象
    auto_taint_objects: List[str]
    # 消毒方法
    sanitize_methods: List[str]


FRAMEWORK_PROPAGATION_RULES: List[FrameworkPropagationRule] = [
    # Flask 框架
    FrameworkPropagationRule(
        framework="flask",
        languages=["python"],
        description="Flask 请求对象传播",
        propagation_patterns=[
            r"request\.args",
            r"request\.form",
            r"request\.json",
            r"request\.data",
            r"request\.cookies",
            r"request\.headers",
            r"request\.files",
            r"request\.values",
            r"g\.\w+",  # Flask g 对象
        ],
        auto_taint_objects=[
            "request",
            "session",
        ],
        sanitize_methods=[
            "escape",
            "Markup",
        ],
    ),
    # Django 框架
    FrameworkPropagationRule(
        framework="django",
        languages=["python"],
        description="Django 请求对象传播",
        propagation_patterns=[
            r"request\.GET",
            r"request\.POST",
            r"request\.body",
            r"request\.COOKIES",
            r"request\.META",
            r"request\.FILES",
            r"request\.user",
        ],
        auto_taint_objects=[
            "request",
        ],
        sanitize_methods=[
            "escape",
            "mark_safe",
            "format_html",
        ],
    ),
    # Express.js 框架
    FrameworkPropagationRule(
        framework="express",
        languages=["javascript", "typescript"],
        description="Express 请求对象传播",
        propagation_patterns=[
            r"req\.body",
            r"req\.query",
            r"req\.params",
            r"req\.cookies",
            r"req\.headers",
            r"req\.files?",
            r"req\.session",
        ],
        auto_taint_objects=[
            "req",
            "request",
        ],
        sanitize_methods=[
            "sanitize",
            "escape",
            "validator",
        ],
    ),
    # FastAPI 框架
    FrameworkPropagationRule(
        framework="fastapi",
        languages=["python"],
        description="FastAPI 请求参数传播",
        propagation_patterns=[
            r"Body\s*\(",
            r"Query\s*\(",
            r"Path\s*\(",
            r"Header\s*\(",
            r"Cookie\s*\(",
            r"Form\s*\(",
            r"File\s*\(",
        ],
        auto_taint_objects=[],
        sanitize_methods=[],
    ),
    # Spring 框架 (Java)
    FrameworkPropagationRule(
        framework="spring",
        languages=["java"],
        description="Spring 请求参数传播",
        propagation_patterns=[
            r"@RequestParam",
            r"@PathVariable",
            r"@RequestBody",
            r"@RequestHeader",
            r"@CookieValue",
            r"HttpServletRequest",
        ],
        auto_taint_objects=[
            "request",
            "HttpServletRequest",
        ],
        sanitize_methods=[
            "HtmlUtils.htmlEscape",
            "StringEscapeUtils",
        ],
    ),
]


class TaintAnalyzer:
    """轻量级污点分析器 - 支持跨函数/跨文件追踪"""

    def __init__(
        self,
        rule_manager: Optional[RuleManager] = None,
        call_graph: Optional[Any] = None,  # CallGraph 类型，避免循环导入
    ):
        self.rule_manager = rule_manager
        self.call_graph = call_graph
        self.tainted_vars: Dict[str, TaintedVariable] = {}
        self.flows: List[TaintFlow] = []

        # === 新增：跨函数污点追踪 ===
        # 函数级污点信息：function_id -> List[InterproceduralTaint]
        self.function_taints: Dict[str, List[InterproceduralTaint]] = {}
        # 跨函数污点流
        self.cross_function_flows: List[CrossFunctionFlow] = []
        # 代码单元缓存：id -> CodeUnit
        self._code_units_cache: Dict[str, CodeUnit] = {}
        # 函数参数映射：function_id -> List[parameter_name]
        self._function_params: Dict[str, List[str]] = {}
        # 检测到的框架
        self._detected_frameworks: Set[str] = set()

    def analyze_code_unit(self, unit: CodeUnit) -> List[TaintFlow]:
        """分析单个代码单元的污点流

        Args:
            unit: 代码单元

        Returns:
            发现的污点流列表
        """
        flows = []
        code = unit.code
        language = unit.language

        # 1. 识别污点源
        tainted_vars = self._find_taint_sources(code, language, unit.file_path, unit.span.start_line)

        if not tainted_vars:
            return flows

        # 2. 追踪污点传播
        self._track_propagation(code, tainted_vars)

        # 3. 检测 sink
        sink_matches = self._find_sinks(code, language)

        # 4. 检查污点是否进入 sink
        for sink_pattern, sink_def, sink_match in sink_matches:
            for var_name, tainted_var in tainted_vars.items():
                # 检查污点变量是否在 sink 调用附近
                if self._is_taint_in_sink(code, var_name, sink_match):
                    # 检查是否被消毒
                    is_sanitized, sanitizers = self._check_sanitization(
                        code, var_name, sink_def.category, language
                    )

                    # 计算置信度
                    confidence = self._calculate_confidence(
                        tainted_var, sink_def, is_sanitized
                    )

                    flow = TaintFlow(
                        source=var_name,
                        source_type=tainted_var.source_type,
                        source_location=tainted_var.source_location,
                        sink=sink_match.group(0),
                        sink_category=sink_def.category,
                        sink_location=f"{unit.file_path}:{unit.span.start_line}",
                        path=tainted_var.propagation_path + [var_name, sink_match.group(0)],
                        is_sanitized=is_sanitized,
                        sanitizers=sanitizers,
                        confidence=confidence,
                        risk_level=sink_def.risk_level if not is_sanitized else RiskLevel.LOW,
                        description=self._generate_description(
                            tainted_var, sink_def, is_sanitized
                        )
                    )
                    flows.append(flow)

        return flows

    def _find_taint_sources(
        self,
        code: str,
        language: str,
        file_path: str,
        start_line: int
    ) -> Dict[str, TaintedVariable]:
        """识别污点源"""
        tainted = {}

        for source_def in TAINT_SOURCES:
            if language not in source_def.languages:
                continue

            for pattern in source_def.patterns:
                for match in re.finditer(pattern, code, re.IGNORECASE):
                    # 找到被赋值的变量
                    var_name = self._find_assigned_variable(code, match.start())
                    if var_name and var_name not in tainted:
                        # 计算行号
                        line_offset = code[:match.start()].count('\n')

                        tainted[var_name] = TaintedVariable(
                            name=var_name,
                            source_type=source_def.taint_type,
                            source_location=f"{file_path}:{start_line + line_offset}",
                            propagation_path=[match.group(0)]
                        )

        return tainted

    def _find_assigned_variable(self, code: str, source_pos: int) -> Optional[str]:
        """找到污点源被赋值给的变量

        例如: user_input = request.args.get('name')
        返回: user_input
        """
        # 找到该行的开头
        line_start = code.rfind('\n', 0, source_pos) + 1
        line = code[line_start:source_pos]

        # 匹配赋值模式
        # Python: var = ...
        # JS: let/const/var name = ... 或 name = ...
        patterns = [
            r'(\w+)\s*=\s*$',                    # var =
            r'(?:let|const|var)\s+(\w+)\s*=\s*$', # let/const/var name =
        ]

        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)

        return None

    def _track_propagation(
        self,
        code: str,
        tainted_vars: Dict[str, TaintedVariable]
    ) -> None:
        """追踪污点传播（浅层）

        检测赋值传播：new_var = tainted_var
        检测字符串操作：new_var = tainted_var + "something"
        检测函数调用：new_var = func(tainted_var)
        """
        # 简单的赋值传播模式
        propagation_patterns = [
            r'(\w+)\s*=\s*(\w+)',                     # a = b
            r'(\w+)\s*=\s*(\w+)\s*\+',                # a = b +
            r'(\w+)\s*=\s*f[\'"].*\{(\w+)\}',         # f-string
            r'(\w+)\s*=\s*[\'"].*\%.*\%\s*(\w+)',     # % formatting
            r'(\w+)\s*=\s*[\'"].*\.format\(.*(\w+)',  # .format()
        ]

        original_tainted = set(tainted_vars.keys())

        for pattern in propagation_patterns:
            for match in re.finditer(pattern, code):
                target_var = match.group(1)
                source_var = match.group(2) if len(match.groups()) > 1 else None

                if source_var and source_var in tainted_vars and target_var not in tainted_vars:
                    # 污点传播
                    original = tainted_vars[source_var]
                    tainted_vars[target_var] = TaintedVariable(
                        name=target_var,
                        source_type=original.source_type,
                        source_location=original.source_location,
                        propagation_path=original.propagation_path + [f"{source_var} -> {target_var}"]
                    )

    def _find_sinks(
        self,
        code: str,
        language: str
    ) -> List[Tuple[str, TaintSink, re.Match]]:
        """找到所有 sink 调用"""
        sinks = []

        for sink_def in TAINT_SINKS:
            if language not in sink_def.languages:
                continue

            for pattern in sink_def.patterns:
                for match in re.finditer(pattern, code, re.IGNORECASE):
                    sinks.append((pattern, sink_def, match))

        return sinks

    def _is_taint_in_sink(
        self,
        code: str,
        var_name: str,
        sink_match: re.Match
    ) -> bool:
        """检查污点变量是否在 sink 调用中使用

        简单检查：sink 调用后的括号内是否包含污点变量
        """
        # 找到 sink 调用的结束位置（匹配括号）
        start = sink_match.end()

        # 找到对应的结束括号
        depth = 1
        end = start
        while end < len(code) and depth > 0:
            if code[end] == '(':
                depth += 1
            elif code[end] == ')':
                depth -= 1
            end += 1

        # 检查这个范围内是否包含污点变量
        sink_args = code[start:end]

        # 检查变量名是否出现在参数中
        # 使用单词边界匹配，避免误匹配
        pattern = r'\b' + re.escape(var_name) + r'\b'
        return bool(re.search(pattern, sink_args))

    def _check_sanitization(
        self,
        code: str,
        var_name: str,
        sink_category: SinkCategory,
        language: str
    ) -> Tuple[bool, List[str]]:
        """检查是否存在消毒处理

        BUG #17 Fix: 消毒判定需要关联污点变量，而非仅检查消毒函数是否出现在代码中。
        """
        found_sanitizers = []

        for sanitizer in SANITIZERS:
            if language not in sanitizer.languages:
                continue
            if sink_category not in sanitizer.sanitizes:
                continue

            for pattern in sanitizer.patterns:
                match = re.search(pattern, code, re.IGNORECASE)
                if match:
                    # 获取匹配位置所在行及前后各 1 行的上下文
                    match_start = match.start()
                    match_end = match.end()

                    # 找到匹配所在行的范围
                    line_start = code.rfind('\n', 0, match_start) + 1
                    line_end = code.find('\n', match_end)
                    if line_end == -1:
                        line_end = len(code)

                    # 扩展到前后各 1 行
                    prev_line_start = code.rfind('\n', 0, max(0, line_start - 1)) + 1
                    next_line_end = code.find('\n', line_end + 1)
                    if next_line_end == -1:
                        next_line_end = len(code)

                    context_window = code[prev_line_start:next_line_end]

                    # 检查污点变量是否出现在消毒函数的上下文窗口中
                    if var_name and var_name in context_window:
                        found_sanitizers.append(sanitizer.description)
                    elif not var_name:
                        # 如果没有指定变量名，保持原有行为（兼容）
                        found_sanitizers.append(sanitizer.description)

        return len(found_sanitizers) > 0, found_sanitizers

    def _calculate_confidence(
        self,
        tainted_var: TaintedVariable,
        sink_def: TaintSink,
        is_sanitized: bool
    ) -> float:
        """计算置信度"""
        confidence = 0.5

        # 基于污点源类型
        high_risk_sources = {TaintType.HTTP_PARAM, TaintType.HTTP_BODY, TaintType.COOKIE}
        if tainted_var.source_type in high_risk_sources:
            confidence += 0.2

        # 基于 sink 危险程度
        if sink_def.risk_level == RiskLevel.CRITICAL:
            confidence += 0.2
        elif sink_def.risk_level == RiskLevel.HIGH:
            confidence += 0.1

        # 如果被消毒，大幅降低置信度
        if is_sanitized:
            confidence *= 0.3

        # 传播路径越长，置信度越低
        path_len = len(tainted_var.propagation_path)
        if path_len > 3:
            confidence *= 0.9 ** (path_len - 3)

        return min(max(confidence, 0.1), 0.95)

    def _generate_description(
        self,
        tainted_var: TaintedVariable,
        sink_def: TaintSink,
        is_sanitized: bool
    ) -> str:
        """生成描述"""
        parts = [
            f"检测到用户输入 ({tainted_var.source_type.value}) 流入 {sink_def.description}",
            f"污点源: {tainted_var.source_location}",
        ]

        if tainted_var.propagation_path:
            parts.append(f"传播路径: {' -> '.join(tainted_var.propagation_path[:5])}")

        if is_sanitized:
            parts.append("注意: 检测到可能的消毒处理，需要人工确认其有效性")

        return "\n".join(parts)

    def analyze_code_units(
        self,
        code_units: List[CodeUnit],
        filter_sanitized: bool = False
    ) -> List[TaintFlow]:
        """批量分析代码单元

        Args:
            code_units: 代码单元列表
            filter_sanitized: 是否过滤已消毒的流

        Returns:
            所有发现的污点流
        """
        all_flows = []

        for unit in code_units:
            try:
                flows = self.analyze_code_unit(unit)
                if filter_sanitized:
                    flows = [f for f in flows if not f.is_sanitized]
                all_flows.extend(flows)
            except Exception as e:
                logger.warning(f"Failed to analyze {unit.file_path}:{unit.symbol}: {e}")

        # 按风险级别和置信度排序
        all_flows.sort(key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.risk_level.value, 4),
            -f.confidence
        ))

        return all_flows

    def get_summary(self, flows: List[TaintFlow]) -> Dict[str, Any]:
        """获取分析摘要"""
        summary = {
            "total_flows": len(flows),
            "by_risk_level": {},
            "by_sink_category": {},
            "by_source_type": {},
            "sanitized_count": 0,
            "high_confidence_count": 0,
        }

        for flow in flows:
            # 按风险级别
            level = flow.risk_level.value
            summary["by_risk_level"][level] = summary["by_risk_level"].get(level, 0) + 1

            # 按 sink 类别
            category = flow.sink_category.value
            summary["by_sink_category"][category] = summary["by_sink_category"].get(category, 0) + 1

            # 按污点源类型
            source = flow.source_type.value
            summary["by_source_type"][source] = summary["by_source_type"].get(source, 0) + 1

            # 统计
            if flow.is_sanitized:
                summary["sanitized_count"] += 1
            if flow.confidence >= 0.7:
                summary["high_confidence_count"] += 1

        return summary

    # ============ 跨函数/跨文件污点分析 (Phase 1 & 2) ============

    def analyze_interprocedural(
        self,
        code_units: List[CodeUnit],
        max_depth: int = 10,
        use_topological: bool = True,
    ) -> List[CrossFunctionFlow]:
        """跨函数污点分析

        Phase 1: 函数间参数传递追踪
        Phase 2: 框架特定污点传播

        Args:
            code_units: 代码单元列表
            max_depth: 最大追踪深度
            use_topological: 是否使用拓扑排序优化

        Returns:
            跨函数污点流列表
        """
        logger.info(f"Starting interprocedural taint analysis on {len(code_units)} units...")

        # 清理上一轮分析的缓存，避免重复或过期污点结果
        self.function_taints.clear()
        self.cross_function_flows.clear()
        self._code_units_cache.clear()
        self._function_params.clear()
        self._detected_frameworks.clear()
        self.tainted_vars.clear()
        self.flows.clear()

        # 1. 缓存代码单元并提取函数参数
        self._build_code_unit_cache(code_units)

        # 2. 检测使用的框架
        self._detect_frameworks(code_units)

        # 3. 使用拓扑排序优化分析顺序
        if use_topological and self.call_graph:
            logger.info("Using topological ordering for taint propagation...")
            self._analyze_with_topological_order()
        else:
            # 原始方法：分析每个函数的内部污点
            for unit in code_units:
                self._analyze_function_taints(unit)

            # 使用迭代传播
            if self.call_graph:
                self._propagate_taints_across_calls(max_depth)

        # 4. 查找最终的 sink
        self._find_cross_function_sinks()

        logger.info(f"Found {len(self.cross_function_flows)} cross-function taint flows")
        return self.cross_function_flows

    def _analyze_with_topological_order(self) -> None:
        """使用拓扑排序优化污点分析

        按依赖顺序分析函数，确保被调用函数先于调用者分析，
        从而实现单次遍历完成污点传播。
        """
        from .optimized_algorithms import OptimizedPathFinder

        optimizer = OptimizedPathFinder(self.call_graph)
        topo_order = optimizer.compute_topological_order()

        logger.debug(f"Analyzing {len(topo_order)} functions in topological order")

        # 按拓扑序分析
        for func_id in topo_order:
            unit = self._code_units_cache.get(func_id)
            if not unit:
                continue

            # 分析函数内部污点
            self._analyze_function_taints(unit)

            # 从调用者传播污点（调用者在拓扑序中已经分析）
            self._propagate_from_callers_single_pass(func_id)

    def _propagate_from_callers_single_pass(self, func_id: str) -> None:
        """从调用者单次传播污点（用于拓扑排序模式）

        Args:
            func_id: 当前函数 ID
        """
        if not self.call_graph:
            return

        # 获取当前函数
        unit = self._code_units_cache.get(func_id)
        if not unit:
            return

        # 获取所有调用者
        callers = self.call_graph._callers.get(func_id, set())

        for caller_id in callers:
            # 获取 caller 的污点
            caller_taints = self.function_taints.get(caller_id, [])
            if not caller_taints:
                continue

            caller_unit = self._code_units_cache.get(caller_id)
            if not caller_unit:
                continue

            # 获取当前函数的参数
            callee_params = self._function_params.get(func_id, [])
            if not callee_params:
                continue

            # 提取调用时的参数
            call_args = self._extract_call_arguments(caller_unit.code, unit.symbol)

            # 检查每个参数是否被污染
            for arg_idx, arg in enumerate(call_args):
                for taint in caller_taints:
                    if taint.tainted_var.name == arg:
                        # 传播到当前函数的对应参数
                        if arg_idx < len(callee_params):
                            param_name = callee_params[arg_idx]

                            # 检查是否已存在
                            existing_taints = self.function_taints.get(func_id, [])
                            already_exists = any(
                                t.tainted_var.name == param_name and t.is_parameter
                                for t in existing_taints
                            )

                            if not already_exists:
                                # 创建新的污点
                                new_tainted_var = TaintedVariable(
                                    name=param_name,
                                    source_type=taint.tainted_var.source_type,
                                    source_location=taint.tainted_var.source_location,
                                    propagation_path=taint.tainted_var.propagation_path + [
                                        f"{caller_unit.symbol}:{arg} -> {unit.symbol}:{param_name}"
                                    ],
                                    origin_function=taint.tainted_var.origin_function,
                                    parameter_index=arg_idx,
                                )

                                new_taint = InterproceduralTaint(
                                    tainted_var=new_tainted_var,
                                    function_id=func_id,
                                    function_name=unit.symbol,
                                    is_parameter=True,
                                    parameter_index=arg_idx,
                                    is_return_value=False,
                                    callers=[caller_id],
                                )

                                if func_id not in self.function_taints:
                                    self.function_taints[func_id] = []
                                self.function_taints[func_id].append(new_taint)

    def _build_code_unit_cache(self, code_units: List[CodeUnit]) -> None:
        """构建代码单元缓存并提取参数信息"""
        for unit in code_units:
            self._code_units_cache[unit.id] = unit
            # 提取函数参数
            params = self._extract_function_parameters(unit)
            self._function_params[unit.id] = params

    def _extract_function_parameters(self, unit: CodeUnit) -> List[str]:
        """从代码单元提取函数参数列表"""
        params = []

        # 从签名中提取
        if unit.signature:
            # Python 风格: def func(a, b, c):
            match = re.search(r'\(([^)]*)\)', unit.signature)
            if match:
                param_str = match.group(1)
                # 分割参数，处理默认值和类型注解
                for param in param_str.split(','):
                    param = param.strip()
                    if not param or param in ('self', 'cls'):
                        continue
                    # 提取参数名（去掉类型注解和默认值）
                    param_name = re.split(r'[:\s=]', param)[0].strip()
                    if param_name and param_name not in ('*', '**'):
                        # 去掉 * 和 **
                        param_name = param_name.lstrip('*')
                        if param_name:
                            params.append(param_name)

        return params

    def _detect_frameworks(self, code_units: List[CodeUnit]) -> None:
        """检测项目使用的框架"""
        framework_indicators = {
            "flask": [r"from flask import", r"Flask\(", r"@app\.route"],
            "django": [r"from django", r"django\.http", r"@login_required"],
            "express": [r"require\(['\"]express", r"app\.get\(", r"app\.post\("],
            "fastapi": [r"from fastapi import", r"FastAPI\(", r"@app\.(get|post|put|delete)"],
            "spring": [r"@RestController", r"@RequestMapping", r"@GetMapping"],
        }

        for unit in code_units:
            code = unit.code
            for framework, patterns in framework_indicators.items():
                for pattern in patterns:
                    if re.search(pattern, code, re.IGNORECASE):
                        self._detected_frameworks.add(framework)
                        break

        if self._detected_frameworks:
            logger.info(f"Detected frameworks: {', '.join(self._detected_frameworks)}")

    def _analyze_function_taints(self, unit: CodeUnit) -> None:
        """分析单个函数的污点信息"""
        taints = []
        code = unit.code
        language = unit.language
        params = self._function_params.get(unit.id, [])

        # 1. 检查参数是否来自框架污点源
        for idx, param in enumerate(params):
            if self._is_framework_tainted_param(param, unit):
                tainted_var = TaintedVariable(
                    name=param,
                    source_type=TaintType.HTTP_PARAM,
                    source_location=f"{unit.file_path}:{unit.span.start_line}",
                    propagation_path=[f"param:{param}"],
                    origin_function=unit.id,
                    parameter_index=idx,
                )
                taint_info = InterproceduralTaint(
                    tainted_var=tainted_var,
                    function_id=unit.id,
                    function_name=unit.symbol,
                    is_parameter=True,
                    parameter_index=idx,
                    is_return_value=False,
                )
                taints.append(taint_info)

        # 2. 查找函数内的污点源
        internal_taints = self._find_taint_sources(
            code, language, unit.file_path, unit.span.start_line
        )

        for var_name, tainted_var in internal_taints.items():
            tainted_var.origin_function = unit.id
            taint_info = InterproceduralTaint(
                tainted_var=tainted_var,
                function_id=unit.id,
                function_name=unit.symbol,
                is_parameter=False,
                parameter_index=-1,
                is_return_value=False,
            )
            taints.append(taint_info)

        # 3. 追踪污点传播并检查是否传递给被调用函数
        all_tainted = {t.tainted_var.name: t.tainted_var for t in taints}
        self._track_propagation(code, all_tainted)

        # 更新 taints 中的 tainted_var
        for taint in taints:
            if taint.tainted_var.name in all_tainted:
                taint.tainted_var = all_tainted[taint.tainted_var.name]

        # 4. 检查是否有污点传递给被调用的函数
        for call in unit.calls:
            call_args = self._extract_call_arguments(code, call)
            for arg_idx, arg in enumerate(call_args):
                if arg in all_tainted:
                    # 找到调用目标
                    callee_units = self._find_callee_units(call, unit.language)
                    for callee in callee_units:
                        taint = InterproceduralTaint(
                            tainted_var=all_tainted[arg],
                            function_id=unit.id,
                            function_name=unit.symbol,
                            is_parameter=False,
                            parameter_index=arg_idx,
                            is_return_value=False,
                            callees=[callee.id],
                        )
                        if taint not in taints:
                            taints.append(taint)

        self.function_taints[unit.id] = taints

    def _is_framework_tainted_param(self, param: str, unit: CodeUnit) -> bool:
        """检查参数是否来自框架污点源"""
        # 检查装饰器
        if unit.decorators:
            for decorator in unit.decorators:
                # FastAPI 参数注解
                if any(pattern in decorator for pattern in ['Body', 'Query', 'Path', 'Header', 'Cookie', 'Form']):
                    return True
                # Flask/Django 路由参数
                if 'route' in decorator.lower() and f'<{param}>' in decorator:
                    return True

        # 检查参数类型注解中的框架标记
        if unit.signature:
            # FastAPI 风格: param: str = Query(...)
            pattern = rf'{re.escape(param)}\s*:\s*\w+\s*=\s*(Body|Query|Path|Header|Cookie|Form)\s*\('
            if re.search(pattern, unit.signature):
                return True

        # 检查是否是 request 参数
        if param.lower() in ('request', 'req'):
            return True

        return False

    def _extract_call_arguments(self, code: str, function_name: str) -> List[str]:
        """从代码中提取函数调用的参数"""
        args = []

        # 匹配函数调用: func_name(arg1, arg2, ...)
        pattern = rf'\b{re.escape(function_name)}\s*\(([^)]*)\)'
        for match in re.finditer(pattern, code):
            arg_str = match.group(1)
            # 简单分割参数（不处理嵌套调用）
            for arg in arg_str.split(','):
                arg = arg.strip()
                # 提取变量名（去掉方法调用等）
                var_match = re.match(r'^(\w+)', arg)
                if var_match:
                    args.append(var_match.group(1))

        return args

    def _find_callee_units(self, function_name: str, language: str) -> List[CodeUnit]:
        """查找被调用的函数对应的代码单元"""
        callees = []

        for unit in self._code_units_cache.values():
            if unit.language == language and unit.symbol == function_name:
                callees.append(unit)

        return callees

    def _propagate_taints_across_calls(self, max_depth: int) -> None:
        """通过调用图传播污点

        Phase 1: 函数间参数传递
        """
        if not self.call_graph:
            return

        # 迭代传播，直到没有新的污点或达到最大深度
        for depth in range(max_depth):
            new_taints_found = False

            for edge in self.call_graph.edges:
                caller_id = edge.caller_id
                callee_id = edge.callee_id

                # 获取 caller 的污点
                caller_taints = self.function_taints.get(caller_id, [])
                if not caller_taints:
                    continue

                # 获取 callee 的参数
                callee_params = self._function_params.get(callee_id, [])
                if not callee_params:
                    continue

                # 获取调用时传递的参数
                caller_unit = self._code_units_cache.get(caller_id)
                callee_unit = self._code_units_cache.get(callee_id)
                if not caller_unit or not callee_unit:
                    continue

                callee_name = callee_unit.symbol
                call_args = self._extract_call_arguments(caller_unit.code, callee_name)

                # 检查每个参数是否被污染
                for arg_idx, arg in enumerate(call_args):
                    # 检查这个参数是否在 caller 的污点变量中
                    for taint in caller_taints:
                        if taint.tainted_var.name == arg:
                            # 传播到 callee 的对应参数
                            if arg_idx < len(callee_params):
                                param_name = callee_params[arg_idx]

                                # 检查是否已存在
                                existing_taints = self.function_taints.get(callee_id, [])
                                already_exists = any(
                                    t.tainted_var.name == param_name and t.is_parameter
                                    for t in existing_taints
                                )

                                if not already_exists:
                                    # 创建新的污点
                                    new_tainted_var = TaintedVariable(
                                        name=param_name,
                                        source_type=taint.tainted_var.source_type,
                                        source_location=taint.tainted_var.source_location,
                                        propagation_path=taint.tainted_var.propagation_path + [
                                            f"{caller_unit.symbol}:{arg} -> {callee_unit.symbol}:{param_name}"
                                        ],
                                        origin_function=taint.tainted_var.origin_function,
                                        parameter_index=arg_idx,
                                    )

                                    new_taint = InterproceduralTaint(
                                        tainted_var=new_tainted_var,
                                        function_id=callee_id,
                                        function_name=callee_unit.symbol,
                                        is_parameter=True,
                                        parameter_index=arg_idx,
                                        is_return_value=False,
                                        callers=[caller_id],
                                    )

                                    if callee_id not in self.function_taints:
                                        self.function_taints[callee_id] = []
                                    self.function_taints[callee_id].append(new_taint)
                                    new_taints_found = True

            if not new_taints_found:
                logger.debug(f"Taint propagation converged at depth {depth + 1}")
                break

    def _find_cross_function_sinks(self) -> None:
        """查找跨函数污点流的最终 sink"""
        for func_id, taints in self.function_taints.items():
            unit = self._code_units_cache.get(func_id)
            if not unit:
                continue

            for taint in taints:
                # 在函数内查找 sink
                sink_matches = self._find_sinks(unit.code, unit.language)

                for sink_pattern, sink_def, sink_match in sink_matches:
                    if self._is_taint_in_sink(unit.code, taint.tainted_var.name, sink_match):
                        # 检查消毒
                        is_sanitized, sanitizers = self._check_sanitization(
                            unit.code, taint.tainted_var.name, sink_def.category, unit.language
                        )

                        # 构建调用链
                        call_chain = self._build_call_chain(taint)

                        # 计算置信度
                        confidence = self._calculate_cross_function_confidence(
                            taint, sink_def, is_sanitized, len(call_chain)
                        )

                        # 创建跨函数污点流
                        flow = CrossFunctionFlow(
                            source_function=taint.tainted_var.origin_function or func_id,
                            source_var=taint.tainted_var.propagation_path[0] if taint.tainted_var.propagation_path else taint.tainted_var.name,
                            source_type=taint.tainted_var.source_type,
                            source_location=taint.tainted_var.source_location,
                            target_function=func_id,
                            target_var=taint.tainted_var.name,
                            target_location=f"{unit.file_path}:{unit.span.start_line}",
                            sink_function=func_id,
                            sink_call=sink_match.group(0),
                            sink_category=sink_def.category,
                            call_chain=call_chain,
                            is_sanitized=is_sanitized,
                            sanitizers=sanitizers,
                            confidence=confidence,
                            risk_level=sink_def.risk_level if not is_sanitized else RiskLevel.LOW,
                            description=self._generate_cross_function_description(
                                taint, unit, sink_def, is_sanitized, call_chain
                            ),
                        )

                        self.cross_function_flows.append(flow)

    def _build_call_chain(self, taint: InterproceduralTaint) -> List[str]:
        """构建污点传播的调用链"""
        chain = []

        # 从传播路径中提取调用链
        for step in taint.tainted_var.propagation_path:
            if ' -> ' in step:
                # 格式: "caller:var -> callee:param"
                parts = step.split(' -> ')
                for part in parts:
                    func_name = part.split(':')[0] if ':' in part else part
                    if func_name and func_name not in chain:
                        chain.append(func_name)
            else:
                # 其他格式
                if ':' in step:
                    func_name = step.split(':')[0]
                    if func_name.startswith('param'):
                        continue
                    if func_name and func_name not in chain:
                        chain.append(func_name)

        # 添加当前函数
        if taint.function_name and taint.function_name not in chain:
            chain.append(taint.function_name)

        return chain

    def _calculate_cross_function_confidence(
        self,
        taint: InterproceduralTaint,
        sink_def: TaintSink,
        is_sanitized: bool,
        chain_length: int,
    ) -> float:
        """计算跨函数污点流的置信度"""
        confidence = 0.6

        # 基于污点源类型
        high_risk_sources = {TaintType.HTTP_PARAM, TaintType.HTTP_BODY, TaintType.COOKIE}
        if taint.tainted_var.source_type in high_risk_sources:
            confidence += 0.2

        # 基于 sink 危险程度
        if sink_def.risk_level == RiskLevel.CRITICAL:
            confidence += 0.15
        elif sink_def.risk_level == RiskLevel.HIGH:
            confidence += 0.1

        # 调用链越长，置信度越低
        if chain_length > 3:
            confidence *= 0.9 ** (chain_length - 3)

        # 如果是参数传递，置信度更高
        if taint.is_parameter:
            confidence += 0.05

        # 如果被消毒，大幅降低置信度
        if is_sanitized:
            confidence *= 0.3

        return min(max(confidence, 0.1), 0.95)

    def _generate_cross_function_description(
        self,
        taint: InterproceduralTaint,
        unit: CodeUnit,
        sink_def: TaintSink,
        is_sanitized: bool,
        call_chain: List[str],
    ) -> str:
        """生成跨函数污点流描述"""
        parts = [
            f"跨函数污点流: {taint.tainted_var.source_type.value} -> {sink_def.category.value}",
            f"源位置: {taint.tainted_var.source_location}",
            f"Sink 位置: {unit.file_path}:{unit.span.start_line}",
        ]

        if call_chain:
            parts.append(f"调用链: {' -> '.join(call_chain)}")

        if is_sanitized:
            parts.append("注意: 检测到消毒处理，需要人工确认有效性")

        return "\n".join(parts)

    def get_cross_function_summary(self) -> Dict[str, Any]:
        """获取跨函数分析摘要"""
        summary = {
            "total_functions_analyzed": len(self.function_taints),
            "total_cross_function_flows": len(self.cross_function_flows),
            "detected_frameworks": list(self._detected_frameworks),
            "by_risk_level": {},
            "by_sink_category": {},
            "by_source_type": {},
            "sanitized_count": 0,
            "high_confidence_count": 0,
            "max_chain_length": 0,
        }

        for flow in self.cross_function_flows:
            # 按风险级别
            level = flow.risk_level.value
            summary["by_risk_level"][level] = summary["by_risk_level"].get(level, 0) + 1

            # 按 sink 类别
            if flow.sink_category:
                category = flow.sink_category.value
                summary["by_sink_category"][category] = summary["by_sink_category"].get(category, 0) + 1

            # 按污点源类型
            source = flow.source_type.value
            summary["by_source_type"][source] = summary["by_source_type"].get(source, 0) + 1

            # 统计
            if flow.is_sanitized:
                summary["sanitized_count"] += 1
            if flow.confidence >= 0.7:
                summary["high_confidence_count"] += 1

            # 最长调用链
            chain_len = len(flow.call_chain)
            if chain_len > summary["max_chain_length"]:
                summary["max_chain_length"] = chain_len

        return summary
