"""
高危漏洞检测模块 - 专门针对 RCE、文件操作、逻辑漏洞等高危问题

功能：
1. 命令注入/RCE 检测
2. 任意文件读写检测
3. 认证/授权绕过检测
4. 业务逻辑漏洞检测
5. 利用 LLM 进行深度逻辑分析
"""

import re
import json
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from enum import Enum

from llm_client import BaseLLMClient, ChatMessage
from indexer import CodeUnit, CodeUnitType
from rules import RuleManager, SecurityRule, RuleType, RiskLevel

logger = logging.getLogger(__name__)


class VulnType(Enum):
    """漏洞类型"""
    RCE = "rce"                          # 远程代码执行
    COMMAND_INJECTION = "command_injection"  # 命令注入
    FILE_READ = "file_read"              # 任意文件读取
    FILE_WRITE = "file_write"            # 任意文件写入
    FILE_UPLOAD = "file_upload"          # 文件上传漏洞
    PATH_TRAVERSAL = "path_traversal"    # 路径遍历
    SQL_INJECTION = "sql_injection"      # SQL 注入
    NOSQL_INJECTION = "nosql_injection"  # NoSQL 注入
    SSRF = "ssrf"                        # 服务端请求伪造
    XXE = "xxe"                          # XML 外部实体
    DESERIALIZATION = "deserialization"  # 反序列化漏洞
    SSTI = "ssti"                        # 服务端模板注入
    AUTH_BYPASS = "auth_bypass"          # 认证绕过
    AUTHZ_BYPASS = "authz_bypass"        # 授权绕过
    IDOR = "idor"                        # 不安全的直接对象引用
    LOGIC_FLAW = "logic_flaw"            # 业务逻辑漏洞
    RACE_CONDITION = "race_condition"    # 竞态条件
    MASS_ASSIGNMENT = "mass_assignment"  # 批量赋值


@dataclass
class VulnPattern:
    """漏洞模式定义"""
    vuln_type: VulnType
    name: str
    description: str
    risk_level: RiskLevel

    # 检测模式
    sink_patterns: List[str]           # 危险函数模式
    source_patterns: List[str]         # 输入源模式
    context_patterns: List[str]        # 上下文模式（用于判断是否真的危险）

    # LLM 分析提示
    analysis_focus: str                # 分析重点
    attack_vectors: List[str]          # 可能的攻击向量

    # 语言支持
    languages: List[str] = field(default_factory=lambda: ["python", "javascript", "typescript"])

    # CWE 映射
    cwe_ids: List[str] = field(default_factory=list)


# 高危漏洞模式库
VULN_PATTERNS: List[VulnPattern] = [
    # ========== RCE / 命令注入 ==========
    VulnPattern(
        vuln_type=VulnType.RCE,
        name="远程代码执行",
        description="通过 eval/exec 等函数执行用户可控的代码",
        risk_level=RiskLevel.CRITICAL,
        sink_patterns=[
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"\bcompile\s*\(",
            r"\b__import__\s*\(",
            r"\bFunction\s*\(",
            r"new\s+Function\s*\(",
            r"setInterval\s*\([^,]*,",
            r"setTimeout\s*\([^,]*,",
        ],
        source_patterns=[
            r"request\.(args|form|json|data|GET|POST)",
            r"req\.(body|query|params)",
            r"input\s*\(",
            r"sys\.argv",
        ],
        context_patterns=[
            r"user",
            r"input",
            r"param",
            r"data",
            r"payload",
        ],
        analysis_focus="""
检查 eval/exec 等动态代码执行函数是否使用了用户可控的输入。
重点关注：
1. 输入是否直接或间接来自用户
2. 是否有任何过滤或验证
3. 是否可以通过编码绕过过滤
""",
        attack_vectors=[
            "直接执行恶意代码",
            "通过字符串拼接注入代码",
            "利用 __import__ 导入危险模块",
        ],
        cwe_ids=["CWE-94", "CWE-95"],
    ),

    VulnPattern(
        vuln_type=VulnType.COMMAND_INJECTION,
        name="命令注入",
        description="通过系统命令执行函数执行用户可控的命令",
        risk_level=RiskLevel.CRITICAL,
        sink_patterns=[
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
            r"subprocess\.(call|run|Popen|check_output)\s*\(",
            r"commands\.(getoutput|getstatusoutput)\s*\(",
            r"child_process\.(exec|execSync|spawn|spawnSync)\s*\(",
            r"shell_exec\s*\(",
            r"`[^`]*\$",  # Shell 反引号
        ],
        source_patterns=[
            r"request\.",
            r"req\.",
            r"input\s*\(",
            r"argv",
        ],
        context_patterns=[
            r"shell\s*=\s*True",
            r"\+\s*['\"]",  # 字符串拼接
            r"f['\"].*\{",  # f-string
            r"\$\{",  # 模板字符串
            r"\.format\s*\(",
            r"%\s*['\"]",
        ],
        analysis_focus="""
检查系统命令执行函数是否使用了用户可控的输入。
重点关注：
1. 是否使用 shell=True（Python）
2. 命令字符串是否通过拼接构造
3. 是否有命令参数过滤
4. 是否可以通过管道符、分号等分隔符注入额外命令
""",
        attack_vectors=[
            "使用 ; | && || 等分隔符执行多个命令",
            "使用反引号或 $() 进行命令替换",
            "使用换行符注入命令",
        ],
        cwe_ids=["CWE-78", "CWE-77"],
    ),

    # ========== 文件操作漏洞 ==========
    VulnPattern(
        vuln_type=VulnType.FILE_READ,
        name="任意文件读取",
        description="读取用户指定路径的文件，可能导致敏感信息泄露",
        risk_level=RiskLevel.HIGH,
        sink_patterns=[
            r"\bopen\s*\([^)]*['\"][^'\"]*['\"]",
            r"\.read\s*\(",
            r"\.readlines\s*\(",
            r"Path\s*\([^)]*\)\.read",
            r"fs\.(readFile|readFileSync)\s*\(",
            r"file_get_contents\s*\(",
            r"include\s*\(",
            r"require\s*\(",
        ],
        source_patterns=[
            r"request\.",
            r"req\.",
            r"params",
            r"filename",
            r"filepath",
            r"path",
        ],
        context_patterns=[
            r"\.\.",  # 路径遍历
            r"/etc/",
            r"/proc/",
            r"\.env",
            r"config",
            r"secret",
            r"password",
            r"\.key",
            r"\.pem",
        ],
        analysis_focus="""
检查文件读取操作是否使用了用户可控的路径。
重点关注：
1. 路径是否直接来自用户输入
2. 是否有路径规范化处理（realpath）
3. 是否检查了路径遍历（../）
4. 是否限制在特定目录内
5. 是否可以读取敏感文件（/etc/passwd, .env 等）
""",
        attack_vectors=[
            "使用 ../ 进行路径遍历",
            "读取 /etc/passwd 等系统文件",
            "读取应用配置文件获取敏感信息",
            "读取源代码文件",
        ],
        cwe_ids=["CWE-22", "CWE-23", "CWE-73"],
    ),

    VulnPattern(
        vuln_type=VulnType.FILE_WRITE,
        name="任意文件写入",
        description="向用户指定路径写入文件，可能导致代码执行",
        risk_level=RiskLevel.CRITICAL,
        sink_patterns=[
            r"\bopen\s*\([^)]*['\"]w",
            r"\.write\s*\(",
            r"Path\s*\([^)]*\)\.write",
            r"fs\.(writeFile|writeFileSync)\s*\(",
            r"file_put_contents\s*\(",
            r"move_uploaded_file\s*\(",
        ],
        source_patterns=[
            r"request\.",
            r"req\.",
            r"filename",
            r"filepath",
        ],
        context_patterns=[
            r"\.py$",
            r"\.php$",
            r"\.jsp$",
            r"\.aspx$",
            r"\.sh$",
            r"\.exe$",
            r"crontab",
            r"authorized_keys",
        ],
        analysis_focus="""
检查文件写入操作是否使用了用户可控的路径或内容。
重点关注：
1. 路径是否来自用户输入
2. 是否可以写入 Web 目录
3. 是否可以覆盖关键文件
4. 文件内容是否可控
5. 是否可以写入可执行文件
""",
        attack_vectors=[
            "写入 Webshell",
            "覆盖配置文件",
            "写入 crontab 实现持久化",
            "写入 SSH authorized_keys",
        ],
        cwe_ids=["CWE-22", "CWE-73", "CWE-434"],
    ),

    # ========== 认证/授权漏洞 ==========
    VulnPattern(
        vuln_type=VulnType.AUTH_BYPASS,
        name="认证绕过",
        description="可能绕过身份认证检查",
        risk_level=RiskLevel.CRITICAL,
        sink_patterns=[
            r"login",
            r"authenticate",
            r"verify.*token",
            r"check.*session",
            r"jwt\.verify",
            r"bcrypt\.compare",
        ],
        source_patterns=[
            r"if\s*\(",
            r"return\s+True",
            r"return\s+False",
            r"raise",
            r"throw",
        ],
        context_patterns=[
            r"or\s+True",
            r"\|\|\s*true",
            r"==\s*['\"]['\"]",  # 空字符串比较
            r"!=\s*None\s*:",
            r"skip.*auth",
            r"debug",
            r"test",
        ],
        analysis_focus="""
检查认证逻辑是否存在绕过可能。
重点关注：
1. 认证检查是否可以被绕过
2. 是否存在调试/测试后门
3. Token 验证是否正确
4. 密码比较是否安全（时序安全）
5. 是否存在默认凭据
6. 是否有短路逻辑导致绕过
""",
        attack_vectors=[
            "利用调试模式绕过认证",
            "使用默认凭据",
            "利用逻辑缺陷绕过检查",
            "JWT 算法混淆攻击",
        ],
        cwe_ids=["CWE-287", "CWE-306", "CWE-798"],
    ),

    VulnPattern(
        vuln_type=VulnType.IDOR,
        name="不安全的直接对象引用",
        description="可以访问其他用户的资源",
        risk_level=RiskLevel.HIGH,
        sink_patterns=[
            r"\.get\s*\(",
            r"\.find\s*\(",
            r"\.findOne\s*\(",
            r"\.filter\s*\(",
            r"SELECT.*WHERE",
            r"DELETE.*WHERE",
            r"UPDATE.*WHERE",
        ],
        source_patterns=[
            r"(user_id|userId|user|id|order_id|orderId)",
            r"request\.",
            r"req\.(params|query|body)",
        ],
        context_patterns=[
            r"current_user",
            r"session\[.user",
            r"request\.user",
            r"\.owner",
            r"\.user_id",
            r"belongs_to",
        ],
        analysis_focus="""
检查资源访问是否验证了用户权限。
重点关注：
1. 资源 ID 是否直接使用用户输入
2. 是否检查资源属于当前用户
3. 是否有租户/组织隔离
4. 批量操作是否逐一验证权限
5. 列表接口是否过滤了权限
""",
        attack_vectors=[
            "修改 ID 参数访问他人资源",
            "批量遍历 ID 获取数据",
            "跨租户访问资源",
        ],
        cwe_ids=["CWE-639", "CWE-284"],
    ),

    # ========== 业务逻辑漏洞 ==========
    VulnPattern(
        vuln_type=VulnType.LOGIC_FLAW,
        name="业务逻辑漏洞",
        description="业务流程中的逻辑缺陷",
        risk_level=RiskLevel.HIGH,
        sink_patterns=[
            r"(payment|pay|transfer|withdraw|deposit)",
            r"(balance|amount|price|quantity|discount)",
            r"(order|checkout|purchase)",
            r"(refund|cancel)",
            r"(coupon|voucher|promo)",
        ],
        source_patterns=[
            r"request\.",
            r"req\.",
            r"form\.",
            r"params",
        ],
        context_patterns=[
            r"if.*>",
            r"if.*<",
            r"if.*==",
            r"transaction",
            r"atomic",
            r"lock",
        ],
        analysis_focus="""
检查业务逻辑是否存在安全缺陷。
重点关注：
1. 金额/数量是否从客户端获取
2. 是否可以跳过支付流程
3. 是否可以重复使用优惠券
4. 是否存在负数/零值问题
5. 状态转换是否合法
6. 是否有并发控制
""",
        attack_vectors=[
            "修改价格/数量参数",
            "重复提交订单",
            "跳过支付步骤",
            "使用负数绕过检查",
            "竞态条件利用",
        ],
        cwe_ids=["CWE-840", "CWE-841"],
    ),

    VulnPattern(
        vuln_type=VulnType.RACE_CONDITION,
        name="竞态条件",
        description="并发操作可能导致数据不一致",
        risk_level=RiskLevel.HIGH,
        sink_patterns=[
            r"balance",
            r"stock",
            r"inventory",
            r"quantity",
            r"count",
            r"limit",
        ],
        source_patterns=[
            r"if.*check",
            r"get.*then.*update",
            r"read.*write",
        ],
        context_patterns=[
            r"transaction",
            r"lock",
            r"atomic",
            r"synchronized",
            r"mutex",
            r"semaphore",
        ],
        analysis_focus="""
检查是否存在 TOCTOU（检查时间/使用时间）漏洞。
重点关注：
1. 读取和更新是否在同一事务中
2. 是否使用了乐观锁/悲观锁
3. 余额/库存检查是否原子化
4. 是否可以通过并发请求绕过限制
""",
        attack_vectors=[
            "并发请求绕过余额检查",
            "超卖攻击",
            "重复领取奖励",
        ],
        cwe_ids=["CWE-362", "CWE-367"],
    ),

    # ========== 注入漏洞 ==========
    VulnPattern(
        vuln_type=VulnType.SSTI,
        name="服务端模板注入",
        description="模板引擎执行用户可控的模板代码",
        risk_level=RiskLevel.CRITICAL,
        sink_patterns=[
            r"Template\s*\(",
            r"render_template_string\s*\(",
            r"Jinja2",
            r"\.render\s*\(",
            r"format_map\s*\(",
            r"\.substitute\s*\(",
        ],
        source_patterns=[
            r"request\.",
            r"req\.",
            r"user.*input",
        ],
        context_patterns=[
            r"\{\{",
            r"\{\%",
            r"\$\{",
            r"<%",
        ],
        analysis_focus="""
检查是否将用户输入作为模板内容。
重点关注：
1. 模板内容是否来自用户输入
2. 是否使用了沙箱
3. Jinja2 是否启用了 autoescape
4. 是否可以访问 __class__.__mro__ 等
""",
        attack_vectors=[
            "{{config}} 读取配置",
            "{{''.__class__.__mro__}} 链式调用",
            "执行系统命令",
        ],
        cwe_ids=["CWE-94", "CWE-1336"],
    ),

    VulnPattern(
        vuln_type=VulnType.SSRF,
        name="服务端请求伪造",
        description="服务器发起用户可控的请求",
        risk_level=RiskLevel.HIGH,
        sink_patterns=[
            r"requests\.(get|post|put|delete|head|options)\s*\(",
            r"urllib\.request\.urlopen\s*\(",
            r"http\.(get|request)\s*\(",
            r"fetch\s*\(",
            r"axios\.(get|post)\s*\(",
            r"curl",
        ],
        source_patterns=[
            r"url",
            r"host",
            r"endpoint",
            r"target",
            r"redirect",
            r"callback",
        ],
        context_patterns=[
            r"127\.0\.0\.1",
            r"localhost",
            r"169\.254",
            r"10\.",
            r"192\.168",
            r"172\.(1[6-9]|2[0-9]|3[01])",
            r"file://",
            r"gopher://",
            r"dict://",
        ],
        analysis_focus="""
检查 HTTP 请求的目标是否用户可控。
重点关注：
1. URL 是否来自用户输入
2. 是否有 URL 白名单验证
3. 是否阻止了内网地址
4. 是否阻止了特殊协议（file://, gopher://）
5. 是否可以通过 DNS 重绑定绕过
""",
        attack_vectors=[
            "访问内网服务",
            "读取云服务元数据",
            "端口扫描",
            "利用 gopher 协议攻击内网服务",
        ],
        cwe_ids=["CWE-918"],
    ),

    VulnPattern(
        vuln_type=VulnType.DESERIALIZATION,
        name="不安全的反序列化",
        description="反序列化不可信数据可能导致代码执行",
        risk_level=RiskLevel.CRITICAL,
        sink_patterns=[
            r"pickle\.loads?\s*\(",
            r"yaml\.load\s*\(",
            r"yaml\.unsafe_load\s*\(",
            r"marshal\.loads?\s*\(",
            r"shelve\.open\s*\(",
            r"jsonpickle\.decode\s*\(",
            r"unserialize\s*\(",
            r"ObjectInputStream",
            r"readObject\s*\(",
        ],
        source_patterns=[
            r"request\.",
            r"req\.",
            r"cookie",
            r"session",
            r"data",
        ],
        context_patterns=[
            r"base64",
            r"decode",
            r"load",
        ],
        analysis_focus="""
检查是否反序列化了不可信的数据。
重点关注：
1. 序列化数据是否来自用户
2. 是否使用了安全的反序列化方法（如 yaml.safe_load）
3. 是否有签名验证
4. 是否限制了可反序列化的类
""",
        attack_vectors=[
            "构造恶意 pickle 对象",
            "YAML 反序列化 RCE",
            "Java 反序列化漏洞利用",
        ],
        cwe_ids=["CWE-502"],
    ),
]


class Exploitability(Enum):
    """可利用性等级"""
    LOW = "low"           # 需要复杂条件或内部访问
    MEDIUM = "medium"     # 需要认证或特定条件
    HIGH = "high"         # 可直接利用


@dataclass
class VulnFinding:
    """漏洞发现"""
    id: str
    vuln_type: VulnType
    name: str
    severity: RiskLevel
    confidence: float  # 0.0 - 1.0

    # 位置信息
    file_path: str
    function_name: str
    line_start: int
    line_end: int
    code_snippet: str

    # 分析结果
    description: str
    attack_scenario: str
    impact: str
    fix_suggestion: str

    # 调用链信息
    call_chain: List[Dict[str, Any]] = field(default_factory=list)
    taint_flow: List[str] = field(default_factory=list)

    # 关联信息
    cwe_ids: List[str] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)

    # LLM 分析
    llm_analysis: Optional[str] = None
    needs_manual_review: bool = False
    review_notes: str = ""

    # === 新增：高危漏洞专用字段 ===
    exploitability: Exploitability = Exploitability.MEDIUM  # 可利用性评估
    required_prerequisites: List[str] = field(default_factory=list)  # 利用前提条件
    entry_point: Optional[str] = None  # 入口点（handler/路由）
    shortest_call_chain: List[str] = field(default_factory=list)  # 最短调用链
    existing_protections: List[str] = field(default_factory=list)  # 现有防护措施
    bypass_techniques: List[str] = field(default_factory=list)  # 可能的绕过技术

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vuln_type": self.vuln_type.value,
            "name": self.name,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "function_name": self.function_name,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "description": self.description,
            "attack_scenario": self.attack_scenario,
            "impact": self.impact,
            "fix_suggestion": self.fix_suggestion,
            "call_chain": self.call_chain,
            "taint_flow": self.taint_flow,
            "cwe_ids": self.cwe_ids,
            "matched_patterns": self.matched_patterns,
            "llm_analysis": self.llm_analysis,
            "needs_manual_review": self.needs_manual_review,
            "review_notes": self.review_notes,
            # 新增高危漏洞专用字段
            "exploitability": self.exploitability.value,
            "required_prerequisites": self.required_prerequisites,
            "entry_point": self.entry_point,
            "shortest_call_chain": self.shortest_call_chain,
            "existing_protections": self.existing_protections,
            "bypass_techniques": self.bypass_techniques,
        }


class HighRiskVulnDetector:
    """高危漏洞检测器"""

    def __init__(
        self,
        llm_client: BaseLLMClient,
        rule_manager: RuleManager,
    ):
        self.llm_client = llm_client
        self.rule_manager = rule_manager
        self.findings: List[VulnFinding] = []
        self._finding_counter = 0

    def detect_vulnerabilities(
        self,
        code_units: List[CodeUnit],
        vuln_types: Optional[List[VulnType]] = None,
        use_llm: bool = True,
        max_llm_calls: int = 20,
    ) -> List[VulnFinding]:
        """检测高危漏洞

        Args:
            code_units: 代码单元列表
            vuln_types: 要检测的漏洞类型，None 表示全部
            use_llm: 是否使用 LLM 进行深度分析
            max_llm_calls: 最大 LLM 调用次数（防止失控）

        Returns:
            漏洞发现列表
        """
        logger.info(f"Detecting high-risk vulnerabilities in {len(code_units)} code units...")

        patterns_to_check = VULN_PATTERNS
        if vuln_types:
            patterns_to_check = [p for p in VULN_PATTERNS if p.vuln_type in vuln_types]

        findings = []
        llm_call_count = 0

        for unit in code_units:
            for pattern in patterns_to_check:
                # 检查语言是否匹配
                if unit.language not in pattern.languages:
                    continue

                # 模式匹配
                matches = self._pattern_match(unit, pattern)
                if matches:
                    finding = self._create_finding(unit, pattern, matches)

                    # 使用 LLM 深度分析（限制调用次数）
                    if use_llm and llm_call_count < max_llm_calls:
                        self._llm_analyze(finding, unit, pattern)
                        llm_call_count += 1
                        logger.info(f"[VulnDetector] LLM 分析 {llm_call_count}/{max_llm_calls}: {unit.symbol}")
                    elif use_llm and llm_call_count >= max_llm_calls:
                        finding.needs_manual_review = True
                        finding.review_notes = "已达到 LLM 分析上限，需人工审核"

                    findings.append(finding)

        # 按严重性和置信度排序
        findings.sort(key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity.value, 4),
            -f.confidence
        ))

        self.findings = findings
        logger.info(f"Found {len(findings)} potential vulnerabilities")

        return findings

    def _pattern_match(
        self,
        unit: CodeUnit,
        pattern: VulnPattern
    ) -> List[Tuple[str, str]]:
        """模式匹配

        Returns:
            匹配结果列表 [(模式类型, 匹配的模式)]
        """
        code = unit.code
        matches = []

        # 检查 sink 模式
        for sink in pattern.sink_patterns:
            if re.search(sink, code, re.IGNORECASE):
                matches.append(("sink", sink))

        if not matches:
            return []

        # 检查上下文模式（增加置信度）
        for ctx in pattern.context_patterns:
            if re.search(ctx, code, re.IGNORECASE):
                matches.append(("context", ctx))

        # 检查 source 模式
        for source in pattern.source_patterns:
            if re.search(source, code, re.IGNORECASE):
                matches.append(("source", source))

        return matches

    def _create_finding(
        self,
        unit: CodeUnit,
        pattern: VulnPattern,
        matches: List[Tuple[str, str]],
    ) -> VulnFinding:
        """创建漏洞发现"""
        self._finding_counter += 1

        # 计算置信度
        confidence = 0.5
        has_sink = any(m[0] == "sink" for m in matches)
        has_source = any(m[0] == "source" for m in matches)
        has_context = any(m[0] == "context" for m in matches)

        if has_sink and has_source:
            confidence = 0.8
        if has_context:
            confidence += 0.1
        if len(matches) > 3:
            confidence += 0.05

        confidence = min(confidence, 0.95)

        return VulnFinding(
            id=f"VULN-{self._finding_counter:04d}",
            vuln_type=pattern.vuln_type,
            name=pattern.name,
            severity=pattern.risk_level,
            confidence=confidence,
            file_path=unit.file_path,
            function_name=unit.symbol,
            line_start=unit.span.start_line,
            line_end=unit.span.end_line,
            code_snippet=unit.code[:1500],
            description=pattern.description,
            attack_scenario="\n".join(pattern.attack_vectors),
            impact=self._get_impact_description(pattern),
            fix_suggestion=self._get_fix_suggestion(pattern),
            cwe_ids=pattern.cwe_ids,
            matched_patterns=[m[1] for m in matches],
        )

    def _get_impact_description(self, pattern: VulnPattern) -> str:
        """获取影响描述"""
        impacts = {
            VulnType.RCE: "攻击者可以在服务器上执行任意代码，完全控制系统",
            VulnType.COMMAND_INJECTION: "攻击者可以执行系统命令，可能导致系统被完全控制",
            VulnType.FILE_READ: "攻击者可以读取服务器上的任意文件，导致敏感信息泄露",
            VulnType.FILE_WRITE: "攻击者可以写入任意文件，可能导致代码执行或数据篡改",
            VulnType.AUTH_BYPASS: "攻击者可以绕过身份认证，访问受保护的功能",
            VulnType.IDOR: "攻击者可以访问其他用户的数据，导致数据泄露",
            VulnType.LOGIC_FLAW: "攻击者可以利用业务逻辑缺陷获取非法利益",
            VulnType.SSRF: "攻击者可以让服务器发起任意请求，访问内网资源",
            VulnType.SSTI: "攻击者可以执行任意代码，完全控制系统",
            VulnType.DESERIALIZATION: "攻击者可以执行任意代码，完全控制系统",
        }
        return impacts.get(pattern.vuln_type, "可能导致安全风险")

    def _get_fix_suggestion(self, pattern: VulnPattern) -> str:
        """获取修复建议"""
        suggestions = {
            VulnType.RCE: "避免使用 eval/exec，如必须使用，严格验证和过滤输入",
            VulnType.COMMAND_INJECTION: "使用参数化方式调用命令，避免 shell=True，不拼接用户输入",
            VulnType.FILE_READ: "使用白名单验证文件路径，使用 realpath 规范化路径，检查路径遍历",
            VulnType.FILE_WRITE: "限制可写入的目录，验证文件扩展名，使用随机文件名",
            VulnType.AUTH_BYPASS: "使用统一的认证中间件，移除调试后门，使用安全的密码比较",
            VulnType.IDOR: "验证资源属于当前用户，使用 UUID 替代自增 ID，实施租户隔离",
            VulnType.LOGIC_FLAW: "不信任客户端数据，服务端验证所有关键参数，使用事务和锁",
            VulnType.SSRF: "使用 URL 白名单，禁止内网地址，禁用特殊协议",
            VulnType.SSTI: "不将用户输入作为模板内容，使用沙箱，启用 autoescape",
            VulnType.DESERIALIZATION: "使用安全的序列化格式（JSON），使用 safe_load，验证签名",
        }
        return suggestions.get(pattern.vuln_type, "请进行安全审查和修复")

    def _llm_analyze(
        self,
        finding: VulnFinding,
        unit: CodeUnit,
        pattern: VulnPattern,
    ) -> None:
        """使用 LLM 进行深度分析 - 增强版高危漏洞 Pipeline"""
        system_prompt = f"""你是一名资深安全研究员，专门从事代码审计和漏洞挖掘。
现在需要分析一段可能存在 {pattern.name} 漏洞的代码。

分析重点：
{pattern.analysis_focus}

可能的攻击向量：
{chr(10).join('- ' + v for v in pattern.attack_vectors)}

请仔细分析代码，重点评估：
1. 是否真的存在该漏洞
2. 漏洞的具体触发条件
3. 可利用性评估（是否需要认证、内网访问等前提条件）
4. 现有防护措施及其有效性
5. 可能的绕过技术
6. 入口点分析（如 Web handler、API 路由等）
7. 给出具体的修复建议

输出 JSON 格式：
{{
    "is_vulnerable": true/false,
    "confidence": 0.0-1.0,
    "vulnerability_analysis": "详细的漏洞分析",
    "trigger_conditions": "触发条件",
    "attack_method": "攻击方法（高层次描述，不含具体 payload）",
    "exploitability": "low/medium/high",
    "required_prerequisites": ["前提条件1", "前提条件2"],
    "entry_point": "入口点（如路由、handler名称）",
    "existing_protections": ["防护措施1", "防护措施2"],
    "bypass_techniques": ["绕过技术1", "绕过技术2"],
    "fix_recommendation": "具体修复建议",
    "needs_manual_review": true/false,
    "review_notes": "需要人工确认的点"
}}
"""

        user_prompt = f"""文件：{unit.file_path}
函数：{unit.symbol}
行号：{unit.span.start_line}-{unit.span.end_line}
装饰器：{', '.join(unit.decorators) if unit.decorators else '无'}

代码：
```{unit.language}
{unit.code}
```

匹配的模式：{', '.join(finding.matched_patterns)}

请分析此代码是否存在 {pattern.name} 漏洞，并评估其可利用性。
"""

        try:
            response = self.llm_client.chat_completion(
                messages=[
                    ChatMessage(role="system", content=system_prompt),
                    ChatMessage(role="user", content=user_prompt),
                ],
                response_format={"type": "json_object"},
                # temperature 使用 LLM 客户端配置的默认值
            )

            # 解析响应
            result = self._parse_llm_response(response.content)

            if result:
                # 更新 finding 基本字段
                finding.confidence = result.get("confidence", finding.confidence)
                finding.llm_analysis = result.get("vulnerability_analysis", "")
                finding.attack_scenario = result.get("attack_method", finding.attack_scenario)
                finding.fix_suggestion = result.get("fix_recommendation", finding.fix_suggestion)
                finding.needs_manual_review = result.get("needs_manual_review", False)
                finding.review_notes = result.get("review_notes", "")

                # 更新新增的高危漏洞专用字段
                exploitability_map = {
                    "low": Exploitability.LOW,
                    "medium": Exploitability.MEDIUM,
                    "high": Exploitability.HIGH,
                }
                finding.exploitability = exploitability_map.get(
                    result.get("exploitability", "medium").lower(),
                    Exploitability.MEDIUM
                )
                finding.required_prerequisites = result.get("required_prerequisites", [])
                finding.entry_point = result.get("entry_point")
                finding.existing_protections = result.get("existing_protections", [])
                finding.bypass_techniques = result.get("bypass_techniques", [])

                # 如果 LLM 认为不是漏洞，降低置信度
                if not result.get("is_vulnerable", True):
                    finding.confidence *= 0.3

                # 根据可利用性调整置信度权重
                if finding.exploitability == Exploitability.HIGH:
                    finding.confidence = min(finding.confidence * 1.1, 0.98)
                elif finding.exploitability == Exploitability.LOW:
                    finding.confidence *= 0.8

        except Exception as e:
            logger.warning(f"LLM analysis failed: {e}")

    def _parse_llm_response(self, content: str) -> Optional[Dict[str, Any]]:
        """解析 LLM 响应"""
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # 尝试提取 JSON
            match = re.search(r'\{[\s\S]*\}', content)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass
            return None

    def detect_logic_vulnerabilities(
        self,
        code_units: List[CodeUnit],
        business_context: Optional[str] = None,
        max_llm_calls: int = 15,
    ) -> List[VulnFinding]:
        """专门检测业务逻辑漏洞

        使用 LLM 进行深度逻辑分析

        Args:
            code_units: 代码单元列表
            business_context: 业务上下文描述
            max_llm_calls: 最大 LLM 调用次数（防止失控）

        Returns:
            漏洞发现列表
        """
        logger.info("Detecting logic vulnerabilities...")

        # 筛选可能涉及业务逻辑的代码
        logic_units = [
            u for u in code_units
            if u.unit_type in (CodeUnitType.HANDLER, CodeUnitType.METHOD)
            and any(kw in u.symbol.lower() or kw in u.code.lower()
                    for kw in ["pay", "order", "balance", "transfer", "auth",
                               "login", "password", "admin", "delete", "update",
                               "create", "permission", "role", "token"])
        ]

        findings = []
        llm_call_count = 0

        logger.info(f"[LogicVuln] 筛选出 {len(logic_units)} 个业务逻辑相关代码单元")

        for unit in logic_units:
            if llm_call_count >= max_llm_calls:
                logger.info(f"[LogicVuln] 已达到 LLM 调用上限 {max_llm_calls}，跳过剩余 {len(logic_units) - llm_call_count} 个单元")
                break

            finding = self._analyze_logic_vuln(unit, business_context)
            llm_call_count += 1
            logger.info(f"[LogicVuln] LLM 分析 {llm_call_count}/{max_llm_calls}: {unit.symbol}")

            if finding:
                findings.append(finding)

        return findings

    def _analyze_logic_vuln(
        self,
        unit: CodeUnit,
        business_context: Optional[str] = None,
    ) -> Optional[VulnFinding]:
        """分析单个代码单元的逻辑漏洞"""
        system_prompt = """你是一名资深安全审计专家，擅长发现业务逻辑漏洞。

业务逻辑漏洞是指应用程序在实现业务流程时的设计或实现缺陷，主要包括：

1. **认证/授权缺陷**
   - 未验证用户身份
   - 未检查用户权限
   - 可以访问他人资源 (IDOR)

2. **业务流程缺陷**
   - 可以跳过步骤（如跳过支付）
   - 可以重复操作（如重复领券）
   - 状态机缺陷

3. **数据验证缺陷**
   - 信任客户端数据（价格、数量）
   - 负数/零值问题
   - 类型混淆

4. **并发问题**
   - 竞态条件
   - TOCTOU 漏洞

5. **敏感操作保护不足**
   - 缺少二次验证
   - 缺少速率限制
   - 缺少审计日志

请仔细分析代码，识别潜在的逻辑漏洞。

输出 JSON 格式：
{
    "has_logic_vuln": true/false,
    "vuln_type": "漏洞类型",
    "severity": "critical/high/medium/low",
    "confidence": 0.0-1.0,
    "description": "漏洞描述",
    "vulnerable_logic": "存在问题的逻辑",
    "attack_scenario": "攻击场景（高层次描述）",
    "impact": "影响",
    "fix_suggestion": "修复建议",
    "needs_manual_review": true/false
}
"""

        context_info = f"\n业务上下文：{business_context}" if business_context else ""

        user_prompt = f"""文件：{unit.file_path}
函数：{unit.symbol}
类型：{unit.unit_type.value}
装饰器：{', '.join(unit.decorators) if unit.decorators else '无'}
{context_info}

代码：
```{unit.language}
{unit.code}
```

请分析此代码是否存在业务逻辑漏洞。
"""

        try:
            response = self.llm_client.chat_completion(
                messages=[
                    ChatMessage(role="system", content=system_prompt),
                    ChatMessage(role="user", content=user_prompt),
                ],
                response_format={"type": "json_object"},
                # temperature 使用 LLM 客户端配置的默认值
            )

            result = self._parse_llm_response(response.content)

            if result and result.get("has_logic_vuln"):
                self._finding_counter += 1

                severity_map = {
                    "critical": RiskLevel.CRITICAL,
                    "high": RiskLevel.HIGH,
                    "medium": RiskLevel.MEDIUM,
                    "low": RiskLevel.LOW,
                }

                return VulnFinding(
                    id=f"LOGIC-{self._finding_counter:04d}",
                    vuln_type=VulnType.LOGIC_FLAW,
                    name=result.get("vuln_type", "业务逻辑漏洞"),
                    severity=severity_map.get(result.get("severity", "medium"), RiskLevel.MEDIUM),
                    confidence=result.get("confidence", 0.7),
                    file_path=unit.file_path,
                    function_name=unit.symbol,
                    line_start=unit.span.start_line,
                    line_end=unit.span.end_line,
                    code_snippet=unit.code[:1500],
                    description=result.get("description", ""),
                    attack_scenario=result.get("attack_scenario", ""),
                    impact=result.get("impact", ""),
                    fix_suggestion=result.get("fix_suggestion", ""),
                    llm_analysis=result.get("vulnerable_logic", ""),
                    needs_manual_review=result.get("needs_manual_review", True),
                )

        except Exception as e:
            logger.warning(f"Logic vulnerability analysis failed: {e}")

        return None

    def export_findings(self, output_path: str) -> str:
        """导出漏洞发现到 JSON"""
        from datetime import datetime

        result = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "LLM Code Auditor - High Risk Vulnerability Detector",
                "total_findings": len(self.findings),
            },
            "statistics": self._get_statistics(),
            "findings": [f.to_dict() for f in self.findings],
        }

        from pathlib import Path
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        logger.info(f"Findings exported to: {path}")
        return str(path)

    def _get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {
            "by_severity": {},
            "by_type": {},
            "high_confidence": 0,
            "needs_review": 0,
        }

        for f in self.findings:
            # 按严重性
            sev = f.severity.value
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1

            # 按类型
            vtype = f.vuln_type.value
            stats["by_type"][vtype] = stats["by_type"].get(vtype, 0) + 1

            # 高置信度
            if f.confidence >= 0.8:
                stats["high_confidence"] += 1

            # 需要人工审查
            if f.needs_manual_review:
                stats["needs_review"] += 1

        return stats
