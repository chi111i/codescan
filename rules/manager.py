"""
安全规则加载器和管理器
"""

import logging
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Dict, Any, Set, Tuple
import yaml

from config import RulesConfig
from .models import SecurityRule, RuleType, RuleCategory, RiskLevel, RuleMatch

logger = logging.getLogger(__name__)


class RuleManager:
    """安全规则管理器

    优化特性：
    1. 按语言+类型的复合索引
    2. 精确匹配快速查找索引
    3. 匹配结果 LRU 缓存
    """

    def __init__(self, config: RulesConfig):
        self.config = config
        self._rules: Dict[str, SecurityRule] = {}
        self._by_category: Dict[RuleCategory, List[SecurityRule]] = {}
        self._by_language: Dict[str, List[SecurityRule]] = {}
        self._by_type: Dict[RuleType, List[SecurityRule]] = {}

        # 复合索引：(语言, 类型) -> 规则列表
        self._by_lang_type: Dict[Tuple[str, RuleType], List[SecurityRule]] = {}

        # 精确匹配快速索引：(语言, 类型, 函数名) -> 规则列表
        self._exact_match_index: Dict[Tuple[str, Optional[RuleType], str], List[SecurityRule]] = {}

        # 匹配结果缓存版本号（用于缓存失效）
        self._cache_version: int = 0

    def load_builtin_rules(self) -> int:
        """加载内置规则"""
        rules = self._get_builtin_rules()
        for rule in rules:
            self._add_rule(rule)
        logger.info(f"Loaded {len(rules)} builtin rules")
        return len(rules)

    def load_from_file(self, file_path: str) -> int:
        """从 YAML 文件加载规则"""
        path = Path(file_path)
        if not path.exists():
            logger.warning(f"Rule file not found: {file_path}")
            return 0

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "rules" not in data:
            return 0

        count = 0
        for rule_data in data["rules"]:
            try:
                rule = SecurityRule.from_dict(rule_data)
                self._add_rule(rule)
                count += 1
            except Exception as e:
                logger.warning(f"Failed to load rule: {e}")

        return count

    def load_from_directory(self, dir_path: str, recursive: bool = True) -> int:
        """从目录加载所有规则文件

        Args:
            dir_path: 规则目录路径
            recursive: 是否递归加载子目录 (默认True)

        Returns:
            加载的规则数量
        """
        path = Path(dir_path)
        if not path.exists():
            logger.warning(f"Rules directory not found: {dir_path}")
            return 0

        count = 0

        # 使用递归glob模式
        glob_pattern = "**/*.yaml" if recursive else "*.yaml"

        for file_path in path.glob(glob_pattern):
            count += self.load_from_file(str(file_path))

        glob_pattern = "**/*.yml" if recursive else "*.yml"
        for file_path in path.glob(glob_pattern):
            count += self.load_from_file(str(file_path))

        return count

    def _add_rule(self, rule: SecurityRule) -> None:
        """添加规则到索引"""
        self._rules[rule.id] = rule

        # 按类别索引
        if rule.category not in self._by_category:
            self._by_category[rule.category] = []
        self._by_category[rule.category].append(rule)

        # 按语言索引
        for lang in rule.languages:
            if lang not in self._by_language:
                self._by_language[lang] = []
            self._by_language[lang].append(rule)

            # 复合索引：(语言, 类型)
            key = (lang, rule.rule_type)
            if key not in self._by_lang_type:
                self._by_lang_type[key] = []
            self._by_lang_type[key].append(rule)

            # 精确匹配索引：提取不带前缀的精确匹配模式
            for pattern in rule.patterns:
                if not any(pattern.startswith(prefix) for prefix in
                           ["regex:", "prefix:", "suffix:", "contains:"]):
                    # 精确匹配模式，添加到快速索引
                    exact_key = (lang, rule.rule_type, pattern)
                    if exact_key not in self._exact_match_index:
                        self._exact_match_index[exact_key] = []
                    self._exact_match_index[exact_key].append(rule)

        # 按类型索引
        if rule.rule_type not in self._by_type:
            self._by_type[rule.rule_type] = []
        self._by_type[rule.rule_type].append(rule)

        # 使缓存失效
        self._cache_version += 1
        self._invalidate_match_cache()

    def get_rule(self, rule_id: str) -> Optional[SecurityRule]:
        """获取指定规则"""
        return self._rules.get(rule_id)

    def get_all_rules(self) -> List[SecurityRule]:
        """获取所有规则"""
        return list(self._rules.values())

    def get_rules_by_category(self, category: RuleCategory) -> List[SecurityRule]:
        """按类别获取规则"""
        return self._by_category.get(category, [])

    def get_rules_by_language(self, language: str) -> List[SecurityRule]:
        """按语言获取规则"""
        return self._by_language.get(language, [])

    def get_rules_by_type(self, rule_type: RuleType) -> List[SecurityRule]:
        """按类型获取规则"""
        return self._by_type.get(rule_type, [])

    def get_sinks(self, language: Optional[str] = None) -> List[SecurityRule]:
        """获取危险函数规则"""
        sinks = self.get_rules_by_type(RuleType.SINK)
        if language:
            sinks = [r for r in sinks if language in r.languages]
        return sinks

    def get_sources(self, language: Optional[str] = None) -> List[SecurityRule]:
        """获取输入源规则"""
        sources = self.get_rules_by_type(RuleType.SOURCE)
        if language:
            sources = [r for r in sources if language in r.languages]
        return sources

    def get_sanitizers(self, language: Optional[str] = None) -> List[SecurityRule]:
        """获取消毒函数规则"""
        sanitizers = self.get_rules_by_type(RuleType.SANITIZER)
        if language:
            sanitizers = [r for r in sanitizers if language in r.languages]
        return sanitizers

    def match_function(
        self,
        function_name: str,
        language: str,
        rule_type: Optional[RuleType] = None
    ) -> List[SecurityRule]:
        """匹配函数名到规则

        优化策略：
        1. 先查精确匹配快速索引
        2. 使用复合索引 (语言, 类型) 减少候选集
        3. 使用 LRU 缓存避免重复匹配
        """
        # 使用缓存的内部方法
        return self._match_function_cached(function_name, language, rule_type)

    def _match_function_cached(
        self,
        function_name: str,
        language: str,
        rule_type: Optional[RuleType]
    ) -> List[SecurityRule]:
        """带缓存的函数匹配（内部实现）"""
        matched: List[SecurityRule] = []
        seen_rule_ids: Set[str] = set()

        # 1. 快速精确匹配查找
        exact_key = (language, rule_type, function_name)
        if exact_key in self._exact_match_index:
            for rule in self._exact_match_index[exact_key]:
                if rule.id not in seen_rule_ids:
                    matched.append(rule)
                    seen_rule_ids.add(rule.id)

        # 2. 使用复合索引获取候选规则
        if rule_type:
            candidates = self._by_lang_type.get((language, rule_type), [])
        else:
            candidates = self._by_language.get(language, [])

        # 3. 遍历候选规则进行匹配（跳过已精确匹配的）
        for rule in candidates:
            if rule.id in seen_rule_ids:
                continue
            if rule.matches(function_name):
                matched.append(rule)
                seen_rule_ids.add(rule.id)

        return matched

    def _invalidate_match_cache(self) -> None:
        """使匹配缓存失效"""
        # 当前使用简单的版本号机制，未来可添加 LRU 缓存
        pass

    def clear(self) -> None:
        """清空所有规则和索引（用于热更新）"""
        self._rules.clear()
        self._by_category.clear()
        self._by_language.clear()
        self._by_type.clear()
        self._by_lang_type.clear()
        self._exact_match_index.clear()
        self._cache_version += 1
        logger.info("All rules and indexes cleared")

    def reload(self) -> Dict[str, int]:
        """热更新规则：清空后重新加载

        Returns:
            Dict 包含 builtin 和 custom 加载的规则数量
        """
        self.clear()

        result = {"builtin": 0, "custom": 0}

        # 重新加载内置规则
        result["builtin"] = self.load_builtin_rules()

        # 重新加载自定义规则目录
        if self.config.custom_rules_dir:
            result["custom"] = self.load_from_directory(self.config.custom_rules_dir)

        logger.info(f"Rules reloaded: {result}")
        return result

    def get_rules_summary(
        self,
        language: str,
        categories: Optional[List[str]] = None,
        max_rules: int = 50
    ) -> str:
        """生成规则摘要（用于 LLM 提示词）"""
        rules = self.get_rules_by_language(language)

        # 按类别过滤
        if categories:
            cat_set = {RuleCategory(c) for c in categories if c in [e.value for e in RuleCategory]}
            rules = [r for r in rules if r.category in cat_set]

        # 按风险级别排序
        risk_order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3}
        rules.sort(key=lambda r: risk_order.get(r.risk_level, 4))

        # 限制数量
        rules = rules[:max_rules]

        # 生成摘要
        lines = [f"=== 安全规则摘要 ({language}) ===", ""]

        # 按类型分组
        by_type: Dict[RuleType, List[SecurityRule]] = {}
        for rule in rules:
            if rule.rule_type not in by_type:
                by_type[rule.rule_type] = []
            by_type[rule.rule_type].append(rule)

        for rule_type in [RuleType.SINK, RuleType.SOURCE, RuleType.SANITIZER]:
            type_rules = by_type.get(rule_type, [])
            if type_rules:
                lines.append(f"[{rule_type.value.upper()}S]")
                for rule in type_rules[:15]:
                    lines.append(rule.to_prompt_text())
                lines.append("")

        return "\n".join(lines)

    def all_rules(self) -> List[SecurityRule]:
        """获取所有规则"""
        return list(self._rules.values())

    def count(self) -> int:
        """规则总数"""
        return len(self._rules)

    def _get_builtin_rules(self) -> List[SecurityRule]:
        """内置规则定义"""
        return [
            # === Python 危险函数 (Sinks) ===
            SecurityRule(
                id="py-sql-injection",
                name="SQL 注入风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.CRITICAL,
                languages=["python"],
                patterns=["execute", "executemany", "raw", "cursor.execute", "prefix:raw_"],
                description="直接拼接 SQL 语句可能导致 SQL 注入",
                cwe_ids=["CWE-89"],
                owasp_ids=["A03:2021"],
                fix_suggestion="使用参数化查询或 ORM",
            ),
            SecurityRule(
                id="py-command-injection",
                name="命令注入风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.CRITICAL,
                languages=["python"],
                patterns=["os.system", "os.popen", "subprocess.call", "subprocess.run", "subprocess.Popen", "eval", "exec"],
                frameworks=["*"],
                description="执行系统命令时使用用户输入可能导致命令注入",
                cwe_ids=["CWE-78"],
                owasp_ids=["A03:2021"],
                fix_suggestion="避免使用 shell=True，对输入进行严格验证",
            ),
            SecurityRule(
                id="py-deserialization",
                name="不安全的反序列化",
                rule_type=RuleType.SINK,
                category=RuleCategory.DESERIALIZATION,
                risk_level=RiskLevel.CRITICAL,
                languages=["python"],
                patterns=["pickle.loads", "pickle.load", "yaml.load", "yaml.unsafe_load", "marshal.loads"],
                description="反序列化不可信数据可能导致远程代码执行",
                cwe_ids=["CWE-502"],
                owasp_ids=["A08:2021"],
                fix_suggestion="使用 yaml.safe_load()，避免反序列化不可信数据",
            ),
            SecurityRule(
                id="py-ssrf",
                name="SSRF 风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.SSRF,
                risk_level=RiskLevel.HIGH,
                languages=["python"],
                patterns=["requests.get", "requests.post", "urllib.request.urlopen", "httpx.get", "httpx.post", "aiohttp.request"],
                description="使用用户输入构造 URL 可能导致 SSRF",
                cwe_ids=["CWE-918"],
                owasp_ids=["A10:2021"],
                fix_suggestion="验证和限制目标 URL，使用白名单",
            ),
            SecurityRule(
                id="py-file-read",
                name="Python 任意文件读取风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.FILE,
                risk_level=RiskLevel.HIGH,
                languages=["python"],
                patterns=["open", "Path.read_text", "Path.read_bytes", "send_file", "send_from_directory", "aiofiles.open"],
                description="使用用户输入构造文件路径可能导致任意文件读取",
                cwe_ids=["CWE-22", "CWE-73"],
                owasp_ids=["A01:2021"],
                fix_suggestion="验证和限制文件路径，使用白名单，避免路径遍历",
            ),
            SecurityRule(
                id="py-file-write",
                name="Python 任意文件写入风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.FILE,
                risk_level=RiskLevel.CRITICAL,
                languages=["python"],
                patterns=["Path.write_text", "Path.write_bytes", "shutil.copy", "shutil.move", "os.rename"],
                description="使用用户输入构造文件路径可能导致任意文件写入",
                cwe_ids=["CWE-22", "CWE-434"],
                owasp_ids=["A01:2021"],
                fix_suggestion="验证和限制文件路径，使用白名单，检查文件扩展名",
            ),
            SecurityRule(
                id="py-template-injection",
                name="Python 模板注入风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.CRITICAL,
                languages=["python"],
                patterns=["render_template_string", "Template", "Environment.from_string", "jinja2.Template"],
                description="使用用户输入构造模板可能导致服务端模板注入(SSTI)",
                cwe_ids=["CWE-94"],
                owasp_ids=["A03:2021"],
                fix_suggestion="避免使用用户输入构造模板，使用预定义模板",
            ),
            SecurityRule(
                id="py-xxe",
                name="Python XXE 风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.XXE,
                risk_level=RiskLevel.HIGH,
                languages=["python"],
                patterns=["xml.etree.ElementTree.parse", "lxml.etree.parse", "xml.dom.minidom.parse", "xml.sax.parse"],
                description="解析不可信 XML 可能导致 XXE 攻击",
                cwe_ids=["CWE-611"],
                owasp_ids=["A05:2021"],
                fix_suggestion="使用 defusedxml 库或禁用外部实体解析",
            ),

            # === Python 输入源 (Sources) ===
            SecurityRule(
                id="py-http-input",
                name="HTTP 请求输入",
                rule_type=RuleType.SOURCE,
                category=RuleCategory.OTHER,
                risk_level=RiskLevel.MEDIUM,
                languages=["python"],
                patterns=["request.args", "request.form", "request.json", "request.data", "request.GET", "request.POST", "request.body"],
                frameworks=["flask", "django"],
                description="来自 HTTP 请求的用户输入",
            ),
            SecurityRule(
                id="py-env-input",
                name="环境变量输入",
                rule_type=RuleType.SOURCE,
                category=RuleCategory.OTHER,
                risk_level=RiskLevel.LOW,
                languages=["python"],
                patterns=["os.environ", "os.getenv"],
                description="来自环境变量的输入",
            ),

            # === Python 消毒函数 (Sanitizers) ===
            SecurityRule(
                id="py-sql-param",
                name="SQL 参数化查询",
                rule_type=RuleType.SANITIZER,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.LOW,
                languages=["python"],
                patterns=["contains:?", "contains:%s", "contains::1", "contains::param"],
                description="使用参数化查询防止 SQL 注入",
            ),
            SecurityRule(
                id="py-escape-html",
                name="HTML 转义",
                rule_type=RuleType.SANITIZER,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.LOW,
                languages=["python"],
                patterns=["escape", "html.escape", "markupsafe.escape", "bleach.clean"],
                description="转义 HTML 特殊字符防止 XSS",
            ),

            # === JavaScript 危险函数 (Sinks) ===
            SecurityRule(
                id="js-xss",
                name="XSS 风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.HIGH,
                languages=["javascript", "typescript"],
                patterns=["innerHTML", "outerHTML", "document.write", "eval", "Function"],
                description="直接插入 HTML 可能导致 XSS",
                cwe_ids=["CWE-79"],
                owasp_ids=["A03:2021"],
                fix_suggestion="使用 textContent 或框架的安全绑定",
            ),
            SecurityRule(
                id="js-sql-injection",
                name="SQL 注入风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.CRITICAL,
                languages=["javascript", "typescript"],
                patterns=["query", "execute", "raw", "prefix:raw"],
                frameworks=["sequelize", "knex", "mysql", "pg"],
                description="直接拼接 SQL 可能导致注入",
                cwe_ids=["CWE-89"],
                fix_suggestion="使用参数化查询或 ORM",
            ),
            SecurityRule(
                id="js-command-injection",
                name="命令注入风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.CRITICAL,
                languages=["javascript", "typescript"],
                patterns=["exec", "execSync", "spawn", "spawnSync", "execFile"],
                description="执行系统命令时使用用户输入可能导致命令注入",
                cwe_ids=["CWE-78"],
                fix_suggestion="避免 shell: true，严格验证输入",
            ),
            SecurityRule(
                id="js-prototype-pollution",
                name="原型链污染",
                rule_type=RuleType.SINK,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.HIGH,
                languages=["javascript", "typescript"],
                patterns=["Object.assign", "_.merge", "_.extend", "$.extend", "prefix:deep"],
                description="不安全的对象合并可能导致原型链污染",
                cwe_ids=["CWE-1321"],
                fix_suggestion="验证合并的键名，禁止 __proto__ 和 constructor",
            ),
            SecurityRule(
                id="js-ssrf",
                name="JavaScript SSRF 风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.SSRF,
                risk_level=RiskLevel.HIGH,
                languages=["javascript", "typescript"],
                patterns=["fetch", "axios.get", "axios.post", "got", "node-fetch", "request", "superagent"],
                description="使用用户输入构造 URL 可能导致 SSRF",
                cwe_ids=["CWE-918"],
                owasp_ids=["A10:2021"],
                fix_suggestion="验证和限制目标 URL，使用白名单",
            ),
            SecurityRule(
                id="js-file-operation",
                name="JavaScript 文件操作风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.FILE,
                risk_level=RiskLevel.HIGH,
                languages=["javascript", "typescript"],
                patterns=["fs.readFile", "fs.readFileSync", "fs.writeFile", "fs.writeFileSync", "fs.unlink", "fs.rename"],
                description="使用用户输入构造文件路径可能导致任意文件读写",
                cwe_ids=["CWE-22", "CWE-73"],
                owasp_ids=["A01:2021"],
                fix_suggestion="验证和限制文件路径，使用白名单，避免路径遍历",
            ),
            SecurityRule(
                id="js-deserialization",
                name="JavaScript 反序列化风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.DESERIALIZATION,
                risk_level=RiskLevel.CRITICAL,
                languages=["javascript", "typescript"],
                patterns=["unserialize", "node-serialize", "serialize-javascript", "funcster"],
                description="反序列化不可信数据可能导致远程代码执行",
                cwe_ids=["CWE-502"],
                owasp_ids=["A08:2021"],
                fix_suggestion="避免反序列化不可信数据，使用 JSON.parse",
            ),

            # === JavaScript 输入源 (Sources) ===
            SecurityRule(
                id="js-http-input",
                name="HTTP 请求输入",
                rule_type=RuleType.SOURCE,
                category=RuleCategory.OTHER,
                risk_level=RiskLevel.MEDIUM,
                languages=["javascript", "typescript"],
                patterns=["req.body", "req.query", "req.params", "req.headers", "request.body", "ctx.request.body"],
                frameworks=["express", "koa", "fastify"],
                description="来自 HTTP 请求的用户输入",
            ),
            SecurityRule(
                id="js-url-input",
                name="URL 输入",
                rule_type=RuleType.SOURCE,
                category=RuleCategory.OTHER,
                risk_level=RiskLevel.MEDIUM,
                languages=["javascript", "typescript"],
                patterns=["location.href", "location.search", "location.hash", "URLSearchParams"],
                description="来自 URL 的用户输入",
            ),

            # === 业务逻辑规则 ===
            SecurityRule(
                id="auth-check-missing",
                name="缺少认证检查",
                rule_type=RuleType.PATTERN,
                category=RuleCategory.AUTH,
                risk_level=RiskLevel.HIGH,
                languages=["python", "javascript", "typescript"],
                patterns=["contains:login_required", "contains:authenticated", "contains:auth", "contains:verify_token", "contains:jwt"],
                description="API 端点应检查用户认证状态",
                cwe_ids=["CWE-306"],
                owasp_ids=["A07:2021"],
                tags=["auth", "api"],
            ),
            SecurityRule(
                id="authz-check-missing",
                name="缺少授权检查",
                rule_type=RuleType.PATTERN,
                category=RuleCategory.ACCESS_CONTROL,
                risk_level=RiskLevel.HIGH,
                languages=["python", "javascript", "typescript"],
                patterns=["contains:permission", "contains:authorize", "contains:can_access", "contains:has_role", "contains:is_owner"],
                description="资源访问应检查用户权限",
                cwe_ids=["CWE-862", "CWE-863"],
                owasp_ids=["A01:2021"],
                tags=["authz", "idor"],
            ),
            SecurityRule(
                id="business-money-operation",
                name="资金操作",
                rule_type=RuleType.PATTERN,
                category=RuleCategory.BUSINESS_LOGIC,
                risk_level=RiskLevel.CRITICAL,
                languages=["python", "javascript", "typescript"],
                patterns=["contains:payment", "contains:transfer", "contains:withdraw", "contains:deposit", "contains:refund", "contains:balance"],
                description="资金相关操作需要特别关注安全性",
                tags=["money", "payment"],
            ),
            SecurityRule(
                id="business-user-delete",
                name="用户删除操作",
                rule_type=RuleType.PATTERN,
                category=RuleCategory.BUSINESS_LOGIC,
                risk_level=RiskLevel.HIGH,
                languages=["python", "javascript", "typescript"],
                patterns=["contains:delete_user", "contains:remove_user", "contains:deactivate", "contains:ban_user"],
                description="用户删除需要权限验证和审计日志",
                tags=["user", "delete"],
            ),
            SecurityRule(
                id="business-password-reset",
                name="密码重置",
                rule_type=RuleType.PATTERN,
                category=RuleCategory.AUTH,
                risk_level=RiskLevel.HIGH,
                languages=["python", "javascript", "typescript"],
                patterns=["contains:reset_password", "contains:forgot_password", "contains:change_password", "contains:set_password"],
                description="密码操作需要二次验证和速率限制",
                tags=["password", "auth"],
            ),

            # === PHP 危险函数 (Sinks) ===
            SecurityRule(
                id="php-sql-injection",
                name="PHP SQL 注入风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.CRITICAL,
                languages=["php"],
                patterns=["mysql_query", "mysqli_query", "pg_query", "sqlite_query", "->query(", "->exec(", "->prepare("],
                description="直接拼接 SQL 语句可能导致 SQL 注入",
                cwe_ids=["CWE-89"],
                owasp_ids=["A03:2021"],
                fix_suggestion="使用参数化查询或预处理语句",
            ),
            SecurityRule(
                id="php-command-injection",
                name="PHP 命令注入风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.CRITICAL,
                languages=["php"],
                patterns=["exec(", "shell_exec(", "system(", "passthru(", "popen(", "proc_open(", "pcntl_exec(", "`"],
                description="执行系统命令时使用用户输入可能导致命令注入",
                cwe_ids=["CWE-78"],
                owasp_ids=["A03:2021"],
                fix_suggestion="避免直接执行用户输入，使用白名单验证",
            ),
            SecurityRule(
                id="php-code-injection",
                name="PHP 代码注入风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.CRITICAL,
                languages=["php"],
                patterns=["eval(", "assert(", "create_function(", "call_user_func(", "call_user_func_array(", "preg_replace"],
                description="动态执行代码可能导致远程代码执行",
                cwe_ids=["CWE-94"],
                owasp_ids=["A03:2021"],
                fix_suggestion="避免使用 eval 等动态执行函数",
            ),
            SecurityRule(
                id="php-file-inclusion",
                name="PHP 文件包含风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.CRITICAL,
                languages=["php"],
                patterns=["include(", "include_once(", "require(", "require_once(", "include $", "require $"],
                description="动态文件包含可能导致本地/远程文件包含漏洞",
                cwe_ids=["CWE-98"],
                owasp_ids=["A03:2021"],
                fix_suggestion="使用白名单限制可包含的文件",
            ),
            SecurityRule(
                id="php-file-operation",
                name="PHP 文件操作风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.FILE_UPLOAD,
                risk_level=RiskLevel.HIGH,
                languages=["php"],
                patterns=["file_get_contents(", "file_put_contents(", "fopen(", "fread(", "fwrite(", "readfile(", "unlink(", "move_uploaded_file("],
                description="文件操作使用用户输入可能导致任意文件读写",
                cwe_ids=["CWE-22"],
                owasp_ids=["A01:2021"],
                fix_suggestion="验证和过滤文件路径，使用白名单",
            ),
            SecurityRule(
                id="php-deserialization",
                name="PHP 反序列化风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.DESERIALIZATION,
                risk_level=RiskLevel.CRITICAL,
                languages=["php"],
                patterns=["unserialize("],
                description="反序列化不可信数据可能导致远程代码执行",
                cwe_ids=["CWE-502"],
                owasp_ids=["A08:2021"],
                fix_suggestion="避免反序列化用户输入，使用 JSON 替代",
            ),
            SecurityRule(
                id="php-ssrf",
                name="PHP SSRF 风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.SSRF,
                risk_level=RiskLevel.HIGH,
                languages=["php"],
                patterns=["curl_exec(", "curl_init(", "file_get_contents(", "fsockopen(", "fopen("],
                description="使用用户输入构造 URL 可能导致 SSRF",
                cwe_ids=["CWE-918"],
                owasp_ids=["A10:2021"],
                fix_suggestion="验证和限制目标 URL，使用白名单",
            ),
            SecurityRule(
                id="php-xss",
                name="PHP XSS 风险",
                rule_type=RuleType.SINK,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.HIGH,
                languages=["php"],
                patterns=["echo", "print", "printf", "<?="],
                description="输出用户输入到 HTML 可能导致 XSS",
                cwe_ids=["CWE-79"],
                owasp_ids=["A03:2021"],
                fix_suggestion="使用 htmlspecialchars() 或 htmlentities() 转义输出",
            ),

            # === PHP 输入源 (Sources) ===
            SecurityRule(
                id="php-http-input",
                name="PHP HTTP 请求输入",
                rule_type=RuleType.SOURCE,
                category=RuleCategory.OTHER,
                risk_level=RiskLevel.MEDIUM,
                languages=["php"],
                patterns=["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER"],
                description="来自 HTTP 请求的用户输入",
            ),

            # === PHP 消毒函数 (Sanitizers) ===
            SecurityRule(
                id="php-sql-escape",
                name="PHP SQL 转义",
                rule_type=RuleType.SANITIZER,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.LOW,
                languages=["php"],
                patterns=["mysql_real_escape_string", "mysqli_real_escape_string", "addslashes", "PDO::quote"],
                description="SQL 转义函数（推荐使用预处理语句）",
            ),
            SecurityRule(
                id="php-html-escape",
                name="PHP HTML 转义",
                rule_type=RuleType.SANITIZER,
                category=RuleCategory.INJECTION,
                risk_level=RiskLevel.LOW,
                languages=["php"],
                patterns=["htmlspecialchars", "htmlentities", "strip_tags"],
                description="HTML 转义函数防止 XSS",
            ),
        ]


def create_rule_manager(config: RulesConfig) -> RuleManager:
    """创建并初始化规则管理器"""
    manager = RuleManager(config)

    # 加载内置规则
    builtin_count = manager.load_builtin_rules()
    logger.info(f"内置规则加载完成: {builtin_count} 条")

    # 加载配置目录的规则
    if config.rules_dir:
        # 解析相对路径（相对于项目根目录）
        from pathlib import Path
        rules_path = Path(config.rules_dir)
        if not rules_path.is_absolute():
            # 尝试从项目根目录解析
            project_root = Path(__file__).parent.parent
            rules_path = project_root / config.rules_dir

        logger.info(f"从目录加载规则: {rules_path}")
        file_count = manager.load_from_directory(str(rules_path))
        logger.info(f"文件规则加载完成: {file_count} 条")

    # 加载自定义规则
    if config.custom_rules_dir:
        custom_count = manager.load_from_directory(config.custom_rules_dir)
        logger.info(f"自定义规则加载完成: {custom_count} 条")

    # 输出规则统计
    total = len(manager.all_rules())
    by_type = {}
    for rule in manager.all_rules():
        type_name = rule.rule_type.value if rule.rule_type else 'unknown'
        by_type[type_name] = by_type.get(type_name, 0) + 1
    logger.info(f"规则加载完成，共 {total} 条。按类型: {by_type}")

    return manager
