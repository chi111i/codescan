"""
跨语言安全模式定义

定义可以在多种语言中使用的安全检测模式。
这些模式基于 Generic AST 工作，可以匹配不同语言中的相似漏洞。
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Callable, Optional, Set, Dict, Any

from .nodes import GenericCall, GenericFunction, GenericNode, NodeKind

logger = logging.getLogger(__name__)


@dataclass
class SecurityPattern:
    """跨语言安全模式定义

    定义一个可以跨语言使用的安全检测模式。
    """
    name: str
    description: str
    severity: str  # critical, high, medium, low
    cwe_ids: List[str]
    matcher: Callable[[GenericCall], bool]
    languages: Optional[List[str]] = None  # None 表示所有语言
    category: str = "general"
    references: List[str] = field(default_factory=list)

    def matches(self, call: GenericCall, language: Optional[str] = None) -> bool:
        """检查调用是否匹配此模式

        Args:
            call: GenericCall 对象
            language: 源语言（可选）

        Returns:
            是否匹配
        """
        # 检查语言限制
        if self.languages and language and language not in self.languages:
            return False

        try:
            return self.matcher(call)
        except Exception as e:
            logger.debug(f"模式匹配失败 ({self.name}): {e}")
            return False


# ============================================================
# 危险函数集合定义
# ============================================================

# 命令执行函数
COMMAND_EXEC_SINKS: Set[str] = {
    # Python
    "system", "popen", "spawn", "exec", "eval", "execfile",
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "os.system", "os.popen", "os.spawn", "os.exec",
    "commands.getoutput", "commands.getstatusoutput",
    # PHP
    "shell_exec", "passthru", "proc_open", "pcntl_exec",
    "backtick", "popen",
    # JavaScript/Node
    "child_process.exec", "child_process.execSync",
    "child_process.spawn", "child_process.spawnSync",
    "execSync", "spawnSync",
    # Ruby
    "Kernel.system", "Kernel.exec", "Kernel.spawn",
    "IO.popen", "Open3.popen3",
    # Go
    "exec.Command", "exec.CommandContext",
    "os.StartProcess",
    # Java
    "Runtime.exec", "ProcessBuilder.start",
}

# 代码执行函数
CODE_EXEC_SINKS: Set[str] = {
    # Python
    "eval", "exec", "compile", "execfile",
    # PHP
    "eval", "assert", "create_function",
    "call_user_func", "call_user_func_array",
    "preg_replace",  # with /e modifier
    # JavaScript
    "eval", "Function", "setTimeout", "setInterval",  # with string arg
    # Ruby
    "eval", "instance_eval", "class_eval", "module_eval",
}

# SQL 查询函数
SQL_SINKS: Set[str] = {
    # 通用
    "execute", "query", "raw", "exec",
    "executeQuery", "executeUpdate", "executeSql",
    # Python
    "cursor.execute", "cursor.executemany",
    "connection.execute", "engine.execute",
    # PHP
    "mysql_query", "mysqli_query", "pg_query", "sqlite_query",
    "PDO.query", "PDO.exec",
    # Java
    "Statement.execute", "Statement.executeQuery",
    "PreparedStatement.execute",
    # Go
    "DB.Query", "DB.Exec", "DB.QueryRow",
}

# 文件操作函数
FILE_SINKS: Set[str] = {
    # 通用读取
    "open", "read", "readFile", "readFileSync",
    "file_get_contents", "fopen", "fread",
    "readfile", "file",
    # 通用写入
    "write", "writeFile", "writeFileSync",
    "file_put_contents", "fwrite", "fputs",
    # 包含/执行
    "include", "include_once", "require", "require_once",
    # 路径操作
    "unlink", "delete", "remove", "rmdir",
    "rename", "move", "copy",
}

# 反序列化函数
DESERIALIZATION_SINKS: Set[str] = {
    # Python
    "pickle.loads", "pickle.load",
    "yaml.load", "yaml.unsafe_load",
    "marshal.loads",
    # PHP
    "unserialize",
    # Java
    "ObjectInputStream.readObject",
    "XMLDecoder.readObject",
    # Ruby
    "Marshal.load", "YAML.load",
    # .NET
    "BinaryFormatter.Deserialize",
    "XmlSerializer.Deserialize",
}

# SSRF 相关函数
SSRF_SINKS: Set[str] = {
    # Python
    "requests.get", "requests.post", "requests.request",
    "urllib.request.urlopen", "urllib2.urlopen",
    "httplib.HTTPConnection", "http.client.HTTPConnection",
    # PHP
    "curl_exec", "curl_init", "file_get_contents",
    "fsockopen", "pfsockopen",
    # JavaScript
    "fetch", "axios", "request",
    "http.get", "https.get",
    # Go
    "http.Get", "http.Post", "http.Do",
    # Java
    "URL.openConnection", "HttpURLConnection",
    "HttpClient.execute",
}


# ============================================================
# 预定义的跨语言安全模式
# ============================================================

def _match_command_injection(call: GenericCall) -> bool:
    """匹配命令注入 sink"""
    # 检查完整限定名
    if call.full_name in COMMAND_EXEC_SINKS:
        return True
    # 检查短名
    if call.callee in {"system", "exec", "popen", "spawn", "shell_exec", "passthru"}:
        return True
    # 检查特定模式
    if call.receiver:
        full = f"{call.receiver}.{call.callee}"
        return full in COMMAND_EXEC_SINKS or \
               ("os" in call.receiver and call.callee in {"system", "popen", "exec"}) or \
               ("child_process" in call.receiver and call.callee in {"exec", "execSync", "spawn"})
    return False


def _match_code_injection(call: GenericCall) -> bool:
    """匹配代码注入 sink"""
    if call.full_name in CODE_EXEC_SINKS:
        return True
    if call.callee in {"eval", "exec", "assert", "Function"}:
        return True
    return False


def _match_sql_injection(call: GenericCall) -> bool:
    """匹配 SQL 注入 sink"""
    if call.full_name in SQL_SINKS:
        return True
    if call.callee in {"execute", "query", "raw", "exec", "executeQuery"}:
        return True
    # 检查方法调用模式
    if call.receiver and call.callee in {"execute", "query", "exec"}:
        return True
    return False


def _match_path_traversal(call: GenericCall) -> bool:
    """匹配路径遍历 sink"""
    if call.full_name in FILE_SINKS:
        return True
    if call.callee in {"open", "read", "readFile", "readFileSync",
                       "file_get_contents", "include", "require"}:
        return True
    return False


def _match_deserialization(call: GenericCall) -> bool:
    """匹配不安全反序列化 sink"""
    if call.full_name in DESERIALIZATION_SINKS:
        return True
    if call.callee in {"loads", "load", "unserialize", "readObject"}:
        # 排除 json.loads（通常安全）
        if call.receiver and "json" in call.receiver.lower():
            return False
        return True
    return False


def _match_ssrf(call: GenericCall) -> bool:
    """匹配 SSRF sink"""
    if call.full_name in SSRF_SINKS:
        return True
    if call.callee in {"get", "post", "request", "fetch", "urlopen"}:
        if call.receiver:
            return any(kw in call.receiver.lower()
                      for kw in {"http", "request", "curl", "urllib"})
    return False


def _match_xxe(call: GenericCall) -> bool:
    """匹配 XXE sink"""
    xxe_patterns = {
        "XMLParser", "SAXParser", "DocumentBuilder",
        "xml.etree.ElementTree.parse", "lxml.etree.parse",
        "simplexml_load_string", "simplexml_load_file",
        "DOMDocument.load", "DOMDocument.loadXML",
    }
    if call.full_name in xxe_patterns:
        return True
    if call.callee in {"parse", "parseString", "load", "loadXML"}:
        if call.receiver and any(kw in call.receiver.lower()
                                 for kw in {"xml", "dom", "sax"}):
            return True
    return False


def _match_ldap_injection(call: GenericCall) -> bool:
    """匹配 LDAP 注入 sink"""
    if call.callee in {"search", "search_s", "search_ext", "ldap_search"}:
        if call.receiver and "ldap" in call.receiver.lower():
            return True
    return False


def _match_xss(call: GenericCall) -> bool:
    """匹配潜在 XSS sink（需要结合污点分析）"""
    xss_sinks = {
        "innerHTML", "outerHTML", "document.write", "document.writeln",
        "insertAdjacentHTML", "render", "dangerouslySetInnerHTML",
        "echo", "print", "printf",
    }
    if call.callee in xss_sinks or call.full_name in xss_sinks:
        return True
    return False


# 预定义模式列表
CROSS_LANGUAGE_PATTERNS: List[SecurityPattern] = [
    SecurityPattern(
        name="command_injection_sink",
        description="命令执行函数调用 - 可能导致远程代码执行",
        severity="critical",
        cwe_ids=["CWE-78", "CWE-77"],
        category="injection",
        matcher=_match_command_injection,
        references=[
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://owasp.org/www-community/attacks/Command_Injection",
        ]
    ),
    SecurityPattern(
        name="code_injection_sink",
        description="代码执行函数调用 - 可能导致任意代码执行",
        severity="critical",
        cwe_ids=["CWE-94", "CWE-95"],
        category="injection",
        matcher=_match_code_injection,
        references=[
            "https://cwe.mitre.org/data/definitions/94.html",
        ]
    ),
    SecurityPattern(
        name="sql_injection_sink",
        description="SQL 查询执行 - 可能导致 SQL 注入",
        severity="critical",
        cwe_ids=["CWE-89"],
        category="injection",
        matcher=_match_sql_injection,
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/www-community/attacks/SQL_Injection",
        ]
    ),
    SecurityPattern(
        name="path_traversal_sink",
        description="文件路径操作 - 可能导致路径遍历",
        severity="high",
        cwe_ids=["CWE-22", "CWE-73"],
        category="file",
        matcher=_match_path_traversal,
        references=[
            "https://cwe.mitre.org/data/definitions/22.html",
        ]
    ),
    SecurityPattern(
        name="deserialization_sink",
        description="反序列化操作 - 可能导致任意代码执行",
        severity="critical",
        cwe_ids=["CWE-502"],
        category="deserialization",
        matcher=_match_deserialization,
        references=[
            "https://cwe.mitre.org/data/definitions/502.html",
        ]
    ),
    SecurityPattern(
        name="ssrf_sink",
        description="HTTP 请求 - 可能导致 SSRF",
        severity="high",
        cwe_ids=["CWE-918"],
        category="ssrf",
        matcher=_match_ssrf,
        references=[
            "https://cwe.mitre.org/data/definitions/918.html",
        ]
    ),
    SecurityPattern(
        name="xxe_sink",
        description="XML 解析 - 可能导致 XXE",
        severity="high",
        cwe_ids=["CWE-611"],
        category="xxe",
        matcher=_match_xxe,
        references=[
            "https://cwe.mitre.org/data/definitions/611.html",
        ]
    ),
    SecurityPattern(
        name="ldap_injection_sink",
        description="LDAP 查询 - 可能导致 LDAP 注入",
        severity="high",
        cwe_ids=["CWE-90"],
        category="injection",
        matcher=_match_ldap_injection,
        references=[
            "https://cwe.mitre.org/data/definitions/90.html",
        ]
    ),
    SecurityPattern(
        name="xss_sink",
        description="HTML 输出 - 可能导致 XSS",
        severity="medium",
        cwe_ids=["CWE-79"],
        category="xss",
        matcher=_match_xss,
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
        ]
    ),
]


def match_security_patterns(
    call: GenericCall,
    language: Optional[str] = None,
    patterns: Optional[List[SecurityPattern]] = None,
    categories: Optional[List[str]] = None,
    min_severity: Optional[str] = None,
) -> List[SecurityPattern]:
    """对调用匹配所有安全模式

    Args:
        call: GenericCall 对象
        language: 源语言
        patterns: 要使用的模式列表，默认使用 CROSS_LANGUAGE_PATTERNS
        categories: 只检查这些类别的模式
        min_severity: 最低严重级别

    Returns:
        匹配的 SecurityPattern 列表
    """
    if patterns is None:
        patterns = CROSS_LANGUAGE_PATTERNS

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    min_severity_level = severity_order.get(min_severity, 0) if min_severity else 0

    matched = []
    for pattern in patterns:
        # 检查类别过滤
        if categories and pattern.category not in categories:
            continue

        # 检查严重级别
        if severity_order.get(pattern.severity, 0) < min_severity_level:
            continue

        # 检查匹配
        if pattern.matches(call, language):
            matched.append(pattern)

    return matched


def get_patterns_by_category(category: str) -> List[SecurityPattern]:
    """获取指定类别的所有模式"""
    return [p for p in CROSS_LANGUAGE_PATTERNS if p.category == category]


def get_patterns_by_severity(severity: str) -> List[SecurityPattern]:
    """获取指定严重级别的所有模式"""
    return [p for p in CROSS_LANGUAGE_PATTERNS if p.severity == severity]


def list_all_sinks() -> Dict[str, Set[str]]:
    """列出所有定义的 sink 函数

    Returns:
        类别 -> 函数集合 的字典
    """
    return {
        "command_exec": COMMAND_EXEC_SINKS,
        "code_exec": CODE_EXEC_SINKS,
        "sql": SQL_SINKS,
        "file": FILE_SINKS,
        "deserialization": DESERIALIZATION_SINKS,
        "ssrf": SSRF_SINKS,
    }
