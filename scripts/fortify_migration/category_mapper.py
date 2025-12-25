"""Fortify 类别映射表

将 Fortify 的漏洞分类映射到 CodeScan 规则系统。
"""

from typing import Dict, Tuple

# Fortify VulnCategory → (CodeScan category, CodeScan rule_type)
CATEGORY_MAPPING: Dict[str, Tuple[str, str]] = {
    # 认证相关
    'Password Management': ('auth', 'pattern'),
    'Missing Authentication': ('auth', 'pattern'),
    'Weak Authentication': ('auth', 'pattern'),
    'Broken Authentication': ('auth', 'pattern'),

    # 访问控制
    'Access Control': ('access-control', 'pattern'),
    'Missing Authorization': ('access-control', 'pattern'),
    'Privilege Escalation': ('access-control', 'pattern'),

    # 注入类
    'SQL Injection': ('injection', 'sink'),
    'Command Injection': ('injection', 'sink'),
    'Code Injection': ('injection', 'sink'),
    'NoSQL Injection': ('injection', 'sink'),
    'LDAP Injection': ('injection', 'sink'),
    'XPath Injection': ('injection', 'sink'),
    'Log Injection': ('injection', 'sink'),
    'Cross-Site Scripting': ('injection', 'sink'),
    'Path Manipulation': ('injection', 'sink'),
    'Header Manipulation': ('injection', 'sink'),
    'Open Redirect': ('injection', 'sink'),
    'Server-Side Template Injection': ('injection', 'sink'),
    'JSON Injection': ('injection', 'sink'),
    'XML Injection': ('injection', 'sink'),
    'Expression Language Injection': ('injection', 'sink'),
    'Dynamic Code Evaluation': ('injection', 'sink'),

    # 反序列化
    'Unsafe Deserialization': ('deserialization', 'sink'),
    'Deserialization of Untrusted Data': ('deserialization', 'sink'),

    # 文件操作
    'File Upload': ('file-upload', 'pattern'),
    'File Disclosure': ('other', 'sink'),
    'Path Traversal': ('injection', 'sink'),

    # SSRF
    'Server-Side Request Forgery': ('ssrf', 'sink'),
    'SSRF': ('ssrf', 'sink'),

    # XXE
    'XML External Entity': ('xxe', 'sink'),
    'XXE': ('xxe', 'sink'),

    # 加密
    'Weak Cryptographic Hash': ('crypto', 'pattern'),
    'Weak Cryptographic Signature': ('crypto', 'pattern'),
    'Insecure Transport': ('crypto', 'pattern'),
    'Insecure SSL': ('crypto', 'pattern'),
    'Key Management': ('crypto', 'pattern'),
    'Weak Encryption': ('crypto', 'pattern'),

    # 业务逻辑
    'Business Logic': ('business-logic', 'pattern'),
    'Race Condition': ('business-logic', 'pattern'),
    'Price Manipulation': ('business-logic', 'pattern'),

    # 其他
    'Privacy Violation': ('other', 'pattern'),
    'Information Leak': ('other', 'pattern'),
    'System Information Leak': ('other', 'pattern'),
    'Error Handling': ('other', 'pattern'),
    'Poor Error Handling': ('other', 'pattern'),
    'Denial of Service': ('other', 'pattern'),
    'Cross-Site Request Forgery': ('other', 'pattern'),
    'CSRF': ('other', 'pattern'),
    'Session Management': ('auth', 'pattern'),
    'Cookie Security': ('auth', 'pattern'),
}


def map_category(fortify_category: str) -> Tuple[str, str]:
    """映射 Fortify 类别到 CodeScan

    Args:
        fortify_category: Fortify VulnCategory

    Returns:
        (codescan_category, rule_type)
    """
    if fortify_category in CATEGORY_MAPPING:
        return CATEGORY_MAPPING[fortify_category]

    # 默认映射
    # 包含 "Injection" 的都是 injection/sink
    if 'Injection' in fortify_category:
        return ('injection', 'sink')

    # 包含 "Authentication" 的都是 auth
    if 'Authentication' in fortify_category or 'Authorization' in fortify_category:
        return ('auth', 'pattern')

    # 包含 "Crypto" 的都是 crypto
    if 'Crypto' in fortify_category or 'Encryption' in fortify_category:
        return ('crypto', 'pattern')

    # 默认
    return ('other', 'pattern')


def is_sink_category(fortify_category: str) -> bool:
    """判断是否是 sink 类型的类别

    Args:
        fortify_category: Fortify VulnCategory

    Returns:
        是否是 sink
    """
    _, rule_type = map_category(fortify_category)
    return rule_type == 'sink'


def get_all_mappings() -> Dict[str, Tuple[str, str]]:
    """获取所有映射

    Returns:
        完整映射表
    """
    return CATEGORY_MAPPING.copy()
