"""
SinkCallScanner - 确定性危险函数触发点扫描器

根据目标文档 P0-1 的要求：
- 不使用向量检索，而是使用 AST/正则进行确定性扫描
- 输出所有危险函数触发点 (SinkCallSite)
- 支持多种匹配模式：精确匹配、前缀匹配、正则匹配、代码包含

流程：
1. 遍历所有 CodeUnit
2. 对每个 CodeUnit 的 calls 列表和代码内容进行规则匹配
3. 输出 SinkCallSite 列表

ID 生成策略：
使用基于内容的确定性哈希 ID，而非递增计数器。
这确保了相同的触发点在多次扫描中具有稳定的 ID。
"""

import re
import logging
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set
from enum import Enum

from indexer.models import CodeUnit
from rules import RuleManager, RuleType
from rules.models import SecurityRule, RiskLevel

logger = logging.getLogger(__name__)


class SinkCategory(Enum):
    """Sink 类别"""
    COMMAND_EXEC = "command_exec"       # 命令执行: os.system, subprocess.call
    CODE_EXEC = "code_exec"             # 代码执行: eval, exec
    SQL_INJECTION = "sql_injection"     # SQL 注入: execute, query
    FILE_READ = "file_read"             # 文件读取: open, file_get_contents
    FILE_WRITE = "file_write"           # 文件写入: file_put_contents, fwrite
    DESERIALIZATION = "deserialization" # 反序列化: pickle.loads, unserialize
    SSRF = "ssrf"                       # SSRF: requests.get, curl_exec
    XSS = "xss"                         # XSS: innerHTML, echo
    PATH_TRAVERSAL = "path_traversal"   # 路径穿越: sendfile, readFile
    OTHER = "other"


@dataclass
class SinkCallSite:
    """危险函数触发点"""
    id: str                             # 唯一标识
    unit_id: str                        # 所在 CodeUnit ID
    file_path: str                      # 文件路径
    line_start: int                     # 起始行
    line_end: int                       # 结束行
    symbol: str                         # 所在函数/方法名
    matched_rule_ids: List[str]         # 命中的规则 ID
    call_snippet: str                   # 调用代码片段（1-5行）
    sink_category: SinkCategory         # Sink 类别
    risk_level: RiskLevel               # 风险等级
    matched_patterns: List[str]         # 匹配的具体模式
    confidence: float = 1.0             # 匹配置信度
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "unit_id": self.unit_id,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "symbol": self.symbol,
            "matched_rule_ids": self.matched_rule_ids,
            "call_snippet": self.call_snippet,
            "sink_category": self.sink_category.value,
            "risk_level": self.risk_level.value,
            "matched_patterns": self.matched_patterns,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


class SinkCallScanner:
    """确定性危险函数触发点扫描器

    不依赖向量检索，直接对代码进行模式匹配。

    匹配策略（按优先级）：
    1. 完整限定名精确匹配: os.system, subprocess.Popen
    2. 短名匹配（降低权重）: system, Popen
    3. 代码文本包含匹配: contains:eval(
    4. 正则匹配: regex:pickle\\.loads?\\(
    """

    # Sink 类别映射（根据规则类别推断）
    CATEGORY_MAP = {
        "injection": SinkCategory.SQL_INJECTION,
        "command": SinkCategory.COMMAND_EXEC,
        "code": SinkCategory.CODE_EXEC,
        "file": SinkCategory.FILE_READ,
        "deserialization": SinkCategory.DESERIALIZATION,
        "ssrf": SinkCategory.SSRF,
        "xss": SinkCategory.XSS,
    }

    def __init__(self, rule_manager: RuleManager):
        self.rule_manager = rule_manager
        self._compiled_patterns: Dict[str, re.Pattern] = {}

    def scan(
        self,
        code_units: List[CodeUnit],
        language: Optional[str] = None,
        categories: Optional[List[str]] = None,
        languages: Optional[List[str]] = None,
    ) -> List[SinkCallSite]:
        """扫描所有代码单元，找出危险函数触发点

        Args:
            code_units: 代码单元列表
            language: 限定单语言（向后兼容）
            categories: 限定类别
            languages: 限定多语言列表（优先于 language）

        Returns:
            SinkCallSite 列表
        """
        # BUG #1 Fix: 支持多语言列表，不再只取第一个语言
        lang_set: Optional[set] = None
        if languages:
            lang_set = set(languages)
        elif language:
            lang_set = {language}

        # 获取所有 sink 规则（多语言时获取所有语言的规则并去重）
        if lang_set:
            seen_ids = set()
            sink_rules = []
            for lang in lang_set:
                for rule in self.rule_manager.get_sinks(lang):
                    if rule.id not in seen_ids:
                        sink_rules.append(rule)
                        seen_ids.add(rule.id)
        else:
            sink_rules = self.rule_manager.get_sinks(None)
        logger.info(f"[SinkScanner] 加载了 {len(sink_rules)} 条 sink 规则 (languages={lang_set})")

        if not sink_rules:
            logger.warning("[SinkScanner] 没有找到 sink 规则")
            return []

        sites: List[SinkCallSite] = []

        for unit in code_units:
            # 语言过滤
            if lang_set and unit.language not in lang_set:
                continue

            # 对每个规则进行匹配
            unit_matches = self._match_unit(unit, sink_rules)

            for rule, patterns, snippet_info in unit_matches:
                # 生成确定性 ID：基于文件路径 + 行号 + 符号 + 规则ID 的哈希
                # 这确保了相同触发点在多次扫描中有稳定的 ID
                line_start = snippet_info.get("line_start", unit.span.start_line)
                id_content = f"{unit.file_path}:{line_start}:{unit.symbol}:{rule.id}"
                stable_hash = hashlib.md5(id_content.encode()).hexdigest()[:8]
                site_id = f"sink-{stable_hash}"

                site = SinkCallSite(
                    id=site_id,
                    unit_id=unit.id,
                    file_path=unit.file_path,
                    line_start=line_start,
                    line_end=snippet_info.get("line_end", unit.span.end_line),
                    symbol=unit.symbol,
                    matched_rule_ids=[rule.id],
                    call_snippet=snippet_info.get("snippet", ""),
                    sink_category=self._get_sink_category(rule),
                    risk_level=rule.risk_level,
                    matched_patterns=patterns,
                    confidence=snippet_info.get("confidence", 1.0),
                    metadata={
                        "rule_name": rule.name,
                        "rule_description": rule.description,
                        "cwe_ids": rule.cwe_ids,
                    },
                )
                sites.append(site)

        # 合并同一位置的多条规则
        sites = self._merge_sites(sites)

        # BUG #17 Fix: 按 categories 过滤（之前接收了参数但未使用）
        if categories:
            cat_set = set(categories)
            sites = [s for s in sites if s.sink_category.value in cat_set]

        logger.info(f"[SinkScanner] 扫描完成，发现 {len(sites)} 个危险函数触发点")
        return sites

    def _match_unit(
        self,
        unit: CodeUnit,
        rules: List[SecurityRule],
    ) -> List[tuple]:
        """匹配单个代码单元

        Returns:
            List of (rule, matched_patterns, snippet_info) tuples
        """
        matches = []
        code = unit.code
        code_lower = code.lower()
        calls_set = set(unit.calls) if unit.calls else set()
        calls_lower = {c.lower() for c in calls_set}

        for rule in rules:
            matched_patterns = []
            best_snippet_info = {"confidence": 0}

            for pattern in rule.patterns:
                match_result = self._match_pattern(
                    pattern, code, code_lower, calls_set, calls_lower, unit
                )

                if match_result:
                    matched_patterns.append(pattern)
                    # 选择置信度最高的 snippet
                    if match_result.get("confidence", 0) > best_snippet_info.get("confidence", 0):
                        best_snippet_info = match_result

            if matched_patterns:
                # 如果没有找到精确的 snippet，使用整个代码单元
                if not best_snippet_info.get("snippet"):
                    best_snippet_info = {
                        "snippet": self._extract_snippet(code, 0, 5),
                        "line_start": unit.span.start_line,
                        "line_end": min(unit.span.start_line + 5, unit.span.end_line),
                        "confidence": 0.7,
                    }

                matches.append((rule, matched_patterns, best_snippet_info))

        return matches

    def _match_pattern(
        self,
        pattern: str,
        code: str,
        code_lower: str,
        calls_set: Set[str],
        calls_lower: Set[str],
        unit: CodeUnit,
    ) -> Optional[Dict[str, Any]]:
        """匹配单个模式

        Returns:
            匹配结果 dict，包含 snippet, line_start, line_end, confidence
            如果不匹配返回 None
        """
        # 1. 正则匹配
        if pattern.startswith("regex:"):
            regex_pattern = pattern[6:]
            try:
                compiled = self._get_compiled_pattern(regex_pattern)
                match = compiled.search(code)
                if match:
                    return self._extract_match_snippet(code, match, unit)
            except re.error:
                logger.warning(f"无效的正则模式: {regex_pattern}")
            return None

        # 2. 前缀匹配
        if pattern.startswith("prefix:"):
            prefix = pattern[7:]
            # 在 calls 中查找前缀
            for call in calls_set:
                if call.startswith(prefix):
                    return self._find_call_in_code(code, call, unit, confidence=0.9)
            return None

        # 3. 后缀匹配
        if pattern.startswith("suffix:"):
            suffix = pattern[7:]
            for call in calls_set:
                if call.endswith(suffix):
                    return self._find_call_in_code(code, call, unit, confidence=0.9)
            return None

        # 4. 包含匹配（在代码文本中搜索）
        if pattern.startswith("contains:"):
            search_text = pattern[9:]
            if search_text in code:
                return self._find_text_in_code(code, search_text, unit, confidence=0.85)
            return None

        # 5. 精确匹配（优先匹配完整限定名）
        # 先尝试完整限定名匹配
        if pattern in calls_set:
            return self._find_call_in_code(code, pattern, unit, confidence=1.0)

        # 再尝试短名匹配（降低置信度）
        pattern_short = pattern.split(".")[-1] if "." in pattern else pattern
        if pattern_short in calls_set or pattern in calls_lower:
            # 在代码中查找该调用
            return self._find_call_in_code(code, pattern_short, unit, confidence=0.8)

        # 6. 代码文本包含匹配（兜底）
        # 例如规则写 os.system，代码中有 os.system(
        if pattern in code or f"{pattern}(" in code:
            return self._find_text_in_code(code, pattern, unit, confidence=0.95)

        return None

    def _get_compiled_pattern(self, regex_pattern: str) -> re.Pattern:
        """获取编译后的正则表达式（带缓存）"""
        if regex_pattern not in self._compiled_patterns:
            self._compiled_patterns[regex_pattern] = re.compile(regex_pattern, re.IGNORECASE)
        return self._compiled_patterns[regex_pattern]

    def _extract_match_snippet(
        self,
        code: str,
        match: re.Match,
        unit: CodeUnit,
    ) -> Dict[str, Any]:
        """从正则匹配中提取代码片段"""
        lines = code.split("\n")
        match_start = match.start()

        # 找到匹配位置的行号
        line_idx = code[:match_start].count("\n")
        start_idx = max(0, line_idx - 1)
        end_idx = min(len(lines), line_idx + 4)

        snippet = "\n".join(lines[start_idx:end_idx])

        return {
            "snippet": snippet,
            "line_start": unit.span.start_line + start_idx,
            "line_end": unit.span.start_line + end_idx - 1,
            "confidence": 1.0,
        }

    def _find_call_in_code(
        self,
        code: str,
        call_name: str,
        unit: CodeUnit,
        confidence: float = 1.0,
    ) -> Optional[Dict[str, Any]]:
        """在代码中查找函数调用的位置"""
        # 构建匹配模式：call_name 后面跟 (
        # 处理可能的点号
        escaped_name = re.escape(call_name)
        pattern = rf'(?:^|[^\w.]){escaped_name}\s*\('

        try:
            match = re.search(pattern, code, re.MULTILINE)
            if match:
                return self._extract_match_snippet(code, match, unit)
        except re.error:
            pass

        # 简单查找
        if call_name + "(" in code:
            return self._find_text_in_code(code, call_name + "(", unit, confidence)

        return {"snippet": "", "confidence": confidence * 0.5}

    def _find_text_in_code(
        self,
        code: str,
        text: str,
        unit: CodeUnit,
        confidence: float = 1.0,
    ) -> Dict[str, Any]:
        """在代码中查找文本的位置"""
        lines = code.split("\n")
        for i, line in enumerate(lines):
            if text in line:
                start_idx = max(0, i - 1)
                end_idx = min(len(lines), i + 4)
                snippet = "\n".join(lines[start_idx:end_idx])

                return {
                    "snippet": snippet,
                    "line_start": unit.span.start_line + start_idx,
                    "line_end": unit.span.start_line + end_idx - 1,
                    "confidence": confidence,
                }

        return {
            "snippet": self._extract_snippet(code, 0, 5),
            "line_start": unit.span.start_line,
            "line_end": min(unit.span.start_line + 5, unit.span.end_line),
            "confidence": confidence * 0.5,
        }

    def _extract_snippet(self, code: str, start_line: int, max_lines: int) -> str:
        """提取代码片段"""
        lines = code.split("\n")
        end_line = min(start_line + max_lines, len(lines))
        return "\n".join(lines[start_line:end_line])

    def _get_sink_category(self, rule: SecurityRule) -> SinkCategory:
        """根据规则推断 Sink 类别"""
        # 根据规则 ID 推断
        rule_id_lower = rule.id.lower()

        if any(kw in rule_id_lower for kw in ["command", "rce", "exec"]):
            return SinkCategory.COMMAND_EXEC
        if any(kw in rule_id_lower for kw in ["sql", "query"]):
            return SinkCategory.SQL_INJECTION
        if any(kw in rule_id_lower for kw in ["file", "path", "read", "write"]):
            if "write" in rule_id_lower or "put" in rule_id_lower:
                return SinkCategory.FILE_WRITE
            return SinkCategory.FILE_READ
        if any(kw in rule_id_lower for kw in ["deserial", "pickle", "unserialize"]):
            return SinkCategory.DESERIALIZATION
        if any(kw in rule_id_lower for kw in ["ssrf", "curl", "request"]):
            return SinkCategory.SSRF
        if any(kw in rule_id_lower for kw in ["xss", "html", "script"]):
            return SinkCategory.XSS
        if any(kw in rule_id_lower for kw in ["eval", "code"]):
            return SinkCategory.CODE_EXEC

        # 根据规则类别推断
        category_value = rule.category.value if hasattr(rule.category, 'value') else str(rule.category)
        return self.CATEGORY_MAP.get(category_value.lower(), SinkCategory.OTHER)

    def _merge_sites(self, sites: List[SinkCallSite]) -> List[SinkCallSite]:
        """合并同一位置的多条规则"""
        if not sites:
            return sites

        # 按位置分组
        grouped: Dict[str, SinkCallSite] = {}

        for site in sites:
            key = f"{site.unit_id}:{site.line_start}"

            if key not in grouped:
                grouped[key] = site
            else:
                # 合并规则和模式
                existing = grouped[key]
                existing.matched_rule_ids.extend(site.matched_rule_ids)
                existing.matched_patterns.extend(site.matched_patterns)

                # 使用更高的风险等级
                risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
                if risk_order.index(site.risk_level) > risk_order.index(existing.risk_level):
                    existing.risk_level = site.risk_level

                # 使用更高的置信度
                existing.confidence = max(existing.confidence, site.confidence)

        # 去重规则和模式，并为合并后的站点生成确定性 ID
        result = []
        for site in grouped.values():
            site.matched_rule_ids = list(set(site.matched_rule_ids))
            site.matched_patterns = list(set(site.matched_patterns))

            # 重新生成确定性 ID：基于文件路径 + 行号 + 符号（不包含规则ID，因为已合并）
            id_content = f"{site.file_path}:{site.line_start}:{site.symbol}"
            stable_hash = hashlib.md5(id_content.encode()).hexdigest()[:8]
            site.id = f"sink-{stable_hash}"
            result.append(site)

        return result

    def get_statistics(self, sites: List[SinkCallSite]) -> Dict[str, Any]:
        """获取扫描统计信息"""
        if not sites:
            return {
                "total": 0,
                "by_category": {},
                "by_risk": {},
                "by_file": {},
            }

        by_category: Dict[str, int] = {}
        by_risk: Dict[str, int] = {}
        by_file: Dict[str, int] = {}

        for site in sites:
            # 按类别统计
            cat = site.sink_category.value
            by_category[cat] = by_category.get(cat, 0) + 1

            # 按风险统计
            risk = site.risk_level.value
            by_risk[risk] = by_risk.get(risk, 0) + 1

            # 按文件统计
            by_file[site.file_path] = by_file.get(site.file_path, 0) + 1

        return {
            "total": len(sites),
            "by_category": by_category,
            "by_risk": by_risk,
            "by_file": by_file,
        }
