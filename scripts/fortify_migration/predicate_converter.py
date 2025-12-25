"""Predicate 转换引擎

将 Fortify 的 Predicate 查询语言转换为 CodeScan patterns。
"""

import re
import logging
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


class PredicateConverter:
    """Predicate 转换器

    分级转换策略：
    - Level 1: 直接转换（简单函数调用）
    - Level 2: 启发式转换（模式匹配）
    - Level 3: 失败（需要 LLM 或人工）
    """

    def __init__(self):
        # Level 0: FunctionIdentifier 格式 (Dataflow规则)
        self.function_identifier_patterns = [
            # namespace:xxx AND function:yyy
            (r'namespace:([^\s]+)\s+AND\s+function:([^\s]+)', lambda m: [f"{m.group(1)}.{m.group(2)}"]),

            # class:xxx AND function:yyy
            (r'class:([^\s]+)\s+AND\s+function:([^\s]+)', lambda m: [f"{m.group(1)}.{m.group(2)}"]),

            # namespace:xxx AND class:yyy AND function:zzz
            (r'namespace:([^\s]+)\s+AND\s+class:([^\s]+)\s+AND\s+function:([^\s]+)',
             lambda m: [f"{m.group(1)}.{m.group(2)}.{m.group(3)}"]),

            # function_pattern:xxx (正则模式)
            (r'function_pattern:([^\s]+)', lambda m: [f"regex:{m.group(1)}"]),

            # 单独的 function:xxx
            (r'function:([^\s]+)', lambda m: [m.group(1)]),
        ]

        # Level 1: 直接转换模式
        self.direct_patterns = [
            # FunctionCall fc: fc.name == "eval"
            (r'FunctionCall\s+fc:\s+fc\.name\s+==\s+"(\w+)"', lambda m: [m.group(1)]),

            # FunctionPointerCall fpc: fpc.name == "system"
            (r'FunctionPointerCall\s+fpc:\s+fpc\.name\s+==\s+"(\w+)"', lambda m: [m.group(1)]),

            # MethodCall mc: mc.name == "execute"
            (r'MethodCall\s+mc:\s+mc\.name\s+==\s+"(\w+)"', lambda m: [m.group(1)]),

            # function is [Function: name == "xxx"]
            (r'function\s+is\s+\[Function:\s+name\s+==\s+"(\w+)"', lambda m: [m.group(1)]),
        ]

        # Level 2: 带模块的调用
        self.module_patterns = [
            # instance is [FieldAccess: name == "os~module"] ... fc.name == "system"
            (
                r'instance\s+is\s+\[FieldAccess:\s+name\s+==\s+"(\w+)~module"\].*?(?:fc|fpc|mc)\.name\s+==\s+"(\w+)"',
                lambda m: [f"{m.group(1)}.{m.group(2)}"]
            ),

            # enclosingClass.name == "os" ... mc.name == "system"
            (
                r'enclosingClass\.name\s+==\s+"(\w+)".*?(?:fc|fpc|mc)\.name\s+==\s+"(\w+)"',
                lambda m: [f"{m.group(1)}.{m.group(2)}"]
            ),

            # 嵌套 FieldAccess: instance is [FieldAccess: instance is [FieldAccess: name == "module"]]
            (
                r'instance\s+is\s+\[FieldAccess:\s+instance\s+is\s+\[FieldAccess:\s+name\s+==\s+"([^"~]+)~module".*?name\s+==\s+"(\w+)"',
                lambda m: [f"{m.group(1)}.{m.group(2)}"]
            ),
        ]

        # Level 2: 正则匹配
        self.regex_patterns = [
            # fc.name matches "exec.*"
            (r'(?:fc|fpc|mc)\.name\s+matches\s+"([^"]+)"', lambda m: [f"regex:{m.group(1)}"]),
        ]

        # Level 2: 字符串常量匹配
        self.string_patterns = [
            # StringLiteral: constantValue matches ".*password.*"
            (
                r'StringLiteral:.*?constantValue\s+matches\s+"[^"]*?(\w{4,})[^"]*"',
                lambda m: [f"contains:{m.group(1)}"]
            ),

            # StringLiteral: contains "password"
            (
                r'StringLiteral:.*?contains\s+"(\w+)"',
                lambda m: [f"contains:{m.group(1)}"]
            ),

            # 忽略 PUT_REGEX_HERE 占位符
            (
                r'PUT_REGEX_HERE',
                lambda m: None
            ),
        ]

        # Level 2: possibleTargets 模式
        self.target_patterns = [
            # possibleTargets contains [Function f: name == "xxx"]
            (
                r'possibleTargets\s+contains\s+\[Function\s+\w+:\s+name\s+==\s+"([\w~]+)"',
                lambda m: [m.group(1).replace('~', '.')]
            ),

            # possibleTargets contains [Function f: name matches "xxx"]
            (
                r'possibleTargets\s+contains\s+\[Function\s+\w+:\s+name\s+matches\s+"([^"]+)"',
                lambda m: [f"regex:{m.group(1)}"]
            ),
        ]

        # Level 2: FieldAccess/VariableAccess 模式
        self.access_patterns = [
            # FieldAccess fa: fa.field.name == "xxx"
            (
                r'FieldAccess\s+\w+:\s+\w+\.field\.name\s+==\s+"(\w+)"',
                lambda m: [f"field:{m.group(1)}"]
            ),

            # FieldAccess fa: fa.field.name matches "xxx"
            (
                r'FieldAccess\s+\w+:\s+\w+\.field\.name\s+matches\s+"([^"]+)"',
                lambda m: [f"regex:{m.group(1)}"]
            ),

            # VariableAccess va: va.variable.name matches "xxx"
            (
                r'VariableAccess\s+\w+:\s+\w+\.variable\.name\s+matches\s+"([^"]+)"',
                lambda m: [f"regex:{m.group(1)}"]
            ),
        ]

    def convert(self, predicate: str) -> Tuple[Optional[List[str]], str, float]:
        """转换 Predicate 为 patterns

        Args:
            predicate: Fortify Predicate 查询

        Returns:
            (patterns, method, confidence)
            - patterns: 转换后的 patterns 列表,None 表示失败
            - method: 'direct' / 'heuristic' / 'failed'
            - confidence: 置信度 0.0-1.0
        """
        if not predicate or not predicate.strip():
            return None, 'failed', 0.0

        # 移除多余空白
        predicate = ' '.join(predicate.split())

        # Level 0: FunctionIdentifier 格式 (Dataflow规则,最高优先级)
        for pattern, converter in self.function_identifier_patterns:
            match = re.search(pattern, predicate, re.IGNORECASE | re.DOTALL)
            if match:
                patterns = converter(match)
                return patterns, 'direct', 1.0

        # Level 1: 直接转换
        for pattern, converter in self.direct_patterns:
            match = re.search(pattern, predicate, re.IGNORECASE | re.DOTALL)
            if match:
                patterns = converter(match)
                return patterns, 'direct', 1.0

        # Level 2: 模块调用
        for pattern, converter in self.module_patterns:
            match = re.search(pattern, predicate, re.IGNORECASE | re.DOTALL)
            if match:
                patterns = converter(match)
                return patterns, 'heuristic', 0.85

        # Level 2: 正则匹配
        for pattern, converter in self.regex_patterns:
            match = re.search(pattern, predicate, re.IGNORECASE | re.DOTALL)
            if match:
                patterns = converter(match)
                return patterns, 'heuristic', 0.8

        # Level 2: 字符串常量
        for pattern, converter in self.string_patterns:
            match = re.search(pattern, predicate, re.IGNORECASE | re.DOTALL)
            if match:
                patterns = converter(match)
                # 跳过 None (占位符)
                if patterns is None:
                    continue
                return patterns, 'heuristic', 0.7

        # Level 2: possibleTargets
        for pattern, converter in self.target_patterns:
            match = re.search(pattern, predicate, re.IGNORECASE | re.DOTALL)
            if match:
                patterns = converter(match)
                if patterns is None:
                    continue
                return patterns, 'heuristic', 0.75

        # Level 2: FieldAccess/VariableAccess
        for pattern, converter in self.access_patterns:
            match = re.search(pattern, predicate, re.IGNORECASE | re.DOTALL)
            if match:
                patterns = converter(match)
                if patterns is None:
                    continue
                return patterns, 'heuristic', 0.7

        # Level 3: 转换失败
        return None, 'failed', 0.0

    def extract_function_names(self, predicate: str) -> List[str]:
        """从 Predicate 提取所有函数名（作为后备）

        Args:
            predicate: Predicate 查询

        Returns:
            函数名列表
        """
        functions = []

        # 提取所有带引号的标识符
        matches = re.findall(r'["\'](\w+)["\']', predicate)
        for match in matches:
            # 过滤掉一些明显不是函数名的
            if match not in ['module', 'name', 'class', 'true', 'false', 'and', 'or']:
                if match not in functions:
                    functions.append(match)

        return functions


def convert_predicate(predicate: str) -> Tuple[Optional[List[str]], str, float]:
    """便捷函数：转换 Predicate

    Args:
        predicate: Fortify Predicate

    Returns:
        (patterns, method, confidence)
    """
    converter = PredicateConverter()
    return converter.convert(predicate)
