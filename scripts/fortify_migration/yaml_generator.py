"""YAML 规则生成器

将转换后的 Fortify 规则生成 CodeScan YAML 格式。
"""

import yaml
import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from . import FortifyRule, ConversionResult
from .category_mapper import map_category
from .xml_parser import FortifyXMLParser

logger = logging.getLogger(__name__)


class YAMLRuleGenerator:
    """YAML 规则生成器"""

    def __init__(self):
        self.xml_parser = FortifyXMLParser()

    def generate_rule(self, result: ConversionResult) -> Dict[str, Any]:
        """生成单条 CodeScan 规则

        Args:
            result: 转换结果

        Returns:
            CodeScan 规则字典
        """
        rule = result.fortify_rule
        category, rule_type = map_category(rule.vuln_category)
        risk_level = self.xml_parser.calculate_risk_level(rule)

        # 生成规则 ID（使用原始 rule_id 的哈希值）
        import hashlib
        id_hash = hashlib.md5(rule.rule_id.encode()).hexdigest()[:8]
        rule_id = f"{rule.language}-{category}-{id_hash}"

        # 生成规则名称
        name = self._generate_name(rule)

        # 生成描述
        description = self._generate_description(rule)

        codescan_rule = {
            'id': rule_id,
            'name': name,
            'rule_type': rule_type,
            'category': category,
            'risk_level': risk_level,
            'languages': [rule.language],
            'patterns': result.patterns or [],
            'description': description,
            'cwe_ids': rule.cwe_ids,
            'owasp_ids': rule.owasp_ids,
            'tags': self._generate_tags(rule),
            'metadata': {
                'source_rule_id': rule.rule_id,
                'source_category': rule.vuln_category,
                'source_severity': rule.default_severity,
                'conversion_method': result.conversion_method,
                'conversion_confidence': result.confidence,
            }
        }

        return codescan_rule

    def _generate_name(self, rule: FortifyRule) -> str:
        """生成规则名称

        Args:
            rule: Fortify 规则

        Returns:
            规则名称
        """
        category = rule.vuln_category
        subcategory = rule.vuln_subcategory

        if subcategory:
            return f"{category}: {subcategory}"
        else:
            return category

    def _generate_description(self, rule: FortifyRule) -> str:
        """生成规则描述

        Args:
            rule: Fortify 规则

        Returns:
            描述文本
        """
        parts = []

        # 类别描述
        parts.append(f"检测 {rule.vuln_category} 相关的安全风险")

        # 子类别
        if rule.vuln_subcategory:
            parts.append(f"（{rule.vuln_subcategory}）")

        return ''.join(parts)

    def _generate_tags(self, rule: FortifyRule) -> List[str]:
        """生成标签

        Args:
            rule: Fortify 规则

        Returns:
            标签列表
        """
        tags = []

        # 添加类别标签
        category = rule.vuln_category.lower().replace(' ', '_')
        tags.append(category)

        # 添加语言标签
        tags.append(rule.language)

        return tags

    def write_yaml(self, rules: List[Dict[str, Any]], output_path: str):
        """写入 YAML 文件

        Args:
            rules: 规则列表
            output_path: 输出文件路径
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # 构建 YAML 结构
        yaml_data = {
            'rules': rules,
            '_metadata': {
                'source': 'Enterprise Security Rules',
                'converted_at': datetime.now().isoformat(),
                'total_rules': len(rules),
            }
        }

        # 写入文件
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(
                yaml_data,
                f,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
                width=120,
            )

        logger.info(f"写入 {len(rules)} 条规则到: {output_path}")

    def organize_by_category(
        self,
        rules: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """按类别和类型组织规则

        Args:
            rules: 规则列表

        Returns:
            {category_type: rules} 字典
        """
        organized = {}

        for rule in rules:
            category = rule['category']
            rule_type = rule['rule_type']
            key = f"{category}_{rule_type}"

            if key not in organized:
                organized[key] = []

            organized[key].append(rule)

        return organized
