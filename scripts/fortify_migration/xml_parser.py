"""Fortify XML 规则解析器

解析 Fortify XML 格式的安全规则文件。
"""

import re
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any
from lxml import etree

from . import FortifyRule

logger = logging.getLogger(__name__)


class FortifyXMLParser:
    """Fortify XML 规则解析器"""

    def __init__(self):
        self.namespace = {
            'f': 'xmlns://www.fortifysoftware.com/schema/rules'
        }

    def parse_file(self, xml_path: str) -> List[FortifyRule]:
        """解析单个 XML 文件

        Args:
            xml_path: XML 文件路径

        Returns:
            FortifyRule 列表
        """
        xml_path = Path(xml_path)
        if not xml_path.exists():
            raise FileNotFoundError(f"XML 文件不存在: {xml_path}")

        logger.info(f"开始解析: {xml_path.name}")

        try:
            # 使用宽松模式解析 XML
            parser = etree.XMLParser(recover=True, huge_tree=True)
            tree = etree.parse(str(xml_path), parser)
            root = tree.getroot()

            rules = []

            # 解析所有规则定义
            for rule_def in root.xpath('.//f:RuleDefinitions/*', namespaces=self.namespace):
                try:
                    rule = self._parse_rule(rule_def)
                    if rule:
                        rules.append(rule)
                except Exception as e:
                    logger.warning(f"解析单条规则失败: {e}")
                    continue

            logger.info(f"解析完成: {len(rules)} 条规则")
            return rules

        except Exception as e:
            logger.error(f"解析文件失败 {xml_path}: {e}")
            raise

    def _parse_rule(self, rule_elem) -> Optional[FortifyRule]:
        """解析单条规则

        Args:
            rule_elem: XML 规则元素

        Returns:
            FortifyRule 对象
        """
        rule_type = rule_elem.tag.split('}')[-1]  # 去除命名空间
        language = rule_elem.get('language', '')

        # 提取基础字段
        rule_id = self._get_text(rule_elem, './/f:RuleID')
        if not rule_id:
            return None

        # 提取 MetaInfo (需要在前面,因为Dataflow规则从metadata提取分类)
        metadata = self._extract_metadata(rule_elem)

        # 提取分类 (支持两种方式)
        vuln_kingdom = self._get_text(rule_elem, './/f:VulnKingdom', default='')
        vuln_category = self._get_text(rule_elem, './/f:VulnCategory', default='')
        vuln_subcategory = self._get_text(rule_elem, './/f:VulnSubcategory')

        # 如果没有VulnCategory,从altcategory提取 (Dataflow规则)
        if not vuln_category:
            vuln_category = self._extract_category_from_altcategory(metadata, rule_type)

        severity_text = self._get_text(rule_elem, './/f:DefaultSeverity', default='0.0')
        try:
            default_severity = float(severity_text)
        except ValueError:
            default_severity = 0.0

        # 提取 Predicate 或 FunctionIdentifier
        predicate = self._get_text(rule_elem, './/f:Predicate', default='')

        # 如果没有Predicate,尝试从FunctionIdentifier提取 (Dataflow规则)
        if not predicate:
            predicate = self._extract_function_identifier(rule_elem)

        # 提取 CWE/OWASP
        cwe_ids = self._extract_cwe_ids(metadata)
        owasp_ids = self._extract_owasp_ids(metadata)

        # 提取评分
        impact = self._get_metadata_float(metadata, 'Impact')
        accuracy = self._get_metadata_float(metadata, 'Accuracy')
        probability = self._get_metadata_float(metadata, 'Probability')

        return FortifyRule(
            rule_id=rule_id,
            rule_type=rule_type,
            language=language,
            vuln_kingdom=vuln_kingdom,
            vuln_category=vuln_category,
            vuln_subcategory=vuln_subcategory,
            default_severity=default_severity,
            predicate=predicate,
            metadata=metadata,
            impact=impact,
            accuracy=accuracy,
            probability=probability,
            cwe_ids=cwe_ids,
            owasp_ids=owasp_ids,
        )

    def _extract_metadata(self, rule_elem) -> Dict[str, str]:
        """提取 MetaInfo Groups

        Args:
            rule_elem: 规则元素

        Returns:
            metadata 字典
        """
        metadata = {}
        for group in rule_elem.xpath('.//f:MetaInfo/f:Group', namespaces=self.namespace):
            name = group.get('name')
            value = group.text or ''
            if name:
                metadata[name] = value.strip()
        return metadata

    def _extract_category_from_altcategory(self, metadata: Dict[str, str], rule_type: str) -> str:
        """从 altcategory 提取分类 (用于Dataflow规则)

        Args:
            metadata: metadata 字典
            rule_type: 规则类型

        Returns:
            分类名称
        """
        # 优先级: GDPR > OWASP2021 > CWE
        for key in ['altcategoryGDPR', 'altcategoryOWASP2021', 'altcategoryCWE']:
            value = metadata.get(key, '').strip()
            if value and value.lower() != 'none':
                # 提取主要类别名
                # 例如: "Privacy Violation" 或 "A02 Cryptographic Failures"
                if key == 'altcategoryOWASP2021':
                    # 提取 "A02 xxx" 中的 xxx 部分
                    match = re.search(r'A\d{2}\s+(.+)', value)
                    if match:
                        return match.group(1)
                else:
                    return value

        return ''

    def _extract_function_identifier(self, rule_elem) -> str:
        """从 FunctionIdentifier 提取函数模式 (用于Dataflow规则)

        Args:
            rule_elem: 规则元素

        Returns:
            函数标识符字符串 (用于后续转换为pattern)
        """
        parts = []

        # 提取 NamespaceName
        namespace = self._get_text(rule_elem, './/f:FunctionIdentifier/f:NamespaceName/f:Value')
        if namespace:
            parts.append(f"namespace:{namespace}")

        # 提取 ClassName
        classname = self._get_text(rule_elem, './/f:FunctionIdentifier/f:ClassName/f:Value')
        if classname:
            parts.append(f"class:{classname}")

        # 提取 FunctionName (可能是Pattern或Value)
        func_pattern = self._get_text(rule_elem, './/f:FunctionIdentifier/f:FunctionName/f:Pattern')
        func_value = self._get_text(rule_elem, './/f:FunctionIdentifier/f:FunctionName/f:Value')

        if func_pattern:
            parts.append(f"function_pattern:{func_pattern}")
        elif func_value:
            parts.append(f"function:{func_value}")

        # 组合为伪Predicate字符串
        if parts:
            return " AND ".join(parts)

        return ''


    def _extract_cwe_ids(self, metadata: Dict[str, str]) -> List[str]:
        """从 metadata 提取 CWE ID

        Args:
            metadata: metadata 字典

        Returns:
            CWE ID 列表
        """
        cwe_ids = []

        # 查找所有包含 CWE 的 key
        for key, value in metadata.items():
            if 'CWE' in key.upper():
                # 提取 CWE-XXX 或 CWE ID XXX
                matches = re.findall(r'CWE[\s-]*(ID\s+)?(\d+)', value, re.IGNORECASE)
                for match in matches:
                    cwe_id = f"CWE-{match[1]}"
                    if cwe_id not in cwe_ids:
                        cwe_ids.append(cwe_id)

        return cwe_ids

    def _extract_owasp_ids(self, metadata: Dict[str, str]) -> List[str]:
        """从 metadata 提取 OWASP 分类

        Args:
            metadata: metadata 字典

        Returns:
            OWASP ID 列表
        """
        owasp_ids = []

        # 查找 OWASP2021
        for key, value in metadata.items():
            if 'OWASP2021' in key or 'OWASP 2021' in key:
                # 提取 A01, A02 等
                matches = re.findall(r'A(\d{2})', value)
                for match in matches:
                    owasp_id = f"A{match}:2021"
                    if owasp_id not in owasp_ids:
                        owasp_ids.append(owasp_id)

        return owasp_ids

    def _get_metadata_float(self, metadata: Dict[str, str], key: str) -> Optional[float]:
        """从 metadata 获取浮点数值

        Args:
            metadata: metadata 字典
            key: 键名

        Returns:
            浮点数值或 None
        """
        value = metadata.get(key, '')
        if value:
            try:
                return float(value)
            except ValueError:
                pass
        return None

    def _get_text(self, elem, xpath: str, default: Optional[str] = None) -> Optional[str]:
        """获取 XML 元素文本

        Args:
            elem: XML 元素
            xpath: XPath 表达式
            default: 默认值

        Returns:
            文本内容
        """
        result = elem.xpath(xpath, namespaces=self.namespace)
        if result and len(result) > 0:
            text = result[0].text
            return text.strip() if text else default
        return default

    def calculate_risk_level(self, rule: FortifyRule) -> str:
        """根据 severity 和 impact 计算风险等级

        Args:
            rule: FortifyRule 对象

        Returns:
            'critical'/'high'/'medium'/'low'
        """
        severity = rule.default_severity
        impact = rule.impact or 0.0

        # 计算综合评分
        score = max(severity, impact)

        if score >= 4.5:
            return 'critical'
        elif score >= 3.5:
            return 'high'
        elif score >= 2.0:
            return 'medium'
        else:
            return 'low'


def parse_fortify_xml(xml_path: str) -> List[FortifyRule]:
    """便捷函数：解析 Fortify XML 文件

    Args:
        xml_path: XML 文件路径

    Returns:
        FortifyRule 列表
    """
    parser = FortifyXMLParser()
    return parser.parse_file(xml_path)
