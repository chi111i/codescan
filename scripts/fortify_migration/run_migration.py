"""Fortify 规则转换主脚本

执行完整的 XML → YAML 转换流程。
"""

import sys
import io
import json
import logging
from pathlib import Path
from typing import List

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 添加项目根目录
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from scripts.fortify_migration import FortifyRule, ConversionResult, ConversionStats
from scripts.fortify_migration.xml_parser import FortifyXMLParser
from scripts.fortify_migration.predicate_converter import PredicateConverter
from scripts.fortify_migration.yaml_generator import YAMLRuleGenerator
from scripts.fortify_migration.category_mapper import is_sink_category

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class FortifyMigrationPipeline:
    """Fortify 转换流水线"""

    def __init__(self, source_dir: Path, output_dir: Path):
        self.source_dir = source_dir
        self.output_dir = output_dir
        self.xml_parser = FortifyXMLParser()
        self.predicate_converter = PredicateConverter()
        self.yaml_generator = YAMLRuleGenerator()
        self.stats = ConversionStats()

    def run(self, target_languages: List[str] = None, limit_per_file: int = None):
        """执行转换

        Args:
            target_languages: 目标语言列表（如 ['python', 'javascript', 'php']）
            limit_per_file: 每个文件限制转换的规则数（用于测试）
        """
        if target_languages is None:
            target_languages = ['python', 'javascript', 'php']

        logger.info("=" * 60)
        logger.info("Fortify Rules 转换流水线")
        logger.info("=" * 60)

        all_results = []

        for lang in target_languages:
            logger.info(f"\n处理语言: {lang}")

            # 找到对应的 XML 文件
            xml_file = self.source_dir / f"core_{lang}.xml"
            if not xml_file.exists():
                logger.warning(f"  文件不存在: {xml_file.name}")
                continue

            # 解析 XML
            logger.info(f"  解析: {xml_file.name}")
            fortify_rules = self.xml_parser.parse_file(str(xml_file))
            logger.info(f"  提取 {len(fortify_rules)} 条规则")

            # 限制数量（用于测试）
            if limit_per_file:
                fortify_rules = fortify_rules[:limit_per_file]
                logger.info(f"  限制为前 {limit_per_file} 条（测试模式）")

            # 转换规则
            lang_results = []
            for rule in fortify_rules:
                result = self._convert_rule(rule)
                lang_results.append(result)
                self.stats.add_result(result)

            # 生成 YAML
            successful_rules = [
                self.yaml_generator.generate_rule(r)
                for r in lang_results
                if r.success
            ]

            if successful_rules:
                # 按类别组织
                organized = self.yaml_generator.organize_by_category(successful_rules)

                for key, rules in organized.items():
                    output_file = self.output_dir / f"{lang}_{key}.yaml"
                    self.yaml_generator.write_yaml(rules, str(output_file))
                    logger.info(f"  生成: {output_file.name} ({len(rules)} 条)")

            all_results.extend(lang_results)

        # 输出统计
        self._print_stats()

        # 保存转换日志
        self._save_conversion_log(all_results)

    def _convert_rule(self, rule: FortifyRule) -> ConversionResult:
        """转换单条规则

        Args:
            rule: Fortify 规则

        Returns:
            转换结果
        """
        # 转换 Predicate
        patterns, method, confidence = self.predicate_converter.convert(rule.predicate)

        # 过滤掉包含占位符的patterns
        if patterns:
            patterns = [p for p in patterns if 'PUT_REGEX_HERE' not in p]
            if not patterns:
                patterns = None

        if patterns:
            return ConversionResult(
                success=True,
                fortify_rule=rule,
                patterns=patterns,
                conversion_method=method,
                confidence=confidence,
            )
        else:
            # 转换失败,尝试提取函数名作为后备
            fallback_patterns = self.predicate_converter.extract_function_names(rule.predicate)

            # 过滤掉占位符
            fallback_patterns = [p for p in fallback_patterns if 'PUT_REGEX_HERE' not in p and p != 'PUT_REGEX_HERE']

            if fallback_patterns and is_sink_category(rule.vuln_category):
                # 对于 sink 类型,使用提取的函数名
                return ConversionResult(
                    success=True,
                    fortify_rule=rule,
                    patterns=fallback_patterns,
                    conversion_method='fallback',
                    confidence=0.5,
                )
            else:
                return ConversionResult(
                    success=False,
                    fortify_rule=rule,
                    conversion_method='failed',
                    confidence=0.0,
                    error_message='无法转换 Predicate'
                )

    def _print_stats(self):
        """打印统计信息"""
        logger.info("\n" + "=" * 60)
        logger.info("转换统计")
        logger.info("=" * 60)

        stats_dict = self.stats.to_dict()

        logger.info(f"总规则数: {stats_dict['total_rules']}")
        logger.info(f"成功转换: {stats_dict['successful']}")
        logger.info(f"转换失败: {stats_dict['failed']}")
        logger.info(f"成功率: {stats_dict['success_rate']}")

        logger.info(f"\n按转换方法:")
        for method, count in stats_dict['by_method'].items():
            logger.info(f"  {method}: {count}")

        logger.info(f"\n按语言:")
        for lang, count in stats_dict['by_language'].items():
            logger.info(f"  {lang}: {count}")

        logger.info(f"\nTop 10 漏洞类别:")
        sorted_cats = sorted(
            stats_dict['by_category'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        for cat, count in sorted_cats:
            logger.info(f"  {cat}: {count}")

    def _save_conversion_log(self, results: List[ConversionResult]):
        """保存转换日志

        Args:
            results: 转换结果列表
        """
        log_dir = project_root / ".fortify_migration"
        log_dir.mkdir(exist_ok=True)

        # 保存详细日志
        log_file = log_dir / "conversion_log.json"
        log_data = []

        for result in results:
            log_data.append({
                'rule_id': result.fortify_rule.rule_id,
                'language': result.fortify_rule.language,
                'category': result.fortify_rule.vuln_category,
                'success': result.success,
                'patterns': result.patterns,
                'method': result.conversion_method,
                'confidence': result.confidence,
                'error': result.error_message,
            })

        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False)

        logger.info(f"\n转换日志已保存: {log_file}")

        # 保存失败的规则
        failed_rules = [r for r in results if not r.success]
        if failed_rules:
            failed_file = log_dir / "failed_rules.json"
            failed_data = []

            for result in failed_rules:
                failed_data.append({
                    'rule_id': result.fortify_rule.rule_id,
                    'language': result.fortify_rule.language,
                    'category': result.fortify_rule.vuln_category,
                    'predicate': result.fortify_rule.predicate[:200],
                    'error': result.error_message,
                })

            with open(failed_file, 'w', encoding='utf-8') as f:
                json.dump(failed_data, f, indent=2, ensure_ascii=False)

            logger.info(f"失败规则日志: {failed_file}")


def main():
    """主函数"""
    # 配置路径
    source_dir = Path("E:/1ceshi/codescan/参考项目/rules")
    output_dir = project_root / "rules" / "data" / "extended"

    # 创建流水线
    pipeline = FortifyMigrationPipeline(source_dir, output_dir)

    # 执行全量转换（Python + JavaScript + PHP）
    logger.info("执行全量转换（Python/JavaScript/PHP）\n")
    pipeline.run(
        target_languages=['python', 'javascript', 'php'],
        limit_per_file=None  # 全量转换
    )

    logger.info("\n" + "=" * 60)
    logger.info("✅ 转换完成")
    logger.info("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"转换失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
