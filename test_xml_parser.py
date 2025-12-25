"""测试 Fortify XML 解析器"""

import sys
import io
from pathlib import Path

# UTF-8 编码设置
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 添加项目根目录
# 本脚本位于仓库根目录下，因此直接使用当前文件所在目录作为项目根目录。
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

from scripts.fortify_migration.xml_parser import FortifyXMLParser

def test_parse_python_rules():
    """测试解析 Python 规则"""
    print("=" * 60)
    print("测试：解析 core_python.xml（前 100 条规则）")
    print("=" * 60)

    # 兼容不同平台/路径：优先使用仓库内的参考文件
    candidates = [
        project_root / "参考项目" / "rules" / "core_python.xml",
        project_root / "#U53c2#U8003#U9879#U76ee" / "rules" / "core_python.xml",
    ]

    xml_path = None
    for p in candidates:
        if p.exists():
            xml_path = p
            break

    if xml_path is None:
        # 仍然允许用户手动指定绝对路径（仅作为最后兜底）
        xml_path = Path("E:/1ceshi/codescan/参考项目/rules/core_python.xml")

    if not xml_path.exists():
        print(f"❌ 文件不存在: {xml_path}")
        return

    parser = FortifyXMLParser()

    try:
        # 解析文件（为了快速测试，只处理前面部分）
        rules = parser.parse_file(str(xml_path))

        print(f"\n✓ 成功解析 {len(rules)} 条规则")

        # 统计信息
        categories = {}
        languages = {}
        severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for rule in rules[:100]:  # 只分析前 100 条
            cat = rule.vuln_category
            categories[cat] = categories.get(cat, 0) + 1

            lang = rule.language
            languages[lang] = languages.get(lang, 0) + 1

            risk = parser.calculate_risk_level(rule)
            severities[risk] += 1

        print(f"\n前 100 条规则统计:")
        print(f"  语言分布: {languages}")
        print(f"  风险等级: {severities}")

        print(f"\n  Top 10 漏洞类别:")
        sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:10]
        for cat, count in sorted_cats:
            print(f"    - {cat}: {count}")

        # 展示几条示例
        print(f"\n示例规则 1:")
        r = rules[0]
        print(f"  ID: {r.rule_id[:16]}...")
        print(f"  类型: {r.rule_type}")
        print(f"  语言: {r.language}")
        print(f"  类别: {r.vuln_category}")
        print(f"  风险: {parser.calculate_risk_level(r)}")
        print(f"  CWE: {r.cwe_ids}")
        print(f"  OWASP: {r.owasp_ids}")
        print(f"  Predicate: {r.predicate[:100]}...")

        print("\n" + "=" * 60)
        print("✅ XML 解析器测试通过")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ 解析失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    test_parse_python_rules()
