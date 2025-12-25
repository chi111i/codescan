# Fortify Rules 转换与集成实施规划

## 一、项目概述

### 1.1 目标
将 Fortify 的 13,000+ 条企业级安全规则转换为 CodeScan 可用的 YAML 格式规则,大幅提升规则覆盖率和检测能力。

### 1.2 源系统特征

**文件结构:**
- 总行数: ~3,786,203 行 XML
- 文件数: 36 个 XML 文件
- 目标语言文件:
  - `core_python.xml`: 198,149 行
  - `core_javascript.xml`: 104,261 行
  - `core_php.xml`: 197,307 行
  - `extended_java.xml`: 788,003 行 (暂不处理)

**XML 规则结构:**
```xml
<StructuralRule formatVersion="23.1" language="python">
  <RuleID>UUID</RuleID>
  <MetaInfo>
    <Group name="package">Python Core</Group>
    <Group name="Impact">4.0</Group>
    <Group name="Accuracy">3.0</Group>
    <Group name="Probability">4.0</Group>
    <Group name="altcategoryCWE">CWE ID 259,CWE ID 798</Group>
    <Group name="altcategoryOWASP2021">A07 Identification...</Group>
  </MetaInfo>
  <VulnKingdom>Security Features</VulnKingdom>
  <VulnCategory>Password Management</VulnCategory>
  <VulnSubcategory>Hardcoded Password</VulnSubcategory>
  <DefaultSeverity>4.0</DefaultSeverity>
  <Predicate><![CDATA[
    StringLiteral: constantValue matches ".*\"(password)\"\\s*:\\s*\"[^{$%]+\".*"
  ]]></Predicate>
</StructuralRule>
```

### 1.3 目标系统结构

**YAML 规则格式:**
```yaml
rules:
  - id: py-sql-injection
    name: SQL 注入风险
    rule_type: sink          # sink/source/sanitizer/pattern
    category: injection      # auth/access-control/injection/...
    risk_level: critical     # low/medium/high/critical
    languages: [python]
    patterns:
      - "execute"
      - "cursor.execute"
      - "prefix:raw_"
    description: "..."
    fix_suggestion: "..."
    cwe_ids: ["CWE-89"]
    owasp_ids: ["A03:2021"]
    tags: ["sql", "injection"]
```

---

## 二、核心挑战与解决方案

### 2.1 挑战矩阵

| 挑战 | 复杂度 | 解决方案 |
|------|--------|----------|
| **Predicate 查询语言转换** | 高 | 启发式解析 + LLM 辅助 + 人工校验 |
| **规则类型映射** | 中 | 基于 VulnCategory 的映射表 |
| **语言过滤** | 低 | XML language 属性直接提取 |
| **风险等级计算** | 中 | Impact × Probability 公式 |
| **CWE/OWASP 提取** | 低 | 正则表达式匹配 MetaInfo |
| **规则去重** | 中 | 基于 patterns 的相似度检测 |

### 2.2 Predicate → Pattern 转换策略

#### 转换分级策略

**Level 1: 直接转换 (30%)**
```xml
<!-- Fortify -->
<Predicate>FunctionCall fc: fc.name == "eval"</Predicate>
```
→
```yaml
patterns: ["eval"]
```

**Level 2: 启发式转换 (50%)**
```xml
<!-- Fortify -->
<Predicate>
  FunctionPointerCall fpc: fpc.name matches "exec.*"
    and instance is [FieldAccess: name == "os~module"]
</Predicate>
```
→
```yaml
patterns: ["os.exec", "regex:os\\.exec.*"]
```

**Level 3: LLM 辅助转换 (15%)**
- 复杂的数据流分析规则
- 需要上下文理解的规则
- 使用 GPT-4 生成等价 patterns

**Level 4: 标记为待处理 (5%)**
- 过于复杂的规则保留原始 Predicate 到 metadata
- 后续人工审核

### 2.3 规则类型映射表

| VulnCategory (Fortify) | CodeScan RuleType | CodeScan Category |
|------------------------|-------------------|-------------------|
| Password Management (Hardcoded) | pattern | auth |
| SQL Injection | sink | injection |
| Command Injection | sink | injection |
| Path Manipulation | sink | injection |
| Dynamic Code Evaluation | sink | injection |
| Unsafe Deserialization | sink | deserialization |
| SSRF | sink | ssrf |
| Privacy Violation | pattern | other |
| Weak Cryptography | pattern | crypto |
| Missing Authentication | pattern | auth |
| Access Control | pattern | access-control |

---

## 三、实施步骤

### 阶段 0: 准备工作 (1 天)

**任务:**
1. 创建工作目录 `scripts/fortify_migration/`
2. 安装依赖: `lxml`, `pyyaml`, `openai`
3. 创建输出目录 `rules/data/fortify/`
4. 备份现有规则

**可交付成果:**
- 目录结构就绪
- 依赖安装完成

---

### 阶段 1: XML 解析器开发 (2-3 天)

**脚本: `scripts/fortify_migration/xml_parser.py`**

```python
from dataclasses import dataclass
from typing import List, Dict, Optional
from lxml import etree

@dataclass
class FortifyRule:
    rule_id: str
    rule_type: str  # StructuralRule/SemanticRule/DataflowRule
    language: str
    vuln_category: str
    vuln_subcategory: Optional[str]
    default_severity: float
    predicate: str
    metadata: Dict[str, any]  # MetaInfo Groups

class FortifyXMLParser:
    def parse_file(self, xml_path: str) -> List[FortifyRule]:
        """解析单个 XML 文件"""

    def extract_metadata(self, rule_elem) -> Dict:
        """提取 MetaInfo Groups"""

    def extract_cwe_ids(self, metadata: Dict) -> List[str]:
        """从 metadata 提取 CWE"""

    def extract_owasp_ids(self, metadata: Dict) -> List[str]:
        """从 metadata 提取 OWASP"""

    def calculate_risk_level(self, severity: float, metadata: Dict) -> str:
        """根据 Impact/Probability 计算风险等级"""
        # critical: severity >= 4.5 or Impact >= 4.5
        # high: severity >= 3.5
        # medium: severity >= 2.0
        # low: severity < 2.0
```

**输出: JSON 中间文件**
```bash
rules/data/fortify_intermediate/core_python_parsed.json
```

**验收标准:**
- ✅ 成功解析 3 个目标语言 XML 文件
- ✅ 提取率 > 95% (允许少量损坏规则)
- ✅ CWE/OWASP 提取准确率 100%

---

### 阶段 2: Predicate 转换引擎 (4-5 天)

**脚本: `scripts/fortify_migration/predicate_converter.py`**

#### 2.1 启发式转换规则

```python
class PredicateConverter:
    def __init__(self):
        self.patterns_map = {
            # 简单函数调用
            r'FunctionCall fc: fc\.name == "(\w+)"': lambda m: [m.group(1)],

            # 带模块限定的调用
            r'instance is \[FieldAccess: name == "(\w+)~module"\].*fc\.name == "(\w+)"':
                lambda m: [f"{m.group(1)}.{m.group(2)}"],

            # 正则匹配
            r'fc\.name matches "(.+?)"': lambda m: [f"regex:{m.group(1)}"],

            # StringLiteral 匹配
            r'StringLiteral:.*matches "(.+?)"': lambda m: self._convert_regex(m.group(1)),
        }

    def convert(self, predicate: str, rule_type: str) -> List[str]:
        """转换 Predicate 为 patterns 列表"""
        for pattern, converter in self.patterns_map.items():
            match = re.search(pattern, predicate, re.DOTALL)
            if match:
                return converter(match)

        # 无法自动转换
        return None

    def _convert_regex(self, fortify_regex: str) -> List[str]:
        """转换 Fortify 正则为简化 patterns"""
        # 示例: ".*\"(password)\"\\s*:\\s*\"[^{$%]+\".*"
        # → contains:password
```

#### 2.2 LLM 辅助转换

```python
class LLMPredicateConverter:
    def __init__(self, openai_client):
        self.client = openai_client

    def convert_complex_predicate(self, predicate: str, context: Dict) -> List[str]:
        """使用 LLM 转换复杂 Predicate"""
        prompt = f"""
Convert this Fortify Predicate query to simple function name patterns:

Predicate:
{predicate}

Context:
Language: {context['language']}
VulnCategory: {context['vuln_category']}

Output format (JSON):
{{
  "patterns": ["func1", "prefix:module.", "regex:pattern.*"],
  "confidence": 0.8,
  "notes": "explanation if needed"
}}
"""
        # 调用 LLM 并解析结果
```

**输出: 转换日志**
```json
{
  "rule_id": "UUID",
  "conversion_method": "heuristic|llm|failed",
  "original_predicate": "...",
  "patterns": ["eval", "exec"],
  "confidence": 0.9
}
```

**验收标准:**
- ✅ Level 1 转换成功率 > 90%
- ✅ Level 2 转换成功率 > 70%
- ✅ 生成转换质量报告

---

### 阶段 3: YAML 生成器 (2 天)

**脚本: `scripts/fortify_migration/yaml_generator.py`**

```python
class YAMLRuleGenerator:
    def __init__(self, category_mapper, type_mapper):
        self.category_mapper = category_mapper
        self.type_mapper = type_mapper

    def generate_rule(self, fortify_rule: FortifyRule, patterns: List[str]) -> Dict:
        """生成 CodeScan 规则字典"""
        return {
            'id': f"fortify-{fortify_rule.rule_id[:8]}",
            'name': self._infer_name(fortify_rule),
            'rule_type': self.type_mapper.map(fortify_rule.vuln_category),
            'category': self.category_mapper.map(fortify_rule.vuln_category),
            'risk_level': self._calculate_risk(fortify_rule),
            'languages': [fortify_rule.language],
            'patterns': patterns,
            'description': self._generate_description(fortify_rule),
            'cwe_ids': fortify_rule.cwe_ids,
            'owasp_ids': fortify_rule.owasp_ids,
            'metadata': {
                'fortify_rule_id': fortify_rule.rule_id,
                'fortify_severity': fortify_rule.default_severity,
                'original_predicate': fortify_rule.predicate[:200],
            }
        }

    def write_yaml(self, rules: List[Dict], output_path: str):
        """写入 YAML 文件"""
```

**输出文件组织:**
```
rules/data/fortify/
├── python_sinks.yaml           # Python sink 规则
├── python_sources.yaml         # Python source 规则
├── python_patterns.yaml        # Python pattern 规则
├── javascript_sinks.yaml
├── javascript_sources.yaml
├── javascript_patterns.yaml
├── php_sinks.yaml
├── php_sources.yaml
└── php_patterns.yaml
```

**验收标准:**
- ✅ 生成的 YAML 符合 SecurityRule 模型
- ✅ Pydantic 验证通过率 100%
- ✅ 每个文件包含合理数量的规则 (100-500 条)

---

### 阶段 4: 质量验证 (2-3 天)

**脚本: `scripts/fortify_migration/validator.py`**

#### 4.1 自动化验证

```python
class RuleValidator:
    def validate_syntax(self, yaml_path: str) -> List[str]:
        """YAML 语法验证"""

    def validate_schema(self, rules: List[Dict]) -> List[str]:
        """Pydantic 模型验证"""
        from rules.models import SecurityRule
        errors = []
        for rule_data in rules:
            try:
                SecurityRule.from_dict(rule_data)
            except Exception as e:
                errors.append(f"{rule_data['id']}: {e}")
        return errors

    def validate_patterns(self, rules: List[Dict]) -> Dict:
        """Pattern 有效性验证"""
        # 检查 regex: 模式是否有效
        # 检查 patterns 是否非空
        # 检查是否有重复 patterns

    def check_duplicates(self, rules: List[Dict]) -> List[str]:
        """检测重复规则"""
        # 基于 patterns 相似度
        # 基于 name 相似度
```

#### 4.2 人工抽样验证

**抽样策略:**
- 从每个语言随机抽取 20 条规则
- 覆盖不同 rule_type
- 覆盖不同 risk_level

**验证清单:**
- [ ] patterns 是否匹配原始 Predicate 意图?
- [ ] category 映射是否合理?
- [ ] risk_level 评估是否准确?
- [ ] description 是否清晰?
- [ ] 是否有明显的误转换?

**质量报告模板:**
```markdown
## Fortify Rules 转换质量报告

### 统计摘要
- 总规则数: 13,000
- 成功转换: 11,500 (88%)
- 需人工审核: 1,200 (9%)
- 转换失败: 300 (3%)

### 按语言统计
| 语言 | 原始规则 | 转换成功 | 成功率 |
|------|---------|---------|--------|
| Python | 4,500 | 4,100 | 91% |
| JavaScript | 3,200 | 2,900 | 91% |
| PHP | 3,800 | 3,400 | 89% |

### 问题分类
1. 复杂数据流分析规则 (500 条)
2. 框架特定规则 (400 条)
3. 缺少语言支持 (200 条)
```

---

### 阶段 5: 规则集成与测试 (2 天)

#### 5.1 集成到 RuleManager

修改 `rules/manager.py`:
```python
def load_fortify_rules(self, enable: bool = True) -> int:
    """加载 Fortify 转换规则"""
    if not enable:
        return 0

    fortify_dir = Path(__file__).parent / "data" / "fortify"
    return self.load_from_directory(str(fortify_dir))
```

修改 `config/__init__.py`:
```python
@dataclass
class RulesConfig:
    enable_fortify_rules: bool = True  # 新增开关
```

#### 5.2 功能测试

```python
# tests/test_fortify_rules.py
def test_load_fortify_rules():
    manager = RuleManager(config)
    count = manager.load_fortify_rules()
    assert count > 1000

def test_fortify_rule_matching():
    # 测试转换后的规则是否能正确匹配
    rules = manager.match_function("eval", "python", RuleType.SINK)
    assert any(r.id.startswith("fortify-") for r in rules)

def test_no_duplicate_patterns():
    # 确保 Fortify 规则不与内置规则冲突
```

#### 5.3 性能测试

```python
def test_load_performance():
    """测试加载 10,000+ 规则的性能"""
    start = time.time()
    manager.load_fortify_rules()
    elapsed = time.time() - start
    assert elapsed < 5.0  # 应在 5 秒内完成
```

---

## 四、优先级与路线图

### P0: MVP (最小可行产品) - 周 1-2

**目标:** 转换 Python 高危规则

**范围:**
- Python sinks: Command Injection, SQL Injection, Deserialization
- 仅处理 Level 1 + Level 2 转换
- 预期产出: 200-300 条高质量规则

**验收:**
- 在真实项目上测试,发现率 > 当前内置规则

### P1: 扩展覆盖 - 周 3-4

**目标:** 完成 Python/JavaScript/PHP 主要规则

**范围:**
- 所有 sink/source/sanitizer 类型
- Level 1-3 转换
- 预期产出: 2,000-3,000 条规则

**验收:**
- 覆盖 OWASP Top 10 主要漏洞类型
- 在 5+ 真实项目上测试

### P2: 全量转换 - 周 5-6

**目标:** 转换所有可行规则

**范围:**
- 包含 pattern 类型规则
- Level 1-4 所有转换策略
- 预期产出: 8,000-10,000 条规则

**验收:**
- 转换成功率 > 85%
- 质量报告完成

### P3: 优化与维护 - 持续

**任务:**
- 人工审核待处理规则
- 修复误报/漏报
- 规则性能优化
- 定期同步 Fortify 更新

---

## 五、输出规范

### 5.1 YAML 文件命名

```
fortify_{language}_{type}_{category}.yaml
```

示例:
```
fortify_python_sink_injection.yaml
fortify_javascript_source_http.yaml
fortify_php_pattern_auth.yaml
```

### 5.2 规则 ID 命名

```
fortify-{uuid前8位}-{语言}-{类型}
```

示例:
```
fortify-b8f58075-py-sink
fortify-5e88df3f-js-pattern
```

### 5.3 字段映射表

| Fortify 字段 | CodeScan 字段 | 转换逻辑 |
|-------------|--------------|----------|
| RuleID | metadata.fortify_rule_id | 直接保留 |
| VulnCategory | category | 映射表 |
| VulnSubcategory | metadata.subcategory | 保留到 metadata |
| DefaultSeverity | risk_level | 计算公式 |
| Predicate | patterns | 转换引擎 |
| altcategoryCWE | cwe_ids | 正则提取 |
| altcategoryOWASP2021 | owasp_ids | 正则提取 |
| Impact | metadata.impact | 保留 |
| Accuracy | metadata.accuracy | 保留 |

---

## 六、风险与缓解

| 风险 | 可能性 | 影响 | 缓解措施 |
|------|--------|------|---------|
| Predicate 转换不准确 | 高 | 高 | 分级转换 + LLM 辅助 + 人工验证 |
| 规则数量导致性能下降 | 中 | 中 | 延迟加载 + 规则索引优化 |
| 与现有规则冲突 | 中 | 中 | 去重检测 + namespace 隔离 |
| Fortify 规则版权问题 | 低 | 高 | 仅用于学习,不分发 |
| 转换脚本复杂度高 | 高 | 中 | 模块化设计 + 单元测试 |

---

## 七、成功指标

### 技术指标
- ✅ 转换成功率 > 85%
- ✅ Pydantic 验证通过率 100%
- ✅ 规则加载时间 < 5 秒
- ✅ 单元测试覆盖率 > 80%

### 业务指标
- ✅ 规则总数增加 200%+
- ✅ 在真实项目上漏洞发现率提升 50%+
- ✅ 覆盖 OWASP Top 10 所有类别

---

## 八、关键文件清单

### 实施脚本
```
scripts/fortify_migration/
├── __init__.py
├── xml_parser.py              # XML 解析
├── predicate_converter.py     # Predicate 转换
├── llm_converter.py           # LLM 辅助转换
├── yaml_generator.py          # YAML 生成
├── validator.py               # 质量验证
├── category_mapper.py         # 分类映射表
├── run_migration.py           # 主入口脚本
└── README.md                  # 使用文档
```

### 输出文件
```
rules/data/fortify/
├── python_sink_injection.yaml
├── python_sink_deserialization.yaml
├── python_source_http.yaml
├── javascript_sink_xss.yaml
├── php_sink_sqli.yaml
└── ...
```

### 质量报告
```
.fortify_migration/
├── conversion_log.json        # 转换日志
├── quality_report.md          # 质量报告
├── failed_rules.json          # 失败规则
└── manual_review.json         # 待人工审核
```

---

## 九、Critical Files for Implementation

基于此规划,实施时最关键的文件:

- **E:\1ceshi\codescan\参考项目\rules\core_python.xml** - 主要源数据,需要深度解析其 Predicate 结构
- **E:\1ceshi\codescan\rules\models.py** - 目标数据模型,确保转换输出符合 SecurityRule 定义
- **E:\1ceshi\codescan\rules\manager.py** - 需要扩展以支持 Fortify 规则加载
- **E:\1ceshi\codescan\rules\data\comprehensive_rules.yaml** - 参考现有规则格式和最佳实践
- **E:\1ceshi\codescan\config\__init__.py** - 添加 Fortify 规则开关配置

---

**规划完成时间:** 2025-12-24
**预计实施周期:** 6-8 周
**优先级:** P0 (MVP) 2周内完成
