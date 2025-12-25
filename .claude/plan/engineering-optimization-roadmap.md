# CodeScan 工程化优化重构规划

**文档版本**: v1.0
**创建日期**: 2025-12-24
**目标**: 借鉴 AI-Codereview-Gitlab 等成熟项目经验,提升 CodeScan 的工程化成熟度和生产可用性

---

## 一、现状分析

### 1.1 已有优势

✅ **核心架构清晰**
- LLM 驱动的深度分析引擎
- 调用链级别的漏洞发现能力
- SinkCallScanner 确定性扫描
- 多种向量存储后端支持

✅ **技术栈现代化**
- Python 3.x + FastAPI
- Vue 3 + Vite
- Qdrant 向量数据库
- SQLite 持久化存储

✅ **已实现的核心功能**
- Prompt 模板系统 (`analyzer/prompts.py`)
- 配置管理系统 (`config/settings.py`)
- LLM 客户端抽象 (`llm_client/client.py`)
- WebSocket 实时推送

### 1.2 工程化缺陷

❌ **Prompt 工程化不足**
- Prompt 模板硬编码在 Python 字符串中
- 缺少版本管理和 A/B 测试能力
- Token 统计不精确,易超限
- 无法动态调整模板

❌ **配置管理问题**
- 配置项分散,缺少统一验证
- 环境变量和配置文件优先级混乱
- 缺少配置热更新能力

❌ **缺少文件过滤机制**
- 扫描时处理大量无用文件 (node_modules, .git)
- 缺少智能文件筛选策略

❌ **单一 LLM 提供商绑定**
- 只支持 OpenAI 兼容 API
- 缺少多模型路由和回退机制

❌ **异步任务管理简陋**
- 使用 ThreadPoolExecutor 原始实现
- 缺少任务队列和优先级调度

---

## 二、优化目标与优先级

### P0 - 核心工程化能力 (2周)

**必须在生产环境上线前完成,直接影响稳定性和可维护性**

| 优化项 | 现状问题 | 目标 | 验收标准 |
|--------|---------|------|---------|
| **Prompt 模板工程化** | 硬编码、无版本控制 | 外部化、可版本管理、支持变量替换 | 1. 所有 Prompt 存储在 `prompts/templates/` 目录<br>2. 支持 Jinja2 语法<br>3. 自动统计 Token 用量 |
| **Token 控制策略** | 无精确控制,易超限 | 精确预估、动态截断、优先级分配 | 1. 超限前自动截断低优先级内容<br>2. Token 用量日志记录<br>3. 支持配置 Token 预算 |
| **配置统一验证** | 运行时才发现配置错误 | 启动时验证、Schema 检查 | 1. Pydantic Schema 完整覆盖<br>2. 启动时验证失败自动中止<br>3. 配置错误提示清晰 |
| **文件过滤机制** | 处理大量无用文件 | .gitignore 风格过滤 + 智能筛选 | 1. 支持 `.auditignore` 文件<br>2. 自动忽略 node_modules 等<br>3. 文件大小/类型过滤 |

### P1 - 高级功能增强 (3周)

**提升用户体验和分析质量,但不阻塞基础功能**

| 优化项 | 现状问题 | 目标 | 验收标准 |
|--------|---------|------|---------|
| **多模型工厂模式** | 单一 LLM 提供商 | 支持多家 LLM,自动路由和回退 | 1. 支持 OpenAI/Claude/Gemini/DeepSeek<br>2. 主备模型自动切换<br>3. 成本优化路由策略 |
| **事件驱动架构** | 同步阻塞调用 | 异步事件总线、解耦业务逻辑 | 1. 事件总线实现<br>2. 核心流程事件化<br>3. 支持事件监听和钩子 |
| **增强型 Agent 工具** | 工具调用日志简陋 | 详细日志、工具调用链可视化 | 1. 工具调用全链路追踪<br>2. 调用时长统计<br>3. 失败重试机制 |
| **结果缓存策略** | 重复分析浪费 Token | 基于 AST Hash 的智能缓存 | 1. 代码未改动时直接返回缓存<br>2. 支持缓存失效策略<br>3. 缓存命中率 >70% |

### P2 - 生态集成与扩展 (4周)

**与 CI/CD 集成,支持企业级部署**

| 优化项 | 现状问题 | 目标 | 验收标准 |
|--------|---------|------|---------|
| **GitLab Webhook 集成** | 无 CI/CD 集成 | MR 触发自动审计 | 1. MR 创建时自动触发<br>2. 结果作为评论回写<br>3. 增量扫描支持 |
| **SARIF 格式输出** | 仅 JSON 格式 | 标准化输出,IDE 集成 | 1. 符合 SARIF 2.1 规范<br>2. VSCode 插件可读取<br>3. GitHub Security 集成 |
| **Docker 镜像优化** | 镜像体积大、启动慢 | 轻量化、多阶段构建 | 1. 镜像 <500MB<br>2. 启动时间 <10s<br>3. 健康检查配置 |

---

## 三、详细实施方案

### 3.1 P0-1: Prompt 模板工程化

#### 目标

将硬编码的 Prompt 模板外部化,支持版本管理、变量替换、Token 统计。

#### 现状分析

```python
# 当前实现 (analyzer/prompts.py)
SYSTEM_PROMPT = """# 代码安全审计专家
你是一名资深安全工程师...
"""

USER_PROMPT_TEMPLATE = """{context}

请分析上述代码是否存在安全问题。按照要求的 JSON 格式输出。
"""
```

**问题**:
- Prompt 修改需要重启服务
- 无法追踪 Prompt 变更历史
- 不同漏洞类型的 Prompt 调整困难
- 无法 A/B 测试不同 Prompt 版本

#### 设计方案

**1. 目录结构**

```
prompts/
├── templates/
│   ├── chain_analysis/
│   │   ├── system.jinja2           # 链级分析系统提示词
│   │   ├── user.jinja2              # 链级分析用户提示词
│   │   └── categories/
│   │       ├── command_exec.jinja2  # 命令执行专项提示
│   │       ├── sql_injection.jinja2
│   │       └── file_read.jinja2
│   ├── single_point/
│   │   ├── system.jinja2            # 单点分析系统提示词
│   │   └── user.jinja2
│   └── agent/
│       ├── task_builder.jinja2      # Agent 任务构建
│       └── tool_calling.jinja2
├── versions/
│   └── v1.0/                        # 版本化存档
│       └── chain_analysis/
│           └── system.jinja2
├── configs/
│   └── prompt_config.yaml           # Prompt 元数据配置
└── manager.py                        # Prompt 管理器
```

**2. Prompt 配置文件 (`prompts/configs/prompt_config.yaml`)**

```yaml
prompts:
  chain_analysis:
    version: "1.2.0"
    system_template: "chain_analysis/system.jinja2"
    user_template: "chain_analysis/user.jinja2"
    variables:
      max_evidence_count: 5
      require_data_flow: true
    token_limits:
      system_max: 1500
      user_max: 5000
      total_max: 6500
    category_templates:
      command_exec: "chain_analysis/categories/command_exec.jinja2"
      sql_injection: "chain_analysis/categories/sql_injection.jinja2"

  single_point:
    version: "1.0.0"
    system_template: "single_point/system.jinja2"
    user_template: "single_point/user.jinja2"
    token_limits:
      system_max: 1000
      user_max: 3000
      total_max: 4000
```

**3. Prompt 管理器 (`prompts/manager.py`)**

```python
from pathlib import Path
from typing import Dict, Any, Optional, List
import yaml
import jinja2
from dataclasses import dataclass
import tiktoken


@dataclass
class PromptTemplate:
    """Prompt 模板封装"""
    name: str
    version: str
    system_template: str
    user_template: str
    token_limits: Dict[str, int]
    variables: Dict[str, Any]
    category_templates: Dict[str, str]


class PromptManager:
    """Prompt 模板管理器"""

    def __init__(self, templates_dir: str = "prompts/templates", config_path: str = "prompts/configs/prompt_config.yaml"):
        self.templates_dir = Path(templates_dir)
        self.config_path = Path(config_path)
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.templates_dir),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.config = self._load_config()
        self.tokenizer = tiktoken.get_encoding("cl100k_base")  # GPT-4 tokenizer

    def _load_config(self) -> Dict[str, Any]:
        """加载 Prompt 配置"""
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def get_template(self, template_name: str) -> PromptTemplate:
        """获取 Prompt 模板"""
        config = self.config['prompts'].get(template_name)
        if not config:
            raise ValueError(f"Template '{template_name}' not found")

        return PromptTemplate(
            name=template_name,
            version=config['version'],
            system_template=config['system_template'],
            user_template=config['user_template'],
            token_limits=config.get('token_limits', {}),
            variables=config.get('variables', {}),
            category_templates=config.get('category_templates', {}),
        )

    def render(
        self,
        template_name: str,
        context: Dict[str, Any],
        category: Optional[str] = None,
    ) -> tuple[str, str, Dict[str, int]]:
        """渲染 Prompt 模板

        Args:
            template_name: 模板名称 (如 'chain_analysis')
            context: 渲染上下文变量
            category: 可选的类别专项提示词

        Returns:
            (system_prompt, user_prompt, token_stats)
        """
        template = self.get_template(template_name)

        # 合并默认变量和用户提供的上下文
        render_context = {**template.variables, **context}

        # 渲染系统提示词
        system_template = self.jinja_env.get_template(template.system_template)
        system_prompt = system_template.render(**render_context)

        # 如果有类别专项提示词,追加到系统提示词
        if category and category in template.category_templates:
            category_template = self.jinja_env.get_template(template.category_templates[category])
            category_prompt = category_template.render(**render_context)
            system_prompt += "\n\n" + category_prompt

        # 渲染用户提示词
        user_template = self.jinja_env.get_template(template.user_template)
        user_prompt = user_template.render(**render_context)

        # Token 统计
        system_tokens = self._count_tokens(system_prompt)
        user_tokens = self._count_tokens(user_prompt)
        total_tokens = system_tokens + user_tokens

        # Token 限制检查
        if 'system_max' in template.token_limits and system_tokens > template.token_limits['system_max']:
            logger.warning(
                f"System prompt exceeds limit: {system_tokens} > {template.token_limits['system_max']}"
            )

        if 'user_max' in template.token_limits and user_tokens > template.token_limits['user_max']:
            logger.warning(
                f"User prompt exceeds limit: {user_tokens} > {template.token_limits['user_max']}"
            )

        # 自动截断 (如果超限)
        if 'total_max' in template.token_limits and total_tokens > template.token_limits['total_max']:
            logger.warning(f"Total tokens {total_tokens} exceeds limit {template.token_limits['total_max']}, truncating...")
            system_prompt, user_prompt = self._truncate_prompts(
                system_prompt, user_prompt, template.token_limits['total_max']
            )
            # 重新统计
            system_tokens = self._count_tokens(system_prompt)
            user_tokens = self._count_tokens(user_prompt)
            total_tokens = system_tokens + user_tokens

        token_stats = {
            "system_tokens": system_tokens,
            "user_tokens": user_tokens,
            "total_tokens": total_tokens,
            "limit": template.token_limits.get('total_max', 0),
        }

        return system_prompt, user_prompt, token_stats

    def _count_tokens(self, text: str) -> int:
        """精确统计 Token 数量"""
        return len(self.tokenizer.encode(text))

    def _truncate_prompts(self, system: str, user: str, max_tokens: int) -> tuple[str, str]:
        """智能截断 Prompt

        策略:
        1. 保留完整的系统提示词 (不截断)
        2. 截断用户提示词中的低优先级部分 (如相关代码、规则列表)
        """
        system_tokens = self._count_tokens(system)
        available_for_user = max_tokens - system_tokens - 100  # 留100 token buffer

        if available_for_user < 500:
            raise ValueError("系统提示词过长,无法容纳用户提示词")

        # 分段截断用户提示词
        user_lines = user.split('\n')

        # 优先级标记 (高优先级保留)
        priority_sections = ['【调用链信息】', '【Sink 触发点】', '【入口点】']

        truncated_user = []
        current_tokens = 0

        for line in user_lines:
            # 检查是否是高优先级段落
            is_priority = any(marker in line for marker in priority_sections)

            line_tokens = self._count_tokens(line + '\n')

            if current_tokens + line_tokens <= available_for_user or is_priority:
                truncated_user.append(line)
                current_tokens += line_tokens
            else:
                # 超限,添加截断提示
                if '...[内容已截断]...' not in truncated_user:
                    truncated_user.append('\n...[内容已截断,仅保留高优先级上下文]...')
                break

        return system, '\n'.join(truncated_user)

    def validate_template(self, template_name: str) -> List[str]:
        """验证模板完整性

        Returns:
            错误列表 (空列表表示验证通过)
        """
        errors = []

        try:
            template = self.get_template(template_name)

            # 检查模板文件是否存在
            system_path = self.templates_dir / template.system_template
            if not system_path.exists():
                errors.append(f"System template not found: {system_path}")

            user_path = self.templates_dir / template.user_template
            if not user_path.exists():
                errors.append(f"User template not found: {user_path}")

            # 检查类别模板
            for category, path in template.category_templates.items():
                category_path = self.templates_dir / path
                if not category_path.exists():
                    errors.append(f"Category template '{category}' not found: {category_path}")

            # 尝试渲染 (空上下文)
            try:
                self.render(template_name, {})
            except jinja2.TemplateError as e:
                errors.append(f"Template rendering error: {e}")

        except Exception as e:
            errors.append(f"Template validation failed: {e}")

        return errors


# 全局单例
_prompt_manager = None

def get_prompt_manager() -> PromptManager:
    """获取全局 Prompt 管理器"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager()
    return _prompt_manager
```

**4. 使用示例 (改造 `analyzer/engine.py`)**

```python
# 旧代码
from .prompts import build_chain_analysis_prompt

system, user = build_chain_analysis_prompt(
    chain_context_text=context_text,
    chain_id=chain_id,
    sink_category=sink_category,
)

# 新代码
from prompts.manager import get_prompt_manager

pm = get_prompt_manager()
system, user, token_stats = pm.render(
    template_name='chain_analysis',
    context={
        'chain_context_text': context_text,
        'chain_id': chain_id,
        'sink_category': sink_category,
    },
    category=sink_category,  # 自动加载类别专项提示词
)

logger.info(f"Prompt rendered: {token_stats}")
```

**5. Jinja2 模板示例 (`prompts/templates/chain_analysis/system.jinja2`)**

```jinja2
# 安全审计专家 - 调用链深度分析

你是一名资深安全工程师,专长是代码审计和高危漏洞挖掘。你拥有丰富的实战经验,曾发现多个 CVE 漏洞。

## 你将收到的信息

一条完整的**调用链上下文**,包含:
1. **入口点信息**: Web Handler、Controller、API 端点等外部可达的入口
2. **调用链路径**: 从入口到危险函数的完整调用序列
3. **Sink 触发点**: 危险函数的详细信息和代码片段
4. **链路关键代码**: 每个节点的函数定义
5. **安全规则信息**: 匹配的 Source/Sink/Sanitizer 规则

## 分析方法论

### 第一步: 理解调用链结构
1. 识别入口点类型 (HTTP 路由、API 端点、消息处理器等)
2. 绘制数据从入口到 Sink 的流转路径
3. 标识链路上的关键节点 (参数传递、数据转换、条件分支)

### 第二步: 数据流追踪
核心问题: **用户可控数据能否到达危险函数?**

追踪要点:
- 参数来源: 直接来自请求? 还是经过处理?
- 数据转换: 是否有类型转换、编码转换?
- 中间存储: 是否经过数据库、缓存、文件?
- 条件分支: 是否有路径使数据绕过检查?

{% if require_data_flow %}
**要求**: 必须在输出中包含完整的 `data_flow` 字段,描述数据从入口到 Sink 的传播路径。
{% endif %}

### 第三步: 安全控制评估
检查链路上是否存在有效的安全措施:

1. **认证检查**
   - 是否验证用户身份 (Token/Session)
   - 认证中间件是否正确应用
   - 是否存在认证绕过路径

2. **授权检查**
   - 是否验证用户权限
   - 资源访问是否有所有权验证
   - 是否存在越权风险

3. **输入验证/过滤**
   - 是否有类型检查
   - 是否有格式验证 (正则、白名单等)
   - 过滤器是否能被绕过

4. **输出编码**
   - 危险字符是否被转义
   - 编码是否在正确位置应用

### 第四步: 可利用性判断

评估漏洞的实际可利用性:
- 攻击前置条件是什么?
- 需要什么权限级别?
- 是否需要特定配置?
- 利用难度如何?

## 分析原则

1. **证据优先**: 所有结论必须基于提供的代码证据
2. **路径完整**: 分析必须覆盖整条调用链,不能只看单点
3. **实事求是**: 不确定的标记为 "uncertain"
4. **安全悲观**: 对安全措施持怀疑态度,考虑绕过可能性
5. **不造 payload**: 描述高层次利用思路,不给出具体攻击代码

## 输出格式要求

必须输出严格的 JSON 格式:
```json
{
    "chain_id": "调用链标识",
    "sink_category": "sink 类别",
    "risk_level": "low/medium/high/critical",
    "has_issue": true/false/"uncertain",
    "issue_type": "问题类型",
    "confidence": 0.0-1.0,
    "summary": "问题简要描述 (中文,50字以内)",
    "data_flow": "数据流描述: 用户输入 → [中间处理] → 危险函数",
    "evidence": [
        {
            "node_index": 0,
            "file_path": "文件路径",
            "line_start": 行号,
            "line_end": 行号,
            "snippet": "关键代码片段",
            "reason": "这段代码为什么是关键证据"
        }
        {# 最多 {{ max_evidence_count }} 条证据 #}
    ],
    "security_controls": [
        {
            "type": "认证/授权/输入验证/过滤/编码",
            "location": "位置描述",
            "effectiveness": "有效/部分有效/无效/可绕过/未知",
            "bypass_possibility": "绕过可能性 (如适用)"
        }
    ],
    "exploitability_conditions": "利用条件描述 (无需具体 payload)",
    "fix_suggestion": "修复建议 (具体可操作)",
    "notes": "需人工确认的事项"
}
```

## 风险等级判定标准

- **Critical**: 可直接导致 RCE、任意文件读写、完全接管系统
- **High**: 可导致敏感数据泄露、权限提升、重要业务影响
- **Medium**: 需要特定条件利用,或影响范围有限
- **Low**: 理论风险,实际利用困难或影响很小
```

#### 验收标准

- [ ] 所有 Prompt 模板存储在 `prompts/templates/` 目录
- [ ] 支持 Jinja2 变量替换和条件渲染
- [ ] 自动统计 Token 用量并记录日志
- [ ] Token 超限时自动截断低优先级内容
- [ ] 模板加载失败时有清晰错误提示
- [ ] 单元测试覆盖率 >80%

---

### 3.2 P0-2: Token 控制策略

#### 目标

实现精确的 Token 预算控制,防止超限导致的 API 错误和成本失控。

#### 现状问题

```python
# 当前实现 (analyzer/engine.py)
response = self.llm_client.chat_completion(
    messages=[...],
    max_tokens=2500,  # 硬编码,无法根据上下文动态调整
)
```

**问题**:
- 无法预估 Prompt Token 数量
- `max_tokens` 硬编码,不灵活
- 超限时直接失败,无降级策略

#### 设计方案

**1. Token 预算管理器 (`llm_client/token_budget.py`)**

```python
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum
import tiktoken


class TokenPriority(Enum):
    """内容优先级"""
    CRITICAL = 0   # 必须保留 (系统提示词核心部分)
    HIGH = 1       # 高优先级 (Sink 触发点代码)
    MEDIUM = 2     # 中等优先级 (调用链路径)
    LOW = 3        # 低优先级 (相关代码、规则列表)


@dataclass
class ContentBlock:
    """内容块"""
    text: str
    priority: TokenPriority
    label: str  # 用于日志


class TokenBudgetManager:
    """Token 预算管理器"""

    def __init__(self, model: str = "gpt-4"):
        self.model = model
        self.tokenizer = tiktoken.encoding_for_model(model)

        # 模型配置
        self.model_limits = {
            "gpt-4": 8192,
            "gpt-4-32k": 32768,
            "gpt-3.5-turbo": 4096,
            "gpt-3.5-turbo-16k": 16384,
            "claude-3-opus": 200000,
            "claude-3-sonnet": 200000,
        }

        self.context_window = self.model_limits.get(model, 8192)

    def count_tokens(self, text: str) -> int:
        """精确统计 Token 数量"""
        return len(self.tokenizer.encode(text))

    def allocate_budget(
        self,
        content_blocks: List[ContentBlock],
        max_tokens: int,
        completion_tokens: int = 2000,
    ) -> Dict[str, Any]:
        """分配 Token 预算

        Args:
            content_blocks: 内容块列表
            max_tokens: 最大 Token 数
            completion_tokens: 预留给 LLM 生成的 Token 数

        Returns:
            {
                "allocated_blocks": List[ContentBlock],  # 最终保留的内容块
                "truncated_blocks": List[str],           # 被截断的内容块标签
                "total_tokens": int,
                "budget_utilization": float,              # 预算利用率
            }
        """
        available = max_tokens - completion_tokens - 100  # 留100 buffer

        # 按优先级排序
        sorted_blocks = sorted(content_blocks, key=lambda b: b.priority.value)

        allocated = []
        truncated = []
        current_tokens = 0

        for block in sorted_blocks:
            block_tokens = self.count_tokens(block.text)

            if current_tokens + block_tokens <= available:
                # 完整保留
                allocated.append(block)
                current_tokens += block_tokens
            elif block.priority == TokenPriority.CRITICAL:
                # 关键内容必须保留,即使超限也要截断其他内容
                allocated.append(block)
                current_tokens += block_tokens
                logger.warning(f"Critical block '{block.label}' causes budget overflow")
            else:
                # 截断
                truncated.append(block.label)
                logger.info(f"Truncated block '{block.label}' ({block_tokens} tokens)")

        return {
            "allocated_blocks": allocated,
            "truncated_blocks": truncated,
            "total_tokens": current_tokens,
            "budget_utilization": current_tokens / available,
        }

    def estimate_completion_tokens(self, task_type: str) -> int:
        """预估 LLM 生成 Token 数量

        Args:
            task_type: 任务类型 ('chain_analysis', 'single_point', etc.)

        Returns:
            预估的生成 Token 数
        """
        estimates = {
            "chain_analysis": 2000,      # 链级分析通常输出较长
            "single_point": 1500,        # 单点分析较短
            "agent_task": 1000,          # Agent 任务通常简洁
        }
        return estimates.get(task_type, 1500)

    def build_truncated_prompt(
        self,
        content_blocks: List[ContentBlock],
        max_tokens: int,
        task_type: str = "chain_analysis",
    ) -> tuple[str, Dict[str, Any]]:
        """构建经过预算控制的 Prompt

        Args:
            content_blocks: 内容块列表
            max_tokens: 最大 Token 数
            task_type: 任务类型

        Returns:
            (final_prompt, budget_info)
        """
        completion_tokens = self.estimate_completion_tokens(task_type)

        result = self.allocate_budget(
            content_blocks, max_tokens, completion_tokens
        )

        # 拼接最终 Prompt
        prompt_parts = []
        for block in result["allocated_blocks"]:
            prompt_parts.append(f"# {block.label}\n{block.text}")

        if result["truncated_blocks"]:
            prompt_parts.append(
                f"\n**[注意]: 以下内容因 Token 限制被截断: {', '.join(result['truncated_blocks'])}]**"
            )

        final_prompt = "\n\n".join(prompt_parts)

        budget_info = {
            "total_tokens": result["total_tokens"],
            "completion_tokens": completion_tokens,
            "budget_utilization": result["budget_utilization"],
            "truncated_count": len(result["truncated_blocks"]),
        }

        return final_prompt, budget_info
```

**2. 使用示例 (改造 `analyzer/engine.py`)**

```python
from llm_client.token_budget import TokenBudgetManager, ContentBlock, TokenPriority

# 初始化
budget_mgr = TokenBudgetManager(model="gpt-4")

# 构建内容块
content_blocks = [
    ContentBlock(
        text=system_prompt,
        priority=TokenPriority.CRITICAL,
        label="系统提示词"
    ),
    ContentBlock(
        text=f"Chain ID: {chain_id}\nSink Category: {sink_category}",
        priority=TokenPriority.CRITICAL,
        label="调用链基本信息"
    ),
    ContentBlock(
        text=sink_site_code,
        priority=TokenPriority.HIGH,
        label="Sink 触发点代码"
    ),
    ContentBlock(
        text=chain_path_text,
        priority=TokenPriority.MEDIUM,
        label="调用链路径"
    ),
    ContentBlock(
        text=related_code,
        priority=TokenPriority.LOW,
        label="相关代码"
    ),
]

# 分配预算并构建 Prompt
max_tokens = self.config.llm.max_context_tokens  # 从配置读取
final_prompt, budget_info = budget_mgr.build_truncated_prompt(
    content_blocks, max_tokens, task_type="chain_analysis"
)

logger.info(f"Token budget: {budget_info}")

# 调用 LLM
response = self.llm_client.chat_completion(
    messages=[ChatMessage(role="user", content=final_prompt)],
    max_tokens=budget_info["completion_tokens"],
)
```

#### 验收标准

- [ ] 支持精确 Token 统计 (基于 tiktoken)
- [ ] 超限时自动截断低优先级内容
- [ ] Token 用量日志记录到数据库
- [ ] 支持配置不同模型的 Token 限制
- [ ] 预算利用率统计 (目标 >90%)

---

### 3.3 P0-3: 配置统一验证

#### 目标

在启动时验证所有配置项,避免运行时错误。

#### 现状问题

```python
# 当前实现 (config/settings.py)
def _validate_config(config: AuditConfig, suppress_warnings: bool = False) -> None:
    """验证配置的必填项和合法性"""
    errors = []
    # ...
    if errors:
        # 只打印警告,不阻止启动 ❌
        if not suppress_warnings:
            import warnings
            for error in errors:
                warnings.warn(f"配置警告: {error}")
```

**问题**:
- 验证失败只 warn,不中止启动
- 缺少 Schema 级别的类型检查
- 环境变量优先级不清晰

#### 设计方案

**1. 增强配置验证 (`config/settings.py`)**

```python
from pydantic import BaseModel, Field, validator, root_validator
from typing import Optional, List


class LLMConfig(BaseModel):
    """LLM 服务配置 (Pydantic Model)"""
    provider: str = Field(default="openai-compatible", description="LLM 提供商")
    base_url: str = Field(..., description="LLM API 基础 URL")  # 必填
    api_key: str = Field(..., description="API Key")  # 必填
    model: str = Field(default="gpt-4", description="模型名称")
    embedding_model: str = Field(default="text-embedding-3-small", description="嵌入模型")
    max_tokens: int = Field(default=4096, ge=1, le=128000, description="最大生成 Token 数")
    temperature: float = Field(default=0.0, ge=0.0, le=2.0, description="温度参数")
    timeout: int = Field(default=60, ge=1, le=600, description="超时时间 (秒)")
    max_retries: int = Field(default=3, ge=0, le=10, description="最大重试次数")

    # 嵌入模型独立配置
    embedding_base_url: Optional[str] = Field(None, description="嵌入模型 API 地址")
    embedding_api_key: Optional[str] = Field(None, description="嵌入模型 API Key")
    embedding_dim: int = Field(default=1536, ge=128, le=4096, description="嵌入向量维度")

    # Token 预算控制
    max_code_tokens_per_call: int = Field(default=3000, ge=500, le=10000)
    max_context_tokens: int = Field(default=6000, ge=1000, le=100000)

    @validator('base_url')
    def validate_base_url(cls, v):
        """验证 base_url 格式"""
        if not v.startswith(('http://', 'https://')):
            raise ValueError("base_url 必须以 http:// 或 https:// 开头")
        return v.rstrip('/')

    @validator('api_key')
    def validate_api_key(cls, v):
        """验证 API Key 不为空"""
        if not v or v.strip() == "":
            raise ValueError("API Key 不能为空")
        return v

    @root_validator
    def validate_embedding_config(cls, values):
        """验证嵌入模型配置完整性"""
        if values.get('embedding_base_url') and not values.get('embedding_api_key'):
            raise ValueError("设置了 embedding_base_url 时必须提供 embedding_api_key")
        return values


class ScanConfig(BaseModel):
    """扫描配置"""
    target_path: str = Field(default=".", description="扫描目标路径")
    languages: List[str] = Field(default_factory=lambda: ["python", "javascript", "php"])
    include_patterns: List[str] = Field(default_factory=lambda: [
        "**/*.py", "**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx", "**/*.php"
    ])
    exclude_patterns: List[str] = Field(default_factory=lambda: [
        "**/node_modules/**", "**/__pycache__/**", "**/venv/**", "**/.git/**"
    ])
    max_file_size_kb: int = Field(default=500, ge=1, le=10000)
    max_concurrent: int = Field(default=4, ge=1, le=32)

    @validator('target_path')
    def validate_target_path(cls, v):
        """验证目标路径存在"""
        from pathlib import Path
        path = Path(v)
        if v != "." and not path.exists():
            raise ValueError(f"扫描目标路径不存在: {v}")
        return str(path.absolute())


# 修改 load_config 函数
def load_config(config_path: Optional[str] = None, target_path: Optional[str] = None) -> AuditConfig:
    """加载配置 (带严格验证)"""
    # ... (现有逻辑)

    try:
        # 使用 Pydantic 验证
        config = AuditConfig(
            llm=LLMConfig(**llm_dict),
            vector_store=VectorStoreConfig(**vector_dict),
            scan=ScanConfig(**scan_dict),
            # ...
        )
        logger.info("✅ 配置验证通过")
        return config
    except pydantic.ValidationError as e:
        logger.error("❌ 配置验证失败:")
        for error in e.errors():
            field = ".".join(str(loc) for loc in error['loc'])
            message = error['msg']
            logger.error(f"  - {field}: {message}")
        raise ValueError("配置验证失败,请检查配置文件和环境变量") from e
```

**2. 启动时验证 (`api/main.py` 或 `start.py`)**

```python
from config import load_config
import sys

try:
    config = load_config()
    logger.info("配置加载成功")
except ValueError as e:
    logger.error(f"配置加载失败: {e}")
    sys.exit(1)  # 强制退出,不允许启动
```

#### 验收标准

- [ ] 所有配置项使用 Pydantic Model
- [ ] 必填项验证 (API Key, base_url 等)
- [ ] 类型和范围验证 (如 max_tokens >= 1)
- [ ] 验证失败时自动中止启动
- [ ] 错误提示清晰易懂

---

### 3.4 P0-4: 文件过滤机制

#### 目标

智能过滤不需要扫描的文件,提升扫描效率。

#### 现状问题

```python
# 当前实现 (indexer/indexer.py)
exclude_patterns = [
    "**/node_modules/**", "**/__pycache__/**", "**/venv/**", "**/.git/**"
]
# 硬编码在配置中,用户无法自定义
```

**问题**:
- 缺少 `.gitignore` 风格的过滤文件支持
- 硬编码排除列表不灵活
- 无法针对不同项目自定义

#### 设计方案

**1. `.auditignore` 文件支持**

用户可以在项目根目录创建 `.auditignore` 文件:

```gitignore
# CodeScan 扫描忽略规则

# 依赖目录
node_modules/
vendor/
bower_components/
packages/

# 构建产物
dist/
build/
*.min.js
*.bundle.js

# 测试文件
**/*.test.js
**/*.spec.ts
tests/
__tests__/

# 配置文件
.env*
*.config.js
webpack*.js

# 文档
docs/
*.md
README*

# 二进制文件
*.exe
*.dll
*.so
*.dylib

# 大文件
*.log
*.csv
*.json  # 可选择性忽略 JSON
```

**2. 文件过滤器 (`indexer/file_filter.py`)**

```python
from pathlib import Path
from typing import List, Set, Optional
import fnmatch
import os


class FileFilter:
    """文件过滤器"""

    def __init__(self, project_root: str, custom_ignore_file: Optional[str] = None):
        self.project_root = Path(project_root).resolve()
        self.ignore_patterns: Set[str] = set()

        # 加载 .auditignore
        ignore_file = custom_ignore_file or (self.project_root / ".auditignore")
        if Path(ignore_file).exists():
            self._load_ignore_file(ignore_file)

        # 加载 .gitignore (如果存在)
        gitignore = self.project_root / ".gitignore"
        if gitignore.exists():
            self._load_ignore_file(gitignore)

        # 内置默认排除规则
        self._add_default_patterns()

    def _load_ignore_file(self, filepath: str):
        """加载 ignore 文件"""
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    self.ignore_patterns.add(line)

    def _add_default_patterns(self):
        """添加默认排除规则"""
        defaults = [
            # 版本控制
            ".git/**", ".svn/**", ".hg/**",
            # 依赖目录
            "node_modules/**", "vendor/**", "__pycache__/**", "venv/**", "env/**",
            # IDE
            ".idea/**", ".vscode/**", "*.swp", "*.swo",
            # 构建产物
            "dist/**", "build/**", "*.pyc", "*.pyo", "*.egg-info/**",
            # 临时文件
            "*.tmp", "*.temp", "*.cache",
        ]
        self.ignore_patterns.update(defaults)

    def should_ignore(self, filepath: str) -> bool:
        """判断文件是否应该被忽略

        Args:
            filepath: 文件路径 (相对于项目根目录)

        Returns:
            True 表示应该忽略
        """
        # 转换为相对路径
        try:
            rel_path = Path(filepath).relative_to(self.project_root)
        except ValueError:
            # 不在项目根目录下,忽略
            return True

        rel_path_str = str(rel_path).replace(os.sep, '/')

        # 检查每个模式
        for pattern in self.ignore_patterns:
            # 支持 .gitignore 风格的模式
            if pattern.endswith('/'):
                # 目录匹配
                if rel_path_str.startswith(pattern.rstrip('/')):
                    return True
            elif fnmatch.fnmatch(rel_path_str, pattern):
                return True
            elif fnmatch.fnmatch(rel_path.name, pattern):
                # 匹配文件名
                return True

        return False

    def filter_files(self, files: List[str]) -> List[str]:
        """批量过滤文件列表

        Args:
            files: 文件路径列表

        Returns:
            过滤后的文件列表
        """
        return [f for f in files if not self.should_ignore(f)]

    def should_ignore_by_size(self, filepath: str, max_size_kb: int = 500) -> bool:
        """根据文件大小判断是否忽略"""
        try:
            size_kb = Path(filepath).stat().st_size / 1024
            return size_kb > max_size_kb
        except OSError:
            return True

    def should_ignore_by_extension(self, filepath: str, allowed_extensions: Set[str]) -> bool:
        """根据文件扩展名判断是否忽略

        Args:
            filepath: 文件路径
            allowed_extensions: 允许的扩展名集合 (如 {'.py', '.js'})

        Returns:
            True 表示应该忽略
        """
        ext = Path(filepath).suffix.lower()
        return ext not in allowed_extensions
```

**3. 集成到 Indexer (`indexer/indexer.py`)**

```python
from .file_filter import FileFilter

class CodeIndexer:
    def __init__(self, ...):
        # ...
        self.file_filter = FileFilter(project_root=config.scan.target_path)

    def parse_directory(self, directory: str, ...) -> List[CodeUnit]:
        """解析目录"""
        # ...

        for file_path in all_files:
            # 应用过滤规则
            if self.file_filter.should_ignore(file_path):
                logger.debug(f"Ignored by pattern: {file_path}")
                continue

            if self.file_filter.should_ignore_by_size(file_path, self.config.scan.max_file_size_kb):
                logger.debug(f"Ignored by size: {file_path}")
                continue

            # 解析文件...
```

#### 验收标准

- [ ] 支持 `.auditignore` 文件 (类 .gitignore 语法)
- [ ] 自动读取 `.gitignore` 规则
- [ ] 内置默认排除规则 (node_modules, .git 等)
- [ ] 支持文件大小过滤 (可配置)
- [ ] 支持文件扩展名白名单过滤
- [ ] 过滤日志记录

---

## 四、风险评估与缓解措施

### 4.1 风险矩阵

| 风险项 | 可能性 | 影响 | 风险等级 | 缓解措施 |
|--------|--------|------|----------|----------|
| Prompt 模板迁移导致分析质量下降 | 中 | 高 | **高** | 1. 保留旧 Prompt 作为 fallback<br>2. A/B 测试新旧 Prompt<br>3. 逐步切换,先小范围试点 |
| Token 截断导致上下文不完整 | 高 | 中 | **高** | 1. 优先级机制保证关键内容<br>2. 截断后添加提示信息<br>3. 监控截断率 |
| 配置验证过严导致无法启动 | 中 | 中 | **中** | 1. 提供详细错误提示<br>2. 支持 `--skip-validation` 参数<br>3. 文档说明所有配置项 |
| 文件过滤过滤掉重要文件 | 低 | 高 | **中** | 1. 日志记录所有被过滤的文件<br>2. 提供 `--verbose` 模式<br>3. `.auditignore` 支持取反规则 |
| 多模型集成引入新 Bug | 中 | 中 | **中** | 1. 先支持 1-2 家厂商<br>2. 充分测试再上线<br>3. 保留单模型模式作为稳定版本 |

### 4.2 回滚策略

**Prompt 模板工程化回滚**

```python
# 保留旧代码作为 fallback
USE_LEGACY_PROMPTS = os.environ.get("AUDIT_USE_LEGACY_PROMPTS", "false") == "true"

if USE_LEGACY_PROMPTS:
    from .prompts import build_chain_analysis_prompt  # 旧实现
    system, user = build_chain_analysis_prompt(...)
else:
    from prompts.manager import get_prompt_manager      # 新实现
    pm = get_prompt_manager()
    system, user, _ = pm.render(...)
```

**配置验证回滚**

```bash
# 启动参数支持跳过验证
python3 start.py all --skip-validation
```

---

## 五、实施时间线

### 阶段一: P0 核心工程化 (2周)

**Week 1**
- [ ] Day 1-2: Prompt 模板工程化设计与实现
- [ ] Day 3-4: Token 控制策略实现
- [ ] Day 5: 单元测试和集成测试

**Week 2**
- [ ] Day 1-2: 配置统一验证实现
- [ ] Day 3-4: 文件过滤机制实现
- [ ] Day 5: 整体联调和文档更新

### 阶段二: P1 高级功能 (3周)

**Week 3**
- [ ] 多模型工厂模式设计
- [ ] OpenAI/Claude/Gemini 适配器实现

**Week 4**
- [ ] 事件驱动架构重构
- [ ] Agent 工具增强

**Week 5**
- [ ] 结果缓存策略实现
- [ ] 性能优化和压测

### 阶段三: P2 生态集成 (4周)

**Week 6-7**
- [ ] GitLab Webhook 集成
- [ ] MR 自动审计流程

**Week 8-9**
- [ ] SARIF 格式输出
- [ ] Docker 镜像优化
- [ ] 上线准备

---

## 六、验收清单

### 功能验收

**Prompt 模板工程化**
- [ ] 所有 Prompt 已外部化到 `prompts/templates/`
- [ ] 支持 Jinja2 变量替换
- [ ] Token 统计准确率 >95%
- [ ] 截断策略测试通过

**Token 控制策略**
- [ ] 超限自动截断功能正常
- [ ] 优先级机制生效
- [ ] Token 日志记录完整

**配置验证**
- [ ] 所有必填项验证生效
- [ ] 验证失败时中止启动
- [ ] 错误提示清晰

**文件过滤**
- [ ] `.auditignore` 文件解析正常
- [ ] 默认排除规则生效
- [ ] 过滤日志完整

### 性能验收

- [ ] 扫描速度无明显下降 (允许 ±10%)
- [ ] Token 用量降低 >20% (通过截断策略)
- [ ] 文件过滤后扫描文件数减少 >50%

### 文档验收

- [ ] 所有新功能有使用文档
- [ ] 配置项有完整说明
- [ ] 迁移指南完整
- [ ] 示例代码可运行

---

## 七、参考资源

### 学习资源

**Prompt 工程**
- [OpenAI Prompt Engineering Guide](https://platform.openai.com/docs/guides/prompt-engineering)
- [Anthropic Prompt Design](https://docs.anthropic.com/claude/docs/prompt-design)

**Token 优化**
- [tiktoken 官方文档](https://github.com/openai/tiktoken)
- [OpenAI Token Counting](https://platform.openai.com/docs/guides/text-generation/managing-tokens)

**配置管理**
- [Pydantic Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)
- [12-Factor App Config](https://12factor.net/config)

### 相关项目

- [AI-Codereview-Gitlab](https://github.com/mimo-x/AI-Codereview-Gitlab) - GitLab MR 自动审查
- [Semgrep](https://semgrep.dev/) - 静态分析工具参考
- [CodeQL](https://codeql.github.com/) - 代码查询语言参考

---

## 八、附录

### A. Prompt 模板目录结构完整示例

```
prompts/
├── templates/
│   ├── chain_analysis/
│   │   ├── system.jinja2
│   │   ├── user.jinja2
│   │   └── categories/
│   │       ├── command_exec.jinja2
│   │       ├── sql_injection.jinja2
│   │       ├── file_read.jinja2
│   │       ├── file_write.jinja2
│   │       ├── deserialization.jinja2
│   │       ├── ssrf.jinja2
│   │       └── xss.jinja2
│   ├── single_point/
│   │   ├── system.jinja2
│   │   └── user.jinja2
│   └── agent/
│       ├── task_builder.jinja2
│       └── tool_calling.jinja2
├── versions/
│   ├── v1.0/
│   │   └── chain_analysis/
│   │       └── system.jinja2
│   └── v1.1/
│       └── chain_analysis/
│           └── system.jinja2
├── configs/
│   └── prompt_config.yaml
├── manager.py
├── __init__.py
└── README.md
```

### B. 配置文件完整示例 (audit.config.yaml)

```yaml
# LLM 驱动的代码审计工具 - 配置文件
# 优先级: 默认配置 → 配置文件 → 环境变量 → 命令行参数

llm:
  provider: openai-compatible
  base_url: "https://api.openai.com/v1"
  api_key: "${OPENAI_API_KEY}"  # 支持环境变量引用
  model: "gpt-4"
  embedding_model: "text-embedding-3-small"
  max_tokens: 4096
  temperature: 0.0
  timeout: 60
  max_retries: 3

  # Token 预算控制
  max_code_tokens_per_call: 3000
  max_context_tokens: 6000

  # 多轮分析配置
  enable_multi_round: true
  max_rounds: 2

vector_store:
  provider: qdrant
  host: localhost
  port: 6333
  collection_name: code_audit
  enable_cache: true
  cache_dir: ".audit_cache"
  cache_ttl_days: 30

scan:
  target_path: "."
  languages:
    - python
    - javascript
    - php
  max_file_size_kb: 500
  max_concurrent: 4
  mode: full  # fast-rule, llm-deep, full, hotspot

  # 文件过滤配置
  use_auditignore: true         # 是否使用 .auditignore
  use_gitignore: true           # 是否读取 .gitignore
  custom_ignore_patterns:        # 额外的忽略规则
    - "**/*.min.js"
    - "**/*.bundle.js"

rules:
  rules_dir: "rules/data"
  enabled_categories:
    - auth
    - access-control
    - business-logic
    - injection
    - deserialization
    - file
  risk_threshold: low
  min_confidence: 0.5

security:
  mask_api_key_in_logs: true
  api_key_mask_length: 4
  enable_desensitization: false
  disable_remote_code_logging: true
  max_code_in_logs: 200

report:
  output_format: json
  output_path: "./audit_report"
  include_evidence: true
  include_fix_suggestions: true
  min_confidence: 0.5

debug: false
log_level: INFO
```

### C. `.auditignore` 示例

```gitignore
# CodeScan 扫描忽略规则
# 语法与 .gitignore 相同

# ============ 依赖目录 ============
node_modules/
vendor/
bower_components/
packages/
*.egg-info/

# ============ 构建产物 ============
dist/
build/
out/
*.min.js
*.min.css
*.bundle.js
*.chunk.js

# ============ 测试文件 ============
**/*.test.js
**/*.spec.ts
**/*.test.py
tests/
__tests__/
test/
spec/

# ============ 配置文件 ============
.env*
*.config.js
webpack*.js
rollup.config.js
vite.config.ts

# ============ 文档 ============
docs/
*.md
!SECURITY.md  # 取反规则: 保留 SECURITY.md

# ============ 二进制文件 ============
*.exe
*.dll
*.so
*.dylib

# ============ 日志和数据 ============
*.log
*.csv
*.json  # 可选择性忽略
data/

# ============ IDE 和编辑器 ============
.idea/
.vscode/
*.swp
*.swo
*~

# ============ 临时文件 ============
*.tmp
*.temp
*.cache
.DS_Store
Thumbs.db
```

---

**文档结束**
