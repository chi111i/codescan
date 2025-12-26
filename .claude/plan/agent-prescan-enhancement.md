# 智能体预扫描增强规划

## 需求概述

优化智能体逻辑，先利用规则扫描代码，（可选择的）高危、中危、低危漏洞，将扫描的函数或代码进行分析函数调用关系和污点传播路径，把以上内容作为智能体辅助信息，辅助智能体深入的漏洞挖掘。

## 已明确的决策

### 技术决策
- 基于现有 `SinkCallScanner` 确定性扫描器作为规则扫描预处理基础
- 基于现有 `CallChainAnalyzer` 和 `TaintAnalyzer` 作为调用链/污点分析基础
- 基于现有 `UnifiedAuditAgent` 作为智能体核心，扩展其工具系统
- 基于现有 `RiskLevel` 枚举（LOW/MEDIUM/HIGH/CRITICAL）支持风险等级过滤
- 复用现有的 `ChainContext` 和 `ChainContextCollector` 收集上下文

### 用户确认的设计决策
| 问题 | 用户选择 |
|------|----------|
| 预扫描结果展示方式 | **WebSocket 实时推送** |
| 默认扫描风险等级 | **仅 HIGH + CRITICAL** |
| 预扫描结果缓存策略 | **SQLite 持久化**（跨会话复用） |
| 智能体信息获取方式 | **主动注入上下文**（系统提示词包含摘要） |

---

## 整体规划概述

### 项目目标

构建"规则扫描 -> 深度分析 -> 智能体辅助挖掘"的三层漏洞挖掘流水线：

1. **规则扫描层**：用静态规则快速发现可疑代码点
2. **分析增强层**：对可疑点进行调用链和污点传播分析
3. **智能体深挖层**：将以上分析结果作为上下文，辅助 LLM 进行深度漏洞挖掘

### 技术栈

- 后端：Python 3.x + FastAPI
- 分析引擎：`analyzer/` 模块（SinkCallScanner、CallChainAnalyzer、TaintAnalyzer）
- 智能体：`agent/` 模块（UnifiedAuditAgent、AgentToolManager）
- 规则系统：`rules/` 模块（RuleManager、SecurityRule）
- 数据模型：dataclass + Pydantic

### 主要阶段

| 阶段 | 内容 | 预估工作量 |
|------|------|------------|
| 阶段 1 | 规则扫描预处理器 | 4-6 小时 |
| 阶段 2 | 深度分析增强器 | 8-10 小时 |
| 阶段 3 | 智能体上下文集成 | 6-8 小时 |
| 阶段 4 | API 集成与测试 | 5-7 小时 |

---

## 详细任务分解

### 阶段 1：规则扫描预处理器

#### 任务 1.1：创建 `RuleScanPreprocessor` 类

- **目标**：封装规则扫描逻辑，提供统一的预处理接口
- **输入**：代码单元列表、语言、风险等级过滤条件
- **输出**：标准化的 `PreScanResult` 数据结构
- **涉及文件**：
  - 新建 `analyzer/prescan.py`
  - 修改 `analyzer/__init__.py`（导出新模块）

**核心数据结构设计**：
```python
@dataclass
class PreScanResult:
    """规则预扫描结果"""
    sink_sites: List[SinkCallSite]           # 发现的危险函数触发点
    risk_summary: Dict[str, int]              # 按风险等级统计
    category_summary: Dict[str, int]          # 按类别统计
    filtered_risk_levels: List[str]           # 用户选择的风险等级
    scan_time_ms: int                         # 扫描耗时
    metadata: Dict[str, Any]                  # 附加信息
```

#### 任务 1.2：实现风险等级过滤逻辑

- **目标**：支持用户选择性扫描高危/中危/低危漏洞
- **输入**：风险等级列表（如 `["high", "critical"]`）
- **输出**：按风险等级过滤后的 `SinkCallSite` 列表
- **涉及文件**：
  - 修改 `analyzer/prescan.py`

**过滤逻辑设计**：
```python
def filter_by_risk_levels(
    sink_sites: List[SinkCallSite],
    risk_levels: List[str]  # ["low", "medium", "high", "critical"]
) -> List[SinkCallSite]:
    """按风险等级过滤"""
    if not risk_levels:
        return sink_sites  # 空列表表示不过滤

    level_set = {RiskLevel(level) for level in risk_levels}
    return [site for site in sink_sites if site.risk_level in level_set]
```

#### 任务 1.3：创建预扫描配置模型

- **目标**：定义预扫描的配置参数
- **涉及文件**：
  - 修改 `analyzer/prescan.py`

```python
@dataclass
class PreScanConfig:
    """预扫描配置"""
    enabled_risk_levels: List[str] = field(default_factory=lambda: ["high", "critical"])
    enabled_categories: Optional[List[str]] = None  # None 表示全部
    max_candidates: int = 100
    enable_call_chain_analysis: bool = True
    enable_taint_analysis: bool = True
    max_chain_depth: int = 5
```

---

### 阶段 2：深度分析增强器

#### 任务 2.1：创建 `DeepAnalysisEnhancer` 类

- **目标**：整合调用链和污点分析，生成增强的分析上下文
- **输入**：`PreScanResult` + 代码单元列表
- **输出**：`EnhancedAnalysisContext` 包含调用链和污点信息
- **涉及文件**：
  - 新建 `analyzer/enhancer.py`
  - 修改 `analyzer/__init__.py`

**核心数据结构设计**：
```python
@dataclass
class EnhancedSinkContext:
    """增强的 Sink 上下文"""
    sink_site: SinkCallSite                  # 原始 Sink 信息
    call_chain: Optional[ChainContext]       # 调用链上下文
    taint_flows: List[TaintFlow]             # 污点传播路径
    entry_points: List[str]                  # 入口点列表
    has_user_input: bool                     # 是否有用户输入
    sanitizers_found: List[str]             # 发现的过滤器
    confidence_score: float                  # 综合置信度评分

@dataclass
class EnhancedAnalysisContext:
    """增强的分析上下文（用于智能体）"""
    prescan_result: PreScanResult            # 预扫描结果
    enhanced_sinks: List[EnhancedSinkContext]  # 增强后的 Sink 上下文列表
    call_graph_summary: Dict[str, Any]       # 调用图摘要
    analysis_time_ms: int                    # 分析耗时
```

#### 任务 2.2：实现调用链分析集成

- **目标**：为每个 `SinkCallSite` 收集调用链上下文
- **涉及文件**：
  - 修改 `analyzer/enhancer.py`
  - 复用 `analyzer/chain_context.py`（ChainContextCollector）

**实现要点**：
- 复用现有 `ChainContextCollector.collect_context()` 方法
- 控制调用链深度防止爆炸
- 并行处理多个 Sink 提高效率

#### 任务 2.3：实现污点分析集成

- **目标**：为每个 `SinkCallSite` 追踪污点传播路径
- **涉及文件**：
  - 修改 `analyzer/enhancer.py`
  - 复用 `analyzer/taint_analysis.py`（TaintAnalyzer）

**实现要点**：
- 复用现有 `TaintAnalyzer.find_taint_flows_to_sink()` 方法
- 识别 Source -> Sink 的完整路径
- 标记路径上的 Sanitizer

#### 任务 2.4：实现置信度评分算法

- **目标**：根据多种因素计算综合置信度评分
- **涉及文件**：
  - 修改 `analyzer/enhancer.py`

**评分因素**：
```python
def calculate_confidence(
    has_user_input: bool,          # +0.3 如果存在用户输入
    chain_length: int,             # 越短越可疑
    has_sanitizer: bool,           # -0.2 如果有过滤器
    is_entry_point_reachable: bool,  # +0.2 如果可从入口点到达
    taint_flow_exists: bool,       # +0.2 如果存在污点路径
) -> float:
    pass
```

---

### 阶段 3：智能体上下文集成

#### 任务 3.1：扩展智能体系统提示词

- **目标**：让智能体了解预扫描和深度分析的结果
- **涉及文件**：
  - 修改 `agent/unified_agent.py`（`_build_system_prompt` 方法）

**提示词模板设计**：
```python
ENHANCED_SYSTEM_PROMPT = """
## 预扫描分析结果

已通过规则扫描发现以下可疑代码点：

### 风险统计
{risk_summary}

### 高优先级目标
{top_priority_sinks}

### 调用链分析结果
{call_chain_summary}

### 污点传播分析结果
{taint_flow_summary}

## 你的任务

基于以上预扫描结果，请深入分析：
1. 验证这些可疑点是否为真实漏洞
2. 寻找预扫描可能遗漏的相关漏洞
3. 分析业务逻辑层面的安全问题
"""
```

#### 任务 3.2：新增辅助信息注入工具

- **目标**：让智能体可以动态获取预扫描结果
- **涉及文件**：
  - 修改 `agent/unified_agent.py`（新增工具注册）
  - 修改 `agent/tools/registry.py`（新增工具定义）

**新增工具定义**：
```python
# 1. get_prescan_results - 获取规则预扫描结果
# 2. get_sink_details - 获取特定 Sink 的详细分析
# 3. get_call_chain_for_sink - 获取特定 Sink 的调用链
# 4. get_taint_flows - 获取污点传播路径
# 5. filter_sinks_by_risk - 按风险等级过滤 Sink 列表
```

#### 任务 3.3：创建分析流水线编排器

- **目标**：协调预扫描、深度分析、智能体分析的完整流程
- **涉及文件**：
  - 新建 `analyzer/pipeline.py`
  - 修改 `analyzer/__init__.py`

**流水线设计**：
```python
class AnalysisPipeline:
    """分析流水线编排器"""

    def __init__(
        self,
        config: AuditConfig,
        llm_client: BaseLLMClient,
        rule_manager: RuleManager,
    ):
        self.preprocessor = RuleScanPreprocessor(rule_manager)
        self.enhancer = DeepAnalysisEnhancer(rule_manager)
        self.agent = None  # 延迟初始化

    async def run(
        self,
        code_units: List[CodeUnit],
        prescan_config: PreScanConfig,
    ) -> List[Finding]:
        """执行完整分析流水线

        1. 规则预扫描
        2. 深度分析增强
        3. 智能体深挖
        """
        # Step 1: 规则预扫描
        prescan_result = self.preprocessor.scan(code_units, prescan_config)

        # Step 2: 深度分析增强
        enhanced_context = self.enhancer.enhance(prescan_result, code_units)

        # Step 3: 智能体分析（带上下文）
        findings = await self._run_agent_with_context(enhanced_context)

        return findings
```

#### 任务 3.4：更新智能体初始化流程

- **目标**：在智能体初始化时注入预分析上下文
- **涉及文件**：
  - 修改 `agent/unified_agent.py`（`initialize` 方法）

---

### 阶段 4：API 集成与测试

#### 任务 4.1：更新扫描 API 端点

- **目标**：支持新的预扫描配置参数
- **涉及文件**：
  - 修改 `api/main.py`（扫描端点）
  - 修改 `api/models.py`（请求/响应模型）

**API 设计**：
```python
class ScanRequest(BaseModel):
    target_path: str
    language: Optional[str] = None
    # 新增预扫描配置
    prescan_config: Optional[PreScanConfigModel] = None

class PreScanConfigModel(BaseModel):
    enabled_risk_levels: List[str] = ["high", "critical"]
    enable_call_chain_analysis: bool = True
    enable_taint_analysis: bool = True
    max_chain_depth: int = 5
```

#### 任务 4.2：新增预扫描专用端点

- **目标**：提供独立的预扫描 API，支持快速预览
- **涉及文件**：
  - 修改 `api/main.py`

```python
@app.post("/api/prescan")
async def prescan(request: PreScanRequest):
    """快速规则预扫描（不触发 LLM）"""
    pass
```

#### 任务 4.3：编写单元测试

- **涉及文件**：
  - 新建 `tests/test_prescan.py`
  - 新建 `tests/test_enhancer.py`
  - 新建 `tests/test_pipeline.py`

#### 任务 4.4：端到端集成测试

- **涉及文件**：
  - 新建 `tests/test_e2e_pipeline.py`

---

## 需要进一步明确的问题

### 问题 1：预扫描结果的展示方式

- **方案 A：WebSocket 实时推送**（推荐，与现有扫描进度推送一致）
  - 优点：用户体验好，可以看到预扫描进度
  - 缺点：实现复杂度略高

- **方案 B：API 轮询**
  - 优点：实现简单
  - 缺点：用户体验略差

### 问题 2：风险等级过滤的默认值

- **方案 A：默认只扫描 HIGH + CRITICAL**（推荐）
  - 优点：减少噪音，聚焦高危漏洞

- **方案 B：默认扫描全部等级**
  - 优点：召回率高

### 问题 3：预扫描结果缓存策略

- **方案 A：内存缓存（会话级）**（推荐作为初始实现）
  - 优点：实现简单，同一会话内复用

- **方案 B：持久化缓存（SQLite）**
  - 优点：跨会话复用

### 问题 4：智能体工具调用的限制

- **方案 A：主动注入上下文，减少工具调用**（推荐）
  - 在系统提示词中直接包含预扫描摘要

- **方案 B：完全依赖工具调用**
  - 智能体自主决定何时获取信息

---

## 文件修改清单

### 新建文件
| 文件路径 | 描述 |
|----------|------|
| `analyzer/prescan.py` | 规则扫描预处理器 |
| `analyzer/enhancer.py` | 深度分析增强器 |
| `analyzer/pipeline.py` | 分析流水线编排器 |
| `tests/test_prescan.py` | 预扫描单元测试 |
| `tests/test_enhancer.py` | 增强器单元测试 |
| `tests/test_pipeline.py` | 流水线单元测试 |

### 修改文件
| 文件路径 | 修改内容 |
|----------|----------|
| `analyzer/__init__.py` | 导出新模块 |
| `agent/unified_agent.py` | 扩展系统提示词、新增工具、注入上下文 |
| `agent/tools/registry.py` | 新增预扫描相关工具定义 |
| `api/main.py` | 更新扫描端点、新增预扫描端点 |
| `api/models.py` | 新增请求/响应模型 |

---

## 架构依赖关系

```
                    ┌──────────────────────┐
                    │   RuleScanPreprocessor   │
                    │   (新建 prescan.py)      │
                    └──────────┬───────────┘
                               │ PreScanResult
                               ▼
                    ┌──────────────────────┐
                    │   DeepAnalysisEnhancer  │
                    │   (新建 enhancer.py)    │
                    └──────────┬───────────┘
         ┌─────────────────────┼─────────────────────┐
         ▼                     ▼                     ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ ChainContextCollector│ │   TaintAnalyzer   │ │ ConfidenceScorer │
│   (现有)              │ │   (现有)            │ │   (新建)           │
└─────────────────┘   └─────────────────┘   └─────────────────┘
                               │
                               ▼ EnhancedAnalysisContext
                    ┌──────────────────────┐
                    │   UnifiedAuditAgent    │
                    │   (修改)                 │
                    └──────────────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   AnalysisPipeline     │
                    │   (新建 pipeline.py)   │
                    └──────────────────────┘
```

---

## 风险识别与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| 调用链分析爆炸 | 分析时间过长 | 设置 max_depth 限制，路径去重 |
| 预扫描结果过多 | 智能体上下文超长 | 按优先级截取 Top N 结果 |
| 污点分析假阳性 | 误报增加 | 结合 Sanitizer 检测，调整置信度 |
| LLM 调用次数过多 | 成本增加 | 批量处理，结果缓存 |

---

## 验收标准

1. [ ] 规则预扫描可正常发现危险函数触发点
2. [ ] 风险等级过滤功能正常工作
3. [ ] 调用链分析可为 Sink 生成调用路径
4. [ ] 污点分析可追踪 Source -> Sink 路径
5. [ ] 智能体系统提示词包含预扫描摘要
6. [ ] 智能体可通过工具获取详细分析结果
7. [ ] API 端点支持新的预扫描配置
8. [ ] 单元测试和集成测试通过
