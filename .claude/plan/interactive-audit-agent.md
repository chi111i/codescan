# 交互式代码审计 LLM 智能体 - 实现计划

## 1. 项目概述

### 1.1 目标
开发一个可对话、可自定义、可选择的交互式代码审计 LLM 智能体，提供以下核心能力：

1. **可视化浏览**：前端展示调用链上下文和代码单元，用户可以浏览和理解代码结构
2. **人工选择**：用户可以勾选部分内容让 LLM 分析，而非一次性分析全部
3. **对话交互**：与 LLM 进行对话，查看具体回复内容
4. **人工确认**：LLM 的发现需要人工确认后才进入最终报告
5. **交互控制**：用户可以控制分析流程（停止、总结、深入查找等）

### 1.2 设计原则
- **用户主导**：所有 LLM 调用由用户触发，没有自动调用限制
- **透明可见**：LLM 的每次响应内容完全展示给用户
- **渐进式分析**：支持分步骤、分模块的渐进式审计
- **会话保持**：支持多轮对话，LLM 可以在上下文中追问

---

## 2. 系统架构

### 2.1 整体架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                        前端 (Vue 3)                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌────────────┐│
│  │ 代码浏览器   │ │ 调用链视图  │ │ LLM对话面板  │ │ 发现管理   ││
│  │ CodeBrowser │ │ ChainView   │ │ ChatPanel   │ │ Findings   ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └────────────┘│
│                           │                                      │
│                    ┌──────┴──────┐                              │
│                    │ WebSocket   │                              │
│                    └──────┬──────┘                              │
└───────────────────────────┼─────────────────────────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────────────┐
│                        后端 (FastAPI)                            │
├───────────────────────────┼─────────────────────────────────────┤
│                    ┌──────┴──────┐                              │
│                    │ Interactive │                              │
│                    │   Router    │                              │
│                    └──────┬──────┘                              │
│   ┌─────────────┐ ┌──────┴──────┐ ┌─────────────┐              │
│   │ Session     │ │ Audit Agent │ │ Finding     │              │
│   │ Manager     │ │ Controller  │ │ Manager     │              │
│   └─────────────┘ └──────┬──────┘ └─────────────┘              │
│                          │                                      │
│   ┌──────────────────────┴─────────────────────────┐           │
│   │              InteractiveAuditAgent              │           │
│   │  ┌─────────┐ ┌──────────┐ ┌─────────────────┐  │           │
│   │  │ Context │ │ LLM Chat │ │ Finding         │  │           │
│   │  │ Builder │ │ Handler  │ │ Processor       │  │           │
│   │  └─────────┘ └──────────┘ └─────────────────┘  │           │
│   └────────────────────────────────────────────────┘           │
│                          │                                      │
│   ┌──────────────────────┴─────────────────────────┐           │
│   │           现有模块 (Existing Modules)           │           │
│   │  SinkScanner │ ChainContextCollector │ LLMClient │         │
│   └────────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 核心组件

#### 后端组件
1. **InteractiveAuditAgent** - 交互式审计代理核心
2. **SessionManager** - 会话管理器（维护对话上下文）
3. **AuditAgentController** - API 控制器
4. **FindingManager** - 发现管理（人工确认工作流）

#### 前端组件
1. **InteractiveAudit.vue** - 交互式审计主页面
2. **CodeBrowser.vue** - 代码单元浏览器（支持选择）
3. **ChainContextViewer.vue** - 调用链上下文可视化
4. **LLMChatPanel.vue** - LLM 对话面板
5. **FindingReview.vue** - 发现审核面板

---

## 3. 后端实现计划

### 3.1 新增文件结构

```
analyzer/
├── interactive_agent.py      # 交互式审计代理
├── session_manager.py        # 会话管理
└── finding_workflow.py       # 发现确认工作流

api/
├── interactive_router.py     # 交互式审计 API 路由
└── schemas_interactive.py    # 交互式审计数据模型
```

### 3.2 InteractiveAuditAgent 设计

```python
class InteractiveAuditAgent:
    """交互式代码审计代理

    核心职责：
    1. 管理审计会话上下文
    2. 响应用户命令（分析、追问、总结等）
    3. 构建 LLM 提示词
    4. 处理 LLM 响应
    """

    def __init__(self, session_id: str, llm_client: BaseLLMClient, ...):
        self.session_id = session_id
        self.llm_client = llm_client
        self.conversation_history: List[ChatMessage] = []
        self.current_context: Optional[AnalysisContext] = None
        self.pending_findings: List[Finding] = []
        self.confirmed_findings: List[Finding] = []

    # === 核心命令 ===
    async def analyze_selection(
        self,
        selected_items: List[str],  # 用户选择的代码单元/调用链 ID
        focus_areas: Optional[List[str]] = None,
    ) -> AgentResponse:
        """分析用户选择的内容"""
        pass

    async def chat(
        self,
        message: str,
    ) -> AgentResponse:
        """与 LLM 对话（在当前上下文中）"""
        pass

    async def dig_deeper(
        self,
        finding_id: str,
        direction: str = "expand",  # expand/trace_source/trace_sink
    ) -> AgentResponse:
        """深入分析某个发现"""
        pass

    async def summarize(self) -> AgentResponse:
        """生成当前分析的总结报告"""
        pass

    async def stop_analysis(self) -> AgentResponse:
        """停止当前分析，保存状态"""
        pass

    # === 发现管理 ===
    def confirm_finding(self, finding_id: str, notes: str = "") -> bool:
        """确认一个发现"""
        pass

    def reject_finding(self, finding_id: str, reason: str = "") -> bool:
        """拒绝一个发现"""
        pass

    def get_pending_findings(self) -> List[Finding]:
        """获取待确认的发现"""
        pass
```

### 3.3 API 端点设计

```python
# api/interactive_router.py

# === 会话管理 ===
POST   /api/interactive/session/start     # 开始新的交互式审计会话
GET    /api/interactive/session/{id}      # 获取会话状态
DELETE /api/interactive/session/{id}      # 结束会话

# === 代码浏览 ===
GET    /api/interactive/code-units        # 获取代码单元列表（支持过滤）
GET    /api/interactive/code-units/{id}   # 获取单个代码单元详情
GET    /api/interactive/sink-sites        # 获取危险函数触发点
GET    /api/interactive/chain-contexts    # 获取调用链上下文

# === LLM 交互 ===
POST   /api/interactive/analyze           # 分析选中的内容
POST   /api/interactive/chat              # 与 LLM 对话
POST   /api/interactive/dig-deeper        # 深入分析
POST   /api/interactive/summarize         # 生成总结

# === 发现管理 ===
GET    /api/interactive/findings          # 获取所有发现（分：待确认/已确认/已拒绝）
POST   /api/interactive/findings/{id}/confirm   # 确认发现
POST   /api/interactive/findings/{id}/reject    # 拒绝发现
PUT    /api/interactive/findings/{id}/notes     # 添加备注

# === WebSocket ===
WS     /ws/interactive/{session_id}       # 实时通信（LLM 响应流、状态更新）
```

### 3.4 数据模型

```python
# api/schemas_interactive.py

class InteractiveSessionSchema(BaseModel):
    """交互式会话"""
    session_id: str
    target_path: str
    status: str  # idle, analyzing, waiting_confirmation
    created_at: datetime
    code_units_count: int
    sink_sites_count: int
    chain_contexts_count: int
    pending_findings_count: int
    confirmed_findings_count: int

class AnalyzeRequest(BaseModel):
    """分析请求"""
    session_id: str
    selected_items: List[str]  # 代码单元/调用链 ID 列表
    focus_areas: Optional[List[str]] = None  # 关注的漏洞类型
    custom_prompt: Optional[str] = None  # 用户自定义提示

class ChatRequest(BaseModel):
    """对话请求"""
    session_id: str
    message: str

class DigDeeperRequest(BaseModel):
    """深入分析请求"""
    session_id: str
    finding_id: str
    direction: str = "expand"  # expand/trace_source/trace_sink

class AgentResponseSchema(BaseModel):
    """代理响应"""
    session_id: str
    response_type: str  # analysis/chat/summary/finding
    content: str  # LLM 原始响应内容
    findings: List[FindingSchema] = []  # 本次发现
    suggestions: List[str] = []  # 后续建议
    metadata: Dict[str, Any] = {}

class ChainContextSchema(BaseModel):
    """调用链上下文（前端展示用）"""
    id: str
    sink_site: SinkSiteSchema
    chain_nodes: List[ChainNodeSchema]
    entry_point: Optional[ChainNodeSchema]
    chain_length: int
    has_user_input: bool
    sanitizers_on_path: List[str]
    risk_level: str
    confidence: float
    prompt_text: str  # 用于展示的格式化文本

class SinkSiteSchema(BaseModel):
    """危险函数触发点"""
    id: str
    unit_id: str
    file_path: str
    line_start: int
    line_end: int
    symbol: str
    sink_category: str
    risk_level: str
    call_snippet: str
    matched_rule_ids: List[str]

class ChainNodeSchema(BaseModel):
    """调用链节点"""
    symbol: str
    qualified_name: str
    file_path: str
    line_start: int
    line_end: int
    node_type: str
    code: str
    is_sink: bool
```

---

## 4. 前端实现计划

### 4.1 新增文件结构

```
frontend/src/
├── views/
│   └── InteractiveAudit.vue      # 交互式审计主页面
├── components/
│   ├── interactive/
│   │   ├── CodeBrowser.vue       # 代码单元浏览器
│   │   ├── ChainContextViewer.vue # 调用链可视化
│   │   ├── LLMChatPanel.vue      # LLM 对话面板
│   │   ├── FindingReview.vue     # 发现审核面板
│   │   ├── SelectionPanel.vue    # 选择面板（已选内容）
│   │   └── ContextPreview.vue    # 上下文预览
│   └── ...
├── composables/
│   └── useInteractiveAudit.ts    # 交互式审计组合函数
└── types/
    └── interactive.ts            # 类型定义
```

### 4.2 InteractiveAudit.vue 页面布局

```
┌─────────────────────────────────────────────────────────────────┐
│  [目标路径输入] [开始会话] [结束会话]              状态: 空闲     │
├───────────────────┬─────────────────────────────────────────────┤
│                   │                                             │
│   代码浏览器       │              LLM 对话面板                   │
│  (可选择内容)      │                                             │
│                   │  ┌─────────────────────────────────────────┐│
│  ☐ function A     │  │ [系统消息]                              ││
│  ☐ function B     │  │ 已准备好分析，请选择要分析的代码单元...    ││
│  ☑ function C     │  │                                         ││
│  ☐ class D        │  │ [用户] 分析 function C 的命令注入风险     ││
│    ☑ method E     │  │                                         ││
│    ☐ method F     │  │ [LLM] 我分析了 function C，发现...       ││
│                   │  │ ... (完整 LLM 响应内容)                  ││
│  ─────────────    │  │                                         ││
│  调用链视图        │  │ [新发现] 命令注入漏洞 - 待确认            ││
│                   │  │   [确认] [拒绝] [深入分析]               ││
│  ☐ Chain 1        │  └─────────────────────────────────────────┘│
│  ☑ Chain 2        │                                             │
│  ☐ Chain 3        │  ┌─────────────────────────────────────────┐│
│                   │  │ 输入消息...                    [发送]    ││
│                   │  └─────────────────────────────────────────┘│
│                   │                                             │
│  [分析选中内容]    │  快捷命令: [总结报告] [停止分析] [清空对话]  │
├───────────────────┴─────────────────────────────────────────────┤
│  已确认发现 (3)  │  待确认发现 (2)  │  已拒绝 (1)               │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ ☑ 命令注入 - function C:15  [High]  [查看详情] [编辑备注]  ││
│  │ ☑ SQL注入 - function E:42   [Critical] ...                 ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 4.3 核心组件设计

#### CodeBrowser.vue - 代码浏览器
```vue
<template>
  <div class="code-browser">
    <!-- 过滤器 -->
    <div class="filters">
      <select v-model="filterLanguage">...</select>
      <select v-model="filterType">...</select>
      <input v-model="searchKeyword" placeholder="搜索..." />
    </div>

    <!-- 代码单元树 -->
    <div class="code-tree">
      <div v-for="unit in filteredUnits" :key="unit.id" class="tree-node">
        <input
          type="checkbox"
          :checked="isSelected(unit.id)"
          @change="toggleSelection(unit.id)"
        />
        <span class="symbol">{{ unit.symbol }}</span>
        <span class="meta">{{ unit.file_path }}:{{ unit.span.start_line }}</span>
        <span :class="['risk-badge', unit.riskLevel]">{{ unit.riskLevel }}</span>
      </div>
    </div>

    <!-- 调用链视图 -->
    <div class="chain-section">
      <h4>调用链上下文</h4>
      <div v-for="chain in chainContexts" :key="chain.id" class="chain-item">
        <input
          type="checkbox"
          :checked="isChainSelected(chain.id)"
          @change="toggleChainSelection(chain.id)"
        />
        <ChainMiniView :chain="chain" />
      </div>
    </div>

    <!-- 操作按钮 -->
    <div class="actions">
      <button @click="analyzeSelection" :disabled="selectedCount === 0">
        分析选中内容 ({{ selectedCount }})
      </button>
    </div>
  </div>
</template>
```

#### LLMChatPanel.vue - LLM 对话面板
```vue
<template>
  <div class="chat-panel">
    <!-- 对话历史 -->
    <div class="chat-history" ref="historyRef">
      <div
        v-for="msg in messages"
        :key="msg.id"
        :class="['message', msg.role]"
      >
        <div class="message-header">
          <span class="role">{{ msg.role === 'assistant' ? 'LLM' : '你' }}</span>
          <span class="time">{{ formatTime(msg.timestamp) }}</span>
        </div>
        <div class="message-content">
          <!-- 支持 Markdown 渲染 -->
          <MarkdownRenderer :content="msg.content" />
        </div>

        <!-- 如果消息包含发现 -->
        <div v-if="msg.findings?.length" class="findings-in-message">
          <FindingCard
            v-for="finding in msg.findings"
            :key="finding.id"
            :finding="finding"
            @confirm="confirmFinding"
            @reject="rejectFinding"
            @dig-deeper="digDeeper"
          />
        </div>
      </div>

      <!-- 正在输入指示器 -->
      <div v-if="isTyping" class="typing-indicator">
        LLM 正在思考...
      </div>
    </div>

    <!-- 输入区域 -->
    <div class="chat-input">
      <textarea
        v-model="inputMessage"
        placeholder="输入消息与 LLM 对话..."
        @keydown.enter.ctrl="sendMessage"
      />
      <button @click="sendMessage" :disabled="!inputMessage.trim()">
        发送
      </button>
    </div>

    <!-- 快捷命令 -->
    <div class="quick-commands">
      <button @click="summarize">生成总结报告</button>
      <button @click="stopAnalysis">停止分析</button>
      <button @click="clearChat">清空对话</button>
    </div>
  </div>
</template>
```

#### ChainContextViewer.vue - 调用链可视化
```vue
<template>
  <div class="chain-viewer">
    <h3>调用链详情</h3>

    <!-- 链路概览 -->
    <div class="chain-overview">
      <span class="label">Sink 类型:</span> {{ chain.sink_site.sink_category }}
      <span class="label">风险等级:</span>
      <span :class="['risk', chain.risk_level]">{{ chain.risk_level }}</span>
      <span class="label">链长:</span> {{ chain.chain_length }}
      <span v-if="chain.has_user_input" class="user-input-badge">包含用户输入</span>
    </div>

    <!-- 调用链可视化 -->
    <div class="chain-graph">
      <div
        v-for="(node, index) in chain.chain_nodes"
        :key="index"
        :class="['chain-node', node.node_type, { 'is-sink': node.is_sink }]"
      >
        <div class="node-header">
          <span class="node-type-icon">{{ getNodeIcon(node.node_type) }}</span>
          <span class="node-name">{{ node.qualified_name }}</span>
        </div>
        <div class="node-location">
          {{ node.file_path }}:{{ node.line_start }}
        </div>
        <div class="node-code">
          <pre><code>{{ node.code }}</code></pre>
        </div>

        <!-- 连接线 -->
        <div v-if="index < chain.chain_nodes.length - 1" class="connector">
          ↓
        </div>
      </div>
    </div>

    <!-- 原始提示文本（可选展示） -->
    <details class="prompt-preview">
      <summary>查看 LLM 提示文本</summary>
      <pre>{{ chain.prompt_text }}</pre>
    </details>
  </div>
</template>
```

### 4.4 状态管理

```typescript
// composables/useInteractiveAudit.ts

export function useInteractiveAudit() {
  // === 会话状态 ===
  const session = ref<InteractiveSession | null>(null)
  const isConnected = ref(false)

  // === 代码数据 ===
  const codeUnits = ref<CodeUnit[]>([])
  const sinkSites = ref<SinkSite[]>([])
  const chainContexts = ref<ChainContext[]>([])

  // === 选择状态 ===
  const selectedUnitIds = ref<Set<string>>(new Set())
  const selectedChainIds = ref<Set<string>>(new Set())

  // === 对话状态 ===
  const messages = ref<ChatMessage[]>([])
  const isTyping = ref(false)

  // === 发现状态 ===
  const pendingFindings = ref<Finding[]>([])
  const confirmedFindings = ref<Finding[]>([])
  const rejectedFindings = ref<Finding[]>([])

  // === WebSocket ===
  let ws: WebSocket | null = null

  // === 方法 ===
  async function startSession(targetPath: string) { ... }
  async function endSession() { ... }

  function toggleUnitSelection(unitId: string) { ... }
  function toggleChainSelection(chainId: string) { ... }

  async function analyzeSelection() { ... }
  async function sendChatMessage(message: string) { ... }
  async function digDeeper(findingId: string, direction: string) { ... }
  async function summarize() { ... }
  async function stopAnalysis() { ... }

  function confirmFinding(findingId: string, notes?: string) { ... }
  function rejectFinding(findingId: string, reason?: string) { ... }

  return {
    // 状态
    session,
    isConnected,
    codeUnits,
    sinkSites,
    chainContexts,
    selectedUnitIds,
    selectedChainIds,
    messages,
    isTyping,
    pendingFindings,
    confirmedFindings,
    rejectedFindings,
    // 方法
    startSession,
    endSession,
    toggleUnitSelection,
    toggleChainSelection,
    analyzeSelection,
    sendChatMessage,
    digDeeper,
    summarize,
    stopAnalysis,
    confirmFinding,
    rejectFinding,
  }
}
```

---

## 5. 交互流程

### 5.1 典型使用流程

```
1. 用户输入目标路径，点击"开始会话"
   └─> 后端：解析代码，生成代码单元和调用链上下文
   └─> 前端：显示代码浏览器和调用链视图

2. 用户浏览代码单元和调用链
   └─> 可以查看每个调用链的详细内容和代码
   └─> 可以预览 LLM 将收到的上下文

3. 用户勾选感兴趣的内容，点击"分析选中内容"
   └─> 后端：构建上下文，调用 LLM
   └─> 前端：显示 LLM 正在思考...
   └─> 后端：流式返回 LLM 响应
   └─> 前端：实时显示 LLM 响应内容

4. LLM 返回分析结果（可能包含发现）
   └─> 前端：显示完整响应
   └─> 如果有发现：显示发现卡片，包含 [确认] [拒绝] [深入] 按钮

5. 用户与 LLM 对话
   └─> 用户：输入追问，如"这个漏洞的前提条件是什么？"
   └─> LLM：基于上下文回答
   └─> 用户：继续追问或开始分析其他内容

6. 用户管理发现
   └─> 确认真实漏洞：添加备注，进入已确认列表
   └─> 拒绝误报：填写原因，进入已拒绝列表
   └─> 深入分析：LLM 进一步追踪数据流

7. 用户请求总结
   └─> LLM：生成当前审计会话的总结报告
   └─> 包含：已确认的漏洞、分析覆盖范围、建议后续关注点

8. 用户结束会话
   └─> 保存所有已确认的发现
   └─> 生成最终报告
```

### 5.2 LLM 命令设计

```
用户可通过以下方式与 LLM 交互：

1. 分析命令（由"分析选中内容"按钮触发）
   - 自动构建选中内容的上下文
   - LLM 进行安全分析

2. 自由对话
   - 用户可以直接输入任何问题
   - LLM 在当前上下文中回答

3. 预设命令（快捷按钮）
   - "总结报告"：生成当前审计的总结
   - "停止分析"：停止当前分析，保存状态
   - "深入分析"：针对某个发现追踪更多细节

4. 高级命令（可在输入框中使用）
   - /focus [漏洞类型]：聚焦特定类型的漏洞
   - /trace [变量名]：追踪某个变量的数据流
   - /expand [symbol]：展开分析某个函数的调用者/被调用者
```

---

## 6. 实现步骤

### Phase 1: 后端基础架构 (预计 2-3 天)
1. 创建 `InteractiveAuditAgent` 类
2. 创建 `SessionManager` 类
3. 实现基础 API 端点
4. 实现 WebSocket 实时通信

### Phase 2: 前端基础界面 (预计 2-3 天)
1. 创建 `InteractiveAudit.vue` 页面
2. 实现 `CodeBrowser.vue` 组件
3. 实现 `ChainContextViewer.vue` 组件
4. 实现基础状态管理

### Phase 3: LLM 对话功能 (预计 2 天)
1. 实现 `LLMChatPanel.vue` 组件
2. 实现流式响应显示
3. 实现对话历史管理
4. 实现上下文保持

### Phase 4: 发现管理 (预计 1-2 天)
1. 实现 `FindingReview.vue` 组件
2. 实现确认/拒绝工作流
3. 实现发现详情展示
4. 实现备注功能

### Phase 5: 高级功能 (预计 2 天)
1. 实现"深入分析"功能
2. 实现"总结报告"功能
3. 实现预设命令
4. 优化用户体验

### Phase 6: 测试与优化 (预计 1-2 天)
1. 端到端测试
2. 性能优化
3. 错误处理完善
4. 文档编写

---

## 7. 技术要点

### 7.1 LLM 上下文管理
- 保持合理的上下文长度，避免超出 token 限制
- 对话历史进行智能压缩
- 提供上下文预览功能

### 7.2 实时通信
- 使用 WebSocket 进行实时通信
- LLM 响应使用流式输出
- 实现重连机制

### 7.3 状态持久化
- 会话状态定期保存
- 支持会话恢复
- 发现数据持久化到数据库

### 7.4 用户体验
- 流畅的选择交互
- 清晰的视觉反馈
- 键盘快捷键支持

---

## 8. 后续扩展

1. **多模型支持**：允许用户选择不同的 LLM 模型
2. **提示词模板**：允许用户自定义分析提示词
3. **协作审计**：多人同时审计同一项目
4. **历史记录**：保存和复用历史审计会话
5. **导出功能**：导出审计报告为多种格式
