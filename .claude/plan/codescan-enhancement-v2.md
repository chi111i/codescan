# 项目任务分解规划 v2.0

## CodeScan 功能增强与 Bug 修复

---

## 已明确的决策（用户确认）

### 技术选择

| 决策项 | 选择结果 | 备注 |
|--------|----------|------|
| **调用图可视化库** | **Cytoscape.js** | 基于项目分析自动选择，专业图可视化库，API 友好 |
| **交互模式** | **方案 A + B 并存** | 前端提供切换选项：两步确认模式 / 一键分析+可选细化 |
| **大规模调用链处理** | **智能排序 + Top N + 分页** | 默认选中 Top 20，支持分页加载，用户可手动调整 |

### 技术栈

- **后端**：Python 3.x + FastAPI + SQLite（不变）
- **前端**：Vue 3 + Vite + Pinia + Tailwind CSS（不变）
- **新增依赖**：Cytoscape.js（图可视化）

---

## 阶段 1：Bug 修复与基础设施改进

**目标**：解决数据库唯一约束冲突问题

### 任务 1.1：修复 Finding ID 生成策略

**问题分析**：
```
ERROR - 批量 SQL 执行失败: UNIQUE constraint failed: scan_findings.id
```

`analyzer/engine.py` 中使用 `id=f"finding-{chain_id}"` 格式，`chain_id` 在多次扫描同一项目时重复。

**修复方案**：使用 `scan_id + 时间戳 + 序号` 组合确保唯一性

```python
# 修改 analyzer/engine.py
import time

finding_id = f"{scan_id[:8]}-{int(time.time())}-{counter:04d}"
```

**涉及文件**：
- `analyzer/engine.py` - 修改 Finding 创建逻辑（约第 857 行）
- `analyzer/models.py` - 可选：添加 `generate_id` 静态方法

---

### 任务 1.2：增加数据库 UPSERT 支持

**目标**：重复插入时使用 UPDATE 而非报错

**涉及文件**：
- `storage/finding_repository.py` - 修改 `create_many` 方法
- `storage/database.py` - 添加错误处理

**修复代码**：
```python
# storage/finding_repository.py - create_many 方法
sql = """
INSERT INTO scan_findings (id, scan_id, severity, confidence, ..., created_at)
VALUES (?, ?, ?, ?, ..., ?)
ON CONFLICT(id) DO UPDATE SET
    scan_id = excluded.scan_id,
    severity = excluded.severity,
    confidence = excluded.confidence,
    ...,
    updated_at = CURRENT_TIMESTAMP
"""
```

---

### 任务 1.3：修复文件路径验证警告

**问题分析**：
```
WARNING - [ChainLLM] 验证警告 chain-sink-0015: ['File does not exist: authbypass/change_user_details.php']
```

LLM 验证时相对路径未正确解析为绝对路径。

**涉及文件**：
- `analyzer/engine.py` - 文件验证逻辑
- `agent/tools/executor.py` - 工具执行时的路径处理

**修复方案**：在验证前将相对路径转换为绝对路径

```python
import os

def validate_file_path(file_path: str, base_path: str) -> str:
    if not os.path.isabs(file_path):
        file_path = os.path.join(base_path, file_path)
    return os.path.normpath(file_path)
```

---

## 阶段 2：触发点展示与用户选择

**目标**：前端展示所有 SinkCallSite，用户可选择要分析的项

### 任务 2.1：新增触发点列表 API

**端点**：`GET /api/scan/{scan_id}/sink-sites`

**涉及文件**：
- `api/main.py` - 新增端点
- `api/schemas.py` - 新增 `SinkSiteResponse` 模型

**API 响应格式**：
```json
{
    "success": true,
    "data": {
        "total": 106,
        "sites": [
            {
                "id": "sink-0001",
                "file_path": "app/auth.py",
                "line_start": 45,
                "line_end": 47,
                "symbol": "execute_query",
                "sink_category": "sql_injection",
                "risk_level": "critical",
                "call_snippet": "cursor.execute(query)",
                "matched_patterns": ["cursor.execute"],
                "code_unit_id": "unit-xxx"
            }
        ],
        "by_category": {
            "sql_injection": 29,
            "command_exec": 15,
            "code_exec": 3,
            "file_read": 11,
            "xss": 33,
            "ssrf": 15
        },
        "by_risk": {
            "critical": 71,
            "high": 35
        }
    }
}
```

---

### 任务 2.2：修改扫描流程，分离扫描与分析

**流程变更**：
```
原流程：扫描 → 构建调用图 → 自动 LLM 分析前 30 个候选点
新流程：扫描 → 构建调用图 → 返回触发点列表 → [用户选择] → LLM 分析选中项
```

**涉及文件**：
- `api/main.py` - 修改 `background_scan_task` 函数
- `analyzer/engine.py` - 提取 `discover_sink_sites` 和 `analyze_selected_sites` 方法

**关键修改**：
```python
# analyzer/engine.py - 新增方法
async def discover_sink_sites(self, code_units: List[CodeUnit]) -> List[SinkSite]:
    """仅发现触发点，不进行 LLM 分析"""
    scanner = SinkCallScanner(self.rule_manager)
    return scanner.scan(code_units)

async def analyze_selected_sites(
    self,
    site_ids: List[str],
    sink_sites: List[SinkSite],
    call_graph: CallGraph,
    on_progress: Callable
) -> List[Finding]:
    """分析用户选中的触发点"""
    selected = [s for s in sink_sites if s.id in site_ids]
    # ... LLM 分析逻辑
```

---

### 任务 2.3：前端触发点选择组件

**新建文件**：`frontend/src/components/SinkSiteSelector.vue`

**组件特性**：
1. 按类别分组展示（类似日志中的 by_category 统计）
2. 支持按类别批量选择/取消
3. 支持按风险级别筛选
4. 显示代码片段预览
5. 全选/清空/反选操作
6. 显示已选数量统计

**组件结构**：
```vue
<template>
  <div class="sink-site-selector glass-card rounded-2xl p-6">
    <!-- 头部：统计信息 -->
    <div class="flex justify-between items-center mb-4">
      <h3 class="text-lg font-semibold text-gray-800">
        危险函数触发点
        <span class="text-sm text-gray-500">({{ total }} 个)</span>
      </h3>
      <div class="flex gap-2">
        <button @click="selectAll" class="btn-secondary text-sm">全选</button>
        <button @click="clearAll" class="btn-secondary text-sm">清空</button>
      </div>
    </div>

    <!-- 类别筛选标签 -->
    <div class="flex flex-wrap gap-2 mb-4">
      <button
        v-for="cat in categories"
        :key="cat.name"
        @click="toggleCategory(cat.name)"
        :class="[
          'px-3 py-1 rounded-full text-sm transition',
          selectedCategories.includes(cat.name)
            ? 'bg-blue-500 text-white'
            : 'bg-white/50 text-gray-700 hover:bg-white/70'
        ]"
      >
        {{ cat.label }} ({{ cat.count }})
      </button>
    </div>

    <!-- 触发点列表 -->
    <div class="space-y-2 max-h-[400px] overflow-y-auto">
      <div
        v-for="site in filteredSites"
        :key="site.id"
        class="flex items-start gap-3 p-3 rounded-xl bg-white/30 hover:bg-white/50 transition cursor-pointer"
        @click="toggleSite(site.id)"
      >
        <input
          type="checkbox"
          :checked="selectedSiteIds.includes(site.id)"
          class="mt-1 rounded border-gray-300"
          @click.stop
        />
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2">
            <span class="text-sm font-medium text-gray-800 truncate">
              {{ site.file_path }}:{{ site.line_start }}
            </span>
            <span
              :class="['px-2 py-0.5 rounded text-xs font-medium', riskClass(site.risk_level)]"
            >
              {{ site.risk_level }}
            </span>
            <span class="px-2 py-0.5 rounded text-xs bg-gray-200 text-gray-700">
              {{ site.sink_category }}
            </span>
          </div>
          <code class="text-xs text-gray-600 mt-1 block truncate">
            {{ site.call_snippet }}
          </code>
        </div>
      </div>
    </div>

    <!-- 底部操作栏 -->
    <div class="flex justify-between items-center mt-4 pt-4 border-t border-white/20">
      <span class="text-sm text-gray-600">
        已选择 {{ selectedSiteIds.length }} / {{ total }} 个触发点
      </span>
      <button
        @click="$emit('analyze', selectedSiteIds)"
        :disabled="selectedSiteIds.length === 0"
        class="btn-primary"
      >
        分析选中项
      </button>
    </div>
  </div>
</template>
```

---

### 任务 2.4：新增选择分析 API

**端点**：`POST /api/scan/{scan_id}/analyze-selected`

**请求体**：
```json
{
    "site_ids": ["sink-0001", "sink-0003", "sink-0007"],
    "options": {
        "use_chain_analysis": true,
        "max_chain_depth": 10,
        "include_call_graph": true
    }
}
```

**响应**：通过 WebSocket 推送进度和结果

---

## 阶段 3：调用图可视化与调用链选择

**目标**：可视化展示调用图，用户选择要分析的调用链

### 任务 3.1：安装 Cytoscape.js 依赖

```bash
cd frontend
npm install cytoscape cytoscape-dagre
```

**涉及文件**：
- `frontend/package.json` - 添加依赖

---

### 任务 3.2：调用图数据 API

**端点**：`GET /api/scan/{scan_id}/call-graph`

**涉及文件**：
- `api/graph_router.py` - 新增/修改端点
- `analyzer/call_chain.py` - 新增 `to_visualization_data` 方法

**响应格式**：
```json
{
    "nodes": [
        {
            "id": "node-001",
            "name": "handle_request",
            "qualified_name": "app.views.handle_request",
            "type": "entry_point",
            "file_path": "app/views.py",
            "line_start": 15,
            "is_sink": false,
            "sink_category": null
        }
    ],
    "edges": [
        {
            "source": "node-001",
            "target": "node-005",
            "call_type": "direct"
        }
    ],
    "stats": {
        "total_nodes": 298,
        "total_edges": 815,
        "entry_points": 12,
        "sinks": 47
    }
}
```

---

### 任务 3.3：调用链枚举 API

**端点**：`GET /api/scan/{scan_id}/chains/{site_id}`

**查询参数**：
- `max_depth`: 最大深度（默认 10）
- `page`: 页码（默认 1）
- `page_size`: 每页数量（默认 20）
- `sort_by`: 排序字段（`risk` | `length`，默认 `risk`）

**响应格式**：
```json
{
    "sink_site": { ... },
    "chains": [
        {
            "chain_id": "chain-001",
            "nodes": [
                {"name": "handle_request", "type": "entry_point", "file": "views.py", "line": 15},
                {"name": "process_input", "type": "normal", "file": "utils.py", "line": 42},
                {"name": "execute_query", "type": "sink", "file": "db.py", "line": 78}
            ],
            "length": 3,
            "has_sanitizer": false,
            "has_user_input": true,
            "estimated_risk": "high",
            "risk_score": 85
        }
    ],
    "pagination": {
        "page": 1,
        "page_size": 20,
        "total_chains": 47,
        "total_pages": 3
    },
    "default_selected": ["chain-001", "chain-002", ..., "chain-020"]
}
```

---

### 任务 3.4：前端调用图可视化组件

**新建文件**：`frontend/src/components/CallGraphViewer.vue`

**组件特性**：
1. 使用 Cytoscape.js 渲染调用图
2. 节点按类型着色：
   - 入口点：蓝色
   - Sink：红色
   - Sanitizer：绿色
   - 普通节点：灰色
3. 支持缩放、拖拽、平移
4. 点击节点显示详情面板
5. 高亮选中触发点的调用链路径
6. 筛选模式：只显示与选中 sink 相关的节点

**核心代码结构**：
```vue
<template>
  <div class="call-graph-viewer glass-card rounded-2xl p-6">
    <div class="flex justify-between items-center mb-4">
      <h3 class="text-lg font-semibold text-gray-800">调用图可视化</h3>
      <div class="flex gap-2">
        <button @click="fitToScreen" class="btn-secondary text-sm">适应屏幕</button>
        <button @click="toggleLayout" class="btn-secondary text-sm">切换布局</button>
      </div>
    </div>

    <!-- 图例 -->
    <div class="flex gap-4 mb-4 text-sm">
      <span class="flex items-center gap-1">
        <span class="w-3 h-3 rounded-full bg-blue-500"></span> 入口点
      </span>
      <span class="flex items-center gap-1">
        <span class="w-3 h-3 rounded-full bg-red-500"></span> 危险函数
      </span>
      <span class="flex items-center gap-1">
        <span class="w-3 h-3 rounded-full bg-green-500"></span> 过滤函数
      </span>
    </div>

    <!-- Cytoscape 容器 -->
    <div ref="cyContainer" class="w-full h-[500px] bg-white/20 rounded-xl"></div>

    <!-- 节点详情面板 -->
    <div v-if="selectedNode" class="mt-4 p-4 bg-white/30 rounded-xl">
      <h4 class="font-medium text-gray-800">{{ selectedNode.name }}</h4>
      <p class="text-sm text-gray-600">{{ selectedNode.file_path }}:{{ selectedNode.line_start }}</p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch } from 'vue'
import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'

cytoscape.use(dagre)

const props = defineProps({
  graphData: Object,
  highlightedChain: Array
})

const cyContainer = ref(null)
const cy = ref(null)
const selectedNode = ref(null)

onMounted(() => {
  initGraph()
})

function initGraph() {
  cy.value = cytoscape({
    container: cyContainer.value,
    elements: formatElements(props.graphData),
    style: graphStyles,
    layout: { name: 'dagre', rankDir: 'TB' }
  })

  cy.value.on('tap', 'node', (e) => {
    selectedNode.value = e.target.data()
  })
}

const graphStyles = [
  {
    selector: 'node',
    style: {
      'label': 'data(name)',
      'background-color': '#9CA3AF',
      'text-valign': 'bottom',
      'font-size': '10px'
    }
  },
  {
    selector: 'node[type="entry_point"]',
    style: { 'background-color': '#3B82F6' }
  },
  {
    selector: 'node[type="sink"]',
    style: { 'background-color': '#EF4444' }
  },
  {
    selector: 'node[type="sanitizer"]',
    style: { 'background-color': '#10B981' }
  },
  {
    selector: 'edge',
    style: {
      'width': 2,
      'line-color': '#D1D5DB',
      'target-arrow-color': '#D1D5DB',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier'
    }
  },
  {
    selector: '.highlighted',
    style: {
      'background-color': '#F59E0B',
      'line-color': '#F59E0B',
      'target-arrow-color': '#F59E0B'
    }
  }
]
</script>
```

---

### 任务 3.5：调用链选择组件

**新建文件**：`frontend/src/components/ChainSelector.vue`

**组件特性**：
1. 分页展示调用链列表
2. 按风险评分排序，默认选中 Top 20
3. 显示链长度、是否有 sanitizer、风险评分
4. 可视化展示链路径（节点连线）
5. 支持批量选择/取消

---

## 阶段 4：快速扫描 LLM 交互增强

**目标**：快速扫描也使用 Function Calling，实时展示 LLM 响应

### 任务 4.1：统一 LLM 分析接口（支持 Function Calling）

**涉及文件**：
- `analyzer/engine.py` - 重构 `analyze_chain_with_llm`
- `agent/tools/registry.py` - 复用现有工具定义

**关键修改**：
```python
async def analyze_chain_with_tools(
    self,
    chain_context: ChainContext,
    tools: List[Dict],
    on_tool_call: Callable[[str, Dict, Any], None],
    on_stream: Callable[[str], None],
    scan_id: str
) -> Finding:
    """
    使用 Function Calling 进行链级分析

    Args:
        chain_context: 调用链上下文
        tools: 可用工具列表（OpenAI 格式）
        on_tool_call: 工具调用回调 (tool_name, input, output)
        on_stream: LLM 流式输出回调
        scan_id: 扫描 ID，用于 WebSocket 推送
    """
    messages = self._build_analysis_messages(chain_context)

    while True:
        response = await self.llm_client.chat_completion(
            messages=messages,
            tools=tools,
            stream=True
        )

        # 处理流式输出
        full_content = ""
        tool_calls = []
        async for chunk in response:
            if chunk.content:
                full_content += chunk.content
                on_stream(chunk.content)
            if chunk.tool_calls:
                tool_calls.extend(chunk.tool_calls)

        # 处理工具调用
        if tool_calls:
            for tc in tool_calls:
                result = await self.tool_executor.execute(tc.name, tc.arguments)
                on_tool_call(tc.name, tc.arguments, result)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result)
                })
        else:
            # 无工具调用，分析完成
            break

    return self._parse_finding(full_content)
```

---

### 任务 4.2：WebSocket 增强消息类型

**涉及文件**：
- `api/main.py` - 修改 WebSocket 处理逻辑
- `api/schemas.py` - 新增消息类型定义

**新增消息类型**：
```python
# 工具调用开始
{
    "type": "tool_call_start",
    "scan_id": str,
    "data": {
        "call_id": str,
        "tool_name": str,
        "tool_input": dict
    }
}

# 工具调用结束
{
    "type": "tool_call_end",
    "scan_id": str,
    "data": {
        "call_id": str,
        "tool_output": any,
        "duration_ms": int
    }
}

# LLM 流式输出
{
    "type": "llm_stream",
    "scan_id": str,
    "content": str,
    "chain_id": str,
    "is_final": bool
}

# 分析思考过程
{
    "type": "thinking",
    "scan_id": str,
    "content": str
}
```

---

### 任务 4.3：前端 LLM 交互面板增强

**修改文件**：`frontend/src/views/Scan.vue`
**新建文件**：`frontend/src/components/LLMInteractionPanel.vue`

**组件特性**：
1. 实时显示工具调用（可折叠展开）
2. 流式显示 LLM 思考和响应内容
3. 按时间线排序
4. 区分不同链的分析过程（标签页或分组）

---

### 任务 4.4：实现流式 LLM 响应

**涉及文件**：
- `llm_client/client.py` - 确保 `chat_completion_stream` 可用
- `analyzer/engine.py` - 使用流式 API
- `api/main.py` - WebSocket 推送流内容

---

## 阶段 5：统一审计模式

**目标**：对话审计和快速扫描共享触发点选择和调用链选择机制

### 任务 5.1：提取共享组件

**移动/重构文件**：
```
frontend/src/components/SinkSiteSelector.vue     → frontend/src/components/shared/SinkSiteSelector.vue
frontend/src/components/ChainSelector.vue        → frontend/src/components/shared/ChainSelector.vue
frontend/src/components/CallGraphViewer.vue      → frontend/src/components/shared/CallGraphViewer.vue
frontend/src/components/LLMInteractionPanel.vue  → frontend/src/components/shared/LLMInteractionPanel.vue
```

---

### 任务 5.2：新增交互模式切换

**前端实现**：用户可在两种模式间切换

```vue
<template>
  <div class="mode-switcher flex gap-2 mb-4">
    <button
      @click="mode = 'two-step'"
      :class="['btn', mode === 'two-step' ? 'btn-primary' : 'btn-secondary']"
    >
      两步确认模式
    </button>
    <button
      @click="mode = 'one-click'"
      :class="['btn', mode === 'one-click' ? 'btn-primary' : 'btn-secondary']"
    >
      一键分析模式
    </button>
  </div>
</template>
```

**模式行为**：
- **两步确认模式**：选择触发点 → 显示调用链 → 选择调用链 → 确认分析
- **一键分析模式**：选择触发点 → 自动选中 Top 20 调用链 → 开始分析（可随时暂停调整）

---

### 任务 5.3：修改 InteractiveAudit.vue

**涉及文件**：
- `frontend/src/views/InteractiveAudit.vue` - 集成共享组件
- `api/interactive_router.py` - 可能需要调整 API

**改造要点**：
1. 集成 SinkSiteSelector 组件
2. 集成 ChainSelector 组件
3. 集成 LLMInteractionPanel 组件
4. 保持对话式交互体验

---

### 任务 5.4：统一状态管理

**新建文件**：`frontend/src/stores/scan.js`

```javascript
import { defineStore } from 'pinia'

export const useScanStore = defineStore('scan', {
  state: () => ({
    // 扫描状态
    scanId: null,
    status: 'idle', // idle | indexing | scanning | selecting | analyzing | completed

    // 触发点数据
    sinkSites: [],
    selectedSiteIds: [],

    // 调用图数据
    callGraph: null,

    // 调用链数据
    chains: {},  // { [siteId]: Chain[] }
    selectedChainIds: [],

    // LLM 交互
    interactions: [],
    currentThinking: '',

    // 分析结果
    findings: [],

    // 用户偏好
    interactionMode: 'two-step', // two-step | one-click
    defaultTopN: 20
  }),

  actions: {
    async loadSinkSites(scanId) { ... },
    async loadCallGraph(scanId) { ... },
    async loadChains(siteId) { ... },
    async analyzeSelected() { ... },

    // WebSocket 消息处理
    handleWebSocketMessage(msg) {
      switch (msg.type) {
        case 'tool_call_start':
          this.interactions.push({ ...msg.data, status: 'running' })
          break
        case 'tool_call_end':
          // 更新对应的交互记录
          break
        case 'llm_stream':
          this.currentThinking += msg.content
          break
        case 'new_finding':
          this.findings.push(msg.finding)
          break
      }
    }
  }
})
```

---

### 任务 5.5：端到端测试

**新建文件**：
- `tests/test_scan_flow.py` - 快速扫描流程测试
- `tests/test_interactive_flow.py` - 对话审计流程测试

---

## 依赖关系图

```
阶段 1 (Bug 修复)
    │
    ├──→ 阶段 2 (触发点选择) ──→ 阶段 3 (调用图可视化) ──┐
    │                                                      │
    └──→ 阶段 4 (LLM 交互增强) ────────────────────────────┼──→ 阶段 5 (统一模式)
                                                           │
                                                           ↓
                                                        完成
```

---

## 文件变更清单

### 新建文件

| 文件 | 说明 |
|------|------|
| `frontend/src/components/shared/SinkSiteSelector.vue` | 触发点选择组件 |
| `frontend/src/components/shared/ChainSelector.vue` | 调用链选择组件 |
| `frontend/src/components/shared/CallGraphViewer.vue` | 调用图可视化组件 |
| `frontend/src/components/shared/LLMInteractionPanel.vue` | LLM 交互面板 |
| `frontend/src/stores/scan.js` | 扫描状态管理 |
| `tests/test_scan_flow.py` | 扫描流程测试 |
| `tests/test_interactive_flow.py` | 交互审计测试 |

### 修改文件

| 文件 | 修改内容 |
|------|----------|
| `analyzer/engine.py` | 修复 Finding ID、分离扫描与分析、添加 Function Calling 支持 |
| `analyzer/models.py` | 可选：添加 ID 生成方法 |
| `analyzer/call_chain.py` | 添加 `to_visualization_data` 方法 |
| `storage/finding_repository.py` | 添加 UPSERT 支持 |
| `storage/database.py` | 增强错误处理 |
| `api/main.py` | 新增 API 端点、增强 WebSocket |
| `api/schemas.py` | 新增响应模型 |
| `api/graph_router.py` | 调用图 API |
| `frontend/package.json` | 添加 Cytoscape.js 依赖 |
| `frontend/src/views/Scan.vue` | 集成新组件 |
| `frontend/src/views/InteractiveAudit.vue` | 集成共享组件 |
| `frontend/src/views/CallGraph.vue` | 重构使用新组件 |
| `frontend/src/api/index.js` | 新增 API 调用 |

---

## 验收标准

### 功能验收

- [ ] **Bug 修复**
  - [ ] 多次扫描同一项目不再出现 UNIQUE constraint 错误
  - [ ] 文件路径验证不再出现误报警告

- [ ] **触发点选择**
  - [ ] 扫描完成后显示所有触发点列表
  - [ ] 支持按类别筛选触发点
  - [ ] 支持多选并发起分析

- [ ] **调用图可视化**
  - [ ] 正确显示调用图节点和边
  - [ ] 节点按类型着色
  - [ ] 支持缩放、拖拽、点击详情

- [ ] **调用链选择**
  - [ ] 选中触发点后显示其所有调用链
  - [ ] 支持分页加载
  - [ ] 默认选中 Top 20（按风险排序）
  - [ ] 用户可自主调整选择

- [ ] **交互模式**
  - [ ] 支持两步确认模式
  - [ ] 支持一键分析模式
  - [ ] 用户可切换模式

- [ ] **LLM 交互展示**
  - [ ] 快速扫描实时显示工具调用
  - [ ] 流式显示 LLM 响应内容
  - [ ] 与对话审计界面交互体验一致

### 性能验收

- [ ] 调用图渲染：500 节点以内无卡顿
- [ ] 触发点列表加载：< 500ms
- [ ] WebSocket 消息延迟：< 100ms
- [ ] 分页加载调用链：< 300ms

---

## 工时估算

| 阶段 | 任务数 | 预估工时 |
|------|--------|----------|
| 阶段 1：Bug 修复 | 3 | 3 小时 |
| 阶段 2：触发点选择 | 4 | 8 小时 |
| 阶段 3：调用图可视化 | 5 | 10 小时 |
| 阶段 4：LLM 交互增强 | 4 | 9 小时 |
| 阶段 5：统一审计模式 | 5 | 8 小时 |
| **总计** | **21** | **38 小时** |
