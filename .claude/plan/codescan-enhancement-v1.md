# 项目任务分解规划

## CodeScan 功能增强与 Bug 修复 v1.0

---

## 已明确的决策

- **技术栈保持不变**：后端 Python 3.x + FastAPI + SQLite，前端 Vue 3 + Vite + Pinia
- **数据库**：继续使用 SQLite，修复唯一约束冲突问题
- **用户体验优先**：取消自动过滤/截断机制，改为用户自主选择
- **统一交互模式**：快速扫描和对话审计采用相同的触发点选择和 LLM 交互展示机制

---

## 整体规划概述

### 项目目标

1. **修复数据库唯一约束冲突 Bug**：解决 `UNIQUE constraint failed: scan_findings.id` 错误
2. **前端展示所有触发点**：让用户可视化选择要分析的危险函数触发点
3. **调用图可视化与调用链选择**：展示调用图，用户选择具体调用链进行 LLM 分析
4. **快速扫描 LLM 交互增强**：引入 Function Calling，实时展示 LLM 响应
5. **统一两种审计模式**：对话审计和快速扫描共享触发点/调用链选择机制

### 技术栈

| 层级 | 技术 | 说明 |
|------|------|------|
| 前端框架 | Vue 3 + Vite | 现有 |
| 状态管理 | Pinia | 现有 |
| UI 组件 | 自定义磨砂玻璃风格 | 现有 |
| 图可视化 | **新增** D3.js / Cytoscape.js | 调用图展示 |
| 后端框架 | FastAPI | 现有 |
| 数据库 | SQLite | 现有，需修复 |
| LLM 交互 | OpenAI Function Calling | 现有，需扩展 |

### 主要阶段

1. **阶段 1：Bug 修复与基础设施改进** - 修复数据库唯一约束冲突，优化 Finding ID 生成策略
2. **阶段 2：触发点展示与用户选择** - 前端展示所有 SinkCallSite，支持用户多选
3. **阶段 3：调用图可视化与调用链选择** - 可视化调用图，用户选择调用链进行分析
4. **阶段 4：快速扫描 LLM 交互增强** - 引入 Function Calling，实时流式展示
5. **阶段 5：统一审计模式** - 对话审计和快速扫描共享组件和交互逻辑

---

## 详细任务分解

### 阶段 1：Bug 修复与基础设施改进

**目标**：解决生产环境中的数据库唯一约束冲突问题

---

#### 任务 1.1：分析 Finding ID 重复原因

- **目标**：定位 `UNIQUE constraint failed: scan_findings.id` 的根本原因
- **输入**：日志分析、代码审查
- **输出**：问题根因报告
- **涉及文件**：
  - `analyzer/engine.py` (第 857 行附近：`id=f"finding-{chain_id}"`)
  - `storage/finding_repository.py` (第 146-205 行：`create_many` 方法)
  - `api/main.py` (第 1500-1548 行：保存发现的逻辑)
- **预估工作量**：0.5 小时

**问题分析**：

```python
# analyzer/engine.py 第 857-858 行
finding = Finding(
    id=f"finding-{chain_id}",  # chain_id 可能重复
    ...
)
```

`chain_id` 基于 sink_site.id + chain 索引生成，但多次扫描同一项目时会产生相同的 ID。

---

#### 任务 1.2：实现唯一 Finding ID 生成策略

- **目标**：确保 Finding ID 全局唯一，避免冲突
- **输入**：任务 1.1 的分析结果
- **输出**：修复后的 ID 生成逻辑
- **涉及文件**：
  - `analyzer/engine.py` - 修改 Finding 创建逻辑
  - `analyzer/models.py` - 修改 `Finding.generate_id()` 静态方法
- **预估工作量**：1 小时

**修复方案**：

```python
# 方案 A：使用 UUID + 时间戳
finding_id = f"f-{uuid.uuid4().hex[:12]}"

# 方案 B：使用 scan_id + 序号
finding_id = f"{scan_id}-{counter:04d}"

# 方案 C：使用内容哈希（推荐）
content = f"{scan_id}:{file_path}:{line_start}:{symbol}:{timestamp}"
finding_id = f"f-{hashlib.sha256(content.encode()).hexdigest()[:12]}"
```

---

#### 任务 1.3：增加数据库 UPSERT 支持

- **目标**：处理重复插入时使用 UPDATE 而非报错
- **输入**：SQLite UPSERT 语法
- **输出**：修改后的 `create_many` 方法
- **涉及文件**：
  - `storage/finding_repository.py` - 修改 `create_many` 方法
  - `storage/database.py` - 添加 `execute_upsert` 方法（可选）
- **预估工作量**：1 小时

**修复方案**：

```python
# storage/finding_repository.py
sql = """
INSERT INTO scan_findings (...) VALUES (...)
ON CONFLICT(id) DO UPDATE SET
    scan_id = excluded.scan_id,
    severity = excluded.severity,
    ...
    created_at = COALESCE(scan_findings.created_at, excluded.created_at)
"""
```

---

#### 任务 1.4：修复文件路径验证警告

- **目标**：解决 LLM 验证时相对路径解析问题
- **输入**：日志中的 `File does not exist` 警告
- **输出**：正确的路径解析逻辑
- **涉及文件**：
  - `analyzer/engine.py` - 文件路径验证逻辑
  - `agent/tools/executor.py` - 工具执行时的路径处理
- **预估工作量**：1 小时

---

### 阶段 2：触发点展示与用户选择

**目标**：前端展示 SinkCallScanner 发现的所有触发点，用户可选择要分析的项

---

#### 任务 2.1：新增触发点列表 API

- **目标**：提供获取所有触发点的 API 端点
- **输入**：SinkCallScanner 扫描结果
- **输出**：RESTful API 端点
- **涉及文件**：
  - `api/main.py` - 新增 `/api/scan/{scan_id}/sink-sites` 端点
  - `api/schemas.py` - 新增 `SinkSiteSchema` 响应模型
- **预估工作量**：1.5 小时

**API 设计**：

```python
# GET /api/scan/{scan_id}/sink-sites
# 响应：
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
                "risk_level": "high",
                "call_snippet": "cursor.execute(query)",
                "matched_patterns": ["cursor.execute"],
                "confidence": 0.95
            },
            ...
        ],
        "by_category": {
            "sql_injection": 23,
            "command_exec": 15,
            ...
        }
    }
}
```

---

#### 任务 2.2：修改扫描流程，分离扫描与分析

- **目标**：扫描完成后不自动进行 LLM 分析，等待用户选择
- **输入**：现有扫描流程
- **输出**：分离的扫描和分析 API
- **涉及文件**：
  - `api/main.py` - 修改 `background_scan_task` 函数
  - `analyzer/engine.py` - 提取 `discover_and_build_graph` 方法
- **预估工作量**：2 小时

**流程变更**：

```
原流程：扫描 → 构建调用图 → 自动 LLM 分析所有候选点
新流程：扫描 → 构建调用图 → 返回触发点列表 → [用户选择] → LLM 分析选中项
```

---

#### 任务 2.3：前端触发点选择组件

- **目标**：创建可视化触发点选择界面
- **输入**：触发点列表 API 响应
- **输出**：Vue 组件
- **涉及文件**：
  - `frontend/src/components/SinkSiteSelector.vue` - **新建**
  - `frontend/src/views/Scan.vue` - 集成选择器
  - `frontend/src/api/index.js` - 新增 API 调用
- **预估工作量**：3 小时

**组件设计**：

```vue
<template>
  <div class="sink-site-selector">
    <!-- 分类过滤器 -->
    <div class="category-filter">
      <button v-for="cat in categories" :key="cat.name"
              @click="toggleCategory(cat.name)"
              :class="{ active: selectedCategories.includes(cat.name) }">
        {{ cat.name }} ({{ cat.count }})
      </button>
    </div>

    <!-- 触发点列表 -->
    <div class="site-list">
      <div v-for="site in filteredSites" :key="site.id" class="site-item">
        <input type="checkbox" v-model="selectedSites" :value="site.id" />
        <div class="site-info">
          <span class="file-path">{{ site.file_path }}:{{ site.line_start }}</span>
          <span class="symbol">{{ site.symbol }}</span>
          <span :class="['risk-badge', site.risk_level]">{{ site.risk_level }}</span>
        </div>
        <code class="snippet">{{ site.call_snippet }}</code>
      </div>
    </div>

    <!-- 操作按钮 -->
    <div class="actions">
      <button @click="selectAll">全选</button>
      <button @click="selectNone">清空</button>
      <button @click="analyzeSelected" :disabled="selectedSites.length === 0">
        分析选中 ({{ selectedSites.length }})
      </button>
    </div>
  </div>
</template>
```

---

#### 任务 2.4：新增选择分析 API

- **目标**：根据用户选择的触发点进行 LLM 分析
- **输入**：用户选中的 sink site IDs
- **输出**：分析结果
- **涉及文件**：
  - `api/main.py` - 新增 `/api/scan/{scan_id}/analyze-selected` 端点
  - `analyzer/engine.py` - 新增 `analyze_selected_sites` 方法
- **预估工作量**：2 小时

**API 设计**：

```python
# POST /api/scan/{scan_id}/analyze-selected
# 请求体：
{
    "site_ids": ["sink-0001", "sink-0003", "sink-0007"],
    "use_chain_analysis": true,
    "max_chain_depth": 5
}

# 响应：通过 WebSocket 推送进度和结果
```

---

### 阶段 3：调用图可视化与调用链选择

**目标**：可视化展示调用图，用户选择要分析的调用链

---

#### 任务 3.1：调用图数据 API

- **目标**：提供调用图的节点和边数据
- **输入**：CallGraph 对象
- **输出**：前端可视化所需的 JSON 数据
- **涉及文件**：
  - `api/graph_router.py` - 新增/修改调用图端点
  - `analyzer/call_chain.py` - 新增 `to_visualization_data` 方法
- **预估工作量**：2 小时

**API 设计**：

```python
# GET /api/scan/{scan_id}/call-graph
# 响应：
{
    "nodes": [
        {
            "id": "node-001",
            "name": "handle_request",
            "qualified_name": "app.views.handle_request",
            "type": "entry_point",  # entry_point/source/sink/sanitizer/normal
            "file_path": "app/views.py",
            "line_start": 15,
            "risk_level": null
        },
        ...
    ],
    "edges": [
        {
            "source": "node-001",
            "target": "node-005",
            "call_type": "direct"
        },
        ...
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

#### 任务 3.2：调用链枚举 API

- **目标**：为选中的触发点返回所有可能的调用链
- **输入**：触发点 ID
- **输出**：调用链列表
- **涉及文件**：
  - `api/main.py` - 新增 `/api/scan/{scan_id}/chains/{site_id}` 端点
  - `analyzer/call_chain.py` - 利用现有 `find_paths_to_sink` 方法
- **预估工作量**：1.5 小时

**API 设计**：

```python
# GET /api/scan/{scan_id}/chains/{site_id}?max_depth=10
# 响应：
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
            "estimated_risk": "high"
        },
        ...
    ],
    "total_chains": 5
}
```

---

#### 任务 3.3：前端调用图可视化组件

- **目标**：使用 D3.js 或 Cytoscape.js 展示调用图
- **输入**：调用图 API 数据
- **输出**：可交互的图形化组件
- **涉及文件**：
  - `frontend/src/components/CallGraphViewer.vue` - **新建**
  - `frontend/src/views/CallGraph.vue` - 重构现有页面
  - `frontend/package.json` - 添加可视化库依赖
- **预估工作量**：4 小时

**组件特性**：

- 节点按类型着色（入口点蓝色、sink 红色、sanitizer 绿色）
- 支持缩放和拖拽
- 点击节点显示详情
- 高亮选中触发点的调用链
- 支持筛选显示（只显示与选中 sink 相关的节点）

---

#### 任务 3.4：调用链选择与分析组件

- **目标**：用户选择调用链后发起 LLM 分析
- **输入**：调用链列表
- **输出**：Vue 组件
- **涉及文件**：
  - `frontend/src/components/ChainSelector.vue` - **新建**
  - `frontend/src/views/Scan.vue` - 集成
- **预估工作量**：2.5 小时

---

### 阶段 4：快速扫描 LLM 交互增强

**目标**：快速扫描也使用 Function Calling，实时展示 LLM 响应

---

#### 任务 4.1：统一 LLM 分析接口

- **目标**：创建支持 Function Calling 的统一分析接口
- **输入**：现有 `analyze_chain_with_llm` 方法
- **输出**：增强的分析方法，支持工具调用
- **涉及文件**：
  - `analyzer/engine.py` - 重构 `analyze_chain_with_llm`
  - `agent/tools/registry.py` - 复用现有工具定义
  - `agent/tools/executor.py` - 复用工具执行器
- **预估工作量**：3 小时

**设计要点**：

```python
async def analyze_chain_with_tools(
    self,
    chain_context: ChainContext,
    tools: List[Dict],
    on_tool_call: Callable,
    on_stream: Callable,
) -> Finding:
    """
    使用 Function Calling 进行链级分析

    - on_tool_call: 工具调用时的回调，用于实时展示
    - on_stream: LLM 流式输出的回调
    """
    ...
```

---

#### 任务 4.2：WebSocket 增强消息类型

- **目标**：支持工具调用和流式输出的实时推送
- **输入**：现有 WebSocket 实现
- **输出**：增强的消息协议
- **涉及文件**：
  - `api/main.py` - 修改 WebSocket 处理逻辑
  - `api/schemas.py` - 新增消息类型定义
- **预估工作量**：2 小时

**消息类型**：

```typescript
// 工具调用开始
{
    type: 'tool_call_start',
    scan_id: string,
    data: {
        tool_name: string,
        tool_input: object,
        call_id: string
    }
}

// 工具调用结束
{
    type: 'tool_call_end',
    scan_id: string,
    data: {
        call_id: string,
        tool_output: any,
        duration_ms: number
    }
}

// LLM 流式输出
{
    type: 'llm_stream',
    scan_id: string,
    content: string,
    is_final: boolean
}

// 分析思考过程
{
    type: 'thinking',
    scan_id: string,
    content: string
}
```

---

#### 任务 4.3：前端 LLM 交互面板增强

- **目标**：Scan.vue 中展示完整的 LLM 交互过程
- **输入**：WebSocket 增强消息
- **输出**：增强的交互面板组件
- **涉及文件**：
  - `frontend/src/views/Scan.vue` - 修改 interactions 展示逻辑
  - `frontend/src/components/LLMInteractionPanel.vue` - **新建** 或增强现有
- **预估工作量**：3 小时

**组件特性**：

- 实时显示工具调用（输入/输出）
- 流式显示 LLM 思考和响应内容
- 可折叠/展开详细信息
- 按时间线排序

---

#### 任务 4.4：实现流式 LLM 响应

- **目标**：后端支持 LLM 流式输出并实时推送
- **输入**：`llm_client/client.py` 中的 `chat_completion_stream`
- **输出**：集成到分析流程
- **涉及文件**：
  - `analyzer/engine.py` - 使用流式 API
  - `api/main.py` - WebSocket 推送流内容
- **预估工作量**：2 小时

---

### 阶段 5：统一审计模式

**目标**：对话审计和快速扫描共享触发点选择和调用链选择机制

---

#### 任务 5.1：提取共享组件

- **目标**：将触发点选择器和调用链选择器抽取为可复用组件
- **输入**：阶段 2、3 中创建的组件
- **输出**：重构后的共享组件
- **涉及文件**：
  - `frontend/src/components/shared/SinkSiteSelector.vue`
  - `frontend/src/components/shared/ChainSelector.vue`
  - `frontend/src/components/shared/CallGraphViewer.vue`
- **预估工作量**：2 小时

---

#### 任务 5.2：修改 InteractiveAudit.vue

- **目标**：集成触发点和调用链选择功能
- **输入**：共享组件
- **输出**：统一的对话审计界面
- **涉及文件**：
  - `frontend/src/views/InteractiveAudit.vue` - 重构
  - `api/interactive_router.py` - 可能需要调整 API
- **预估工作量**：3 小时

---

#### 任务 5.3：统一状态管理

- **目标**：使用 Pinia 统一管理扫描状态、触发点、调用链
- **输入**：现有 appStore
- **输出**：增强的状态管理
- **涉及文件**：
  - `frontend/src/stores/app.js` - 扩展
  - `frontend/src/stores/scan.js` - **新建** 专门的扫描状态 store
- **预估工作量**：2 小时

---

#### 任务 5.4：端到端测试

- **目标**：确保两种审计模式的完整流程正常工作
- **输入**：测试用例
- **输出**：测试报告
- **涉及文件**：
  - `tests/test_scan_flow.py` - **新建**
  - `tests/test_interactive_flow.py` - **新建**
- **预估工作量**：2 小时

---

## 依赖关系图

```
阶段 1 ──┬──> 阶段 2 ──┬──> 阶段 3 ──┬──> 阶段 5
         │             │             │
         └─────────────┴──> 阶段 4 ──┘
```

- 阶段 1（Bug 修复）是基础，必须先完成
- 阶段 2（触发点选择）和阶段 4（LLM 交互）可部分并行
- 阶段 3（调用图可视化）依赖阶段 2
- 阶段 5（统一模式）依赖阶段 2、3、4

---

## 风险识别与缓解

| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|----------|
| 调用图节点过多导致前端卡顿 | 高 | 中 | 实现虚拟化渲染、分层加载、只显示相关子图 |
| LLM 流式输出兼容性问题 | 中 | 中 | 提供降级方案（非流式模式） |
| 数据库迁移影响现有数据 | 高 | 低 | 使用 UPSERT 而非 schema 变更 |
| 前端组件复杂度增加 | 中 | 高 | 合理拆分组件，使用 composables 复用逻辑 |

---

## 验收标准

### 功能验收

1. **Bug 修复**
   - [ ] 多次扫描同一项目不再出现 UNIQUE constraint 错误
   - [ ] 文件路径验证不再出现误报警告

2. **触发点选择**
   - [ ] 扫描完成后显示所有触发点列表（如日志中的 106 个）
   - [ ] 支持按类别筛选触发点
   - [ ] 支持多选并发起分析

3. **调用图可视化**
   - [ ] 正确显示调用图节点和边（如 298 节点, 815 边）
   - [ ] 节点按类型着色
   - [ ] 支持交互（缩放、拖拽、点击详情）

4. **调用链选择**
   - [ ] 选中触发点后显示其所有调用链
   - [ ] 取消"超过 30 个自动截断"的限制
   - [ ] 用户可自主选择要分析的调用链

5. **LLM 交互展示**
   - [ ] 快速扫描实时显示工具调用过程
   - [ ] 流式显示 LLM 响应内容
   - [ ] 与对话审计界面交互体验一致

### 性能验收

- [ ] 调用图渲染：500 节点以内无卡顿
- [ ] 触发点列表加载：< 500ms
- [ ] WebSocket 消息延迟：< 100ms

---

## 需要进一步明确的问题

### 问题 1：调用图可视化库选择

**背景**：需要选择合适的 JavaScript 图可视化库

**推荐方案**：

- **方案 A：D3.js Force Layout**
  - 优点：灵活度高，可高度定制
  - 缺点：学习曲线陡峭，需要更多开发时间

- **方案 B：Cytoscape.js**
  - 优点：专门为图可视化设计，API 友好，内置布局算法
  - 缺点：定制性略低于 D3

- **方案 C：Vue Flow（基于 React Flow）**
  - 优点：Vue 生态，组件化，支持节点自定义
  - 缺点：相对较新，社区资源少

**等待用户选择**：

```
请选择您偏好的图可视化库：
[ ] 方案 A：D3.js Force Layout
[ ] 方案 B：Cytoscape.js（推荐）
[ ] 方案 C：Vue Flow
[ ] 其他方案：______________________
```

---

### 问题 2：触发点/调用链选择的 UX 交互模式

**背景**：需要确定用户选择触发点后的交互流程

**推荐方案**：

- **方案 A：两步确认模式**
  1. 选择触发点 → 显示调用链 → 选择调用链 → 确认分析
  - 优点：用户控制粒度高
  - 缺点：步骤多，操作繁琐

- **方案 B：一键分析 + 可选细化**
  1. 选择触发点 → 一键分析所有调用链
  2. 可选：展开查看调用链详情并选择性分析
  - 优点：简单快捷，同时保留精细控制
  - 缺点：默认分析所有链可能较慢

**等待用户选择**：

```
请选择您偏好的交互模式：
[ ] 方案 A：两步确认模式（先选触发点，再选调用链）
[ ] 方案 B：一键分析 + 可选细化（推荐）
[ ] 其他方案：______________________
```

---

### 问题 3：大规模调用链的处理策略

**背景**：某些触发点可能有数百条调用链，全部分析不现实

**推荐方案**：

- **方案 A：智能排序 + 默认选中 Top N**
  - 按风险评分排序，默认选中前 20 条
  - 用户可调整选择

- **方案 B：分页加载 + 用户主动选择**
  - 分页显示调用链，用户手动选择

- **方案 C：风险阈值过滤**
  - 只显示风险评分 > 阈值的调用链
  - 用户可调整阈值

**等待用户选择**：

```
请选择您偏好的大规模调用链处理策略：
[ ] 方案 A：智能排序 + 默认选中 Top N（推荐）
[ ] 方案 B：分页加载 + 用户主动选择
[ ] 方案 C：风险阈值过滤
[ ] 其他方案：______________________
```

---

## 工时估算汇总

| 阶段 | 任务数 | 预估工时 |
|------|--------|----------|
| 阶段 1：Bug 修复 | 4 | 3.5 小时 |
| 阶段 2：触发点选择 | 4 | 8.5 小时 |
| 阶段 3：调用图可视化 | 4 | 10 小时 |
| 阶段 4：LLM 交互增强 | 4 | 10 小时 |
| 阶段 5：统一审计模式 | 4 | 9 小时 |
| **总计** | **20** | **41 小时** |

---

## 用户反馈区域

请在此区域补充您对整体规划的意见和建议：

```
用户补充内容：

---

---

---

```
