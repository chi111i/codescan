# 多漏洞逐个分析与LLM过程实时展示规划

## 需求概述

1. **前端动态查看LLM调用过程**：实时展示每次LLM调用的请求、响应、工具调用
2. **多漏洞按序分析**：发现多个漏洞时逐个分析，每分析完一个立即输出，继续分析下一个
3. **解决当前问题**：全部项目只输出一个漏洞总结 → 改为逐个输出

---

## 问题根源分析

从日志 `E:\1ceshi\codescan\日志.txt` 分析：

### 现状
- 预扫描发现 321 个触发点，过滤后 194 个高危点
- LLM 进行了 6 轮调用 (llm-1 到 llm-6)
- LLM 分析了 command_exec、SQL injection、file_read 多种漏洞
- **问题1**：前端看不到 LLM 调用实时过程
- **问题2**：LLM 没有调用 `report_finding` 保存单个发现
- **问题3**：最终只返回一次总结性响应

### 根本原因
1. `UnifiedAgent.chat()` 方法中没有调用 WebSocket 广播函数
2. 系统缺少 `report_finding` 工具，LLM 无法在分析过程中报告单个发现
3. 没有"漏洞迭代分析"循环机制，系统提示未强制要求按序处理每个触发点

---

## 已明确的决策

- 使用现有的 WebSocket 广播机制（`broadcast_interaction`、`broadcast_llm_stream`）
- 在 `UnifiedAuditAgent` 中添加 `report_finding` 工具
- 采用"漏洞队列驱动"的分析模式，逐个分析预扫描发现的触发点
- 前端使用现有的 `interactions` 数据结构展示 LLM 过程
- 后端回调机制使用现有的 `on_tool_call_async` 配置项

---

## 整体规划概述

### 项目目标

1. **实时展示 LLM 分析过程**：前端能动态查看每次 LLM 调用的请求、响应、工具调用
2. **逐漏洞分析与报告**：发现漏洞时立即通过 `report_finding` 工具保存并推送，而非最后一次性总结
3. **自动迭代分析**：分析完一个漏洞点后自动继续分析下一个，直到所有高危点处理完毕

### 技术栈

- **后端**：Python 3.x + FastAPI + WebSocket + SQLite
- **前端**：Vue 3 + Vite + Pinia
- **核心模块**：`agent/unified_agent.py`、`api/agent_router.py`、`api/main.py`、`frontend/src/views/Scan.vue`

### 主要阶段

1. **阶段 1：LLM 交互实时广播**（后端增强）
2. **阶段 2：report_finding 工具实现**（后端新增）
3. **阶段 3：漏洞迭代分析循环**（后端重构）
4. **阶段 4：前端 LLM 过程展示增强**（前端优化）

---

## 详细任务分解

### 阶段 1：LLM 交互实时广播

**目标**：让前端能实时看到每次 LLM 调用的过程

#### 任务 1.1：在 UnifiedAgentConfig 中添加 WebSocket 广播回调
- **目标**：配置 Agent 支持异步广播回调
- **输入**：`UnifiedAgentConfig` 类定义
- **输出**：新增 `on_llm_call_async`、`on_llm_response_async` 回调配置项
- **涉及文件**：`agent/unified_agent.py`（行 110-150）

#### 任务 1.2：在 `_call_llm_with_tools` 方法中注入 LLM 调用事件
- **目标**：每次 LLM 调用前后触发回调通知
- **输入**：现有 `_call_llm_with_tools` 方法
- **输出**：调用开始时广播 `llm_call_start`，响应后广播 `llm_call_end`（含 content、tool_calls）
- **涉及文件**：`agent/unified_agent.py`（约行 1050-1100）

#### 任务 1.3：在 agent_router 中配置 Agent 回调与 WebSocket 广播的连接
- **目标**：将 Agent 的回调事件转发到 WebSocket
- **输入**：现有 `agent_router.py` 中的会话初始化逻辑
- **输出**：创建 Agent 时注入异步回调，回调内部调用 `broadcast_interaction`
- **涉及文件**：`api/agent_router.py`（会话创建部分）

#### 任务 1.4：定义新的 WebSocket 事件类型
- **目标**：区分 LLM 调用、工具调用、发现报告等事件
- **输入**：现有 `api/main.py` 广播函数
- **输出**：新增事件类型：`llm_call_start`、`llm_call_end`、`llm_thinking`、`new_finding`
- **涉及文件**：`api/main.py`、`api/schemas_agent.py`

---

### 阶段 2：report_finding 工具实现

**目标**：让 LLM 能在分析过程中随时报告发现的漏洞

#### 任务 2.1：定义 report_finding 工具 Schema
- **目标**：创建符合 OpenAI Function Calling 格式的工具定义
- **输入**：现有 `agent/tools/registry.py` 工具定义模式
- **输出**：`report_finding` 工具定义，参数包括：severity、title、description、file_path、line_number、code_evidence、attack_scenario、fix_suggestion
- **涉及文件**：`agent/tools/registry.py`（新增在 SECURITY_ANALYSIS_TOOLS 列表中）

#### 任务 2.2：实现 report_finding 工具执行器
- **目标**：工具被调用时保存 Finding 到数据库并广播
- **输入**：工具参数、FindingRepository、WebSocket 广播函数
- **输出**：将 Finding 保存到 SQLite，通过 WebSocket 推送 `new_finding` 事件
- **涉及文件**：`agent/unified_agent.py`（新增 `_execute_report_finding` 方法）

#### 任务 2.3：在 UnifiedAgent 初始化时注册 report_finding 工具
- **目标**：确保工具在 Agent 可用工具列表中
- **输入**：`_register_security_tools` 方法
- **输出**：调用 `tool_manager.register_tool` 注册 report_finding
- **涉及文件**：`agent/unified_agent.py`（`_register_security_tools` 方法）

#### 任务 2.4：更新系统提示，指导 LLM 使用 report_finding
- **目标**：让 LLM 知道发现问题时应调用此工具
- **输入**：现有 `_build_system_prompt` 方法
- **输出**：在系统提示中添加"发现漏洞时必须调用 report_finding 工具"的指令
- **涉及文件**：`agent/unified_agent.py`（`_build_system_prompt` 方法）

---

### 阶段 3：漏洞迭代分析循环

**目标**：分析完一个漏洞点后自动继续分析下一个

#### 任务 3.1：创建漏洞分析任务队列
- **目标**：管理待分析的触发点队列
- **输入**：预扫描结果 `prescan_result.filtered_sites`
- **输出**：新增 `AnalysisTaskQueue` 类，管理待分析、分析中、已完成的触发点
- **涉及文件**：新增 `agent/analysis_queue.py`

#### 任务 3.2：实现迭代分析驱动方法
- **目标**：自动从队列取下一个触发点并启动分析
- **输入**：任务队列、UnifiedAgent
- **输出**：新增 `analyze_next_sink` 方法，自动构建分析 prompt 并调用 chat
- **涉及文件**：`agent/unified_agent.py`（新增方法）

#### 任务 3.3：修改 chat 方法支持批量分析模式
- **目标**：分析完成后检查队列，自动继续下一个
- **输入**：现有 `chat` 方法
- **输出**：添加 `auto_continue` 参数，分析结束后检查队列触发下一轮
- **涉及文件**：`agent/unified_agent.py`（`chat` 方法）

#### 任务 3.4：添加分析进度广播
- **目标**：前端能看到"正在分析第 X/Y 个触发点"
- **输入**：任务队列状态
- **输出**：广播 `analysis_progress` 事件，包含 current/total/current_site 信息
- **涉及文件**：`api/agent_router.py`、`api/main.py`

---

### 阶段 4：前端 LLM 过程展示增强

**目标**：优化前端展示，清晰呈现 LLM 分析过程

#### 任务 4.1：扩展 WebSocket 事件处理
- **目标**：处理新增的事件类型
- **输入**：现有 `ws.onmessage` 处理器
- **输出**：处理 `llm_call_start`、`llm_call_end`、`new_finding`、`analysis_progress`
- **涉及文件**：`frontend/src/views/Scan.vue`（`ws.onmessage` 部分）

#### 任务 4.2：创建 LLM 调用过程可视化组件
- **目标**：展示每次 LLM 调用的输入/输出/工具调用
- **输入**：UI 设计规范（磨砂玻璃风格）
- **输出**：新增 `LLMCallCard.vue` 组件，展示 LLM 请求内容、响应内容、工具调用列表
- **涉及文件**：新增 `frontend/src/components/LLMCallCard.vue`

#### 任务 4.3：创建发现实时推送列表组件
- **目标**：新发现的漏洞实时添加到列表顶部
- **输入**：`new_finding` 事件数据
- **输出**：新增/修改发现列表组件，支持实时添加并高亮新项
- **涉及文件**：`frontend/src/views/Scan.vue`（findings 展示部分）

#### 任务 4.4：添加分析进度指示器
- **目标**：展示"分析第 X/Y 个触发点"进度
- **输入**：`analysis_progress` 事件
- **输出**：在扫描页面添加进度条和当前分析触发点信息
- **涉及文件**：`frontend/src/views/Scan.vue`

---

## 待确认问题

### 问题 1：LLM 调用内容展示的详细程度

**描述**：前端展示 LLM 调用过程时，是否需要展示完整的 prompt/response 内容？

| 方案 | 描述 | 优点 | 缺点 |
|------|------|------|------|
| **A（推荐）** | 展示摘要 + 可展开完整内容 | 界面简洁，关键信息一目了然 | 需要额外交互 |
| B | 始终展示完整内容 | 调试方便 | 界面过长 |

### 问题 2：漏洞迭代分析的触发方式

**描述**：是自动分析所有触发点，还是分析一个后等待用户确认再继续？

| 方案 | 描述 | 优点 | 缺点 |
|------|------|------|------|
| A | 全自动模式 | 适合批量扫描，效率高 | 用户可能错过重要发现 |
| B | 半自动模式 | 用户可控 | 需要持续参与 |
| **C（推荐）** | 混合模式（高危暂停） | 平衡效率和重要性 | 实现稍复杂 |

### 问题 3：Finding 存储与会话关联

**描述**：report_finding 保存的发现应该关联到哪个实体？

| 方案 | 描述 | 优点 | 缺点 |
|------|------|------|------|
| **A（推荐）** | 关联到 session_id | 与当前会话上下文一致 | 需映射到扫描任务 |
| B | 关联到 scan_id | 与现有扫描流程一致 | 需传递 scan_id |

---

## 验收标准

### 功能验收

1. **LLM 过程可见**：
   - [ ] 每次 LLM 调用开始时，前端显示"正在调用 LLM..."
   - [ ] LLM 响应后，前端显示响应内容摘要和工具调用列表
   - [ ] 工具调用执行过程中显示执行状态

2. **逐漏洞报告**：
   - [ ] LLM 调用 report_finding 工具后，前端立即显示新发现
   - [ ] 发现保存到数据库，刷新页面后仍可见
   - [ ] 每个发现包含：严重程度、标题、描述、代码证据、修复建议

3. **自动迭代分析**：
   - [ ] 分析完一个触发点后自动开始分析下一个
   - [ ] 前端显示"正在分析第 X/Y 个触发点"进度
   - [ ] 可暂停/恢复分析过程

### 性能验收

- [ ] WebSocket 广播延迟 < 100ms
- [ ] 前端不因大量事件卡顿（使用虚拟列表或限制显示条数）

### 兼容性验收

- [ ] 现有扫描功能正常工作
- [ ] 现有 API 接口不破坏

---

## 涉及文件清单

| 文件 | 修改类型 | 主要改动 |
|------|----------|----------|
| `agent/unified_agent.py` | 修改 | 添加回调、report_finding 工具、迭代分析 |
| `agent/analysis_queue.py` | 新增 | 漏洞分析任务队列 |
| `agent/tools/registry.py` | 修改 | 添加 report_finding 工具定义 |
| `api/agent_router.py` | 修改 | 配置回调、广播进度 |
| `api/main.py` | 修改 | 新增事件类型 |
| `api/schemas_agent.py` | 修改 | 新增消息 Schema |
| `frontend/src/views/Scan.vue` | 修改 | WebSocket 事件处理、进度展示 |
| `frontend/src/components/LLMCallCard.vue` | 新增 | LLM 调用可视化组件 |

---

## 用户反馈区域

请在此区域补充您对整体规划的意见和建议：

```
用户补充内容：




```
