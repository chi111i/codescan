# 智能审计聊天记录功能规划

## 已明确的决策

- **功能定位**：将"扫描结果"功能改造为"智能审计聊天记录"，支持查看历史对话和继续审计
- **技术栈**：延续现有架构（Vue 3 + FastAPI + SQLite）
- **数据持久化**：使用 SQLite 存储会话和消息，与现有 `scan_tasks`/`scan_findings` 表并列
- **路由复用**：使用 `/results` 路由（保持 URL 兼容），但内容完全改为聊天记录
- **Agent 内存**：会话恢复时需要重建 Agent 内存状态

### ✅ 用户确认的设计选择（2024-12-25）

| 问题 | 用户选择 | 说明 |
|------|----------|------|
| **问题 1：会话标题生成** | **方案 B：LLM 自动摘要** | 首次对话后由 LLM 生成简短标题 |
| **问题 2：历史消息加载** | **方案 A：加载全部（上限 100 条）** | 完整上下文优先 |
| **问题 3：Results.vue 处理** | **方案 A：完全删除** | 简化代码，聚焦智能审计 |

---

## 整体规划概述

### 项目目标

**核心目标**：
1. 持久化智能审计会话和消息，服务重启后数据不丢失
2. 提供聊天记录浏览界面，支持按时间、项目筛选
3. 支持从历史会话继续对话，恢复完整上下文

**验收标准**：
- [ ] 新会话创建时自动持久化到数据库
- [ ] 每条对话消息实时保存
- [ ] 聊天记录页面能分页展示所有历史会话
- [ ] 点击历史会话能恢复到 UnifiedAudit 页面继续对话
- [ ] 侧边栏"扫描结果"改为"聊天记录"且功能正常

### 技术栈

- **前端**：Vue 3 + Vite + Pinia + Vue Router
- **后端**：Python 3.x + FastAPI + SQLite
- **数据层**：SQLite + 自定义 Repository 模式
- **实时通信**：WebSocket（已有）

### 主要阶段

1. **阶段 1：数据库层设计与实现** - 新增会话和消息表，编写 Repository
2. **阶段 2：后端 API 改造** - 修改 agent_router.py 实现持久化和会话恢复
3. **阶段 3：前端页面改造** - 新建 ChatHistory.vue，修改路由和侧边栏
4. **阶段 4：集成测试与优化** - 端到端测试，修复问题

---

## 详细任务分解

### 阶段 1：数据库层设计与实现

#### 任务 1.1：设计数据库 Schema

- **目标**：定义 `agent_sessions` 和 `agent_messages` 表结构
- **输入**：现有 `storage/database.py` Schema 设计模式
- **输出**：SQL DDL 语句
- **涉及文件**：`storage/database.py`
- **预估工作量**：0.5 小时

**Schema 设计**：

```sql
-- 智能审计会话表
CREATE TABLE IF NOT EXISTS agent_sessions (
    session_id TEXT PRIMARY KEY,
    target_path TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',  -- active/completed/archived
    title TEXT,  -- 会话标题（可由用户编辑或自动生成）
    config JSON,  -- 会话配置 (enable_call_chain, enable_variant_analysis, languages)
    messages_count INTEGER DEFAULT 0,
    tool_calls_count INTEGER DEFAULT 0,
    total_tokens_used INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_message_at TIMESTAMP
);

-- 智能审计消息表
CREATE TABLE IF NOT EXISTS agent_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,  -- user/assistant/system/tool
    content TEXT,
    tool_calls JSON,  -- [{id, tool_name, arguments, status, result, error, duration_ms}]
    metadata JSON,  -- 额外元数据
    tokens_used INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES agent_sessions(session_id) ON DELETE CASCADE
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_agent_sessions_status ON agent_sessions(status);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_created ON agent_sessions(created_at);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_updated ON agent_sessions(updated_at);
CREATE INDEX IF NOT EXISTS idx_agent_messages_session ON agent_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_agent_messages_created ON agent_messages(created_at);
```

#### 任务 1.2：创建 AgentSessionRepository

- **目标**：实现会话 CRUD 操作
- **输入**：DatabaseManager 实例
- **输出**：完整的会话数据访问层
- **涉及文件**：新建 `storage/agent_session_repository.py`
- **预估工作量**：1 小时

**接口设计**：

```python
class AgentSessionRepository:
    def create(self, session_id: str, target_path: str, config: dict) -> dict
    def get(self, session_id: str) -> Optional[dict]
    def update(self, session_id: str, **kwargs) -> bool
    def delete(self, session_id: str) -> bool
    def list_all(self, status: str = None, limit: int = 50, offset: int = 0) -> List[dict]
    def update_stats(self, session_id: str, messages_count: int, tool_calls_count: int, tokens: int) -> bool
    def set_title(self, session_id: str, title: str) -> bool
    def archive(self, session_id: str) -> bool
```

#### 任务 1.3：创建 AgentMessageRepository

- **目标**：实现消息 CRUD 操作
- **输入**：DatabaseManager 实例
- **输出**：完整的消息数据访问层
- **涉及文件**：新建 `storage/agent_message_repository.py`
- **预估工作量**：1 小时

**接口设计**：

```python
class AgentMessageRepository:
    def create(self, session_id: str, role: str, content: str, tool_calls: list = None, metadata: dict = None, tokens: int = 0) -> int
    def get_by_session(self, session_id: str, limit: int = 100, offset: int = 0) -> List[dict]
    def get_latest(self, session_id: str, since_id: int = 0) -> List[dict]
    def count_by_session(self, session_id: str) -> int
    def delete_by_session(self, session_id: str) -> int
```

#### 任务 1.4：更新 storage/__init__.py

- **目标**：导出新的 Repository 类
- **涉及文件**：`storage/__init__.py`
- **预估工作量**：0.25 小时

---

### 阶段 2：后端 API 改造

#### 任务 2.1：修改会话创建逻辑

- **目标**：创建会话时同步写入数据库
- **输入**：CreateUnifiedSessionRequest
- **输出**：会话信息持久化
- **涉及文件**：`api/agent_router.py`
- **预估工作量**：0.5 小时

**改动点**：
- 在 `create_session()` 中调用 `AgentSessionRepository.create()`
- 存储 session_id, target_path, config

#### 任务 2.2：修改对话交互逻辑

- **目标**：每次对话保存用户消息和助手回复
- **输入**：UnifiedChatRequest, Agent 响应
- **输出**：消息持久化
- **涉及文件**：`api/agent_router.py`
- **预估工作量**：0.75 小时

**改动点**：
- 在 `chat()` 中调用 `AgentMessageRepository.create()` 保存用户消息
- 保存助手回复（包含 tool_calls）
- 更新 `agent_sessions.updated_at` 和统计信息

#### 任务 2.3：新增会话恢复 API

- **目标**：支持从数据库加载历史会话并重建 Agent
- **输入**：session_id
- **输出**：恢复后的会话状态
- **涉及文件**：`api/agent_router.py`
- **预估工作量**：1.5 小时

**新增端点**：

```python
@router.post("/session/{session_id}/restore", response_model=APIResponse)
async def restore_session(session_id: str):
    """恢复历史会话

    1. 从数据库加载会话配置
    2. 创建新的 Agent 实例
    3. 加载历史消息到 Agent 内存
    4. 返回会话状态
    """
```

**关键逻辑**：
- 读取 `agent_sessions` 获取配置
- 创建 `UnifiedAuditAgent` 实例
- 读取 `agent_messages` 并调用 `agent.load_history(messages)`
- 将 Agent 存入 `_unified_sessions` 内存

#### 任务 2.4：增强会话列表 API

- **目标**：返回持久化的会话列表（而非仅内存中的）
- **涉及文件**：`api/agent_router.py`
- **预估工作量**：0.5 小时

**改动点**：
- 修改 `list_sessions()` 从数据库读取
- 合并内存中活跃会话的实时状态
- 支持分页和状态筛选

#### 任务 2.5：更新会话删除逻辑

- **目标**：删除会话时同步删除数据库记录
- **涉及文件**：`api/agent_router.py`
- **预估工作量**：0.25 小时

#### 任务 2.6：Agent 类增强 - 支持历史加载

- **目标**：在 UnifiedAuditAgent 中添加 `load_history()` 方法
- **涉及文件**：`agent/unified_agent.py` 或相关文件
- **预估工作量**：1 小时

**接口设计**：

```python
class UnifiedAuditAgent:
    def load_history(self, messages: List[dict]) -> None:
        """从数据库加载历史消息到 Agent 内存

        恢复 self.messages 列表，用于上下文连续性
        """
```

---

### 阶段 3：前端页面改造

#### 任务 3.1：创建 ChatHistory.vue 页面

- **目标**：新建聊天记录浏览页面
- **输入**：API 返回的会话列表
- **输出**：可交互的历史会话列表
- **涉及文件**：新建 `frontend/src/views/ChatHistory.vue`
- **预估工作量**：2 小时

**页面设计**：

```
+--------------------------------------------------+
| 聊天记录                            [筛选] [搜索] |
+--------------------------------------------------+
| +----------------------------------------------+ |
| | [项目图标] 项目名称                          | |
| | 最后消息: "分析这个函数的安全性..."          | |
| | 消息数: 12  |  工具调用: 8  |  2小时前       | |
| | [继续对话] [查看详情] [删除]                 | |
| +----------------------------------------------+ |
| +----------------------------------------------+ |
| | ...更多会话卡片...                           | |
| +----------------------------------------------+ |
+--------------------------------------------------+
| [加载更多]  显示 1-10 / 共 25 条                 |
+--------------------------------------------------+
```

**功能要点**：
- 卡片式布局展示会话
- 显示项目路径、消息数、工具调用数、最后更新时间
- "继续对话"按钮跳转到 UnifiedAudit 并恢复会话
- 支持删除、归档操作
- 分页加载

#### 任务 3.2：修改路由配置

- **目标**：将 `/results` 路由指向 ChatHistory.vue
- **涉及文件**：`frontend/src/main.js`
- **预估工作量**：0.25 小时

**改动**：

```javascript
// 修改前
{
  path: '/results/:scanId?',
  name: 'Results',
  component: () => import('./views/Results.vue'),
},

// 修改后
{
  path: '/results',  // 移除 :scanId 参数
  name: 'ChatHistory',
  component: () => import('./views/ChatHistory.vue'),
},
```

#### 任务 3.3：修改侧边栏

- **目标**：将"扫描结果"改为"聊天记录"
- **涉及文件**：`frontend/src/components/Sidebar.vue`
- **预估工作量**：0.25 小时

**改动点**（约第 231 行）：

```javascript
// 修改前
{ name: '扫描结果', path: '/results', icon: ResultsIcon, ... }

// 修改后
{ name: '聊天记录', path: '/results', icon: ChatHistoryIcon, ... }
```

**UI 设计考虑**：
- 更换图标为聊天气泡样式
- 保留 badge 显示未读/新会话数（可选）

#### 任务 3.4：增强 UnifiedAudit.vue - 支持会话恢复

- **目标**：从聊天记录跳转时能恢复历史会话
- **涉及文件**：`frontend/src/views/UnifiedAudit.vue`
- **预估工作量**：1.5 小时

**改动点**：
- 支持 URL 参数 `?session=xxx` 或路由 query
- 页面加载时检测是否有待恢复的 session_id
- 调用 `restoreSession` API
- 加载历史消息并渲染到聊天界面

**流程**：
1. 从 ChatHistory 点击"继续对话"
2. 跳转到 `/audit?restore=session-xxx`
3. UnifiedAudit 检测到 `restore` 参数
4. 调用 `POST /api/agent/session/{id}/restore`
5. 设置 `currentSession` 状态
6. 渲染历史消息

#### 任务 3.5：新增 API 调用函数

- **目标**：添加会话恢复相关的 API 封装
- **涉及文件**：`frontend/src/api/index.js`
- **预估工作量**：0.25 小时

**新增函数**：

```javascript
// 恢复会话
export const restoreAgentSession = (sessionId) =>
  api.post(`/agent/session/${sessionId}/restore`)

// 获取持久化的会话列表（带分页）
export const listPersistedSessions = (params) =>
  api.get('/agent/sessions/persisted', { params })
```

#### 任务 3.6：可选 - 删除或保留 Results.vue

- **目标**：决定是否保留传统扫描结果页面
- **涉及文件**：`frontend/src/views/Results.vue`
- **预估工作量**：0.25 小时（删除）或 0（保留）

**建议**：暂时保留文件，但从路由中移除。后续根据需求决定是否彻底删除。

---

### 阶段 4：集成测试与优化

#### 任务 4.1：端到端功能测试

- **目标**：验证完整工作流
- **测试用例**：
  1. 新建会话 -> 对话 -> 关闭页面 -> 刷新 -> 查看聊天记录 -> 能看到会话
  2. 从聊天记录继续对话 -> 历史消息显示正确 -> 新对话能正常保存
  3. 删除会话 -> 数据库记录清除 -> 列表刷新
  4. 服务重启 -> 会话列表不丢失
- **预估工作量**：1 小时

#### 任务 4.2：性能优化

- **目标**：确保大量会话时列表加载流畅
- **优化点**：
  - 分页加载（默认 20 条/页）
  - 消息预览只显示最后一条
  - 虚拟滚动（可选，会话 >100 时考虑）
- **预估工作量**：0.5 小时

#### 任务 4.3：错误处理与边缘情况

- **目标**：处理异常情况
- **场景**：
  - 恢复不存在的会话 -> 友好提示
  - 索引项目路径已删除 -> 提示重新索引
  - 数据库迁移（旧数据无新字段）
- **预估工作量**：0.5 小时

---

## 技术方案详情

### API 接口设计

| 方法 | 路径 | 描述 | 请求体 | 响应 |
|------|------|------|--------|------|
| POST | `/api/agent/session/create` | 创建会话（已有，增加持久化） | `{target_path, ...}` | `{session_id, ...}` |
| POST | `/api/agent/session/{id}/restore` | **新增** 恢复历史会话 | - | `{session_id, messages_count, ...}` |
| GET | `/api/agent/sessions` | 会话列表（改为从 DB 读取） | `?status=active&limit=20&offset=0` | `{sessions: [...], total: N}` |
| DELETE | `/api/agent/session/{id}` | 删除会话（增加 DB 删除） | - | `{success: true}` |
| POST | `/api/agent/session/{id}/archive` | **新增** 归档会话 | - | `{success: true}` |

### 前端组件设计

**ChatHistory.vue 组件结构**：

```
ChatHistory.vue
├── SessionFilter.vue (可选，筛选组件)
├── SessionCard.vue (会话卡片组件)
│   ├── 项目信息
│   ├── 统计信息
│   └── 操作按钮
└── Pagination.vue (分页组件，可复用)
```

**状态管理**：

```javascript
// stores/agent.js (可选，新建或扩展 app.js)
const useAgentStore = defineStore('agent', {
  state: () => ({
    persistedSessions: [],
    totalSessions: 0,
    currentPage: 1,
  }),
  actions: {
    async loadSessions(page = 1) { ... },
    async restoreSession(sessionId) { ... },
    async deleteSession(sessionId) { ... },
  }
})
```

---

## 需要进一步明确的问题

### 问题 1：会话标题生成策略

**背景**：会话列表需要显示标题以便用户识别。

**推荐方案**：

- **方案 A**：自动生成 - 使用 `target_path` 最后一级目录名 + 创建时间
  - 优点：无需用户操作
  - 缺点：不够个性化

- **方案 B**：LLM 自动摘要 - 首次对话后由 LLM 生成简短标题
  - 优点：语义相关性强
  - 缺点：增加 API 调用成本

- **方案 C**：用户手动编辑 - 提供编辑按钮
  - 优点：用户可控
  - 缺点：可能不填写

**等待用户选择**：

```
请选择您偏好的方案，或提供其他建议：
[ ] 方案 A：自动生成（目录名 + 时间）
[ ] 方案 B：LLM 自动摘要
[ ] 方案 C：用户手动编辑
[ ] 组合方案（如 A + C）
[ ] 其他方案：______________________
```

### 问题 2：历史消息加载深度

**背景**：恢复会话时需要将历史消息加载到 Agent 内存以保持上下文连续性，但过多消息会增加 token 消耗。

**推荐方案**：

- **方案 A**：加载全部消息（默认上限 100 条）
  - 优点：完整上下文
  - 缺点：长对话时 token 消耗高

- **方案 B**：智能截断 - 只加载最近 N 条 + 关键消息（首条、发现漏洞的对话）
  - 优点：平衡上下文与成本
  - 缺点：实现复杂

- **方案 C**：用户选择 - 恢复时询问"加载多少历史"
  - 优点：灵活
  - 缺点：增加操作步骤

**等待用户选择**：

```
请选择您偏好的方案，或提供其他建议：
[ ] 方案 A：加载全部（上限 100 条）
[ ] 方案 B：智能截断
[ ] 方案 C：用户选择
[ ] 其他方案：______________________
```

### 问题 3：Results.vue 的处理方式

**背景**：现有 `Results.vue` 约 870 行，展示传统扫描结果（scan_findings 表）。

**推荐方案**：

- **方案 A**：完全删除 - 不再支持传统扫描结果查看
  - 优点：简化代码
  - 缺点：丢失已有功能

- **方案 B**：保留但隐藏 - 从导航移除，保留 `/legacy-results` 路由供高级用户使用
  - 优点：兼容性
  - 缺点：维护两套代码

- **方案 C**：整合 - 在新的 ChatHistory 页面中增加 Tab 切换"审计对话" / "扫描结果"
  - 优点：统一入口
  - 缺点：页面复杂度增加

**等待用户选择**：

```
请选择您偏好的方案，或提供其他建议：
[ ] 方案 A：完全删除 Results.vue
[ ] 方案 B：保留但隐藏（/legacy-results）
[ ] 方案 C：整合到 ChatHistory 作为 Tab
[ ] 其他方案：______________________
```

---

## 风险识别与应对

| 风险 | 影响 | 概率 | 应对策略 |
|------|------|------|----------|
| Agent 内存状态与数据库不一致 | 恢复后对话异常 | 中 | 每次对话后同步更新 DB；恢复时重建 Agent |
| 长会话 token 消耗过高 | 成本增加/API 超限 | 中 | 设置消息加载上限；实现消息摘要 |
| 数据库迁移问题 | 旧实例启动失败 | 低 | Schema 使用 `IF NOT EXISTS`；提供迁移脚本 |
| 前端路由变更导致书签失效 | 用户体验下降 | 低 | 保持 `/results` 路径，仅更改组件 |
| WebSocket 连接在会话恢复时中断 | 实时消息丢失 | 低 | 恢复成功后自动重连 WS |

---

## 任务清单（按执行顺序）

### 第一阶段：数据库层（预估 3 小时）

- [ ] 1.1 在 `database.py` 添加 agent_sessions 和 agent_messages 表 Schema
- [ ] 1.2 创建 `storage/agent_session_repository.py`
- [ ] 1.3 创建 `storage/agent_message_repository.py`
- [ ] 1.4 更新 `storage/__init__.py` 导出

### 第二阶段：后端 API（预估 4.5 小时）

- [ ] 2.1 修改 `create_session()` 添加数据库写入
- [ ] 2.2 修改 `chat()` 保存消息
- [ ] 2.3 新增 `restore_session()` API
- [ ] 2.4 修改 `list_sessions()` 从数据库读取
- [ ] 2.5 修改 `delete_session()` 同步删除 DB
- [ ] 2.6 在 Agent 类添加 `load_history()` 方法

### 第三阶段：前端改造（预估 4.5 小时）

- [ ] 3.1 创建 `ChatHistory.vue` 页面
- [ ] 3.2 修改 `main.js` 路由配置
- [ ] 3.3 修改 `Sidebar.vue` 导航项
- [ ] 3.4 增强 `UnifiedAudit.vue` 支持会话恢复
- [ ] 3.5 新增 API 调用函数

### 第四阶段：测试与优化（预估 2 小时）

- [ ] 4.1 端到端功能测试
- [ ] 4.2 性能优化（分页、加载）
- [ ] 4.3 错误处理与边缘情况

---

## 用户反馈区域

请在此区域补充您对整体规划的意见和建议：

```
用户补充内容：

---

---

---

```

---

## 附录：文件修改清单

| 文件路径 | 操作 | 说明 |
|----------|------|------|
| `storage/database.py` | 修改 | 添加新表 Schema |
| `storage/agent_session_repository.py` | 新建 | 会话 CRUD |
| `storage/agent_message_repository.py` | 新建 | 消息 CRUD |
| `storage/__init__.py` | 修改 | 导出新类 |
| `api/agent_router.py` | 修改 | 持久化逻辑、恢复 API |
| `agent/unified_agent.py` | 修改 | 添加 load_history() |
| `frontend/src/views/ChatHistory.vue` | 新建 | 聊天记录页面 |
| `frontend/src/main.js` | 修改 | 路由配置 |
| `frontend/src/components/Sidebar.vue` | 修改 | 导航项名称和图标 |
| `frontend/src/views/UnifiedAudit.vue` | 修改 | 会话恢复逻辑 |
| `frontend/src/api/index.js` | 修改 | 新增 API 函数 |
| `frontend/src/views/Results.vue` | 待定 | 根据用户选择处理 |
