# LLM Agent 代码审计增强方案

> 版本: v1.0
> 创建日期: 2024-12-14
> 状态: 待确认

## 一、需求背景与目标

### 1.1 当前问题

1. **LLM 能力受限**：当前 LLM 只能被动接收上下文，无法像代码编辑器一样主动查找代码
2. **扫描结果存储**：全部存储在内存中，大型扫描结果无法持久化和分页展示
3. **实时反馈缺失**：扫描过程中无法动态查看每次 LLM 返回的结果
4. **向量搜索定位模糊**：只能辅助定位，精确性不足

### 1.2 目标愿景

**让 LLM 像人类安全专家使用 IDE 一样进行代码审计：**
- 可以主动搜索文件、查找函数定义
- 可以查看指定行号范围的代码
- 可以追踪调用链和数据流
- 每一步分析都能实时展示给用户

---

## 二、核心功能设计

### 2.1 LLM Function Calling 工具集

#### 2.1.1 代码导航工具

| 工具名称 | 功能描述 | 参数 |
|---------|---------|-----|
| `list_files` | 列出目录下的文件 | `path`, `pattern`, `recursive` |
| `search_files` | 按文件名/路径搜索 | `query`, `include_pattern`, `exclude_pattern` |
| `read_file` | 读取文件内容 | `file_path`, `start_line`, `end_line` |
| `read_symbol` | 读取函数/类定义 | `symbol_name`, `file_path` |
| `get_file_outline` | 获取文件结构大纲 | `file_path` |

#### 2.1.2 代码分析工具

| 工具名称 | 功能描述 | 参数 |
|---------|---------|-----|
| `search_code` | 代码内容搜索（正则/语义） | `query`, `search_type`, `language`, `max_results` |
| `find_references` | 查找符号引用 | `symbol_name`, `file_path` |
| `get_call_chain` | 获取调用链 | `function_name`, `direction`, `max_depth` |
| `trace_data_flow` | 追踪数据流 | `variable`, `file_path`, `line_number` |

#### 2.1.3 安全分析工具

| 工具名称 | 功能描述 | 参数 |
|---------|---------|-----|
| `check_sink_pattern` | 检查危险函数调用 | `code_snippet`, `sink_category` |
| `get_security_context` | 获取安全相关上下文 | `file_path`, `line_range` |
| `report_finding` | 报告发现的问题 | `finding_data` |

### 2.2 扫描结果持久化存储

#### 2.2.1 数据库 Schema 设计

```sql
-- 扫描任务表
CREATE TABLE scan_tasks (
    scan_id TEXT PRIMARY KEY,
    target_path TEXT NOT NULL,
    status TEXT NOT NULL,  -- pending/indexing/analyzing/completed/failed
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    total_units INTEGER,
    config JSON,
    error_message TEXT
);

-- 扫描发现表（支持增量插入）
CREATE TABLE scan_findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    finding_type TEXT,  -- security/vuln/taint
    title TEXT,
    file_path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    symbol TEXT,
    severity TEXT,
    confidence REAL,
    category TEXT,
    summary TEXT,
    details TEXT,
    evidence JSON,
    attack_scenario TEXT,
    fix_suggestion TEXT,
    code_snippet TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan_tasks(scan_id)
);

-- LLM 交互日志表（记录每次调用）
CREATE TABLE llm_interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    interaction_type TEXT,  -- tool_call/analysis/finding
    tool_name TEXT,
    tool_input JSON,
    tool_output JSON,
    llm_response JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan_tasks(scan_id)
);

-- 创建索引
CREATE INDEX idx_findings_scan_id ON scan_findings(scan_id);
CREATE INDEX idx_findings_severity ON scan_findings(severity);
CREATE INDEX idx_interactions_scan_id ON llm_interactions(scan_id);
```

#### 2.2.2 API 分页接口

```python
# 获取扫描发现（分页）
GET /api/scan/{scan_id}/findings?page=1&limit=20&severity=high&category=rce

# 获取 LLM 交互日志（实时查看）
GET /api/scan/{scan_id}/interactions?page=1&limit=50

# 获取最新发现（轮询或 SSE）
GET /api/scan/{scan_id}/findings/latest?since_id={last_id}
```

### 2.3 实时结果展示

#### 2.3.1 WebSocket 增强消息类型

```typescript
interface ScanProgressMessage {
    type: 'progress';
    scan_id: string;
    status: string;
    progress: number;
    current_step: string;
}

interface LLMInteractionMessage {
    type: 'llm_interaction';
    scan_id: string;
    interaction: {
        type: 'tool_call' | 'analysis' | 'thinking';
        tool_name?: string;
        tool_input?: object;
        tool_output?: object;
        content?: string;
        timestamp: string;
    };
}

interface NewFindingMessage {
    type: 'new_finding';
    scan_id: string;
    finding: FindingSchema;
}
```

#### 2.3.2 前端实时展示组件

- **LLM 思考过程面板**：显示 LLM 当前正在做什么
- **工具调用日志**：显示每次工具调用的输入输出
- **发现列表实时更新**：新发现自动添加到列表顶部

---

## 三、实施步骤

### Phase 1: 数据持久化层（优先级：P0）

#### 任务 1.1: 创建数据库模块
- [ ] 创建 `storage/` 目录
- [ ] 实现 `storage/database.py` - SQLite 连接管理
- [ ] 实现 `storage/scan_repository.py` - 扫描任务 CRUD
- [ ] 实现 `storage/finding_repository.py` - 发现结果 CRUD
- [ ] 实现 `storage/interaction_repository.py` - LLM 交互日志 CRUD

#### 任务 1.2: 迁移 API 层
- [ ] 修改 `api/main.py` - 使用数据库替代内存存储
- [ ] 添加分页参数支持
- [ ] 添加过滤参数支持
- [ ] 确保向后兼容

### Phase 2: LLM Agent 工具系统（优先级：P0）

#### 任务 2.1: 工具执行引擎
- [ ] 创建 `agent/tool_executor.py` - 工具调用执行器
- [ ] 实现代码导航工具的实际逻辑
- [ ] 实现代码分析工具的实际逻辑
- [ ] 实现安全分析工具的实际逻辑

#### 任务 2.2: Agent 循环实现
- [ ] 创建 `agent/audit_agent.py` - 审计 Agent 主循环
- [ ] 实现 tool use 循环（调用 → 执行 → 返回 → 继续）
- [ ] 实现最大步数限制和超时控制
- [ ] 实现中间结果记录

#### 任务 2.3: LLM 客户端增强
- [ ] 修改 `llm_client/client.py` - 支持流式输出
- [ ] 支持 tool_choice 参数
- [ ] 支持中间状态回调

### Phase 3: 实时展示系统（优先级：P1）

#### 任务 3.1: WebSocket 增强
- [ ] 修改 `api/main.py` - 增强 WebSocket 消息类型
- [ ] 实现 LLM 交互实时推送
- [ ] 实现新发现实时推送

#### 任务 3.2: 前端组件开发
- [ ] 创建 `LLMInteractionPanel.vue` - LLM 交互展示组件
- [ ] 修改 `Scan.vue` - 添加实时交互面板
- [ ] 修改 `Results.vue` - 添加分页和虚拟滚动
- [ ] 优化代码片段展示（语法高亮）

### Phase 4: 向量搜索优化（优先级：P2）

#### 任务 4.1: 混合检索增强
- [ ] 结合 AST 分析和向量搜索
- [ ] 实现代码结构感知的检索
- [ ] 支持更精确的符号定位

---

## 四、技术方案详解

### 4.1 LLM Agent 审计流程

```
┌─────────────────────────────────────────────────────────────────┐
│                     LLM Agent 审计循环                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. 初始化：提供项目概览 + 安全规则 + 可用工具列表                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. LLM 决策：分析当前信息，决定下一步                           │
│    - 需要更多上下文？→ 调用工具                                 │
│    - 发现问题？→ 调用 report_finding                           │
│    - 分析完成？→ 结束循环                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
           ┌──────────────────┼──────────────────┐
           ▼                  ▼                  ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ 调用工具      │   │ 报告发现      │   │ 结束分析      │
│ - 执行工具    │   │ - 保存到 DB   │   │ - 汇总结果    │
│ - 记录日志    │   │ - WebSocket   │   │ - 更新状态    │
│ - 返回结果    │   │   推送        │   │               │
└───────┬───────┘   └───────────────┘   └───────────────┘
        │
        └───────────────────────────────────────────────┐
                                                        ▼
                                          ┌───────────────────┐
                                          │ 返回步骤 2 继续   │
                                          └───────────────────┘
```

### 4.2 工具调用示例

```python
# LLM 返回的工具调用请求
{
    "tool_calls": [{
        "id": "call_abc123",
        "type": "function",
        "function": {
            "name": "search_code",
            "arguments": "{\"query\": \"eval(\", \"search_type\": \"regex\", \"language\": \"python\"}"
        }
    }]
}

# 工具执行结果
{
    "tool_call_id": "call_abc123",
    "content": "[{\"file\": \"app/utils.py\", \"line\": 45, \"code\": \"result = eval(user_input)\", \"context\": \"...\"}]"
}

# LLM 继续分析并报告发现
{
    "tool_calls": [{
        "id": "call_def456",
        "type": "function",
        "function": {
            "name": "report_finding",
            "arguments": "{\"title\": \"危险的 eval 调用\", \"severity\": \"critical\", ...}"
        }
    }]
}
```

### 4.3 数据库存储方案

使用 **SQLite** 作为默认存储（轻量、零配置），支持升级到 PostgreSQL。

```python
# storage/database.py
class DatabaseManager:
    def __init__(self, db_path: str = ".audit_data/audit.db"):
        self.db_path = db_path
        self._ensure_schema()

    def _ensure_schema(self):
        """确保数据库 schema 存在"""
        ...

    def get_connection(self) -> sqlite3.Connection:
        """获取数据库连接"""
        ...
```

---

## 五、验收标准

### 5.1 功能验收

- [ ] LLM 可以通过工具调用主动查找代码文件
- [ ] LLM 可以读取指定行号范围的代码
- [ ] 扫描结果持久化存储，服务重启不丢失
- [ ] 前端可以分页查看大型扫描结果
- [ ] 前端可以实时看到 LLM 的每一步分析过程
- [ ] WebSocket 推送新发现的漏洞

### 5.2 性能验收

- [ ] 1000+ 代码单元的项目扫描不超时
- [ ] 结果列表滚动流畅（虚拟滚动）
- [ ] LLM 工具调用响应时间 < 2s

### 5.3 兼容性验收

- [ ] 现有 API 接口保持向后兼容
- [ ] 现有前端功能正常工作
- [ ] 配置文件格式兼容

---

## 六、风险与缓解

| 风险 | 影响 | 缓解措施 |
|-----|------|---------|
| LLM 工具调用死循环 | 资源耗尽 | 设置最大步数限制（如 50 步） |
| SQLite 并发写入性能 | 大量发现时写入慢 | 使用 WAL 模式，或升级 PostgreSQL |
| WebSocket 消息积压 | 前端卡顿 | 消息队列 + 节流推送 |
| LLM Token 消耗过多 | 成本增加 | 优化提示词，压缩上下文 |

---

## 七、时间估算（参考）

| 阶段 | 预计工作量 |
|-----|-----------|
| Phase 1: 数据持久化层 | 4-6 小时 |
| Phase 2: LLM Agent 工具系统 | 8-12 小时 |
| Phase 3: 实时展示系统 | 6-8 小时 |
| Phase 4: 向量搜索优化 | 4-6 小时 |
| **总计** | **22-32 小时** |

---

## 八、待讨论事项

1. **工具粒度**：是提供细粒度工具（如 `read_line_range`）还是粗粒度工具（如 `analyze_function`）？
2. **LLM 模型选择**：是否需要针对不同任务使用不同模型（如 GPT-4 分析，GPT-3.5 工具调用）？
3. **存储方案**：SQLite 是否足够，还是需要直接使用 PostgreSQL？
4. **前端技术栈**：是否需要引入状态管理库（如 Pinia）来管理实时数据？

---

**请确认此规划方案，或提出修改意见。确认后将开始实施。**
