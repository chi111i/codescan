# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

**CodeScan** 是一个 LLM 驱动的代码安全审计工具，专注于检测传统静态分析工具难以发现的**业务逻辑漏洞、权限控制问题和高危安全缺陷**（RCE、任意文件读写、反序列化、SSRF、鉴权绕过、IDOR、状态机绕过等）。

### 北极星目标

**核心使命**：挖掘深层次高危逻辑漏洞，通过：

1. 扫描所有危险函数（sinks）触发点
2. 找到每个 sink 的所有调用链（入口点 → ... → 触发 sink 的函数）
3. 自动收集调用链涉及的代码上下文
4. 交给 LLM 做链级逐步推理与结构化结论输出

**衡量标准**：能否在中大型仓库里高召回地输出 sink 触发点、调用链路径、链上代码证据 + LLM 结构化审计结论。

---

## 常用命令

### 开发启动

```bash
# 安装依赖
pip3 install -r requirements.txt
cd frontend && npm install

# 同时启动前后端（开发模式）
python3 start.py all

# 仅后端 API (端口 8000)
python3 start.py api --host 0.0.0.0 --port 8000

# 仅前端开发服务器 (端口 3000)
python3 start.py frontend
```

### CLI 命令

```bash
# 初始化配置
python3 -m codescan init -o audit.config.yaml

# 索引项目
python3 -m codescan index ./project-path
python3 -m codescan index ./project-path --clear  # 清空重建

# 安全扫描
python3 -m codescan scan ./project-path -l python -f json -o report.json

# 高危漏洞扫描
python3 -m codescan vulnscan ./project-path -t rce,sql_injection,file_read
python3 -m codescan vulnscan ./project-path --no-llm  # 不使用 LLM

# 调用链分析
python3 -m codescan callgraph ./project-path -d 15 -o call_graph.json

# 代码搜索
python3 -m codescan search "用户认证逻辑" -l python -n 20

# 规则管理
python3 -m codescan rules list -l python
python3 -m codescan rules stats
```

### 测试

```bash
# 运行所有测试
python3 tests/

# 单个测试文件
python3 tests/test_parser.py -v
```

---

## 核心架构

```
后端: Python 3.x + FastAPI + Qdrant
前端: Vue 3 + Vite + Pinia
```

### 核心数据流

```
目标代码 → indexer/parser.py (AST解析)
        → indexer/indexer.py (生成 CodeUnit)
        → llm_client/client.py (嵌入向量)
        → indexer/vector_store.py (Qdrant/内存存储)
        → analyzer/call_chain.py (构建调用图)
        → analyzer/engine.py (候选点发现 + LLM 分析)
        → api/main.py (WebSocket 进度推送)
        → 前端展示
```

### 核心抽象

| 概念 | 文件 | 职责 |
|------|------|------|
| **CodeUnit** | `indexer/models.py` | 代码分析单元（函数/方法/类），包含 id、symbol、calls、span、code |
| **SecurityRule** | `rules/models.py` | 安全规则（sink/source/sanitizer），支持 patterns、risk_level、CWE |
| **Finding** | `analyzer/models.py` | 分析发现结果，包含 severity、confidence、evidence、attack_scenario |
| **CallGraph** | `analyzer/call_chain.py` | 函数调用图，用于求入口点到 sink 的路径 |
| **TaintPath** | `analyzer/taint_analysis.py` | 污点传播路径 source → sink |

### 模块职责

- **`config/`** - 配置加载（YAML + 环境变量），LLM/向量库/扫描参数
- **`llm_client/`** - OpenAI 兼容 API 封装（chat_completion、embed），支持任意 base_url
- **`indexer/`** - 代码解析（Python AST、JS/PHP 正则）+ 向量存储 + 嵌入缓存
- **`rules/`** - 安全规则管理（sink/source/sanitizer），内置 + 自定义规则
- **`analyzer/`** - 核心分析引擎：候选点发现、调用链、污点分析、LLM 深度审计
- **`agent/`** - LLM Function Calling 代理，支持自主代码探索
- **`storage/`** - SQLite 持久化存储：扫描任务、发现结果、LLM 交互日志
- **`api/`** - FastAPI 后端，WebSocket 实时进度
- **`frontend/`** - Vue 3 界面，磨砂玻璃风格 UI

---

## LLM Agent 工具系统

### 核心理念

**让 LLM 像人类安全专家使用 IDE 一样进行代码审计**：可以主动搜索文件、查找函数定义、查看指定行号范围的代码、追踪调用链和数据流。

### 已实现的 Function Calling 工具

#### 代码导航工具 (`agent/tools/registry.py`)

| 工具名称 | 功能描述 |
|---------|---------|
| `search_code` | 语义搜索查找相关代码片段 |
| `read_file` | 读取文件内容（支持行号范围） |
| `get_function` | 获取函数/方法完整代码 |
| `list_functions` | 列出文件中的所有函数和类 |
| `get_callers` | 查找调用指定函数的位置 |
| `get_callees` | 查找函数调用的其他函数 |

#### 安全分析工具

| 工具名称 | 功能描述 |
|---------|---------|
| `analyze_taint_path` | 分析 Source → Sink 的污点传播路径 |
| `check_auth` | 检查函数是否有认证授权检查 |
| `find_entry_points` | 查找项目入口点（HTTP 路由、API 端点） |

### Agent 执行流程

```
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
└───────────────┘   └───────────────┘   └───────────────┘
```

### 关键模块

| 模块 | 文件 | 职责 |
|------|------|------|
| **ToolRegistry** | `agent/tools/registry.py` | OpenAI Function Calling 格式的工具定义管理 |
| **ToolExecutor** | `agent/tools/executor.py` | 工具调用执行 + 日志记录 |
| **LoggedSecurityAgent** | `agent/logged_agent.py` | 带日志记录的安全审计 Agent |

---

## 数据持久化层

### 存储模块 (`storage/`)

扫描结果使用 SQLite 持久化存储，服务重启不丢失。

| 模块 | 职责 |
|------|------|
| `database.py` | SQLite 连接管理，自动创建 schema |
| `scan_repository.py` | 扫描任务 CRUD |
| `finding_repository.py` | 发现结果 CRUD（支持分页、过滤） |
| `interaction_repository.py` | LLM 交互日志 CRUD |

### 数据库位置

```
.audit_data/audit.db    # 扫描结果、发现、交互日志
.audit_cache/           # 嵌入缓存、文件追踪
```

### 新增 API 端点

```
GET  /api/scan/{id}/findings?page=1&limit=20&severity=high
GET  /api/scan/{id}/interactions?page=1&limit=50
GET  /api/scan/{id}/findings/latest?since_id={last_id}
GET  /api/scan/{id}/timeline
```

---

## 实时展示系统

### WebSocket 消息类型

```typescript
// 扫描进度
{ type: 'progress', scan_id, status, progress, current_step }

// LLM 交互（工具调用、思考过程）
{ type: 'interaction', data: { type, tool_name, tool_input, tool_output, content } }

// 新发现推送
{ type: 'new_finding', finding: {...} }
```

### 前端组件

- **LLM 交互面板** (`Scan.vue`): 显示 LLM 每一步分析过程
- **工具调用日志**: 显示每次工具调用的输入输出
- **发现列表实时更新**: 新发现自动添加到列表顶部

---

## 向量搜索优化

### 嵌入缓存 (`indexer/embedding_cache.py`)

- **LRU 淘汰策略**: 基于 `accessed_at` 追踪访问时间
- **压缩存储**: `struct.pack` + `zlib` 压缩嵌入向量
- **持久化统计**: 命中率、淘汰次数等统计信息

### 增量索引 (`indexer/indexer.py`)

- **FileTracker**: 基于 mtime + 内容哈希追踪文件变更
- **index_directory_incremental()**: 只处理新增/修改的文件

### 高级重排序 (`indexer/vector_store.py`)

```python
RerankerConfig(
    enable_reranking=True,
    vector_weight=0.4,           # 向量相似度权重
    keyword_weight=0.25,         # 关键词匹配权重
    security_weight=0.2,         # 安全相关性权重
    context_weight=0.15,         # 上下文相关性权重
    security_priority_mode=True, # 安全相关代码提升 1.5x
    prefer_entry_points=True,    # 优先 handler/controller
)
```

**CodeReranker** 评分因素：
1. 高危模式检测（exec/eval/SQL/文件操作等正则匹配）
2. 敏感符号名（auth/login/password/admin/delete/payment）
3. 入口点识别（handler/controller/route 等）
4. 代码长度偏好（更短更聚焦的函数优先）

---

## 关键设计原则

### 1. 候选点发现必须确定性

**当前问题**：向量搜索作为主召回手段会导致漏报。

**正确做法**：
- 使用 **SinkCallScanner** 做确定性扫描（AST/regex 匹配 sink patterns）
- 向量检索仅用于**上下文补充**（相似代码、配置定义、变体分析）
- `discover_candidates_from_units` 直接遍历 CodeUnit 匹配规则 patterns

### 2. 调用链驱动的分析

LLM 分析单位是**调用链**而非单个函数：
- 链上下文包含：入口点 → 中间节点 → sink 触发点的所有函数代码
- 链级 Finding 输出：chain_id、evidence（按节点列出）、exploitability_conditions
- 爆炸控制：max_depth、max_chains_per_sink、路径去重

### 3. calls 提取与规则匹配

**关键**：Python AST 提取的 `calls` 需要完整限定名：
- `os.system("id")` → 提取 `os.system`（不仅是 `system`）
- 规则 patterns 支持：精确匹配、prefix:、suffix:、contains:、regex:

### 4. 异步任务不阻塞

FastAPI 后台任务使用 `asyncio.to_thread()` 包装同步重操作：
```python
code_units = await asyncio.to_thread(indexer.parse_directory_without_index, path)
findings = await asyncio.to_thread(analyzer.analyze, ...)
```

---

## LLM 分析输出格式

LLM 必须输出结构化 JSON：

```json
{
  "has_issue": true,
  "issue_type": "command_injection",
  "severity": "critical",
  "confidence": 0.85,
  "summary": "用户输入直接传入 os.system",
  "details": "...",
  "evidence": [
    {"file_path": "app.py", "line_start": 45, "code_snippet": "...", "reason": "..."}
  ],
  "attack_scenario": "高层次攻击思路（不含 payload）",
  "fix_suggestion": "使用 subprocess + shlex.quote",
  "notes": "需要确认的点"
}
```

---

## 开发注意事项

### 安全审计重点领域

1. **认证授权**：未检查登录状态、授权可绕过、信任客户端字段
2. **IDOR**：用户可控 ID 直接查询、缺少资源归属验证
3. **业务流程**：状态机可跳步、关键参数信任客户端
4. **敏感操作**：缺少二次验证、无审计日志、无频率限制
5. **跨服务信任**：内部 API 信任可伪造的 header/claim

### 高危 Sink 类别

| 类别 | Python 示例 | PHP 示例 |
|------|-------------|----------|
| RCE | `os.system`, `eval`, `exec`, `subprocess.*` | `exec`, `eval`, `system`, `shell_exec` |
| 文件读 | `open`, `Path.read_text`, `send_file` | `file_get_contents`, `fopen`, `readfile` |
| 文件写 | `open(..., 'w')`, `Path.write_text` | `file_put_contents`, `fwrite` |
| 反序列化 | `pickle.loads`, `yaml.load` | `unserialize` |
| SSRF | `requests.get`, `urllib.request.urlopen` | `curl_exec`, `file_get_contents` |
| SQLi | `cursor.execute`, `raw()` | `mysql_query`, `mysqli_query` |

### API 端点

```
POST /api/scan          # 创建扫描任务
GET  /api/scan/{id}     # 获取结果
WS   /ws/scan/{id}      # 实时进度
POST /api/index         # 索引项目
GET  /api/rules         # 列出规则
POST /api/settings      # 更新配置
```

---

## 优先级指南

### P0 - 必须正确

1. LLM base_url 拼接不能重复 `/v1`（client.py）
2. FastAPI 异步任务使用 `asyncio.to_thread` 不阻塞事件循环
3. 候选点发现用确定性扫描，不依赖向量检索
4. calls 提取要有完整限定名，与规则 patterns 匹配

### P1 - 结果可信

1. 调用图 `build_call_graph()` 每次重置状态
2. Pydantic 模型使用 `Field(default_factory=list)` 不用 `=[]`
3. 污点分析要基于 AST 变量关系，不是字符串包含

### 反目标（Anti-goals）

在核心链路分析跑通前，不要投入：
- 复杂多模型路由、复杂权限系统
- 重前端功能（工单、评论、仪表盘大而全）
- 只靠 embedding 就下结论的"语义审计"
