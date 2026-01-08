# CodeScan - LLM 驱动的代码安全审计工具

一款基于大语言模型（LLM）的智能代码安全审计工具，专注于检测传统静态分析工具难以发现的**业务逻辑漏洞、权限控制问题和高危安全缺陷**（RCE、任意文件读写、反序列化、SSRF、鉴权绕过、IDOR、状态机绕过等）。

## 核心理念

### 北极星目标

**核心使命**：挖掘深层次高危逻辑漏洞，通过：

1. **扫描所有危险函数（sinks）触发点**
2. **找到每个 sink 的所有调用链**（入口点 → ... → 触发 sink 的函数）
3. **自动收集调用链涉及的代码上下文**
4. **交给 LLM 做链级逐步推理与结构化结论输出**

**衡量标准**：能否在中大型仓库里高召回地输出 sink 触发点、调用链路径、链上代码证据 + LLM 结构化审计结论。

## 功能特性

### 核心功能

- **智能代码索引**：使用向量数据库（Qdrant）存储代码嵌入，支持语义搜索和增量索引
- **多语言支持**：Python（AST 解析）、JavaScript、TypeScript、PHP（正则解析）代码解析
- **高危漏洞检测**：RCE、命令注入、SQL 注入、文件操作、SSRF、反序列化等
- **业务逻辑分析**：认证绕过、权限控制、IDOR、竞态条件等逻辑漏洞
- **污点分析**：Source → Sink 数据流追踪
- **调用链分析**：函数调用图构建与危险路径识别
- **LLM Agent**：支持 Function Calling 的自主代码探索
- **LLM 深度分析**：以调用链为单位进行复杂漏洞验证和分析

### 界面特性

- **Apple 风格 UI**：磨砂玻璃效果的现代化界面
- **实时扫描进度**：WebSocket 实时更新扫描状态
- **LLM 交互面板**：显示 LLM 每一步分析过程和工具调用
- **可视化仪表盘**：安全评分、严重性分布、语言统计
- **详细报告**：支持 JSON、Console、SARIF 多种输出格式

## 系统要求

- Python 3.8+
- Node.js 16+
- Qdrant 向量数据库（可选，支持内存模式）

## 快速开始

### 1. 安装依赖

```bash
# 后端依赖
pip install -r requirements.txt

# 前端依赖
cd frontend
npm install
```

### 2. 配置

创建配置文件：

```bash
python -m codescan init -o audit.config.yaml
```

编辑 `audit.config.yaml`，设置 LLM API：

```yaml
llm:
  provider: openai
  base_url: https://api.openai.com/v1  # 或自定义 API 地址
  api_key: your-api-key
  model: gpt-4
  embedding_model: text-embedding-ada-002

vector_store:
  provider: qdrant  # 或 memory
  collection_name: code_audit
  # Qdrant 配置（如使用）
  host: localhost
  port: 6333
```

### 3. 启动服务

#### 方式一：同时启动前后端

```bash
python start.py all
```

#### 方式二：分别启动

```bash
# 启动后端 API (端口 8000)
python start.py api

# 启动前端开发服务器 (端口 3000)
python start.py frontend
```

#### 方式三：仅使用 CLI

```bash
# 索引代码
python -m codescan index ./your-project

# 执行扫描
python -m codescan scan ./your-project

# 高危漏洞扫描
python -m codescan vulnscan ./your-project
```

### 4. 访问界面

打开浏览器访问：http://localhost:3000

## 命令行使用

### 初始化配置

```bash
python -m codescan init -o audit.config.yaml
```

### 索引项目

```bash
python -m codescan index ./project-path
python -m codescan index ./project-path --clear  # 清空后重建索引
```

### 安全扫描

```bash
# 基本扫描
python -m codescan scan ./project-path

# 指定语言和输出格式
python -m codescan scan ./project-path -l python -f json -o report.json

# 控制分析数量
python -m codescan scan ./project-path -n 100 --reindex
```

### 高危漏洞扫描

```bash
# 完整扫描
python -m codescan vulnscan ./project-path

# 指定漏洞类型
python -m codescan vulnscan ./project-path -t rce,sql_injection,file_read

# 禁用 LLM 深度分析
python -m codescan vulnscan ./project-path --no-llm

# 仅模式匹配，不扫描逻辑漏洞
python -m codescan vulnscan ./project-path --no-logic
```

支持的漏洞类型：
- `rce` - 远程代码执行
- `command_injection` - 命令注入
- `sql_injection` - SQL 注入
- `file_read` - 任意文件读取
- `file_write` - 任意文件写入
- `file_upload` - 文件上传漏洞
- `path_traversal` - 路径穿越
- `ssrf` - 服务端请求伪造
- `xxe` - XML 外部实体注入
- `deserialization` - 反序列化漏洞
- `ssti` - 模板注入
- `auth_bypass` - 认证绕过
- `authz_bypass` - 授权绕过
- `idor` - 不安全的直接对象引用
- `logic_flaw` - 业务逻辑漏洞
- `race_condition` - 竞态条件
- `mass_assignment` - 批量赋值漏洞

### 调用链分析

```bash
# 构建调用图并分析污点路径
python -m codescan callgraph ./project-path

# 设置最大深度
python -m codescan callgraph ./project-path -d 15

# 导出到指定文件
python -m codescan callgraph ./project-path -o call_graph.json
```

### 代码搜索

```bash
# 语义搜索
python -m codescan search "用户认证逻辑"

# 限定语言和数量
python -m codescan search "数据库查询" -l python -n 20
```

### 规则管理

```bash
# 列出所有规则
python -m codescan rules list

# 按语言过滤
python -m codescan rules list -l python

# 查看规则详情
python -m codescan rules show --id RULE-001

# 规则统计
python -m codescan rules stats
```

### 查看发现详情

```bash
python -m codescan explain FINDING-001 -r report.json
```

### 存储管理

```bash
# 查看存储统计
python -m codescan storage stats

# 清空所有存储
python -m codescan storage clear
```

## API 接口

### 健康检查

```
GET /api/health
```

### 索引管理

```
POST /api/index          # 索引项目
GET  /api/index/stats    # 获取索引统计
```

### 扫描

```
POST /api/scan                    # 创建扫描任务
GET  /api/scan/{scan_id}          # 获取扫描结果
GET  /api/scan/{scan_id}/findings # 获取扫描发现
GET  /api/scans                   # 列出所有扫描任务
```

### 调用图

```
POST /api/callgraph    # 分析调用图
```

### 规则

```
GET /api/rules              # 列出规则
GET /api/rules/{rule_id}    # 获取规则详情
```

### 代码单元

```
GET /api/units              # 列出代码单元
GET /api/units/{unit_id}    # 获取代码单元详情
```

### 搜索

```
POST /api/search    # 搜索代码
```

### WebSocket

```
WS /ws/scan/{scan_id}    # 实时扫描进度
```

## 核心架构

### 技术栈

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

## 项目结构

```
codescan/
├── agent/                 # LLM Agent 系统
│   ├── tools/            # Function Calling 工具
│   │   ├── registry.py   # 工具定义管理
│   │   └── executor.py   # 工具调用执行
│   ├── logged_agent.py   # 带日志的安全审计 Agent
│   └── unified_agent.py  # 统一 Agent 入口
├── analyzer/              # 核心分析引擎
│   ├── engine.py          # 安全分析器
│   ├── call_chain.py      # 调用链分析
│   ├── taint_analysis.py  # 污点分析
│   ├── sink_scanner.py    # Sink 确定性扫描
│   ├── vuln_detector.py   # 漏洞检测器
│   ├── models.py          # 数据模型
│   └── prompts.py         # LLM 提示词
├── api/                    # FastAPI 后端
│   ├── main.py            # 主应用
│   ├── schemas.py         # Pydantic 模型
│   └── agent_router.py    # Agent API 路由
├── cli/                   # 命令行接口
│   └── main.py
├── config/                # 配置管理
│   ├── settings.py        # 配置加载
│   └── validator.py       # 配置验证
├── frontend/              # Vue 3 前端
│   ├── src/
│   │   ├── views/        # 页面组件
│   │   ├── components/   # 通用组件
│   │   ├── stores/       # Pinia 状态管理
│   │   ├── api/          # API 调用
│   │   └── style.css     # 全局样式
│   └── package.json
├── indexer/               # 代码索引
│   ├── indexer.py         # 索引器（支持增量索引）
│   ├── parser.py          # 语言解析器
│   ├── vector_store/      # 向量存储（Qdrant/内存）
│   ├── embedding_cache.py # 嵌入缓存（LRU + 压缩）
│   └── models.py          # 代码单元模型
├── llm_client/            # LLM 客户端
│   ├── client.py          # OpenAI 兼容 API 封装
│   └── output_validator.py
├── prompts/               # 提示词模板
├── reporting/             # 报告生成
│   └── reporter.py
├── rules/                 # 安全规则
│   ├── manager.py         # 规则管理器
│   ├── models.py          # 规则模型
│   └── data/              # 内置规则（YAML）
├── storage/               # 数据持久化
│   ├── database.py        # SQLite 连接管理
│   ├── scan_repository.py # 扫描任务 CRUD
│   ├── finding_repository.py  # 发现结果 CRUD
│   └── interaction_repository.py # LLM 交互日志
├── utils/                 # 工具函数
├── requirements.txt       # Python 依赖
├── start.py               # 启动脚本
└── __main__.py            # CLI 入口
```

## 配置说明

### LLM 配置

```yaml
llm:
  provider: openai          # openai, azure, custom
  base_url: https://api.openai.com/v1
  api_key: sk-xxx
  model: gpt-4              # 分析模型
  embedding_model: text-embedding-ada-002  # 嵌入模型
  temperature: 0            # 推荐使用 0 获得稳定结果
  max_tokens: 4096
  timeout: 120
```

### 向量存储配置

```yaml
vector_store:
  provider: qdrant          # qdrant, memory
  collection_name: code_audit
  host: localhost
  port: 6333
  embedding_dim: 1536       # 与嵌入模型匹配
```

### 扫描配置

```yaml
scan:
  target_path: .
  include_patterns:
    - "*.py"
    - "*.js"
    - "*.ts"
    - "*.php"
  exclude_patterns:
    - "node_modules/**"
    - "venv/**"
    - "__pycache__/**"
    - "*.min.js"
  max_file_size: 1048576    # 1MB
  max_workers: 4
```

### 报告配置

```yaml
report:
  output_path: ./audit_report.json
  output_format: json       # json, console, sarif
  include_code: true
  max_code_lines: 20
```

## 安全规则

规则存储在 `rules/data/` 目录下，支持 YAML 格式：

```yaml
- id: RULE-PYTHON-001
  name: eval 函数使用
  rule_type: sink
  category: injection
  risk_level: critical
  languages:
    - python
  patterns:
    - "eval("
    - "exec("
  description: 使用 eval/exec 执行动态代码可能导致代码注入
  fix_suggestion: 避免使用 eval/exec，使用安全的替代方案
```

## 输出示例

### Console 输出

```
╭─────────────────────────────────────────────────────────────╮
│           LLM 代码安全审计工具                                │
│ 目标: ./my-project                                          │
╰─────────────────────────────────────────────────────────────╯

正在分析...
发现 5 个潜在问题

┌────────────┬─────────────┬────────┬─────────┬──────────────────────┐
│ ID         │ 类型        │ 严重性  │ 置信度  │ 位置                  │
├────────────┼─────────────┼────────┼─────────┼──────────────────────┤
│ VULN-001   │ sql_injection│ critical│ 85%    │ app/models.py:45     │
│ VULN-002   │ auth_bypass │ high    │ 72%    │ app/auth.py:128      │
│ VULN-003   │ idor        │ high    │ 68%    │ app/views.py:234     │
└────────────┴─────────────┴────────┴─────────┴──────────────────────┘
```

### JSON 输出

```json
{
  "scan_id": "abc123",
  "target_path": "./my-project",
  "scan_time": "2024-01-15T10:30:00Z",
  "summary": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 0
  },
  "findings": [
    {
      "id": "VULN-001",
      "title": "SQL 注入漏洞",
      "vuln_type": "sql_injection",
      "severity": "critical",
      "confidence": 0.85,
      "file_path": "app/models.py",
      "line_start": 45,
      "line_end": 52,
      "description": "用户输入直接拼接到 SQL 查询中",
      "attack_scenario": "攻击者可通过构造恶意输入执行任意 SQL",
      "fix_suggestion": "使用参数化查询或 ORM"
    }
  ]
}
```

## LLM Agent 工具系统

### 核心理念

让 LLM 像人类安全专家使用 IDE 一样进行代码审计：可以主动搜索文件、查找函数定义、查看指定行号范围的代码、追踪调用链和数据流。

### 已实现的 Function Calling 工具

#### 代码导航工具

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

## 数据持久化

### 存储架构

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

- **LLM 交互面板**：显示 LLM 每一步分析过程
- **工具调用日志**：显示每次工具调用的输入输出
- **发现列表实时更新**：新发现自动添加到列表顶部

## 向量搜索优化

### 嵌入缓存

- **LRU 淘汰策略**: 基于 `accessed_at` 追踪访问时间
- **压缩存储**: `struct.pack` + `zlib` 压缩嵌入向量
- **持久化统计**: 命中率、淘汰次数等统计信息

### 增量索引

- **FileTracker**: 基于 mtime + 内容哈希追踪文件变更
- 只处理新增/修改的文件，大幅提升重复扫描效率

### 高级重排序

**CodeReranker** 评分因素：
1. 高危模式检测（exec/eval/SQL/文件操作等正则匹配）
2. 敏感符号名（auth/login/password/admin/delete/payment）
3. 入口点识别（handler/controller/route 等）
4. 代码长度偏好（更短更聚焦的函数优先）

## 关键设计原则

### 候选点发现必须确定性

- 使用 **SinkCallScanner** 做确定性扫描（AST/regex 匹配 sink patterns）
- 向量检索仅用于**上下文补充**（相似代码、配置定义、变体分析）
- 不依赖向量检索作为主召回手段

### 调用链驱动的分析

LLM 分析单位是**调用链**而非单个函数：
- 链上下文包含：入口点 → 中间节点 → sink 触发点的所有函数代码
- 链级 Finding 输出：chain_id、evidence（按节点列出）、exploitability_conditions
- 爆炸控制：max_depth、max_chains_per_sink、路径去重

### LLM 分析输出格式

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

## 高危 Sink 类别

| 类别 | Python 示例 | PHP 示例 |
|------|-------------|----------|
| RCE | `os.system`, `eval`, `exec`, `subprocess.*` | `exec`, `eval`, `system`, `shell_exec` |
| 文件读 | `open`, `Path.read_text`, `send_file` | `file_get_contents`, `fopen`, `readfile` |
| 文件写 | `open(..., 'w')`, `Path.write_text` | `file_put_contents`, `fwrite` |
| 反序列化 | `pickle.loads`, `yaml.load` | `unserialize` |
| SSRF | `requests.get`, `urllib.request.urlopen` | `curl_exec`, `file_get_contents` |
| SQLi | `cursor.execute`, `raw()` | `mysql_query`, `mysqli_query` |

## 常见问题

### Q: 如何使用自建 LLM 服务？

配置 `base_url` 指向你的服务地址，确保兼容 OpenAI API 格式：

```yaml
llm:
  base_url: http://localhost:8080/v1
  api_key: your-key
  model: your-model
```

> **注意**：如果你的服务 URL 已包含 `/v1`，不要在配置中重复添加。

### Q: 扫描速度很慢？

- 减少 `max_candidates` 数量
- 禁用 LLM 深度分析：`--no-llm`
- 使用更快的嵌入模型
- 增加并发数

### Q: 误报太多？

- 提高 `min_confidence` 阈值
- 使用 `--no-logic` 跳过逻辑漏洞扫描
- 自定义规则，排除特定模式

### Q: 如何添加新的语言支持？

在 `indexer/parser.py` 中添加新的解析器类，继承 `BaseLanguageParser`。

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！
