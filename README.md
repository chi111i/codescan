# CodeScan

LLM 驱动的代码安全审计平台原型，聚焦“确定性候选点 + 调用链上下文 + LLM 深度验证”的组合分析流程。

- 后端：FastAPI + Python
- 前端：Vue 3 + Vite + Pinia
- 索引：向量检索（Qdrant/Memory）+ 增量索引
- 分析：规则扫描、调用链分析、污点分析、LLM 辅助判断

## 当前状态

项目已具备可运行的扫描、会话、交互式审计能力，但仍有原型特征：

- `/api/graph/*` 与 `/api/variant/*` 为实验性模块（内存存储，重启丢失）
- 变体分析链路在部分场景存在 mock 回退路径
- 默认未提供完整认证与多租户隔离（对外部署前必须补齐）
- Tree-sitter 解析依赖本地语法包安装情况，未安装时会降级

## 核心能力

### 安全分析

- 代码索引与语义检索
- 安全规则扫描（sink/source/sanitizer）
- 调用链构建与危险路径分析
- 污点传播分析（Source -> Sink）
- 两步扫描流程（先定位触发点，再按需深度分析）
- LLM 辅助深度验证与结构化结论输出

### 会话与交互

- Interactive 会话（交互式代码审计）
- Agent 会话（统一智能体 + 工具调用）
- WebSocket 实时进度与消息推送
- 扫描结果与会话数据持久化（SQLite）

### 多语言解析

- Python（AST + Tree-sitter）
- JavaScript / TypeScript / PHP / Java / Go / Rust / C / C++ / C# / Ruby / Kotlin（Tree-sitter 为主，含回退策略）

## 系统要求

- Python 3.8+（推荐 3.10+）
- Node.js 16+（前端开发）
- 可选：Qdrant 1.7+（不用时可使用 memory 向量存储）

## 安装

```bash
# 后端依赖
python3 -m pip install -r requirements.txt

# 前端依赖
cd frontend
npm install
cd ..
```

### 可选依赖（建议）

`requirements.txt` 中 Tree-sitter 与测试工具是注释状态，按需安装：

```bash
python3 -m pip install tree-sitter tree-sitter-python tree-sitter-javascript tree-sitter-php tree-sitter-typescript
python3 -m pip install pytest pytest-asyncio
```

## 快速开始

### 1. 初始化配置

```bash
python3 -m codescan init -o audit.config.yaml
```

### 2. 配置 LLM

建议通过环境变量注入密钥，不要在配置文件中保存明文 key。

```yaml
llm:
  base_url: https://api.openai.com/v1
  api_key: ""
  model: gpt-4
  embedding_model: text-embedding-3-small

vector_store:
  provider: memory   # 或 qdrant
```

环境变量示例（Windows）：

```bash
setx AUDIT_LLM_API_KEY "your-key"
# 或
setx OPENAI_API_KEY "your-key"
```

### 3. 启动服务

```bash
# 同时启动前后端
python3 start.py all

# 仅后端
python3 start.py api

# 仅前端
python3 start.py frontend
```

默认访问地址：

- 后端 API：`http://localhost:8000`
- 前端开发服务：`http://localhost:5173`
- Swagger：`http://localhost:8000/docs`

## CLI 使用

命令入口：`python3 -m codescan ...`

### 索引

```bash
python3 -m codescan index ./your-project
python3 -m codescan index ./your-project --clear
```

### 扫描

```bash
python3 -m codescan scan ./your-project
python3 -m codescan scan ./your-project -l python -f json -o report.json
python3 -m codescan scan ./your-project --chain --chain-depth 5
```

### 高危漏洞扫描

```bash
python3 -m codescan vulnscan ./your-project
python3 -m codescan vulnscan ./your-project -t rce,sql_injection,ssrf
python3 -m codescan vulnscan ./your-project --no-llm --logic
```

### 调用链分析

```bash
python3 -m codescan callgraph ./your-project -d 10
python3 -m codescan callgraph ./your-project --taint --stats
```

### 搜索、规则、解释、存储

```bash
python3 -m codescan search "auth bypass" -l python -n 20
python3 -m codescan rules list
python3 -m codescan rules show --id RULE-001
python3 -m codescan explain FINDING-001 -r report.json
python3 -m codescan storage stats
```

### 交互式 Agent（CLI REPL）

```bash
python3 -m codescan agent ./your-project --show-tools
python3 -m codescan agent ./your-project --offline
```

## API 概览（主要端点）

### 基础与索引

- `GET /api/health`
- `POST /api/index`
- `POST /api/index/async`
- `GET /api/index/{index_id}/progress`
- `GET /api/index/stats`
- `DELETE /api/index`

### 扫描与结果

- `POST /api/scan`
- `GET /api/scan/{scan_id}`
- `DELETE /api/scan/{scan_id}`
- `GET /api/scan/{scan_id}/findings`
- `GET /api/scans`
- `GET /api/findings/recent`
- `GET /api/scan/{scan_id}/interactions`
- `GET /api/scan/{scan_id}/timeline`
- `GET /api/scan/{scan_id}/interactions/latest`
- `GET /api/scan/{scan_id}/stats`

### 两步扫描与调用图

- `POST /api/scan/sink-sites`
- `GET /api/scan/{scan_id}/sink-sites`
- `GET /api/scan/{scan_id}/sink-sites/{site_id}/chains`
- `POST /api/analyze/selected`
- `POST /api/callgraph`
- `POST /api/callgraph/analyze`
- `GET /api/callgraph/chains/{sink_id}`

### 规则、设置、代码单元

- `GET /api/rules`
- `GET /api/rules/stats`
- `GET /api/rules/{rule_id}`
- `POST /api/rules/reload`
- `GET /api/settings`
- `POST /api/settings`
- `POST /api/settings/test-connection`
- `POST /api/settings/test-embedding`
- `GET /api/units`
- `GET /api/units/{unit_id}`

### Interactive 会话

前缀：`/api/interactive`

- 会话：`/session/start`, `/session/{id}`, `/sessions`
- 代码与上下文：`/code-units`, `/sink-sites`, `/chain-contexts`
- 分析：`/analyze`, `/chat`, `/dig-deeper`, `/session/{id}/summarize`, `/session/{id}/stop`
- 发现管理：`/session/{id}/findings`, `/confirm`, `/reject`, `/notes`

### Agent 会话

前缀：`/api/agent`

- 会话：`/session/create`, `/session/{id}`, `/session/{id}/restore`, `/sessions`, `/sessions/active`
- 对话：`/session/{id}/chat`, `/messages`, `/tool-calls`, `/clear-history`
- 工具与统计：`/tools`, `/stats`, `/index`

### 实验性模块

- `/api/graph/*`：实验性，内存存储
- `/api/variant/*`：实验性，内存存储，部分逻辑含 mock 路径

## WebSocket

- `WS /ws/scan/{scan_id}`：扫描进度
- `WS /ws/index/{index_id}`：索引进度
- `WS /api/interactive/ws/{session_id}`：Interactive 会话
- `WS /api/agent/ws/{session_id}`：Agent 会话

## 配置优先级

`默认值 < 项目配置(audit.config.yaml) < 用户配置(.user_config.yaml) < 环境变量 < 运行参数`

常用环境变量：

- `AUDIT_LLM_BASE_URL`
- `AUDIT_LLM_API_KEY`
- `AUDIT_LLM_MODEL`
- `AUDIT_LLM_EMBEDDING_MODEL`
- `AUDIT_LLM_EMBEDDING_BASE_URL`
- `AUDIT_LLM_EMBEDDING_API_KEY`
- `AUDIT_LLM_EMBEDDING_DIM`
- `AUDIT_VECTOR_HOST`
- `AUDIT_VECTOR_PORT`
- `AUDIT_VECTOR_API_KEY`
- `AUDIT_SCAN_TARGET`
- `AUDIT_DEBUG`
- `AUDIT_LOG_LEVEL`
- `OPENAI_API_KEY`（兼容）

## 数据持久化

默认数据目录：

- `.audit_data/audit.db`：扫描任务、发现、交互日志、agent 会话与消息、预扫描数据
- `.audit_cache/`：索引与缓存数据

## 项目结构（精简）

```text
codescan/
├── api/                 # FastAPI 主服务与路由
├── analyzer/            # 规则分析、调用链、污点、会话管理
├── indexer/             # 解析、索引、搜索、向量存储适配
├── agent/               # 统一智能体与工具系统
├── storage/             # SQLite + Repository
├── rules/               # 规则模型与规则库
├── llm_client/          # LLM 客户端
├── frontend/            # Vue3 前端
├── cli/                 # Typer CLI
└── tests/               # 测试
```

## 开发与测试

```bash
# Python 单测
pytest -q

# 前端构建
npm --prefix frontend run build
```

说明：当前分支可能存在部分测试失败（主要集中在 chunk 机制与 tree-sitter 兼容性相关），建议在 CI 中拆分测试分组并逐步收敛。

## 安全部署注意事项

- 不要提交 `.user_config.yaml`、`.env`、密钥文件
- 设置相关接口会写本地用户配置，生产部署前必须补齐认证与权限控制
- 实验性路由默认不建议暴露到公网

## License

MIT
