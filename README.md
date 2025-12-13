# CodeScan - LLM 驱动的代码安全审计工具

一款基于大语言模型（LLM）的智能代码安全审计工具，专注于检测传统静态分析工具难以发现的业务逻辑漏洞、权限控制问题和安全缺陷。

## 功能特性

### 核心功能

- **智能代码索引**：使用向量数据库（Qdrant）存储代码嵌入，支持语义搜索
- **多语言支持**：Python、JavaScript、TypeScript、PHP 代码解析
- **高危漏洞检测**：RCE、命令注入、SQL 注入、文件操作、SSRF、反序列化等
- **业务逻辑分析**：认证绕过、权限控制、IDOR、竞态条件等逻辑漏洞
- **污点分析**：Source → Sink 数据流追踪
- **调用链分析**：函数调用图构建与危险路径识别
- **LLM 深度分析**：使用 AI 进行复杂漏洞验证和分析

### 界面特性

- **Apple 风格 UI**：磨砂玻璃效果的现代化界面
- **实时扫描进度**：WebSocket 实时更新扫描状态
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

## 项目结构

```
codescan/
├── api/                    # FastAPI 后端
│   ├── main.py            # 主应用
│   └── schemas.py         # Pydantic 模型
├── analyzer/              # 分析引擎
│   ├── engine.py          # 安全分析器
│   ├── call_chain.py      # 调用链分析
│   ├── taint_analysis.py  # 污点分析
│   ├── vuln_detector.py   # 漏洞检测器
│   ├── models.py          # 数据模型
│   └── prompts.py         # LLM 提示词
├── cli/                   # 命令行接口
│   └── main.py
├── config/                # 配置管理
│   └── settings.py
├── frontend/              # Vue 3 前端
│   ├── src/
│   │   ├── views/        # 页面组件
│   │   ├── components/   # 通用组件
│   │   ├── stores/       # Pinia 状态管理
│   │   ├── api/          # API 调用
│   │   └── style.css     # 全局样式
│   └── package.json
├── indexer/               # 代码索引
│   ├── indexer.py        # 索引器
│   ├── parser.py         # 语言解析器
│   ├── vector_store.py   # 向量存储
│   └── models.py         # 代码单元模型
├── llm_client/           # LLM 客户端
│   ├── client.py         # API 封装
│   └── output_validator.py
├── reporting/            # 报告生成
│   └── reporter.py
├── rules/                # 安全规则
│   ├── manager.py        # 规则管理器
│   └── models.py         # 规则模型
├── utils/                # 工具函数
├── requirements.txt      # Python 依赖
├── start.py              # 启动脚本
└── __main__.py           # CLI 入口
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

## 常见问题

### Q: 如何使用自建 LLM 服务？

配置 `base_url` 指向你的服务地址，确保兼容 OpenAI API 格式：

```yaml
llm:
  base_url: http://localhost:8080/v1
  api_key: your-key
  model: your-model
```

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
