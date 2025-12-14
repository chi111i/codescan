# 优化规划：函数调用分析、污点传播与 LLM 审计流程

## 1. 问题分析

### 1.1 当前架构存在的问题

经过深入分析现有代码，发现以下主要问题：

#### 问题 1：调用关系和污点分析未集成到 Agent

**现状**：
- `CallChainAnalyzer` 和 `TaintAnalyzer` 已经实现
- **但没有与新的 `CodeAnalysisAgent` 集成**
- LLM 无法使用这些高级分析能力

**影响**：
- LLM 只能读取代码，无法获取调用图和污点路径
- 缺少结构化的安全分析上下文

#### 问题 2：SecurityAnalyzer 流程陈旧

**现状**：
- `SecurityAnalyzer.analyze()` 使用旧的单次 LLM 调用模式
- 不支持 Function Calling
- 无法利用 Agent 的多轮工具调用能力

**影响**：
- LLM 无法主动探索代码
- 上下文构建低效，容易遗漏关键信息

#### 问题 3：调用链分析算法效率问题

**现状**：
- `_dfs_find_paths` 使用简单 DFS，可能遍历大量无效路径
- `_trace_back_to_entry` 可能重复计算
- 缺少缓存和剪枝

**影响**：
- 大型项目分析耗时长
- 内存占用高

#### 问题 4：污点分析覆盖不全

**现状**：
- 跨函数污点追踪逻辑复杂，但**未在 CLI 中使用**
- 缺少与 Agent 的集成
- 框架特定的污点传播未充分利用

**影响**：
- 漏报率高
- 复杂污点流无法检测

---

## 2. 优化目标

### 2.1 核心目标

1. **集成调用链和污点分析到 Agent**
   - 新增 Tools：`analyze_call_chain`、`trace_taint_path`
   - LLM 可以主动请求调用链和污点分析

2. **重构 SecurityAnalyzer 使用 Agent**
   - 替换旧的单次调用模式
   - 使用 `SecurityAnalysisAgent` 执行多轮分析

3. **优化调用链算法**
   - 双向 BFS 替代 DFS
   - 路径缓存和剪枝
   - 支持并行计算

4. **增强污点分析**
   - 与 Call Graph 深度集成
   - 支持跨文件污点传播
   - 优化框架特定规则

---

## 3. 技术方案

### 3.1 新增 Agent Tools

#### Tool 1: analyze_call_chain

```python
{
    "name": "analyze_call_chain",
    "description": "分析函数的调用关系链，包括调用者和被调用者。",
    "parameters": {
        "symbol_name": "函数/方法名",
        "direction": "both | callers | callees",
        "max_depth": "最大深度，默认 3",
        "include_sources": "是否标记输入源节点",
        "include_sinks": "是否标记危险函数节点",
    }
}
```

**功能**：
- 基于已构建的 CallGraph 查询
- 返回结构化的调用链数据
- 标记 Source/Sink/Sanitizer 节点

#### Tool 2: trace_taint_path

```python
{
    "name": "trace_taint_path",
    "description": "追踪污点传播路径，从输入源到危险函数。",
    "parameters": {
        "source_symbol": "污点源函数/符号",
        "sink_symbol": "危险函数/符号（可选）",
        "max_depth": "最大路径深度",
        "show_sanitizers": "是否显示路径上的过滤函数",
    }
}
```

**功能**：
- 查找 Source → Sink 路径
- 识别路径上的 Sanitizer
- 计算风险等级和置信度

#### Tool 3: get_code_context

```python
{
    "name": "get_code_context",
    "description": "获取代码的完整上下文，包括调用者、被调用者和相关定义。",
    "parameters": {
        "symbol_name": "函数/方法名",
        "include_callers": "包含调用者",
        "include_callees": "包含被调用者",
        "include_class": "包含所属类的其他方法",
        "include_imports": "包含导入语句",
    }
}
```

### 3.2 优化调用链算法

#### 当前算法（DFS）问题

```python
# 现有实现
def _dfs_find_paths(self, start_id, target_ids, max_depth, max_paths):
    paths = []
    stack = [(start_id, [start_id])]
    # 可能遍历指数级路径
    while stack and len(paths) < max_paths:
        node_id, current_path = stack.pop()
        # 没有有效的剪枝策略
        ...
```

**问题**：
- 时间复杂度高：O(b^d)，b=平均分支因子，d=深度
- 无记忆化，重复计算
- 可能陷入无效路径探索

#### 优化方案：双向 BFS + 缓存

```python
class OptimizedCallChainAnalyzer:
    def __init__(self):
        # 路径缓存
        self._path_cache: Dict[Tuple[str, str], List[List[str]]] = {}
        # 可达性缓存
        self._reachability: Dict[Tuple[str, str, int], bool] = {}

    def find_paths_bidirectional_bfs(
        self,
        start_id: str,
        target_ids: Set[str],
        max_depth: int = 10,
        max_paths: int = 100,
    ) -> List[List[str]]:
        """双向 BFS 查找路径

        从 start 正向搜索，从 targets 反向搜索，在中间相遇
        """
        # 正向层级
        forward_layers = {0: {start_id: [[start_id]]}}
        # 反向层级
        backward_layers = {0: {tid: [[tid]] for tid in target_ids}}

        paths_found = []

        for depth in range((max_depth + 1) // 2):
            # 正向扩展
            forward_frontier = self._expand_forward(forward_layers, depth)
            # 反向扩展
            backward_frontier = self._expand_backward(backward_layers, depth)

            # 检查是否相遇
            for node_id in forward_frontier:
                if node_id in backward_frontier:
                    # 找到路径，合并
                    for f_path in forward_layers[depth + 1][node_id]:
                        for b_path in backward_layers[depth + 1][node_id]:
                            # 合并路径（去掉重复的中间节点）
                            full_path = f_path + b_path[1:][::-1]
                            if full_path not in paths_found:
                                paths_found.append(full_path)
                                if len(paths_found) >= max_paths:
                                    return paths_found

            if not forward_frontier and not backward_frontier:
                break

        return paths_found
```

**优势**：
- 时间复杂度：O(b^(d/2))，显著降低
- 提前相遇，避免无效探索
- 结合缓存，重复查询几乎无开销

#### 路径剪枝策略

```python
def _should_prune_path(self, current_path: List[str]) -> bool:
    """判断是否应该剪枝"""
    # 1. 检查路径中的节点类型
    node_types = [self.call_graph.get_node(nid).node_type for nid in current_path]

    # 如果已经经过 Sanitizer，且后续没有新的污点源，剪枝
    has_sanitizer = any(nt == NodeType.SANITIZER for nt in node_types)
    has_sink_after_sanitizer = False
    for i, nt in enumerate(node_types):
        if nt == NodeType.SANITIZER:
            # 检查后续是否有 Sink
            if any(node_types[j] == NodeType.SINK for j in range(i+1, len(node_types))):
                has_sink_after_sanitizer = True

    if has_sanitizer and not has_sink_after_sanitizer:
        return True

    # 2. 检查是否进入低价值分支（如工具函数）
    # 例如：logger.info, print, assert 等
    low_value_patterns = ['log', 'print', 'assert', 'debug']
    last_node = self.call_graph.get_node(current_path[-1])
    if any(pattern in last_node.name.lower() for pattern in low_value_patterns):
        return True

    return False
```

### 3.3 重构 SecurityAnalyzer

#### 新架构

```python
class SecurityAnalyzer:
    def __init__(self, config, llm_client, indexer, rule_manager):
        self.config = config
        self.llm_client = llm_client
        self.indexer = indexer
        self.rule_manager = rule_manager

        # 新增：调用链和污点分析器
        self.call_chain_analyzer = CallChainAnalyzer(rule_manager)
        self.taint_analyzer = TaintAnalyzer(rule_manager)

        # 新增：Agent 实例
        self.agent = None

    def analyze(self, language=None, file_pattern=None, max_candidates=50):
        """执行完整分析流程（使用 Agent）"""

        # 1. 构建调用图和污点分析（一次性完成）
        code_units = self.indexer.get_all_units()

        logger.info("构建调用图...")
        call_graph = self.call_chain_analyzer.build_call_graph(code_units)

        logger.info("执行污点分析...")
        taint_flows = self.taint_analyzer.analyze_interprocedural(
            code_units,
            call_graph=call_graph,
        )

        # 2. 发现高优先级候选点
        candidates = self.discover_candidates_v2(
            call_graph=call_graph,
            taint_flows=taint_flows,
            max_candidates=max_candidates,
        )

        # 3. 为每个候选点创建 Agent 并分析
        findings = []
        for candidate in candidates:
            finding = self.analyze_candidate_with_agent(
                candidate,
                call_graph,
                taint_flows,
            )
            if finding:
                findings.append(finding)

        return findings

    def analyze_candidate_with_agent(
        self,
        candidate,
        call_graph,
        taint_flows,
    ) -> Optional[Finding]:
        """使用 Agent 分析候选点"""
        from agent import SecurityAnalysisAgent, CODE_READER_TOOLS
        from indexer import CodeReader

        # 创建 CodeReader
        code_reader = CodeReader(
            project_path=self.config.scan.target_path,
            indexer=self.indexer,
        )

        # 扩展 Tools 以支持调用链和污点分析
        enhanced_tools = CODE_READER_TOOLS + [
            self._build_analyze_call_chain_tool(),
            self._build_trace_taint_path_tool(),
        ]

        # 创建 Agent（注入调用图和污点分析结果）
        agent = SecurityAnalysisAgent(
            llm_client=self.llm_client,
            code_reader=code_reader,
            tools=enhanced_tools,
        )

        # 注册自定义工具执行器
        agent.register_tool(
            "analyze_call_chain",
            lambda args: self._execute_analyze_call_chain(args, call_graph),
            self._build_analyze_call_chain_tool(),
        )
        agent.register_tool(
            "trace_taint_path",
            lambda args: self._execute_trace_taint_path(args, call_graph, taint_flows),
            self._build_trace_taint_path_tool(),
        )

        # 构建分析任务
        task = f"""请分析以下代码是否存在安全漏洞：

**目标**：{candidate.symbol} ({candidate.file_path}:{candidate.line_start})
**触发规则**：{', '.join(candidate.triggered_rules)}

你可以使用以下工具：
1. 基础代码读取工具 (search_code, read_file, read_symbol, etc.)
2. analyze_call_chain - 分析调用关系
3. trace_taint_path - 追踪污点传播路径

请按以下步骤进行分析：
1. 首先使用 read_symbol 读取目标函数的完整代码
2. 使用 analyze_call_chain 了解其调用关系
3. 如果涉及用户输入，使用 trace_taint_path 追踪污点传播
4. 根据需要读取相关的调用者或被调用者代码
5. 最后给出完整的安全分析结论

重点关注：
- 认证和授权检查
- 用户输入验证
- 业务逻辑完整性
- 越权访问风险
"""

        # 执行 Agent 分析
        result = agent.analyze_security(task)

        # 从 Agent 结果提取 Finding
        if result.error:
            logger.error(f"Agent analysis failed: {result.error}")
            return None

        # 解析 LLM 的最终结论（应该是 JSON）
        finding = self._parse_agent_result_to_finding(
            result.content,
            candidate,
            result.tool_calls_history,
        )

        return finding
```

### 3.4 优化污点传播算法

#### 当前问题

- 跨函数传播使用迭代固定点算法，收敛慢
- 没有利用 Call Graph 的拓扑序

#### 优化方案：拓扑排序 + 数据流方程

```python
def optimize_interprocedural_taint(
    self,
    code_units: List[CodeUnit],
    call_graph: CallGraph,
) -> List[CrossFunctionFlow]:
    """优化的跨函数污点分析"""

    # 1. 计算 Call Graph 的拓扑序（或强连通分量）
    topo_order = self._compute_topological_order(call_graph)

    # 2. 按拓扑序分析函数（保证依赖已分析）
    for func_id in topo_order:
        unit = self._code_units_cache.get(func_id)
        if not unit:
            continue

        # 分析函数内部污点
        self._analyze_function_taints(unit)

        # 从调用者传播污点（此时调用者必然已分析）
        self._propagate_from_callers(func_id, call_graph)

    # 3. 查找 Sink
    self._find_cross_function_sinks()

    return self.cross_function_flows

def _compute_topological_order(self, call_graph: CallGraph) -> List[str]:
    """计算拓扑排序（Kahn 算法）"""
    # 计算入度
    in_degree = {nid: 0 for nid in call_graph.nodes}
    for edge in call_graph.edges:
        in_degree[edge.callee_id] += 1

    # 从入度为 0 的节点开始
    queue = [nid for nid, deg in in_degree.items() if deg == 0]
    topo_order = []

    while queue:
        node_id = queue.pop(0)
        topo_order.append(node_id)

        # 减少后继的入度
        for callee_id in call_graph._callees.get(node_id, set()):
            in_degree[callee_id] -= 1
            if in_degree[callee_id] == 0:
                queue.append(callee_id)

    # 处理环（强连通分量）
    if len(topo_order) < len(call_graph.nodes):
        remaining = set(call_graph.nodes) - set(topo_order)
        topo_order.extend(remaining)

    return topo_order
```

**优势**：
- 单次遍历即可完成污点传播
- 时间复杂度：O(V + E)
- 避免重复计算

---

## 4. 实施步骤

### 阶段一：扩展 Agent Tools（优先级：最高）

| 步骤 | 任务 | 文件 |
|------|------|------|
| 1.1 | 定义 analyze_call_chain Tool Schema | `agent/tools.py` |
| 1.2 | 定义 trace_taint_path Tool Schema | `agent/tools.py` |
| 1.3 | 定义 get_code_context Tool Schema | `agent/tools.py` |
| 1.4 | 实现工具执行器 | `agent/code_agent.py` |
| 1.5 | 测试工具调用 | `tests/test_agent_tools.py` |

### 阶段二：优化调用链算法（优先级：高）

| 步骤 | 任务 | 文件 |
|------|------|------|
| 2.1 | 实现双向 BFS 路径查找 | `analyzer/call_chain.py` |
| 2.2 | 添加路径缓存机制 | `analyzer/call_chain.py` |
| 2.3 | 实现路径剪枝策略 | `analyzer/call_chain.py` |
| 2.4 | 添加性能基准测试 | `tests/bench_call_chain.py` |

### 阶段三：优化污点分析（优先级：高）

| 步骤 | 任务 | 文件 |
|------|------|------|
| 3.1 | 实现拓扑排序 | `analyzer/taint_analysis.py` |
| 3.2 | 优化跨函数传播算法 | `analyzer/taint_analysis.py` |
| 3.3 | 增强框架特定规则 | `analyzer/taint_analysis.py` |
| 3.4 | 与 Call Graph 深度集成 | `analyzer/taint_analysis.py` |

### 阶段四：重构 SecurityAnalyzer（优先级：高）

| 步骤 | 任务 | 文件 |
|------|------|------|
| 4.1 | 添加 Agent 集成接口 | `analyzer/engine.py` |
| 4.2 | 实现 analyze_candidate_with_agent | `analyzer/engine.py` |
| 4.3 | 重构 analyze 主流程 | `analyzer/engine.py` |
| 4.4 | 添加分析结果解析 | `analyzer/engine.py` |

### 阶段五：更新 CLI 和测试（优先级：中）

| 步骤 | 任务 | 文件 |
|------|------|------|
| 5.1 | 更新 scan 命令使用 Agent | `cli/main.py` |
| 5.2 | 添加 --use-agent 选项 | `cli/main.py` |
| 5.3 | 集成测试 | `tests/test_integration.py` |
| 5.4 | 性能对比测试 | `tests/bench_analyzer.py` |

---

## 5. 新增模块结构

```
codescan/
├── agent/
│   ├── tools.py           # 扩展：新增 3 个分析工具
│   └── code_agent.py      # 扩展：工具执行器
├── analyzer/
│   ├── call_chain.py      # 优化：算法重构
│   ├── taint_analysis.py  # 优化：算法优化
│   └── engine.py          # 重构：集成 Agent
└── cli/
    └── main.py            # 更新：使用 Agent 模式
```

---

## 6. 核心工作流程（优化后）

### 6.1 完整审计流程

```
1. 项目索引
   ├─ 代码解析 (parser.py)
   ├─ 嵌入向量化 (indexer.py)
   └─ 向量存储 (vector_store.py)

2. 静态分析预处理
   ├─ 构建 Call Graph (call_chain.py)
   │   ├─ 节点分类 (Source/Sink/Sanitizer)
   │   └─ 边构建 (调用关系)
   └─ 污点分析 (taint_analysis.py)
       ├─ 函数内污点追踪
       └─ 跨函数污点传播

3. 候选点发现（优先级排序）
   ├─ 基于规则匹配 (rule_manager)
   ├─ 基于调用链分析
   └─ 基于污点流分析

4. LLM Agent 深度分析
   ├─ 创建 SecurityAnalysisAgent
   ├─ Agent 主动调用 Tools：
   │   ├─ search_code / read_file / read_symbol
   │   ├─ analyze_call_chain（调用关系）
   │   ├─ trace_taint_path（污点路径）
   │   └─ get_code_context（完整上下文）
   └─ 多轮推理，给出最终结论

5. 结果汇总与报告
   ├─ Finding 对象创建
   ├─ 置信度过滤
   └─ 报告生成 (JSON/SARIF/Console)
```

### 6.2 LLM 分析示例流程

```
用户任务：扫描项目

┌─ Agent 收到任务：分析 delete_user 函数的安全性
│
├─ Tool Call 1: read_symbol("delete_user", include_callers=True)
│  └─ 返回：delete_user 定义 + 3个调用者
│
├─ Agent 判断：这是删除操作，需要检查权限
│
├─ Tool Call 2: analyze_call_chain("delete_user", direction="callers", max_depth=2)
│  └─ 返回：调用链，标记了入口点（Web handler）
│
├─ Agent 判断：需要查看入口点是否有权限检查
│
├─ Tool Call 3: read_symbol("UserController.delete", include_callees=True)
│  └─ 返回：Controller 代码 + 调用的函数列表
│
├─ Tool Call 4: search_code("权限检查 用户身份验证", file_pattern="**/auth/*.py")
│  └─ 返回：相关的权限检查函数
│
├─ Agent 判断：delete_user 直接被调用，未经权限验证
│
└─ 返回结论：{
    "has_issue": true,
    "issue_type": "authorization_bypass",
    "severity": "high",
    "confidence": 0.85,
    "summary": "delete_user 函数缺少权限验证，任意登录用户可删除其他用户",
    ...
  }
```

---

## 7. 性能优化指标

### 7.1 算法优化目标

| 指标 | 当前 | 目标 | 方法 |
|------|------|------|------|
| 路径查找时间 | O(b^d) | O(b^(d/2)) | 双向 BFS |
| 污点传播时间 | O(n*m*k) | O(V+E) | 拓扑排序 |
| 重复查询 | 每次重算 | O(1) | 路径缓存 |
| 内存占用 | 高 | 中 | 路径剪枝 |

### 7.2 分析质量目标

| 指标 | 当前 | 目标 |
|------|------|------|
| 调用链覆盖率 | 60% | 90%+ |
| 污点路径准确率 | 75% | 85%+ |
| 误报率 | 30% | <15% |
| LLM 调用次数 | 50-100次/项目 | 20-40次/项目 |

---

## 8. 验收标准

### 8.1 Agent Tools

- [ ] `analyze_call_chain` 正确返回调用链
- [ ] `trace_taint_path` 正确追踪污点路径
- [ ] `get_code_context` 提供完整上下文
- [ ] LLM 能够正确使用这些工具

### 8.2 算法优化

- [ ] 双向 BFS 实现并测试通过
- [ ] 路径查找性能提升 3x+
- [ ] 污点分析使用拓扑排序
- [ ] 跨函数传播正确率 >80%

### 8.3 流程集成

- [ ] SecurityAnalyzer 使用 Agent 模式
- [ ] CLI `scan` 命令调用 LLM
- [ ] 分析结果包含工具调用历史
- [ ] 端到端测试通过

### 8.4 向后兼容

- [ ] 支持 `--no-agent` 选项使用旧模式
- [ ] 现有配置文件兼容
- [ ] API 接口保持稳定

---

## 9. 风险与缓解

### 9.1 技术风险

1. **LLM Token 消耗增加**
   - 风险：多轮工具调用消耗更多 tokens
   - 缓解：
     - 限制最大工具调用次数
     - 智能上下文窗口管理
     - 工具返回结果压缩

2. **分析时间延长**
   - 风险：Agent 多轮调用增加延迟
   - 缓解：
     - 并行分析多个候选点
     - 工具调用缓存
     - 预计算 Call Graph

3. **调用链算法复杂性**
   - 风险：双向 BFS 实现可能有 bug
   - 缓解：
     - 充分单元测试
     - 与原算法对比验证
     - 保留旧算法作为 fallback

### 9.2 质量风险

1. **Agent 可能偏离分析目标**
   - 缓解：
     - 系统提示词明确分析步骤
     - 限制工具调用范围
     - 最终结果格式校验

2. **工具返回数据过大**
   - 缓解：
     - 限制返回结果数量
     - 压缩代码片段
     - 分页机制

---

## 10. 实施优先级

### P0（立即开始）

1. 扩展 Agent Tools（analyze_call_chain, trace_taint_path）
2. 重构 SecurityAnalyzer 集成 Agent

### P1（本周完成）

3. 优化调用链算法（双向 BFS）
4. 优化污点分析（拓扑排序）

### P2（后续迭代）

5. 性能优化和缓存
6. 完善测试覆盖
7. 文档更新

---

## 11. 后续扩展

- 支持增量分析（只分析变更部分）
- 引入符号执行引擎
- 集成现有工具（Semgrep/CodeQL）结果
- 可视化调用图和污点路径
