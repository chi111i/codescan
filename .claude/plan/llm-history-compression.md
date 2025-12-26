# LLM 对话历史压缩功能实现方案

> 创建时间: 2024-12-25
> 状态: 待确认

## 一、需求分析

### 1.1 核心需求

| 需求项 | 描述 | 优先级 |
|--------|------|--------|
| LLM API 请求包含对话历史 | 确保每次 LLM 调用时携带上下文 | P0 |
| 自动压缩对话历史 | 当对话历史超过阈值时自动压缩 | P0 |
| 默认压缩阈值 10000 字符 | 以字符数作为触发压缩的条件 | P0 |
| 阈值可通过配置文件修改 | 支持用户自定义阈值 | P1 |

### 1.2 现状分析

**当前实现（`agent/unified_agent.py`）：**

1. **`conversation_history: List[ChatMessage]`**（第 222 行）：存储对话历史
2. **`_trim_conversation_history()`**（第 1345-1351 行）：简单的基于消息数量的裁剪
   ```python
   def _trim_conversation_history(self):
       max_messages = self.config.context_window_messages * 2  # 默认 40 条
       if len(self.conversation_history) > max_messages:
           self.conversation_history = self.conversation_history[-max_messages:]
   ```
3. **`_build_llm_messages()`**（第 973-988 行）：构建发送给 LLM 的消息列表
   - 已经包含最近 `context_window_messages` 条历史消息（默认 20 条）
   - 但没有基于字符/token 长度的智能压缩

**现有但未使用的模块（`agent/context_manager.py`）：**
- `ContextManager` 类已有完善的 token 管理和裁剪策略
- 支持 FIFO、优先级、混合三种裁剪策略
- 但 **UnifiedAuditAgent 未使用此模块**

---

## 二、设计方案

### 2.1 配置增强

在 `UnifiedAgentConfig` 中添加历史压缩配置项：

```python
# agent/unified_agent.py 第 109-154 行附近

@dataclass
class UnifiedAgentConfig:
    # ... 现有配置 ...

    # === 对话历史压缩配置 ===
    enable_history_compression: bool = True  # 启用历史压缩
    history_compression_threshold: int = 10000  # 压缩阈值（字符数）
    history_compression_ratio: float = 0.3  # 压缩后保留比例（30%）
    history_preserve_recent: int = 4  # 始终保留最近 N 条消息（不压缩）
    history_compression_method: str = "summarize"  # 压缩方式: "summarize" | "truncate"
```

同时需要在全局配置 `config/settings.py` 的 `LLMConfig` 或新增 `AgentConfig` 中添加对应配置，支持 YAML 配置文件读取。

### 2.2 压缩算法设计

#### 2.2.1 触发条件

```python
def _should_compress_history(self) -> bool:
    """判断是否需要压缩对话历史"""
    if not self.config.enable_history_compression:
        return False

    # 计算当前对话历史的总字符数
    total_chars = sum(len(msg.content or "") for msg in self.conversation_history)
    return total_chars > self.config.history_compression_threshold
```

#### 2.2.2 压缩策略

**方案 A：LLM 摘要压缩（推荐）**

```
优点：语义保留完整，上下文质量高
缺点：额外消耗 API 调用，有延迟
适用：对话质量优先的场景
```

**方案 B：简单截断**

```
优点：无额外 API 调用，速度快
缺点：丢失早期上下文语义
适用：对话历史主要是工具调用结果的场景
```

**推荐：混合策略**

1. 保留最近 N 条消息（不压缩）
2. 对较早的消息进行 LLM 摘要压缩
3. 将摘要作为 system message 的一部分注入

#### 2.2.3 核心压缩流程

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. 检查是否需要压缩                                              │
│    - 计算 conversation_history 总字符数                         │
│    - 比较 history_compression_threshold                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ 超过阈值
┌─────────────────────────────────────────────────────────────────┐
│ 2. 分离消息                                                      │
│    - 保护区：最近 preserve_recent 条消息（不压缩）               │
│    - 压缩区：更早的消息                                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. 执行压缩                                                      │
│    - method="summarize": 调用 LLM 生成摘要                      │
│    - method="truncate": 直接截断保留最后 N 条                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. 更新状态                                                      │
│    - 替换 conversation_history                                   │
│    - 存储压缩摘要到 self._compressed_history_summary            │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 集成方案

#### 2.3.1 修改 `_build_llm_messages()`

在构建消息列表时检查并触发压缩：

```python
def _build_llm_messages(self, user_message: str) -> List[ChatMessage]:
    """构建 LLM 消息列表（增强版：支持历史压缩）"""
    messages = []

    # 1. 检查是否需要压缩（在构建消息前执行）
    if self._should_compress_history():
        self._compress_conversation_history()

    # 2. 系统提示（包含压缩后的历史摘要）
    system_prompt = self._build_system_prompt()
    if self._compressed_history_summary:
        system_prompt += f"\n\n## 早期对话摘要\n{self._compressed_history_summary}"
    messages.append(ChatMessage(role="system", content=system_prompt))

    # 3. 最近的对话历史（保护区，未压缩）
    recent_history = self.conversation_history[-self.config.context_window_messages:]
    messages.extend(recent_history)

    # 4. 当前用户消息
    messages.append(ChatMessage(role="user", content=user_message))

    return messages
```

#### 2.3.2 新增压缩方法

```python
def _compress_conversation_history(self):
    """压缩对话历史"""
    if self.config.history_compression_method == "summarize":
        self._compress_with_llm_summary()
    else:
        self._compress_with_truncation()

def _compress_with_llm_summary(self):
    """使用 LLM 生成历史摘要"""
    preserve_count = self.config.history_preserve_recent
    to_compress = self.conversation_history[:-preserve_count] if preserve_count > 0 else []
    protected = self.conversation_history[-preserve_count:] if preserve_count > 0 else self.conversation_history

    if not to_compress:
        return

    # 构建压缩提示
    history_text = "\n".join([
        f"[{msg.role}]: {msg.content[:500]}..."  # 截断过长的单条消息
        for msg in to_compress
    ])

    compress_prompt = f"""请将以下对话历史压缩为简洁的摘要，保留关键信息：
- 用户问了什么问题
- 分析了哪些代码/文件
- 发现了什么问题
- 得出了什么结论

对话历史：
{history_text}

请用 3-5 句话概括。"""

    # 调用 LLM 生成摘要
    response = self.llm_client.chat_completion(
        messages=[ChatMessage(role="user", content=compress_prompt)],
        max_tokens=500,
        temperature=0.3,
    )

    self._compressed_history_summary = response.content
    self.conversation_history = protected

    logger.info(f"[UnifiedAgent] 对话历史压缩完成，从 {len(to_compress) + len(protected)} 条压缩为 {len(protected)} 条 + 摘要")

def _compress_with_truncation(self):
    """简单截断压缩"""
    preserve_count = self.config.history_preserve_recent
    if len(self.conversation_history) > preserve_count:
        self.conversation_history = self.conversation_history[-preserve_count:]
```

---

## 三、配置文件支持

### 3.1 全局配置扩展

在 `config/settings.py` 添加新配置：

```python
# config/settings.py

@dataclass
class AgentContextConfig:
    """Agent 上下文配置"""
    # 历史压缩
    enable_history_compression: bool = True
    history_compression_threshold: int = 10000  # 字符数
    history_compression_ratio: float = 0.3
    history_preserve_recent: int = 4
    history_compression_method: str = "summarize"  # summarize | truncate
```

并在 `AuditConfig` 中添加该子配置：

```python
@dataclass
class AuditConfig:
    # ... 现有配置 ...
    agent_context: AgentContextConfig = field(default_factory=AgentContextConfig)
```

### 3.2 YAML 配置模板

在 `save_default_config()` 函数生成的模板中添加：

```yaml
# =============================================================================
# Agent 上下文配置（对话历史管理）
# =============================================================================
agent_context:
  # 对话历史压缩
  enable_history_compression: true     # 启用历史压缩
  history_compression_threshold: 10000 # 压缩阈值（字符数），超过此值触发压缩
  history_compression_ratio: 0.3       # 压缩后保留比例
  history_preserve_recent: 4           # 始终保留最近 N 条消息
  history_compression_method: summarize # 压缩方式: summarize(LLM摘要) | truncate(简单截断)
```

### 3.3 环境变量覆盖

支持环境变量覆盖：
- `AUDIT_AGENT_HISTORY_THRESHOLD` → `history_compression_threshold`
- `AUDIT_AGENT_HISTORY_COMPRESSION` → `enable_history_compression`

---

## 四、实现步骤

### 步骤 1：扩展配置系统（预计 1 小时）

**涉及文件：**
- `config/settings.py`（第 186 行附近添加 `AgentContextConfig`）
- `config/settings.py`（第 218-227 行修改 `AuditConfig`）
- `config/settings.py`（第 595-776 行更新 YAML 模板）

**任务：**
1. 添加 `AgentContextConfig` dataclass
2. 在 `AuditConfig` 中添加 `agent_context` 字段
3. 更新 `_dict_to_config()` 函数处理新配置
4. 更新 `save_default_config()` 模板

### 步骤 2：扩展 UnifiedAgentConfig（预计 0.5 小时）

**涉及文件：**
- `agent/unified_agent.py`（第 109-154 行）

**任务：**
1. 在 `UnifiedAgentConfig` 添加历史压缩配置字段
2. 添加 `_compressed_history_summary: str = ""` 属性

### 步骤 3：实现压缩检测方法（预计 0.5 小时）

**涉及文件：**
- `agent/unified_agent.py`

**任务：**
1. 添加 `_should_compress_history()` 方法
2. 添加 `_calculate_history_chars()` 辅助方法

### 步骤 4：实现 LLM 摘要压缩方法（预计 1.5 小时）

**涉及文件：**
- `agent/unified_agent.py`

**任务：**
1. 添加 `_compress_conversation_history()` 方法
2. 添加 `_compress_with_llm_summary()` 方法
3. 添加 `_compress_with_truncation()` 方法
4. 添加压缩提示模板常量

### 步骤 5：修改 `_build_llm_messages()` 集成压缩（预计 1 小时）

**涉及文件：**
- `agent/unified_agent.py`（第 973-988 行）

**任务：**
1. 在构建消息前调用压缩检查
2. 在系统提示中注入压缩摘要

### 步骤 6：测试与验证（预计 1 小时）

**测试场景：**
1. 正常对话不触发压缩（历史 < 10000 字符）
2. 长对话触发压缩（历史 > 10000 字符）
3. 压缩后继续对话上下文连贯
4. 配置文件修改阈值生效
5. 禁用压缩功能正常工作
6. LLM 摘要失败回退到截断

---

## 五、关键文件清单

| 文件 | 修改类型 | 主要变更 |
|------|----------|----------|
| `config/settings.py` | 修改 | 添加 AgentContextConfig, 更新 AuditConfig |
| `agent/unified_agent.py` | 修改 | 添加压缩配置、压缩方法、修改 _build_llm_messages |
| `agent/context_manager.py` | 参考 | 复用其裁剪策略思路（可选） |

---

## 六、风险与回滚

### 6.1 风险识别

| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|----------|
| LLM 摘要调用失败 | 历史丢失 | 中 | 回退到截断模式 |
| 摘要质量差导致上下文断裂 | 对话质量下降 | 中 | 提供截断回退选项 |
| 配置加载失败 | 服务启动失败 | 低 | 使用默认值保护 |

### 6.2 回滚方案

1. **配置回滚**：设置 `enable_history_compression: false`
2. **代码回滚**：恢复原有的 `_build_llm_messages()` 方法

---

## 七、验收标准

- [ ] LLM API 每次请求携带对话历史
- [ ] 历史超过 10000 字符时自动触发压缩
- [ ] 压缩阈值可通过配置文件修改
- [ ] 压缩后对话上下文保持连贯
- [ ] 支持 LLM 摘要和简单截断两种压缩方式
- [ ] 压缩失败时有合理的回退机制
