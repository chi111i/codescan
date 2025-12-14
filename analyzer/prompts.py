"""
LLM 分析提示词模板

根据目标文档 P0-5 的要求：
- LLM 分析必须以"链"为单位输出结构化结果
- 输出包含 chain_id, sink_category, has_issue, issue_type, confidence 等字段
- 为高危类别（command/file/deserialize）提供专用提示词
"""

from typing import Tuple, Optional, Dict, Any


# ============================================================================
# 传统单点分析提示词（保留兼容）
# ============================================================================

SYSTEM_PROMPT = """你是一名资深安全工程师，专长是代码审计和业务逻辑漏洞挖掘。
你将收到：
- 若干段源代码（包含当前函数、相关调用方/被调用方、模型定义、路由、配置片段等）；
- 与当前语言/框架相关的安全规则摘要（危险函数、输入源、消毒函数等）；
- 额外的业务上下文说明（如"这是支付回调处理函数"、"这是删除用户的接口"等）。

你的任务是：
1. 从**逻辑与权限控制**角度分析这些代码是否存在安全隐患，尤其关注：
   - 身份认证/授权是否正确、完整；
   - 访问控制是否可被低权限用户绕过；
   - 业务流程是否可被跳过、重复或篡改关键参数；
   - 跨服务调用中的信任边界问题。

2. 如果你认为存在问题，请给出：
   - 问题的大致类型（例如：水平越权、业务逻辑绕过、缺少二次验证等）；
   - 形成漏洞的关键代码位置和简要原因；
   - 攻击者可能利用该问题的**高层次思路**（不要给出具体 payload）；
   - 建议的修复思路。

3. 如果你不确定是否构成漏洞，也要明确说明不确定的原因，并指出需要额外人工确认的点。

输出时请使用严格的 JSON 格式，字段包括：
- `has_issue`: boolean，是否存在问题
- `issue_type`: string，问题类型
- `severity`: "low" | "medium" | "high" | "critical"
- `confidence`: 0~1 之间的小数，置信度
- `summary`: 对问题的简要中文描述
- `details`: 更详细的分析说明（可分点）
- `evidence`: 代码位置和关键片段说明列表，每项包含 {location, snippet, reason}
- `attack_scenario`: 高层次攻击思路文本（不包含具体 payload）
- `fix_suggestion`: 修复建议文本
- `notes`: 需要人工进一步确认的事项

如果你没有足够信息判断，请显式说明"信息不足"，不要臆造代码或逻辑。
如果代码没有明显问题，将 has_issue 设为 false，并简要说明原因。

重要提示：
- 不要输出可直接利用的攻击 payload
- 重点关注业务逻辑和权限控制问题，而非仅仅查找危险函数
- 结合数据流分析判断用户输入是否真正到达危险点
"""

USER_PROMPT_TEMPLATE = """{context}

请分析上述代码是否存在安全问题。按照要求的 JSON 格式输出。
"""


# 专门针对不同漏洞类型的补充提示
FOCUS_PROMPTS = {
    "auth": """
请特别检查：
- 是否验证了用户登录状态（token/session）
- 认证检查是否可以被绕过
- 是否存在认证绕过的条件分支
""",
    "access-control": """
请特别检查：
- 是否验证了当前用户有权访问该资源
- 资源 ID 是否直接使用用户输入而未校验归属
- 是否存在水平越权（访问其他用户的资源）或垂直越权（执行更高权限操作）的可能
""",
    "business-logic": """
请特别检查：
- 业务流程是否可以被跳过中间步骤
- 关键参数（价格、数量、状态）是否完全信任客户端
- 是否存在重放攻击或竞态条件的风险
- 是否缺少必要的频率限制
""",
    "injection": """
请特别检查：
- 用户输入是否直接拼接到危险操作中
- 是否存在有效的消毒/转义处理
- 参数化查询是否正确使用
""",
}


def build_analysis_prompt(context_text: str, focus_category: Optional[str] = None) -> Tuple[str, str]:
    """构建分析提示词

    Args:
        context_text: 上下文文本
        focus_category: 重点关注的类别

    Returns:
        (system_prompt, user_prompt)
    """
    system = SYSTEM_PROMPT

    user = USER_PROMPT_TEMPLATE.format(context=context_text)

    if focus_category and focus_category in FOCUS_PROMPTS:
        user += "\n" + FOCUS_PROMPTS[focus_category]

    return system, user


# ============================================================================
# 链级分析提示词（根据目标文档 P0-5）
# ============================================================================

CHAIN_SYSTEM_PROMPT = """你是一名资深安全工程师，专长是代码审计和高危漏洞挖掘（RCE、任意文件读写、反序列化、SSRF、鉴权绕过等）。

你将收到一条完整的**调用链上下文**，包含：
- 入口点（如 Web Handler、Controller、API 端点）
- 调用链路径（从入口到危险函数触发点的完整调用链）
- 危险函数触发点（Sink）的详细信息和代码片段
- 链路上的关键代码（每个节点的函数定义）
- 匹配的安全规则信息

你的任务是分析这条**完整的调用链**，判断：
1. 外部用户输入是否能够到达危险函数（Sink）
2. 链路上是否存在有效的安全检查（认证、授权、输入验证、过滤）
3. 如果存在安全检查，是否可能被绕过
4. 综合评估该链路是否构成可利用的安全漏洞

重要原则：
- 你必须基于提供的代码证据进行分析，不要臆造代码或逻辑
- 重点关注"可控输入 → 危险操作"的数据流
- 如果链路上有有效的过滤/验证，需明确指出
- 如果信息不足以判断，标记为"待人工确认"而非强行下结论

输出必须是严格的 JSON 格式，字段包括：
{
    "chain_id": "调用链标识（从输入中获取）",
    "sink_category": "sink 类别（command_exec/file_read/file_write/deserialization/ssrf/sql_injection/xss/other）",
    "risk_level": "风险等级（low/medium/high/critical）",
    "has_issue": true/false/"uncertain",
    "issue_type": "问题类型（如 command_injection、path_traversal、authz_bypass 等）",
    "confidence": 0.0-1.0,
    "summary": "问题简要描述（中文）",
    "evidence": [
        {
            "node_index": 0,
            "file_path": "文件路径",
            "line_start": 起始行号,
            "line_end": 结束行号,
            "snippet": "关键代码片段",
            "reason": "为什么这段代码是关键证据"
        }
    ],
    "data_flow": "描述用户输入如何流向危险函数的数据流路径",
    "security_controls": [
        {
            "type": "认证/授权/输入验证/过滤",
            "location": "位置描述",
            "effectiveness": "有效/部分有效/无效/未知",
            "bypass_possibility": "绕过可能性描述（如适用）"
        }
    ],
    "exploitability_conditions": "高层次利用条件描述（不要包含具体 payload）",
    "fix_suggestion": "修复建议",
    "notes": "需要人工确认的事项"
}

不要输出可直接利用的攻击 payload。"""


CHAIN_USER_PROMPT_TEMPLATE = """{context}

请基于上述调用链上下文，分析该链路是否存在安全漏洞。
按照要求的 JSON 格式输出分析结果。
"""


# ============================================================================
# 高危类别专用提示词（根据目标文档要求）
# ============================================================================

SINK_CATEGORY_PROMPTS = {
    "command_exec": """
【命令执行类漏洞专项分析指南】

重点检查：
1. 命令字符串是否包含用户可控输入
2. 是否使用了 shell=True（Python）或类似的 shell 执行模式
3. 参数是否经过 shlex.quote() 或等效的转义处理
4. 是否有命令白名单校验

常见危险模式：
- os.system(user_input)
- subprocess.call(cmd, shell=True) 其中 cmd 拼接了用户输入
- exec()/eval() 执行用户可控字符串
- PHP: exec(), shell_exec(), system(), passthru(), popen()
- JS: child_process.exec(), child_process.spawn() with shell

安全检查要点：
- shlex.quote() / escapeshellarg() 是否正确应用
- 命令模板 + 参数列表模式是否使用
- 是否有命令/参数白名单限制
""",

    "code_exec": """
【代码执行类漏洞专项分析指南】

重点检查：
1. eval/exec/Function 等是否执行用户可控代码
2. 模板引擎是否存在 SSTI 可能
3. 反射/动态加载是否可被滥用

常见危险模式：
- eval(user_input), exec(user_input)
- Python: compile() + exec()
- JS: new Function(user_input), eval()
- PHP: eval(), assert(), create_function(), preg_replace with /e

安全检查要点：
- 是否有代码签名/白名单验证
- 沙箱隔离是否存在
- AST 预检查是否实施
""",

    "sql_injection": """
【SQL 注入类漏洞专项分析指南】

重点检查：
1. SQL 语句是否通过字符串拼接构造
2. 参数化查询是否正确使用
3. ORM 是否安全使用（是否有 raw SQL）

常见危险模式：
- "SELECT * FROM users WHERE id=" + user_id
- cursor.execute(f"SELECT * FROM {table}")
- Model.objects.raw(user_input)
- mysqli_query($conn, "SELECT * FROM users WHERE id=$id")

安全检查要点：
- 参数化查询 (?, %s, :param) 是否使用
- ORM 安全方法是否使用
- 输入是否经过类型转换（如 int()）
""",

    "file_read": """
【任意文件读取类漏洞专项分析指南】

重点检查：
1. 文件路径是否包含用户可控部分
2. 是否存在路径穿越风险（../）
3. 是否限制在安全目录内

常见危险模式：
- open(user_path, 'r')
- file_get_contents($_GET['file'])
- fs.readFile(req.query.path)
- send_file(user_provided_path)

安全检查要点：
- os.path.realpath() + startswith() 目录限制
- 路径规范化是否在检查之前
- 白名单文件列表是否存在
- 是否禁止 ../ 和绝对路径
""",

    "file_write": """
【任意文件写入类漏洞专项分析指南】

重点检查：
1. 写入路径是否用户可控
2. 写入内容是否用户可控
3. 是否可覆盖关键配置文件

常见危险模式：
- open(user_path, 'w').write(user_content)
- file_put_contents($_GET['file'], $_POST['data'])
- fs.writeFile(req.body.path, req.body.content)
- move_uploaded_file() 目标路径可控

安全检查要点：
- 写入目录白名单限制
- 文件扩展名白名单
- 文件名随机化/UUID
- 内容类型检查（如上传文件）
""",

    "deserialization": """
【反序列化类漏洞专项分析指南】

重点检查：
1. 反序列化数据是否来自不可信源
2. 是否使用了不安全的反序列化方法
3. 是否有类型限制或白名单

常见危险模式：
- pickle.loads(user_data)
- yaml.load(user_input)（非 safe_load）
- unserialize($_GET['data'])（PHP）
- ObjectInputStream.readObject()（Java）
- JSON.parse() 配合原型污染（JS）

安全检查要点：
- 是否使用安全替代方案（如 pickle -> json, yaml.safe_load）
- 是否有签名/HMAC 验证
- 是否有类型白名单
- 数据来源是否可信（如仅限内部服务）
""",

    "ssrf": """
【SSRF 类漏洞专项分析指南】

重点检查：
1. URL 是否包含用户可控部分
2. 是否可以访问内网资源
3. 协议是否受限（http/https only）

常见危险模式：
- requests.get(user_url)
- curl_exec() with user-provided URL
- file_get_contents(user_url)
- fetch(req.body.url)

安全检查要点：
- URL 白名单/黑名单校验
- 协议限制（禁止 file://, gopher:// 等）
- 内网 IP 过滤（127.0.0.1, 10.x, 172.16.x, 192.168.x）
- DNS rebinding 防护
""",

    "xss": """
【XSS 类漏洞专项分析指南】

重点检查：
1. 用户输入是否直接输出到 HTML
2. 是否经过适当的转义/编码
3. 模板引擎是否正确配置

常见危险模式：
- echo $_GET['name']（PHP）
- innerHTML = user_input（JS）
- render_template_string(user_input)（Flask SSTI）
- v-html="user_input"（Vue）

安全检查要点：
- HTML 实体编码是否应用
- Content-Type 是否正确设置
- CSP 策略是否配置
- 模板自动转义是否开启
""",
}


def build_chain_analysis_prompt(
    chain_context_text: str,
    chain_id: str,
    sink_category: str,
) -> Tuple[str, str]:
    """构建链级分析提示词

    根据目标文档 P0-5 的要求，LLM 分析必须以"链"为单位。

    Args:
        chain_context_text: 调用链上下文文本（由 ChainContext.to_prompt_text() 生成）
        chain_id: 调用链标识
        sink_category: sink 类别

    Returns:
        (system_prompt, user_prompt)
    """
    # 基础系统提示词
    system = CHAIN_SYSTEM_PROMPT

    # 添加高危类别专用提示词
    category_prompt = SINK_CATEGORY_PROMPTS.get(sink_category)
    if category_prompt:
        system += "\n" + category_prompt

    # 构建用户提示词
    user = f"""【调用链信息】
Chain ID: {chain_id}
Sink 类别: {sink_category}

{chain_context_text}

{CHAIN_USER_PROMPT_TEMPLATE.split('{context}')[1]}"""

    return system, user


def get_chain_output_schema() -> Dict[str, Any]:
    """获取链级分析的输出 Schema

    用于验证 LLM 输出的格式正确性。
    """
    return {
        "required_fields": [
            "chain_id",
            "sink_category",
            "has_issue",
            "confidence",
        ],
        "optional_fields": [
            "risk_level",
            "issue_type",
            "summary",
            "evidence",
            "data_flow",
            "security_controls",
            "exploitability_conditions",
            "fix_suggestion",
            "notes",
        ],
        "field_types": {
            "chain_id": str,
            "sink_category": str,
            "has_issue": (bool, str),  # 允许 "uncertain"
            "confidence": (int, float),
            "risk_level": str,
            "issue_type": str,
            "summary": str,
            "evidence": list,
            "data_flow": str,
            "security_controls": list,
            "exploitability_conditions": str,
            "fix_suggestion": str,
            "notes": str,
        },
        "enum_values": {
            "risk_level": ["low", "medium", "high", "critical"],
            "sink_category": [
                "command_exec", "code_exec", "sql_injection",
                "file_read", "file_write", "deserialization",
                "ssrf", "xss", "path_traversal", "other"
            ],
        },
        "range_constraints": {
            "confidence": (0.0, 1.0),
        },
    }
