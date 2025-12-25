"""
带数据库日志的增强安全分析 Agent

结合 EnhancedSecurityAgent 的调用链/污点分析能力
与 LoggedCodeAgent 的数据库日志记录功能。
"""

import time
import logging
from typing import Optional, List, Dict, Any

from llm_client import BaseLLMClient, ChatMessage
from indexer import CodeReader, CodeIndexer
from storage import InteractionRepository
from .enhanced_agent import EnhancedSecurityAgent
from .code_agent import AgentResult, ToolCallRecord
from .tools import SECURITY_ANALYSIS_TOOLS

logger = logging.getLogger(__name__)


class LoggedEnhancedSecurityAgent(EnhancedSecurityAgent):
    """带数据库日志的增强安全分析 Agent

    结合了：
    - EnhancedSecurityAgent 的调用链和污点分析能力
    - 数据库日志记录功能，记录所有工具调用和分析过程

    用于代码安全审计，支持：
    1. LLM Function Calling 工具调用
    2. 调用链分析
    3. 污点传播分析
    4. 所有操作记录到数据库
    """

    def __init__(
        self,
        llm_client: BaseLLMClient,
        code_reader: CodeReader,
        indexer: CodeIndexer,
        call_chain_analyzer: Optional[Any] = None,
        taint_analyzer: Optional[Any] = None,
        interaction_repo: Optional[InteractionRepository] = None,
        scan_id: Optional[str] = None,
        **kwargs,
    ):
        """初始化 Agent

        Args:
            llm_client: LLM 客户端
            code_reader: 代码读取器
            indexer: 代码索引器
            call_chain_analyzer: 调用链分析器（可选）
            taint_analyzer: 污点分析器（可选）
            interaction_repo: 交互日志仓库（可选）
            scan_id: 扫描任务 ID（可选）
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(
            llm_client=llm_client,
            code_reader=code_reader,
            indexer=indexer,
            call_chain_analyzer=call_chain_analyzer,
            taint_analyzer=taint_analyzer,
            **kwargs
        )
        self.interaction_repo = interaction_repo
        self.scan_id = scan_id
        self._interaction_count = 0

    def set_scan_context(
        self,
        scan_id: str,
        interaction_repo: InteractionRepository
    ):
        """设置扫描上下文

        Args:
            scan_id: 扫描任务 ID
            interaction_repo: 交互日志仓库
        """
        self.scan_id = scan_id
        self.interaction_repo = interaction_repo

    def analyze(
        self,
        task: str,
        system_prompt: Optional[str] = None,
        context: Optional[str] = None,
    ) -> AgentResult:
        """执行分析任务（带日志记录）

        Args:
            task: 分析任务描述
            system_prompt: 系统提示词
            context: 额外上下文

        Returns:
            AgentResult 分析结果
        """
        self._interaction_count = 0

        # 记录任务开始
        if self.interaction_repo and self.scan_id:
            self._log_thinking(f"开始安全分析任务: {task[:200]}...")

        # 调用父类方法执行分析
        result = super().analyze(task, system_prompt, context)

        # 记录最终结果
        if self.interaction_repo and self.scan_id:
            self._log_analysis(result.content, result.total_tokens)

        return result

    def analyze_security_target(
        self,
        target: str,
        focus_areas: Optional[List[str]] = None,
        vuln_types: Optional[List[str]] = None,
        use_call_chain: bool = True,
        use_taint: bool = True,
    ) -> AgentResult:
        """执行安全分析（带日志记录）

        这是主要的安全分析入口点，会利用调用链和污点分析能力。

        Args:
            target: 分析目标（函数名、文件路径等）
            focus_areas: 重点关注的安全领域
            vuln_types: 要检查的漏洞类型
            use_call_chain: 是否使用调用链分析
            use_taint: 是否使用污点分析

        Returns:
            AgentResult 分析结果
        """
        # 记录分析开始
        if self.interaction_repo and self.scan_id:
            self._log_thinking(
                f"开始深度安全分析: {target}\n"
                f"调用链分析: {'启用' if use_call_chain else '禁用'}, "
                f"污点分析: {'启用' if use_taint else '禁用'}"
            )

        # 准备分析环境
        if use_call_chain or use_taint:
            self.prepare_analysis()
            if self.interaction_repo and self.scan_id:
                self._log_thinking(
                    f"分析环境准备完成: "
                    f"调用图节点数={len(self._call_graph.nodes) if self._call_graph else 0}, "
                    f"污点流数量={len(self._taint_flows) if self._taint_flows else 0}"
                )

        # 构建分析任务
        focus_text = ""
        if focus_areas:
            focus_text = "\n\n重点关注以下安全领域：\n" + "\n".join(
                f"- {area}" for area in focus_areas
            )

        vuln_text = ""
        if vuln_types:
            vuln_text = "\n\n要检查的漏洞类型：\n" + "\n".join(
                f"- {vt}" for vt in vuln_types
            )

        # 根据是否启用调用链分析选择工具列表
        tool_instructions = """
请按以下步骤进行分析：
1. 使用 read_symbol 或 search_code 读取目标代码
2. 使用 analyze_call_chain 分析调用关系
3. 如果涉及用户输入，使用 trace_taint_path 追踪污点传播
4. 使用 get_code_context 获取完整上下文
5. 根据分析结果判断是否存在安全问题
"""

        task = f"""请对以下目标进行深度安全分析：

**分析目标**: {target}
{focus_text}
{vuln_text}

{tool_instructions}

请从以下角度进行分析：
1. 身份认证和授权是否正确实现
2. 是否存在输入验证缺陷
3. 是否存在越权访问风险（水平/垂直越权）
4. 业务逻辑是否可被绕过
5. 是否存在敏感信息泄露风险
6. 调用链中是否存在安全隐患

请使用工具获取相关代码，然后给出详细的分析结果。如果发现潜在问题，请以 JSON 格式输出：
```json
{{
  "has_issue": true/false,
  "issues": [
    {{
      "type": "问题类型",
      "severity": "critical/high/medium/low",
      "confidence": 0.0-1.0,
      "file_path": "文件路径",
      "line_start": 行号,
      "symbol": "函数名",
      "summary": "问题简述",
      "attack_scenario": "攻击场景",
      "fix_suggestion": "修复建议",
      "call_chain": ["调用链"],
      "taint_source": "污点源（如有）"
    }}
  ]
}}
```"""

        system_prompt = """你是一位资深的安全工程师，专注于代码审计和漏洞挖掘。

你可以使用以下工具来获取信息：
- search_code: 语义搜索代码
- read_file: 读取文件内容
- get_function: 获取函数定义
- list_functions: 列出文件中的函数
- get_callers: 查找调用者
- get_callees: 查找被调用者
- analyze_call_chain: 分析完整调用链
- trace_taint_path: 追踪污点传播路径
- get_code_context: 获取代码上下文
- check_vulnerability_pattern: 检查漏洞模式

在分析代码时，请特别关注：
1. **认证与授权**：登录状态检查、权限验证、会话管理
2. **输入验证**：用户输入是否经过验证和过滤
3. **业务逻辑**：流程是否可被跳过、参数是否可被篡改
4. **数据访问**：是否存在未授权的数据访问（IDOR）
5. **敏感操作**：关键操作是否有适当保护
6. **调用链安全**：完整调用路径是否存在安全隐患

使用工具自主获取代码，像真正的安全工程师一样思考和分析。
发现问题时，给出具体的代码位置和修复建议。
如果不确定是否构成漏洞，请明确说明需要人工确认的原因。"""

        return self.analyze(task=task, system_prompt=system_prompt)

    def analyze_function(
        self,
        symbol_name: str,
        file_path: Optional[str] = None,
        check_auth: bool = True,
        check_input: bool = True,
        check_call_chain: bool = True,
    ) -> AgentResult:
        """分析指定函数的安全性

        Args:
            symbol_name: 函数名
            file_path: 文件路径（可选）
            check_auth: 是否检查认证授权
            check_input: 是否检查输入验证
            check_call_chain: 是否检查调用链

        Returns:
            AgentResult 分析结果
        """
        location = f"函数 `{symbol_name}`"
        if file_path:
            location += f" (位于 {file_path})"

        focus_areas = []
        if check_auth:
            focus_areas.extend(["认证检查", "授权检查", "权限验证"])
        if check_input:
            focus_areas.extend(["输入验证", "参数校验", "SQL 注入", "命令注入"])
        if check_call_chain:
            focus_areas.extend(["调用链分析", "污点传播", "数据流追踪"])

        return self.analyze_security_target(
            target=location,
            focus_areas=focus_areas,
            use_call_chain=check_call_chain,
            use_taint=check_call_chain,
        )

    def _execute_tool(self, tool_call) -> tuple:
        """执行工具调用（带日志记录）

        重写父类方法，在执行前后记录日志。

        Args:
            tool_call: 工具调用对象

        Returns:
            (结果, 成功标志) 元组
        """
        start_time = time.time()

        # 执行工具
        result, success = super()._execute_tool(tool_call)

        duration_ms = int((time.time() - start_time) * 1000)

        # 记录工具调用
        if self.interaction_repo and self.scan_id:
            try:
                self.interaction_repo.log_tool_call(
                    scan_id=self.scan_id,
                    tool_name=tool_call.name,
                    tool_input=tool_call.arguments,
                    tool_output=result,
                    duration_ms=duration_ms,
                )
                self._interaction_count += 1
            except Exception as e:
                logger.warning(f"记录工具调用日志失败: {e}")

        return result, success

    def _log_thinking(self, content: str):
        """记录思考过程

        Args:
            content: 思考内容
        """
        if self.interaction_repo and self.scan_id:
            try:
                self.interaction_repo.log_thinking(self.scan_id, content)
                self._interaction_count += 1
            except Exception as e:
                logger.warning(f"记录思考日志失败: {e}")

    def _log_analysis(self, content: str, tokens_used: int):
        """记录分析结果

        Args:
            content: 分析结果内容
            tokens_used: 使用的 token 数量
        """
        if self.interaction_repo and self.scan_id:
            try:
                self.interaction_repo.log_analysis(
                    scan_id=self.scan_id,
                    llm_response=content,
                    tokens_used=tokens_used,
                )
                self._interaction_count += 1
            except Exception as e:
                logger.warning(f"记录分析日志失败: {e}")

    def get_interaction_count(self) -> int:
        """获取交互记录数量

        Returns:
            交互记录数量
        """
        return self._interaction_count
