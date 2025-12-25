"""
带数据库日志的代码分析 Agent

在原有 Agent 基础上，集成数据库日志记录功能，
将所有工具调用和分析过程记录到数据库。
"""

import json
import time
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from llm_client import BaseLLMClient, ChatMessage
from indexer import CodeReader
from storage import InteractionRepository
from .tools import CODE_READER_TOOLS, SECURITY_ANALYSIS_TOOLS
from .code_agent import CodeAnalysisAgent, AgentResult, ToolCallRecord

logger = logging.getLogger(__name__)


@dataclass
class LoggedAgentResult(AgentResult):
    """带日志的 Agent 执行结果"""
    interaction_count: int = 0  # 记录的交互数量


class LoggedCodeAgent(CodeAnalysisAgent):
    """带数据库日志的代码分析 Agent

    自动将工具调用、LLM 响应等记录到数据库，
    便于后续回放和分析。
    """

    def __init__(
        self,
        llm_client: BaseLLMClient,
        code_reader: CodeReader,
        interaction_repo: Optional[InteractionRepository] = None,
        scan_id: Optional[str] = None,
        **kwargs,
    ):
        """初始化 Agent

        Args:
            llm_client: LLM 客户端
            code_reader: 代码读取器
            interaction_repo: 交互日志仓库
            scan_id: 扫描任务 ID
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(llm_client, code_reader, **kwargs)
        self.interaction_repo = interaction_repo
        self.scan_id = scan_id
        self._interaction_count = 0

    def set_scan_context(self, scan_id: str, interaction_repo: InteractionRepository):
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
    ) -> LoggedAgentResult:
        """执行分析任务（带日志记录）"""
        self._interaction_count = 0

        # 记录任务开始
        if self.interaction_repo and self.scan_id:
            self._log_thinking(f"开始分析任务: {task[:200]}...")

        # 调用父类方法
        result = super().analyze(task, system_prompt, context)

        # 转换为带日志的结果
        logged_result = LoggedAgentResult(
            content=result.content,
            tool_calls_history=result.tool_calls_history,
            total_tool_calls=result.total_tool_calls,
            total_tokens=result.total_tokens,
            truncated=result.truncated,
            error=result.error,
            interaction_count=self._interaction_count,
        )

        # 记录最终结果
        if self.interaction_repo and self.scan_id:
            self._log_analysis(result.content, result.total_tokens)

        return logged_result

    def _execute_tool(self, tool_call) -> tuple:
        """执行工具调用（带日志记录）"""
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
        """记录思考过程"""
        if self.interaction_repo and self.scan_id:
            try:
                self.interaction_repo.log_thinking(self.scan_id, content)
                self._interaction_count += 1
            except Exception as e:
                logger.warning(f"记录思考日志失败: {e}")

    def _log_analysis(self, content: str, tokens_used: int):
        """记录分析结果"""
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


class LoggedSecurityAgent(LoggedCodeAgent):
    """带数据库日志的安全分析 Agent

    专门用于安全代码审计，集成安全分析工具。
    """

    def __init__(self, *args, **kwargs):
        # 使用安全分析工具
        kwargs.setdefault("tools", SECURITY_ANALYSIS_TOOLS)
        super().__init__(*args, **kwargs)

    def analyze_security(
        self,
        target: str,
        focus_areas: Optional[List[str]] = None,
        vuln_types: Optional[List[str]] = None,
    ) -> LoggedAgentResult:
        """执行安全分析（带日志记录）

        Args:
            target: 分析目标
            focus_areas: 重点关注的安全领域
            vuln_types: 要检查的漏洞类型

        Returns:
            LoggedAgentResult
        """
        # 记录分析开始
        if self.interaction_repo and self.scan_id:
            self._log_thinking(f"开始安全分析: {target}")

        focus_text = ""
        if focus_areas:
            focus_text = "\n\n重点关注以下安全领域：\n" + "\n".join(f"- {area}" for area in focus_areas)

        vuln_text = ""
        if vuln_types:
            vuln_text = "\n\n要检查的漏洞类型：\n" + "\n".join(f"- {vt}" for vt in vuln_types)

        task = f"""请对以下目标进行安全分析：

**分析目标**: {target}
{focus_text}
{vuln_text}

请从以下角度进行分析：
1. 身份认证和授权是否正确实现
2. 是否存在输入验证缺陷
3. 是否存在越权访问风险（水平/垂直越权）
4. 业务逻辑是否可被绕过
5. 是否存在敏感信息泄露风险

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
      "fix_suggestion": "修复建议"
    }}
  ]
}}
```"""

        system_prompt = """你是一位资深的安全工程师，专注于代码审计和漏洞挖掘。

在分析代码时，请特别关注：
1. **认证与授权**：登录状态检查、权限验证、会话管理
2. **输入验证**：用户输入是否经过验证和过滤
3. **业务逻辑**：流程是否可被跳过、参数是否可被篡改
4. **数据访问**：是否存在未授权的数据访问（IDOR）
5. **敏感操作**：关键操作是否有适当保护

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
    ) -> LoggedAgentResult:
        """分析指定函数的安全性

        Args:
            symbol_name: 函数名
            file_path: 文件路径（可选）
            check_auth: 是否检查认证授权
            check_input: 是否检查输入验证

        Returns:
            LoggedAgentResult
        """
        location = f"函数 `{symbol_name}`"
        if file_path:
            location += f" (位于 {file_path})"

        focus_areas = []
        if check_auth:
            focus_areas.extend(["认证检查", "授权检查", "权限验证"])
        if check_input:
            focus_areas.extend(["输入验证", "参数校验", "SQL 注入", "命令注入"])

        return self.analyze_security(target=location, focus_areas=focus_areas)
