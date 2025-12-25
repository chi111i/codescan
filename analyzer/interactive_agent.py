"""
交互式代码审计代理 - 核心组件

提供用户可交互、可选择、可对话的代码审计功能。

功能：
1. 管理审计会话上下文
2. 响应用户命令（分析、追问、总结等）
3. 构建 LLM 提示词
4. 处理 LLM 响应
5. 管理待确认/已确认的发现
"""

import asyncio
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any, Callable

from llm_client import BaseLLMClient, ChatMessage
from indexer import CodeUnit

from .sink_scanner import SinkCallSite, SinkCategory
from .chain_context import ChainContext, ChainContextCollector
from .models import Finding, Severity, Evidence

logger = logging.getLogger(__name__)


class AgentResponseType(Enum):
    """代理响应类型"""
    ANALYSIS = "analysis"       # 分析结果
    CHAT = "chat"               # 对话响应
    SUMMARY = "summary"         # 总结报告
    FINDING = "finding"         # 发现报告
    ERROR = "error"             # 错误信息
    STATUS = "status"           # 状态更新


class FindingStatus(Enum):
    """发现状态"""
    PENDING = "pending"         # 待确认
    CONFIRMED = "confirmed"     # 已确认
    REJECTED = "rejected"       # 已拒绝


@dataclass
class InteractiveFinding:
    """交互式发现（带状态管理）"""
    id: str
    title: str
    category: str
    severity: Severity
    confidence: float
    file_path: str
    line_start: int
    line_end: int
    symbol: str
    summary: str
    details: str
    evidence: List[Evidence] = field(default_factory=list)
    attack_scenario: str = ""
    fix_suggestion: str = ""

    # 状态管理
    status: FindingStatus = FindingStatus.PENDING
    user_notes: str = ""
    confirmed_at: Optional[datetime] = None
    rejected_reason: str = ""

    # 来源信息
    source_chain_id: Optional[str] = None
    source_sink_site_id: Optional[str] = None
    llm_raw_response: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "symbol": self.symbol,
            "summary": self.summary,
            "details": self.details,
            "evidence": [
                {
                    "file_path": e.file_path,
                    "line_start": e.line_start,
                    "line_end": e.line_end,
                    "code_snippet": e.code_snippet,
                    "description": e.description,
                }
                for e in self.evidence
            ],
            "attack_scenario": self.attack_scenario,
            "fix_suggestion": self.fix_suggestion,
            "status": self.status.value,
            "user_notes": self.user_notes,
            "confirmed_at": self.confirmed_at.isoformat() if self.confirmed_at else None,
            "rejected_reason": self.rejected_reason,
            "source_chain_id": self.source_chain_id,
            "source_sink_site_id": self.source_sink_site_id,
        }


@dataclass
class AgentResponse:
    """代理响应"""
    response_type: AgentResponseType
    content: str                           # LLM 原始响应内容
    findings: List[InteractiveFinding] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)  # 后续建议
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "response_type": self.response_type.value,
            "content": self.content,
            "findings": [f.to_dict() for f in self.findings],
            "suggestions": self.suggestions,
            "metadata": self.metadata,
            "error": self.error,
        }


@dataclass
class AnalysisContext:
    """分析上下文"""
    selected_chain_ids: List[str] = field(default_factory=list)
    selected_unit_ids: List[str] = field(default_factory=list)
    focus_areas: List[str] = field(default_factory=list)
    custom_prompt: Optional[str] = None

    # 实际数据
    chain_contexts: List[ChainContext] = field(default_factory=list)
    code_units: List[CodeUnit] = field(default_factory=list)

    def to_prompt_text(self) -> str:
        """生成用于 LLM 的上下文文本"""
        parts = []

        # 添加选中的调用链上下文
        if self.chain_contexts:
            parts.append("【选中的调用链上下文】")
            for i, ctx in enumerate(self.chain_contexts, 1):
                parts.append(f"\n--- 调用链 {i} ---")
                parts.append(ctx.to_prompt_text())

        # 添加选中的代码单元
        if self.code_units:
            parts.append("\n【选中的代码单元】")
            for unit in self.code_units:
                parts.append(f"\n--- {unit.symbol} ({unit.file_path}:{unit.span.start_line}) ---")
                parts.append(f"```{unit.language}")
                parts.append(unit.code)
                parts.append("```")

        # 添加关注领域
        if self.focus_areas:
            parts.append(f"\n【关注的漏洞类型】")
            parts.append(", ".join(self.focus_areas))

        # 添加自定义提示
        if self.custom_prompt:
            parts.append(f"\n【用户附加说明】")
            parts.append(self.custom_prompt)

        return "\n".join(parts)


class InteractiveAuditAgent:
    """交互式代码审计代理

    核心职责：
    1. 管理审计会话上下文
    2. 响应用户命令（分析、追问、总结等）
    3. 构建 LLM 提示词
    4. 处理 LLM 响应
    5. 管理发现确认工作流
    """

    def __init__(
        self,
        session_id: str,
        llm_client: BaseLLMClient,
        target_path: str,
        code_units: List[CodeUnit],
        sink_sites: List[SinkCallSite],
        chain_contexts: List[ChainContext],
        on_stream_callback: Optional[Callable[[str], None]] = None,
    ):
        """
        Args:
            session_id: 会话 ID
            llm_client: LLM 客户端
            target_path: 目标路径
            code_units: 代码单元列表
            sink_sites: 危险函数触发点列表
            chain_contexts: 调用链上下文列表
            on_stream_callback: 流式输出回调函数
        """
        self.session_id = session_id
        self.llm_client = llm_client
        self.target_path = target_path

        # 代码数据
        self.code_units = code_units
        self.sink_sites = sink_sites
        self.chain_contexts = chain_contexts

        # 索引映射
        self._unit_map: Dict[str, CodeUnit] = {u.id: u for u in code_units}
        self._sink_map: Dict[str, SinkCallSite] = {s.id: s for s in sink_sites}
        self._chain_map: Dict[str, ChainContext] = {}
        for ctx in chain_contexts:
            chain_id = f"chain-{ctx.sink_site.id}"
            self._chain_map[chain_id] = ctx

        # 对话历史
        self.conversation_history: List[ChatMessage] = []

        # 当前分析上下文
        self.current_context: Optional[AnalysisContext] = None

        # 发现管理
        self.pending_findings: List[InteractiveFinding] = []
        self.confirmed_findings: List[InteractiveFinding] = []
        self.rejected_findings: List[InteractiveFinding] = []

        # 流式输出回调
        self.on_stream_callback = on_stream_callback

        # 统计
        self.total_llm_calls = 0
        self.total_tokens_used = 0

        logger.info(
            f"[InteractiveAgent] 初始化会话 {session_id}: "
            f"{len(code_units)} 代码单元, {len(sink_sites)} sink sites, "
            f"{len(chain_contexts)} 调用链"
        )

    # ========== 核心命令 ==========

    async def analyze_selection(
        self,
        selected_chain_ids: List[str] = None,
        selected_unit_ids: List[str] = None,
        focus_areas: Optional[List[str]] = None,
        custom_prompt: Optional[str] = None,
    ) -> AgentResponse:
        """分析用户选择的内容

        Args:
            selected_chain_ids: 选中的调用链 ID 列表
            selected_unit_ids: 选中的代码单元 ID 列表
            focus_areas: 关注的漏洞类型
            custom_prompt: 用户自定义提示

        Returns:
            AgentResponse
        """
        selected_chain_ids = selected_chain_ids or []
        selected_unit_ids = selected_unit_ids or []

        if not selected_chain_ids and not selected_unit_ids:
            return AgentResponse(
                response_type=AgentResponseType.ERROR,
                content="",
                error="请至少选择一个调用链或代码单元进行分析",
            )

        logger.info(
            f"[InteractiveAgent] 分析选择: "
            f"{len(selected_chain_ids)} 调用链, {len(selected_unit_ids)} 代码单元"
        )

        # 构建分析上下文
        context = AnalysisContext(
            selected_chain_ids=selected_chain_ids,
            selected_unit_ids=selected_unit_ids,
            focus_areas=focus_areas or [],
            custom_prompt=custom_prompt,
        )

        # 获取实际数据
        context.chain_contexts = [
            self._chain_map[cid] for cid in selected_chain_ids
            if cid in self._chain_map
        ]
        context.code_units = [
            self._unit_map[uid] for uid in selected_unit_ids
            if uid in self._unit_map
        ]

        self.current_context = context

        # 构建提示词
        system_prompt = self._build_analysis_system_prompt()
        user_prompt = self._build_analysis_user_prompt(context)

        # 调用 LLM
        try:
            response = await self._call_llm(system_prompt, user_prompt)

            # 解析响应
            findings = self._parse_analysis_response(response, context)

            # 添加到待确认列表
            self.pending_findings.extend(findings)

            # 生成建议
            suggestions = self._generate_suggestions(findings, context)

            # 添加到对话历史
            self._add_to_history("user", user_prompt)
            self._add_to_history("assistant", response)

            return AgentResponse(
                response_type=AgentResponseType.ANALYSIS,
                content=response,
                findings=findings,
                suggestions=suggestions,
                metadata={
                    "analyzed_chains": len(context.chain_contexts),
                    "analyzed_units": len(context.code_units),
                    "new_findings": len(findings),
                },
            )

        except Exception as e:
            logger.error(f"[InteractiveAgent] 分析失败: {e}")
            return AgentResponse(
                response_type=AgentResponseType.ERROR,
                content="",
                error=f"分析失败: {str(e)}",
            )

    async def chat(self, message: str) -> AgentResponse:
        """与 LLM 对话（在当前上下文中）

        Args:
            message: 用户消息

        Returns:
            AgentResponse
        """
        logger.info(f"[InteractiveAgent] 对话: {message[:50]}...")

        # 构建上下文感知的提示
        system_prompt = self._build_chat_system_prompt()

        # 构建包含历史的消息
        messages = [
            ChatMessage(role="system", content=system_prompt),
        ]

        # 添加最近的对话历史（限制长度）
        recent_history = self.conversation_history[-10:]
        for msg in recent_history:
            messages.append(msg)

        # 添加当前消息
        messages.append(ChatMessage(role="user", content=message))

        try:
            # 调用 LLM
            response = await self._call_llm_with_messages(messages)

            # 检查是否包含新发现
            findings = self._extract_findings_from_chat(response)
            if findings:
                self.pending_findings.extend(findings)

            # 添加到对话历史
            self._add_to_history("user", message)
            self._add_to_history("assistant", response)

            return AgentResponse(
                response_type=AgentResponseType.CHAT,
                content=response,
                findings=findings,
                suggestions=[],
            )

        except Exception as e:
            logger.error(f"[InteractiveAgent] 对话失败: {e}")
            return AgentResponse(
                response_type=AgentResponseType.ERROR,
                content="",
                error=f"对话失败: {str(e)}",
            )

    async def dig_deeper(
        self,
        finding_id: str,
        direction: str = "expand",
    ) -> AgentResponse:
        """深入分析某个发现

        Args:
            finding_id: 发现 ID
            direction: 分析方向
                - "expand": 扩展分析（更多上下文）
                - "trace_source": 追踪数据源
                - "trace_sink": 追踪数据汇
                - "verify": 验证可利用性

        Returns:
            AgentResponse
        """
        logger.info(f"[InteractiveAgent] 深入分析: {finding_id}, 方向: {direction}")

        # 查找发现
        finding = self._find_finding(finding_id)
        if not finding:
            return AgentResponse(
                response_type=AgentResponseType.ERROR,
                content="",
                error=f"未找到发现: {finding_id}",
            )

        # 构建深入分析提示
        system_prompt = self._build_dig_deeper_system_prompt(direction)
        user_prompt = self._build_dig_deeper_user_prompt(finding, direction)

        try:
            response = await self._call_llm(system_prompt, user_prompt)

            # 解析可能的新发现
            new_findings = self._extract_findings_from_chat(response)
            if new_findings:
                self.pending_findings.extend(new_findings)

            # 添加到对话历史
            self._add_to_history("user", user_prompt)
            self._add_to_history("assistant", response)

            return AgentResponse(
                response_type=AgentResponseType.ANALYSIS,
                content=response,
                findings=new_findings,
                metadata={
                    "original_finding_id": finding_id,
                    "direction": direction,
                },
            )

        except Exception as e:
            logger.error(f"[InteractiveAgent] 深入分析失败: {e}")
            return AgentResponse(
                response_type=AgentResponseType.ERROR,
                content="",
                error=f"深入分析失败: {str(e)}",
            )

    async def summarize(self) -> AgentResponse:
        """生成当前分析的总结报告

        Returns:
            AgentResponse
        """
        logger.info("[InteractiveAgent] 生成总结报告")

        system_prompt = self._build_summary_system_prompt()
        user_prompt = self._build_summary_user_prompt()

        try:
            response = await self._call_llm(system_prompt, user_prompt)

            return AgentResponse(
                response_type=AgentResponseType.SUMMARY,
                content=response,
                findings=[],
                metadata={
                    "total_findings": len(self.pending_findings) + len(self.confirmed_findings),
                    "confirmed_count": len(self.confirmed_findings),
                    "pending_count": len(self.pending_findings),
                    "rejected_count": len(self.rejected_findings),
                    "total_llm_calls": self.total_llm_calls,
                },
            )

        except Exception as e:
            logger.error(f"[InteractiveAgent] 生成总结失败: {e}")
            return AgentResponse(
                response_type=AgentResponseType.ERROR,
                content="",
                error=f"生成总结失败: {str(e)}",
            )

    def stop_analysis(self) -> AgentResponse:
        """停止当前分析，返回状态

        Returns:
            AgentResponse
        """
        logger.info("[InteractiveAgent] 停止分析")

        return AgentResponse(
            response_type=AgentResponseType.STATUS,
            content="分析已停止",
            findings=[],
            metadata={
                "session_id": self.session_id,
                "total_findings": len(self.pending_findings) + len(self.confirmed_findings),
                "confirmed_count": len(self.confirmed_findings),
                "pending_count": len(self.pending_findings),
                "rejected_count": len(self.rejected_findings),
                "total_llm_calls": self.total_llm_calls,
                "total_tokens_used": self.total_tokens_used,
            },
        )

    # ========== 发现管理 ==========

    def confirm_finding(self, finding_id: str, notes: str = "") -> bool:
        """确认一个发现

        Args:
            finding_id: 发现 ID
            notes: 用户备注

        Returns:
            是否成功
        """
        finding = self._find_pending_finding(finding_id)
        if not finding:
            return False

        finding.status = FindingStatus.CONFIRMED
        finding.user_notes = notes
        finding.confirmed_at = datetime.now()

        self.pending_findings.remove(finding)
        self.confirmed_findings.append(finding)

        logger.info(f"[InteractiveAgent] 确认发现: {finding_id}")
        return True

    def reject_finding(self, finding_id: str, reason: str = "") -> bool:
        """拒绝一个发现

        Args:
            finding_id: 发现 ID
            reason: 拒绝原因

        Returns:
            是否成功
        """
        finding = self._find_pending_finding(finding_id)
        if not finding:
            return False

        finding.status = FindingStatus.REJECTED
        finding.rejected_reason = reason

        self.pending_findings.remove(finding)
        self.rejected_findings.append(finding)

        logger.info(f"[InteractiveAgent] 拒绝发现: {finding_id}")
        return True

    def update_finding_notes(self, finding_id: str, notes: str) -> bool:
        """更新发现的备注

        Args:
            finding_id: 发现 ID
            notes: 新备注

        Returns:
            是否成功
        """
        finding = self._find_finding(finding_id)
        if not finding:
            return False

        finding.user_notes = notes
        return True

    def get_pending_findings(self) -> List[InteractiveFinding]:
        """获取待确认的发现"""
        return self.pending_findings.copy()

    def get_confirmed_findings(self) -> List[InteractiveFinding]:
        """获取已确认的发现"""
        return self.confirmed_findings.copy()

    def get_rejected_findings(self) -> List[InteractiveFinding]:
        """获取已拒绝的发现"""
        return self.rejected_findings.copy()

    def get_all_findings(self) -> Dict[str, List[InteractiveFinding]]:
        """获取所有发现（按状态分组）"""
        return {
            "pending": self.pending_findings.copy(),
            "confirmed": self.confirmed_findings.copy(),
            "rejected": self.rejected_findings.copy(),
        }

    # ========== 数据访问 ==========

    def get_chain_context(self, chain_id: str) -> Optional[ChainContext]:
        """获取调用链上下文"""
        return self._chain_map.get(chain_id)

    def get_code_unit(self, unit_id: str) -> Optional[CodeUnit]:
        """获取代码单元"""
        return self._unit_map.get(unit_id)

    def get_sink_site(self, sink_id: str) -> Optional[SinkCallSite]:
        """获取 sink site"""
        return self._sink_map.get(sink_id)

    def list_chain_contexts(self) -> List[Dict[str, Any]]:
        """列出所有调用链上下文（简化信息）"""
        result = []
        for chain_id, ctx in self._chain_map.items():
            result.append({
                "id": chain_id,
                "sink_site": {
                    "id": ctx.sink_site.id,
                    "symbol": ctx.sink_site.symbol,
                    "file_path": ctx.sink_site.file_path,
                    "line_start": ctx.sink_site.line_start,
                    "sink_category": ctx.sink_site.sink_category.value,
                    "risk_level": ctx.sink_site.risk_level.value,
                },
                "chain_length": ctx.chain_length,
                "has_user_input": ctx.has_user_input,
                "risk_level": ctx.risk_level,
                "confidence": ctx.confidence,
            })
        return result

    def list_code_units(self) -> List[Dict[str, Any]]:
        """列出所有代码单元（简化信息）"""
        return [
            {
                "id": u.id,
                "symbol": u.symbol,
                "file_path": u.file_path,
                "language": u.language,
                "unit_type": u.unit_type.value,
                "line_start": u.span.start_line,
                "line_end": u.span.end_line,
            }
            for u in self.code_units
        ]

    def list_sink_sites(self) -> List[Dict[str, Any]]:
        """列出所有 sink sites（简化信息）"""
        return [
            {
                "id": s.id,
                "symbol": s.symbol,
                "file_path": s.file_path,
                "line_start": s.line_start,
                "line_end": s.line_end,
                "sink_category": s.sink_category.value,
                "risk_level": s.risk_level.value,
                "call_snippet": s.call_snippet[:200] if s.call_snippet else "",
            }
            for s in self.sink_sites
        ]

    # ========== 内部方法 ==========

    def _find_finding(self, finding_id: str) -> Optional[InteractiveFinding]:
        """在所有列表中查找发现"""
        for f in self.pending_findings:
            if f.id == finding_id:
                return f
        for f in self.confirmed_findings:
            if f.id == finding_id:
                return f
        for f in self.rejected_findings:
            if f.id == finding_id:
                return f
        return None

    def _find_pending_finding(self, finding_id: str) -> Optional[InteractiveFinding]:
        """在待确认列表中查找发现"""
        for f in self.pending_findings:
            if f.id == finding_id:
                return f
        return None

    def _add_to_history(self, role: str, content: str):
        """添加到对话历史"""
        self.conversation_history.append(
            ChatMessage(role=role, content=content)
        )
        # 限制历史长度
        if len(self.conversation_history) > 50:
            self.conversation_history = self.conversation_history[-50:]

    async def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """调用 LLM（单轮）"""
        messages = [
            ChatMessage(role="system", content=system_prompt),
            ChatMessage(role="user", content=user_prompt),
        ]
        return await self._call_llm_with_messages(messages)

    async def _call_llm_with_messages(self, messages: List[ChatMessage]) -> str:
        """调用 LLM（带完整消息列表）

        使用 asyncio.to_thread() 包装同步的 LLM 调用，防止阻塞事件循环。
        """
        self.total_llm_calls += 1

        logger.info(f"[InteractiveAgent] LLM 调用 #{self.total_llm_calls}")

        # 使用 asyncio.to_thread() 在线程池中执行同步的 LLM 调用，避免阻塞事件循环
        response = await asyncio.to_thread(
            self.llm_client.chat_completion,
            messages=messages,
            temperature=0.1,
            max_tokens=4000,
        )

        # 更新统计
        if response.usage:
            self.total_tokens_used += response.usage.get("total_tokens", 0)

        # 回调通知
        if self.on_stream_callback and response.content:
            self.on_stream_callback(response.content)

        return response.content or ""

    def _build_analysis_system_prompt(self) -> str:
        """构建分析系统提示"""
        return """你是一名资深安全工程师，专长是代码审计和安全漏洞分析。

你将收到用户选择的代码片段（可能包含调用链上下文、代码单元等），需要分析其中的安全问题。

分析重点：
1. 认证与授权是否正确、完整
2. 访问控制是否可被绕过
3. 业务流程是否可被跳过或篡改
4. 用户输入是否经过适当验证
5. 危险函数调用是否安全

请仔细分析代码，如果发现安全问题，以 JSON 格式输出结果：
{
    "has_issue": true/false,
    "findings": [
        {
            "title": "问题标题",
            "category": "漏洞类型（如 command_injection, sql_injection, idor 等）",
            "severity": "low/medium/high/critical",
            "confidence": 0.0-1.0,
            "summary": "简要描述",
            "details": "详细分析",
            "attack_scenario": "攻击场景（高层次描述，不含具体 payload）",
            "fix_suggestion": "修复建议"
        }
    ],
    "notes": "其他说明或需要人工确认的点"
}

如果没有发现问题，返回：
{
    "has_issue": false,
    "notes": "分析说明"
}

重要提示：
- 不要生成可直接利用的攻击 payload
- 如果不确定，请明确说明需要人工确认
- 关注业务逻辑漏洞，不仅仅是技术漏洞
"""

    def _build_analysis_user_prompt(self, context: AnalysisContext) -> str:
        """构建分析用户提示"""
        return f"""请分析以下代码的安全性：

{context.to_prompt_text()}

请仔细检查并输出 JSON 格式的分析结果。
"""

    def _build_chat_system_prompt(self) -> str:
        """构建对话系统提示"""
        # 包含当前上下文摘要
        context_summary = ""
        if self.current_context:
            context_summary = f"""
当前分析上下文：
- 已分析 {len(self.current_context.chain_contexts)} 个调用链
- 已分析 {len(self.current_context.code_units)} 个代码单元
- 关注领域: {', '.join(self.current_context.focus_areas) if self.current_context.focus_areas else '全部'}
"""

        findings_summary = f"""
当前发现状态：
- 待确认: {len(self.pending_findings)} 个
- 已确认: {len(self.confirmed_findings)} 个
- 已拒绝: {len(self.rejected_findings)} 个
"""

        return f"""你是一名资深安全工程师，正在与用户进行代码审计对话。

{context_summary}
{findings_summary}

你可以：
1. 回答用户关于代码安全的问题
2. 解释已发现的安全问题
3. 提供更深入的分析
4. 建议下一步的审计方向

如果在对话中发现新的安全问题，请以 JSON 格式嵌入在回复中：
```json
{{"new_finding": {{"title": "...", "category": "...", "severity": "...", ...}}}}
```

保持专业、简洁，使用中文回复。
"""

    def _build_dig_deeper_system_prompt(self, direction: str) -> str:
        """构建深入分析系统提示"""
        direction_prompts = {
            "expand": "请扩展分析范围，查找更多相关的安全问题和上下文。",
            "trace_source": "请追踪数据的来源，分析用户输入如何流入该漏洞点。",
            "trace_sink": "请追踪数据的去向，分析该漏洞可能造成的影响范围。",
            "verify": "请验证该漏洞的可利用性，分析利用条件和前提。",
        }

        return f"""你是一名资深安全工程师，正在深入分析一个潜在的安全漏洞。

{direction_prompts.get(direction, direction_prompts['expand'])}

请提供详细的分析结果。如果发现新的安全问题，以 JSON 格式输出。
"""

    def _build_dig_deeper_user_prompt(
        self,
        finding: InteractiveFinding,
        direction: str,
    ) -> str:
        """构建深入分析用户提示"""
        return f"""请深入分析以下安全发现：

**发现 ID**: {finding.id}
**标题**: {finding.title}
**类型**: {finding.category}
**严重性**: {finding.severity.value}
**置信度**: {finding.confidence}

**位置**: {finding.file_path}:{finding.line_start}-{finding.line_end}
**符号**: {finding.symbol}

**摘要**: {finding.summary}

**详情**: {finding.details}

**攻击场景**: {finding.attack_scenario}

---

分析方向: {direction}

请提供更深入的分析。
"""

    def _build_summary_system_prompt(self) -> str:
        """构建总结系统提示"""
        return """你是一名资深安全工程师，需要生成代码审计的总结报告。

请根据审计过程中的发现，生成一份清晰、专业的总结报告，包括：
1. 审计概述
2. 发现的安全问题摘要（按严重性排序）
3. 风险评估
4. 修复建议优先级
5. 后续建议

使用 Markdown 格式输出。
"""

    def _build_summary_user_prompt(self) -> str:
        """构建总结用户提示"""
        # 收集所有发现
        all_findings = self.confirmed_findings + self.pending_findings

        findings_text = ""
        if all_findings:
            findings_text = "## 发现列表\n\n"
            for f in sorted(all_findings, key=lambda x: x.severity.value, reverse=True):
                findings_text += f"""
### {f.title}
- **严重性**: {f.severity.value}
- **置信度**: {f.confidence:.1%}
- **类型**: {f.category}
- **位置**: {f.file_path}:{f.line_start}
- **状态**: {f.status.value}
- **摘要**: {f.summary}
"""
        else:
            findings_text = "未发现明显的安全问题。\n"

        return f"""请为以下代码审计会话生成总结报告：

## 审计信息
- **会话 ID**: {self.session_id}
- **目标路径**: {self.target_path}
- **代码单元数**: {len(self.code_units)}
- **扫描的 Sink 点**: {len(self.sink_sites)}
- **分析的调用链**: {len(self.chain_contexts)}

## 统计
- **LLM 调用次数**: {self.total_llm_calls}
- **待确认发现**: {len(self.pending_findings)}
- **已确认发现**: {len(self.confirmed_findings)}
- **已拒绝发现**: {len(self.rejected_findings)}

{findings_text}

请生成完整的总结报告。
"""

    def _parse_analysis_response(
        self,
        response: str,
        context: AnalysisContext,
    ) -> List[InteractiveFinding]:
        """解析分析响应，提取发现"""
        findings = []

        try:
            # 尝试解析 JSON
            data = self._extract_json(response)

            if not data or not data.get("has_issue"):
                return findings

            for item in data.get("findings", []):
                finding = self._create_finding_from_dict(item, context)
                if finding:
                    findings.append(finding)

        except Exception as e:
            logger.warning(f"[InteractiveAgent] 解析响应失败: {e}")

        return findings

    def _extract_findings_from_chat(self, response: str) -> List[InteractiveFinding]:
        """从对话响应中提取发现"""
        findings = []

        # 查找嵌入的 JSON
        json_pattern = r'```json\s*({.*?})\s*```'
        matches = re.findall(json_pattern, response, re.DOTALL)

        for match in matches:
            try:
                data = json.loads(match)
                if "new_finding" in data:
                    finding = self._create_finding_from_dict(data["new_finding"], None)
                    if finding:
                        findings.append(finding)
            except json.JSONDecodeError:
                continue

        return findings

    def _extract_json(self, text: str) -> Optional[Dict]:
        """从文本中提取 JSON"""
        # 尝试直接解析
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 尝试提取 JSON 块
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # 尝试查找 { } 块
        brace_match = re.search(r'\{[\s\S]*\}', text)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except json.JSONDecodeError:
                pass

        return None

    def _create_finding_from_dict(
        self,
        data: Dict,
        context: Optional[AnalysisContext],
    ) -> Optional[InteractiveFinding]:
        """从字典创建发现对象"""
        try:
            # 生成唯一 ID
            finding_id = f"finding-{uuid.uuid4().hex[:8]}"

            # 解析严重性
            severity_map = {
                "low": Severity.LOW,
                "medium": Severity.MEDIUM,
                "high": Severity.HIGH,
                "critical": Severity.CRITICAL,
            }
            severity = severity_map.get(
                data.get("severity", "medium").lower(),
                Severity.MEDIUM
            )

            # 获取位置信息（优先从上下文获取）
            file_path = data.get("file_path", "")
            line_start = data.get("line_start", 0)
            line_end = data.get("line_end", line_start)
            symbol = data.get("symbol", "")

            if context and context.chain_contexts:
                first_chain = context.chain_contexts[0]
                if not file_path:
                    file_path = first_chain.sink_site.file_path
                if not line_start:
                    line_start = first_chain.sink_site.line_start
                    line_end = first_chain.sink_site.line_end
                if not symbol:
                    symbol = first_chain.sink_site.symbol
            elif context and context.code_units:
                first_unit = context.code_units[0]
                if not file_path:
                    file_path = first_unit.file_path
                if not line_start:
                    line_start = first_unit.span.start_line
                    line_end = first_unit.span.end_line
                if not symbol:
                    symbol = first_unit.symbol

            return InteractiveFinding(
                id=finding_id,
                title=data.get("title", "未命名发现"),
                category=data.get("category", "unknown"),
                severity=severity,
                confidence=float(data.get("confidence", 0.5)),
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                symbol=symbol,
                summary=data.get("summary", ""),
                details=data.get("details", ""),
                attack_scenario=data.get("attack_scenario", ""),
                fix_suggestion=data.get("fix_suggestion", ""),
            )

        except Exception as e:
            logger.warning(f"[InteractiveAgent] 创建发现失败: {e}")
            return None

    def _generate_suggestions(
        self,
        findings: List[InteractiveFinding],
        context: AnalysisContext,
    ) -> List[str]:
        """生成后续建议"""
        suggestions = []

        if findings:
            # 有发现时的建议
            high_severity = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
            if high_severity:
                suggestions.append("发现高危问题，建议优先处理")

            suggestions.append("可以选择具体发现进行深入分析")
            suggestions.append("确认或拒绝发现以更新报告")
        else:
            # 无发现时的建议
            suggestions.append("可以选择其他代码进行分析")
            suggestions.append("尝试关注特定漏洞类型")

        # 基于上下文的建议
        remaining_chains = len(self._chain_map) - len(context.selected_chain_ids)
        if remaining_chains > 0:
            suggestions.append(f"还有 {remaining_chains} 个调用链可供分析")

        return suggestions

    # ========== 会话状态 ==========

    def get_session_state(self) -> Dict[str, Any]:
        """获取会话状态"""
        return {
            "session_id": self.session_id,
            "target_path": self.target_path,
            "code_units_count": len(self.code_units),
            "sink_sites_count": len(self.sink_sites),
            "chain_contexts_count": len(self.chain_contexts),
            "pending_findings_count": len(self.pending_findings),
            "confirmed_findings_count": len(self.confirmed_findings),
            "rejected_findings_count": len(self.rejected_findings),
            "conversation_length": len(self.conversation_history),
            "total_llm_calls": self.total_llm_calls,
            "total_tokens_used": self.total_tokens_used,
        }
