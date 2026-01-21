"""多阶段 LLM 验证模块

P2-1: Triage → Deep Verify → Patch Suggest
- Triage: 使用便宜模型快速筛选
- Deep Verify: 使用强模型 + 工具调用深度验证
- Patch Suggest: 可选的修复建议
"""

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Tuple

logger = logging.getLogger(__name__)


class TriageDecision(Enum):
    """Triage 阶段决策"""
    DROP = "drop"              # 明显误报，直接丢弃
    KEEP = "keep"              # 可能是真漏洞，进入深度验证
    NEED_MORE_CONTEXT = "need_more_context"  # 需要更多上下文


class VerifyStatus(Enum):
    """深度验证状态"""
    CONFIRMED = "confirmed"      # 确认是漏洞
    FALSE_POSITIVE = "false_positive"  # 确认是误报
    UNCERTAIN = "uncertain"      # 无法确定
    NEEDS_REVIEW = "needs_review"  # 需要人工审查


class VerificationStage(Enum):
    """验证阶段"""
    TRIAGE = "triage"
    DEEP_VERIFY = "deep_verify"
    PATCH_SUGGEST = "patch_suggest"


@dataclass
class TriageResult:
    """Triage 阶段结果"""
    decision: TriageDecision
    reason: str
    confidence: float
    context_requests: List[str] = field(default_factory=list)  # 需要的额外上下文

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "confidence": self.confidence,
            "context_requests": self.context_requests,
        }


@dataclass
class DeepVerifyResult:
    """深度验证结果"""
    status: VerifyStatus
    is_vulnerability: bool
    severity: str  # critical, high, medium, low, info
    confidence: float
    summary: str
    attack_scenario: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    taint_path: List[str] = field(default_factory=list)
    conditions: List[str] = field(default_factory=list)  # 利用条件
    mitigations: List[str] = field(default_factory=list)  # 现有缓解措施
    tool_calls_made: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "is_vulnerability": self.is_vulnerability,
            "severity": self.severity,
            "confidence": self.confidence,
            "summary": self.summary,
            "attack_scenario": self.attack_scenario,
            "evidence": self.evidence,
            "taint_path": self.taint_path,
            "conditions": self.conditions,
            "mitigations": self.mitigations,
            "tool_calls_made": self.tool_calls_made,
        }


@dataclass
class PatchSuggestion:
    """修复建议"""
    description: str
    fix_type: str  # input_validation, sanitization, access_control, etc.
    code_before: str
    code_after: str
    file_path: str
    line_start: int
    line_end: int
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "fix_type": self.fix_type,
            "code_before": self.code_before,
            "code_after": self.code_after,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "confidence": self.confidence,
        }


@dataclass
class MultiStageResult:
    """多阶段验证完整结果"""
    finding_id: str
    stages_completed: List[VerificationStage]
    triage_result: Optional[TriageResult] = None
    deep_verify_result: Optional[DeepVerifyResult] = None
    patch_suggestion: Optional[PatchSuggestion] = None
    total_tokens_used: int = 0
    total_time_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "stages_completed": [s.value for s in self.stages_completed],
            "triage_result": self.triage_result.to_dict() if self.triage_result else None,
            "deep_verify_result": self.deep_verify_result.to_dict() if self.deep_verify_result else None,
            "patch_suggestion": self.patch_suggestion.to_dict() if self.patch_suggestion else None,
            "total_tokens_used": self.total_tokens_used,
            "total_time_seconds": self.total_time_seconds,
        }

    @property
    def final_decision(self) -> str:
        """获取最终决策"""
        if self.deep_verify_result:
            return self.deep_verify_result.status.value
        if self.triage_result:
            return self.triage_result.decision.value
        return "unknown"

    @property
    def is_confirmed_vuln(self) -> bool:
        """是否确认为漏洞"""
        if self.deep_verify_result:
            return self.deep_verify_result.is_vulnerability
        return False


@dataclass
class MultiStageConfig:
    """多阶段验证配置"""
    # Triage 阶段
    enable_triage: bool = True
    triage_model: str = "gpt-4o-mini"  # 便宜模型
    triage_max_tokens: int = 500
    triage_drop_threshold: float = 0.8  # 置信度高于此才 DROP

    # Deep Verify 阶段
    enable_deep_verify: bool = True
    deep_verify_model: str = "gpt-4o"  # 强模型
    deep_verify_max_tokens: int = 2000
    deep_verify_max_tool_calls: int = 5  # 最多工具调用次数

    # Patch Suggest 阶段
    enable_patch_suggest: bool = False  # 默认关闭
    patch_model: str = "gpt-4o"
    patch_max_tokens: int = 1500

    # 通用配置
    temperature: float = 0.1
    skip_triage_for_high_risk: bool = True  # 高风险直接深度验证


class MultiStageVerifier:
    """多阶段 LLM 验证器

    P2-1: 实现 Triage → Deep Verify → Patch Suggest 流水线

    设计原则：
    - Triage 使用便宜模型快速筛选，减少成本
    - Deep Verify 使用强模型 + 工具调用，提高准确率
    - 每个阶段输出结构化 JSON，便于验证和追踪
    """

    # Triage 阶段 prompt
    TRIAGE_SYSTEM_PROMPT = """你是一个代码安全审计专家，负责快速筛选潜在的安全漏洞。

你的任务是根据提供的候选点信息，快速判断这是否值得深入分析：
- DROP: 明显是误报（例如：sanitizer 已存在、非用户可控输入、纯测试代码等）
- KEEP: 可能是真漏洞，需要深入验证
- NEED_MORE_CONTEXT: 当前信息不足以判断，需要更多上下文

你必须输出 JSON 格式：
{
    "decision": "drop|keep|need_more_context",
    "reason": "简要说明判断依据",
    "confidence": 0.0-1.0,
    "context_requests": ["需要查看的函数/文件列表（仅当 decision=need_more_context 时）"]
}

注意：
- 快速决策，不需要详细分析
- 高风险 sink（如 eval/exec/system）应倾向 KEEP
- 有明显 sanitization 的应倾向 DROP
"""

    TRIAGE_USER_PROMPT_TEMPLATE = """请快速评估以下候选点：

## 规则信息
- 规则 ID: {rule_id}
- 类别: {category}
- 风险等级: {risk_level}

## 位置信息
- 文件: {file_path}
- 行号: {line_start}-{line_end}

## Sink 调用
```{language}
{sink_snippet}
```

## 所在函数
```{language}
{function_code}
```

## 调用者（1层）
{caller_info}

请给出你的 Triage 决策（JSON 格式）："""

    # Deep Verify 阶段 prompt
    DEEP_VERIFY_SYSTEM_PROMPT = """你是一个资深的代码安全审计专家，负责深度验证潜在的安全漏洞。

你需要仔细分析提供的完整证据包，包括：
- 调用链路径（从入口点到 sink）
- 每个节点的代码
- 参数传递关系
- 可能存在的 sanitization

你必须输出 JSON 格式：
{
    "is_vulnerability": true/false,
    "status": "confirmed|false_positive|uncertain|needs_review",
    "severity": "critical|high|medium|low|info",
    "confidence": 0.0-1.0,
    "summary": "漏洞/误报的简要总结",
    "attack_scenario": "如果是漏洞，描述高层次的攻击场景（不含具体 payload）",
    "evidence": [
        {"file_path": "...", "line_start": N, "code_snippet": "...", "role": "source|sink|propagate|sanitize"}
    ],
    "taint_path": ["入口参数名", "中间变量名", "...", "sink 参数名"],
    "conditions": ["利用条件1", "利用条件2"],
    "mitigations": ["现有缓解措施1（如果有）"]
}

关键判断标准：
1. 用户输入是否可控（source 可达）
2. 是否有有效的 sanitization
3. sink 参数是否直接受污点影响
4. 是否有认证/授权检查

如果无法确定，设置 status="uncertain" 并说明原因。
"""

    DEEP_VERIFY_USER_PROMPT_TEMPLATE = """请深度验证以下候选点：

## 漏洞类型
- 规则 ID: {rule_id}
- 类别: {category}
- CWE: {cwe}

## Sink 位置
- 文件: {file_path}
- 行号: {line_start}-{line_end}

## Sink 调用代码
```{language}
{sink_snippet}
```

## 完整调用链（入口点 → ... → Sink）
{call_chain_context}

## 污点分析信息
{taint_info}

## 额外上下文
{additional_context}

请进行深度验证并输出 JSON 结果："""

    # Patch Suggest 阶段 prompt
    PATCH_SUGGEST_SYSTEM_PROMPT = """你是一个安全修复专家，负责为已确认的漏洞提供修复建议。

你需要：
1. 分析漏洞的根本原因
2. 提供最小化的修复代码
3. 确保修复不会破坏业务逻辑

你必须输出 JSON 格式：
{
    "description": "修复方案描述",
    "fix_type": "input_validation|sanitization|access_control|config_change|other",
    "code_before": "原始代码片段",
    "code_after": "修复后的代码片段",
    "file_path": "需要修改的文件",
    "line_start": N,
    "line_end": N,
    "confidence": 0.0-1.0
}

修复原则：
- 最小化修改
- 不改变业务逻辑
- 使用该语言的最佳实践
- 优先使用内置安全函数
"""

    def __init__(
        self,
        llm_client: Any,
        config: Optional[MultiStageConfig] = None,
        tool_executor: Optional[Callable] = None,
    ):
        """
        Args:
            llm_client: LLM 客户端（需要支持 chat_completion）
            config: 验证配置
            tool_executor: 工具执行器（用于 Deep Verify 阶段的 tool calling）
        """
        self.llm_client = llm_client
        self.config = config or MultiStageConfig()
        self.tool_executor = tool_executor
        self._stats = {
            "triage_total": 0,
            "triage_drop": 0,
            "triage_keep": 0,
            "triage_need_context": 0,
            "deep_verify_total": 0,
            "deep_verify_confirmed": 0,
            "deep_verify_false_positive": 0,
        }

    def verify(
        self,
        finding: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> MultiStageResult:
        """执行多阶段验证

        Args:
            finding: 候选发现
            context: 额外上下文（调用链、污点信息等）

        Returns:
            MultiStageResult 完整验证结果
        """
        import time
        start_time = time.time()

        result = MultiStageResult(
            finding_id=finding.get("id", "unknown"),
            stages_completed=[],
        )

        context = context or {}

        # 判断是否跳过 Triage（高风险直接深度验证）
        skip_triage = self._should_skip_triage(finding)

        # Stage 1: Triage
        if self.config.enable_triage and not skip_triage:
            triage_result = self._run_triage(finding, context)
            result.triage_result = triage_result
            result.stages_completed.append(VerificationStage.TRIAGE)

            self._stats["triage_total"] += 1
            if triage_result.decision == TriageDecision.DROP:
                self._stats["triage_drop"] += 1
                result.total_time_seconds = time.time() - start_time
                return result  # 直接返回，不进入深度验证
            elif triage_result.decision == TriageDecision.NEED_MORE_CONTEXT:
                self._stats["triage_need_context"] += 1
                # 尝试获取更多上下文
                if triage_result.context_requests:
                    context = self._fetch_additional_context(
                        context, triage_result.context_requests
                    )
            else:
                self._stats["triage_keep"] += 1

        # Stage 2: Deep Verify
        if self.config.enable_deep_verify:
            deep_result = self._run_deep_verify(finding, context)
            result.deep_verify_result = deep_result
            result.stages_completed.append(VerificationStage.DEEP_VERIFY)

            self._stats["deep_verify_total"] += 1
            if deep_result.is_vulnerability:
                self._stats["deep_verify_confirmed"] += 1
            elif deep_result.status == VerifyStatus.FALSE_POSITIVE:
                self._stats["deep_verify_false_positive"] += 1

        # Stage 3: Patch Suggest (仅对确认漏洞)
        if (self.config.enable_patch_suggest and
            result.deep_verify_result and
            result.deep_verify_result.is_vulnerability):
            patch = self._run_patch_suggest(finding, context, result.deep_verify_result)
            result.patch_suggestion = patch
            result.stages_completed.append(VerificationStage.PATCH_SUGGEST)

        result.total_time_seconds = time.time() - start_time
        return result

    def verify_batch(
        self,
        findings: List[Dict[str, Any]],
        contexts: Optional[List[Dict[str, Any]]] = None,
    ) -> List[MultiStageResult]:
        """批量验证

        Args:
            findings: 候选发现列表
            contexts: 对应的上下文列表

        Returns:
            验证结果列表
        """
        contexts = contexts or [{}] * len(findings)
        results = []

        for finding, context in zip(findings, contexts):
            try:
                result = self.verify(finding, context)
                results.append(result)
            except Exception as e:
                logger.warning(f"Verification failed for {finding.get('id')}: {e}")
                results.append(MultiStageResult(
                    finding_id=finding.get("id", "unknown"),
                    stages_completed=[],
                ))

        return results

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return dict(self._stats)

    def _should_skip_triage(self, finding: Dict[str, Any]) -> bool:
        """判断是否应跳过 Triage 阶段"""
        if not self.config.skip_triage_for_high_risk:
            return False

        # 高风险类别直接深度验证
        high_risk_categories = {
            "command_injection", "code_injection", "sql_injection",
            "deserialization", "rce", "xxe", "ssrf",
        }

        category = finding.get("category", "").lower()
        if category in high_risk_categories:
            return True

        risk_level = finding.get("risk_level", "").lower()
        if risk_level in ("critical", "high"):
            return True

        return False

    def _run_triage(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> TriageResult:
        """执行 Triage 阶段"""
        # 构建 prompt
        caller_info = self._format_caller_info(context.get("callers", []))

        user_prompt = self.TRIAGE_USER_PROMPT_TEMPLATE.format(
            rule_id=finding.get("rule_id", "unknown"),
            category=finding.get("category", "unknown"),
            risk_level=finding.get("risk_level", "medium"),
            file_path=finding.get("file_path", "unknown"),
            line_start=finding.get("line_start", 0),
            line_end=finding.get("line_end", 0),
            language=finding.get("language", "python"),
            sink_snippet=finding.get("sink_snippet", finding.get("call_snippet", "")),
            function_code=finding.get("function_code", "")[:1000],  # 限制长度
            caller_info=caller_info,
        )

        # 调用 LLM
        try:
            response = self.llm_client.chat_completion(
                messages=[
                    {"role": "system", "content": self.TRIAGE_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                model=self.config.triage_model,
                max_tokens=self.config.triage_max_tokens,
                temperature=self.config.temperature,
                response_format={"type": "json_object"},
            )

            result = self._parse_triage_response(response)
            return result

        except Exception as e:
            logger.warning(f"Triage LLM call failed: {e}")
            # 失败时默认 KEEP
            return TriageResult(
                decision=TriageDecision.KEEP,
                reason=f"Triage failed: {e}",
                confidence=0.5,
            )

    def _run_deep_verify(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
    ) -> DeepVerifyResult:
        """执行深度验证阶段"""
        # 构建完整证据包
        call_chain_context = self._format_call_chain(context.get("call_chain", []))
        taint_info = self._format_taint_info(context.get("taint_paths", []))
        additional_context = self._format_additional_context(context)

        user_prompt = self.DEEP_VERIFY_USER_PROMPT_TEMPLATE.format(
            rule_id=finding.get("rule_id", "unknown"),
            category=finding.get("category", "unknown"),
            cwe=finding.get("cwe", []),
            file_path=finding.get("file_path", "unknown"),
            line_start=finding.get("line_start", 0),
            line_end=finding.get("line_end", 0),
            language=finding.get("language", "python"),
            sink_snippet=finding.get("sink_snippet", finding.get("call_snippet", "")),
            call_chain_context=call_chain_context,
            taint_info=taint_info,
            additional_context=additional_context,
        )

        tool_calls_made = 0

        # 支持多轮工具调用
        messages = [
            {"role": "system", "content": self.DEEP_VERIFY_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        for _ in range(self.config.deep_verify_max_tool_calls + 1):
            try:
                response = self.llm_client.chat_completion(
                    messages=messages,
                    model=self.config.deep_verify_model,
                    max_tokens=self.config.deep_verify_max_tokens,
                    temperature=self.config.temperature,
                    response_format={"type": "json_object"},
                    tools=self._get_verify_tools() if self.tool_executor else None,
                )

                # 检查是否有工具调用
                if hasattr(response, "tool_calls") and response.tool_calls:
                    # 执行工具调用
                    for tool_call in response.tool_calls:
                        if self.tool_executor and tool_calls_made < self.config.deep_verify_max_tool_calls:
                            tool_result = self.tool_executor(
                                tool_call.function.name,
                                json.loads(tool_call.function.arguments),
                            )
                            messages.append({
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [tool_call],
                            })
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": str(tool_result),
                            })
                            tool_calls_made += 1
                    continue

                # 解析最终结果
                result = self._parse_deep_verify_response(response)
                result.tool_calls_made = tool_calls_made
                return result

            except Exception as e:
                logger.warning(f"Deep verify LLM call failed: {e}")
                break

        # 失败时返回 UNCERTAIN
        return DeepVerifyResult(
            status=VerifyStatus.UNCERTAIN,
            is_vulnerability=False,
            severity="unknown",
            confidence=0.0,
            summary="Deep verification failed",
            attack_scenario="",
            tool_calls_made=tool_calls_made,
        )

    def _run_patch_suggest(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
        verify_result: DeepVerifyResult,
    ) -> Optional[PatchSuggestion]:
        """执行修复建议阶段"""
        user_prompt = f"""请为以下确认的漏洞提供修复建议：

## 漏洞信息
- 类型: {finding.get("category", "unknown")}
- 严重性: {verify_result.severity}
- 文件: {finding.get("file_path", "unknown")}
- 行号: {finding.get("line_start", 0)}-{finding.get("line_end", 0)}

## 漏洞代码
```{finding.get("language", "python")}
{finding.get("function_code", "")}
```

## 漏洞分析
{verify_result.summary}

## 攻击场景
{verify_result.attack_scenario}

请提供修复方案（JSON 格式）："""

        try:
            response = self.llm_client.chat_completion(
                messages=[
                    {"role": "system", "content": self.PATCH_SUGGEST_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                model=self.config.patch_model,
                max_tokens=self.config.patch_max_tokens,
                temperature=self.config.temperature,
                response_format={"type": "json_object"},
            )

            return self._parse_patch_response(response, finding)

        except Exception as e:
            logger.warning(f"Patch suggest failed: {e}")
            return None

    def _fetch_additional_context(
        self,
        context: Dict[str, Any],
        requests: List[str],
    ) -> Dict[str, Any]:
        """获取额外上下文"""
        if not self.tool_executor:
            return context

        additional = {}
        for request in requests[:3]:  # 限制最多 3 个请求
            try:
                # 尝试解析请求类型
                if "函数" in request or "function" in request.lower():
                    result = self.tool_executor("get_function", {"name": request})
                    additional[f"function_{request}"] = result
                elif "文件" in request or "file" in request.lower():
                    result = self.tool_executor("read_file", {"path": request})
                    additional[f"file_{request}"] = result
            except Exception as e:
                logger.debug(f"Failed to fetch context for {request}: {e}")

        context["additional"] = additional
        return context

    def _format_caller_info(self, callers: List[Dict[str, Any]]) -> str:
        """格式化调用者信息"""
        if not callers:
            return "（无调用者信息）"

        parts = []
        for i, caller in enumerate(callers[:3]):  # 最多 3 个
            parts.append(f"""
### 调用者 {i + 1}: {caller.get("symbol", "unknown")}
- 文件: {caller.get("file_path", "unknown")}:{caller.get("line_start", 0)}
```
{caller.get("code", "")[:500]}
```
""")
        return "\n".join(parts)

    def _format_call_chain(self, chain: List[Dict[str, Any]]) -> str:
        """格式化调用链"""
        if not chain:
            return "（无调用链信息）"

        parts = ["调用链路径："]
        for i, node in enumerate(chain):
            arrow = "→" if i < len(chain) - 1 else ""
            parts.append(f"{node.get('symbol', 'unknown')} {arrow}")

        parts.append("\n\n详细代码：")
        for i, node in enumerate(chain):
            parts.append(f"""
### 节点 {i + 1}: {node.get("symbol", "unknown")}
- 文件: {node.get("file_path", "unknown")}:{node.get("line_start", 0)}
- 类型: {node.get("node_type", "unknown")}
```
{node.get("code", "")[:800]}
```
""")

        return "\n".join(parts)

    def _format_taint_info(self, taint_paths: List[Dict[str, Any]]) -> str:
        """格式化污点信息"""
        if not taint_paths:
            return "（无污点分析信息）"

        parts = []
        for i, path in enumerate(taint_paths[:2]):  # 最多 2 条路径
            parts.append(f"""
### 污点路径 {i + 1}
- Source: {path.get("source", "unknown")} @ {path.get("source_location", "")}
- Sink: {path.get("sink", "unknown")} @ {path.get("sink_location", "")}
- 传播路径: {" → ".join(path.get("variables", []))}
- Sanitizers: {", ".join(path.get("sanitizers", [])) or "无"}
""")
        return "\n".join(parts)

    def _format_additional_context(self, context: Dict[str, Any]) -> str:
        """格式化额外上下文"""
        parts = []

        # 入口点信息
        entry_points = context.get("entry_points", [])
        if entry_points:
            parts.append("### 入口点")
            for ep in entry_points[:2]:
                parts.append(f"- {ep.get('type', 'unknown')}: {ep.get('path', 'unknown')}")

        # Sanitizer 信息
        sanitizers = context.get("sanitizers", [])
        if sanitizers:
            parts.append("\n### 可能的 Sanitizer")
            for s in sanitizers[:3]:
                parts.append(f"- {s.get('name', 'unknown')} @ {s.get('location', '')}")

        # 认证检查
        auth_checks = context.get("auth_checks", [])
        if auth_checks:
            parts.append("\n### 认证/授权检查")
            for check in auth_checks[:2]:
                parts.append(f"- {check.get('type', 'unknown')} @ {check.get('location', '')}")

        return "\n".join(parts) if parts else "（无额外上下文）"

    def _get_verify_tools(self) -> List[Dict[str, Any]]:
        """获取深度验证阶段可用的工具定义"""
        return [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "读取指定文件的内容",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "文件路径"},
                            "start_line": {"type": "integer", "description": "起始行（可选）"},
                            "end_line": {"type": "integer", "description": "结束行（可选）"},
                        },
                        "required": ["path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_function",
                    "description": "获取指定函数的完整代码",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "函数名"},
                            "file": {"type": "string", "description": "文件路径（可选）"},
                        },
                        "required": ["name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_callers",
                    "description": "获取调用指定函数的位置",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "function_name": {"type": "string", "description": "函数名"},
                        },
                        "required": ["function_name"],
                    },
                },
            },
        ]

    def _parse_triage_response(self, response: Any) -> TriageResult:
        """解析 Triage 阶段响应"""
        try:
            content = response.choices[0].message.content
            data = json.loads(content)

            decision_str = data.get("decision", "keep").lower()
            decision_map = {
                "drop": TriageDecision.DROP,
                "keep": TriageDecision.KEEP,
                "need_more_context": TriageDecision.NEED_MORE_CONTEXT,
            }

            return TriageResult(
                decision=decision_map.get(decision_str, TriageDecision.KEEP),
                reason=data.get("reason", ""),
                confidence=float(data.get("confidence", 0.5)),
                context_requests=data.get("context_requests", []),
            )
        except Exception as e:
            logger.warning(f"Failed to parse triage response: {e}")
            return TriageResult(
                decision=TriageDecision.KEEP,
                reason=f"Parse error: {e}",
                confidence=0.5,
            )

    def _parse_deep_verify_response(self, response: Any) -> DeepVerifyResult:
        """解析深度验证响应"""
        try:
            content = response.choices[0].message.content
            data = json.loads(content)

            status_str = data.get("status", "uncertain").lower()
            status_map = {
                "confirmed": VerifyStatus.CONFIRMED,
                "false_positive": VerifyStatus.FALSE_POSITIVE,
                "uncertain": VerifyStatus.UNCERTAIN,
                "needs_review": VerifyStatus.NEEDS_REVIEW,
            }

            return DeepVerifyResult(
                status=status_map.get(status_str, VerifyStatus.UNCERTAIN),
                is_vulnerability=data.get("is_vulnerability", False),
                severity=data.get("severity", "unknown"),
                confidence=float(data.get("confidence", 0.0)),
                summary=data.get("summary", ""),
                attack_scenario=data.get("attack_scenario", ""),
                evidence=data.get("evidence", []),
                taint_path=data.get("taint_path", []),
                conditions=data.get("conditions", []),
                mitigations=data.get("mitigations", []),
            )
        except Exception as e:
            logger.warning(f"Failed to parse deep verify response: {e}")
            return DeepVerifyResult(
                status=VerifyStatus.UNCERTAIN,
                is_vulnerability=False,
                severity="unknown",
                confidence=0.0,
                summary=f"Parse error: {e}",
                attack_scenario="",
            )

    def _parse_patch_response(
        self,
        response: Any,
        finding: Dict[str, Any],
    ) -> Optional[PatchSuggestion]:
        """解析修复建议响应"""
        try:
            content = response.choices[0].message.content
            data = json.loads(content)

            return PatchSuggestion(
                description=data.get("description", ""),
                fix_type=data.get("fix_type", "other"),
                code_before=data.get("code_before", ""),
                code_after=data.get("code_after", ""),
                file_path=data.get("file_path", finding.get("file_path", "")),
                line_start=data.get("line_start", finding.get("line_start", 0)),
                line_end=data.get("line_end", finding.get("line_end", 0)),
                confidence=float(data.get("confidence", 0.5)),
            )
        except Exception as e:
            logger.warning(f"Failed to parse patch response: {e}")
            return None
