"""
UnifiedAuditAgent 工具执行回归测试

覆盖日志中出现的两类真实故障：
1) read_file: name 'os' is not defined
2) analyze_sink_call_chain: SinkCallSite 缺少 sink_name 字段导致崩溃
"""

import asyncio

from agent.unified_agent import UnifiedAuditAgent, UnifiedAgentConfig
from analyzer.enhancer import EnhancementResult, EnhancedSite
from analyzer.prescan import PreScanResult, PreScanStatus
from analyzer.sink_scanner import SinkCallSite, SinkCategory
from llm_client import ChatResponse, ToolCall
from rules.models import RiskLevel


class _DummyLLMClient:
    """占位 LLM 客户端（测试不触发真实调用）。"""


class _SeqLLMClient:
    """按顺序返回预设响应。"""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0
        self.call_kwargs = []

    def chat_completion(self, **kwargs):
        self.call_kwargs.append(kwargs)
        idx = self.calls if self.calls < len(self._responses) else len(self._responses) - 1
        self.calls += 1
        return self._responses[idx]


class _NoCallLLMClient:
    """不允许被调用的 LLM 客户端（用于验证路由是否短路）。"""

    def __init__(self):
        self.calls = 0

    def chat_completion(self, **kwargs):
        self.calls += 1
        raise AssertionError("该用例不应触发 LLM 调用")


class _DummyIndexer:
    """最小索引器桩对象。"""

    def read_file(self, file_path: str, start_line=None, end_line=None):
        return f"file={file_path};start={start_line};end={end_line}"


class _DummyNodeType:
    def __init__(self, value: str):
        self.value = value


class _DummyNode:
    def __init__(self, node_id: str, name: str, file_path: str, line_start: int = 1):
        self.id = node_id
        self.name = name
        self.qualified_name = name
        self.file_path = file_path
        self.line_start = line_start
        self.node_type = _DummyNodeType("normal")


class _DummyCallGraph:
    def __init__(self, nodes):
        self._nodes = {n.id: n for n in nodes}
        self._by_name = {}
        for n in nodes:
            self._by_name.setdefault(n.name, []).append(n)

    def get_nodes_by_name(self, name):
        return self._by_name.get(name, [])

    def get_node(self, node_id):
        return self._nodes.get(node_id)

    def get_callees(self, node_id):
        return []


class _DummyCallChainAnalyzer:
    def __init__(self, graph):
        self.call_graph = graph


async def _collect_stream_events(async_gen):
    events = []
    async for event in async_gen:
        events.append(event)
    return events


def _build_site() -> SinkCallSite:
    return SinkCallSite(
        id="sink-0001",
        unit_id="unit-1",
        file_path="source/high.php",
        line_start=10,
        line_end=10,
        symbol="<script:high.php>",
        matched_rule_ids=["php-command-exec"],
        call_snippet="shell_exec($cmd);",
        sink_category=SinkCategory.COMMAND_EXEC,
        risk_level=RiskLevel.HIGH,
        matched_patterns=["shell_exec"],
    )


def test_read_file_tool_does_not_crash_on_os_reference():
    """回归：_execute_read_file 不应因缺少 os 导致 NameError。"""
    agent = UnifiedAuditAgent(
        session_id="test-read-file",
        llm_client=_DummyLLMClient(),
        indexer=_DummyIndexer(),
        config=UnifiedAgentConfig(),
    )

    result = agent._execute_read_file({"file_path": "source/high.php"})

    assert result["success"] is True
    assert "source/high.php" in result["content"]


def test_analyze_sink_call_chain_uses_symbol_when_sink_name_missing():
    """回归：SinkCallSite 无 sink_name 字段时，回调应使用 symbol 作为 sink_name。"""
    progress_events = []

    def _on_progress(data):
        progress_events.append(data)

    agent = UnifiedAuditAgent(
        session_id="test-analyze-chain",
        llm_client=_DummyLLMClient(),
        indexer=_DummyIndexer(),
        config=UnifiedAgentConfig(on_analysis_progress=_on_progress),
    )

    site = _build_site()
    agent.prescan_result = PreScanResult(
        project_path="dummy",
        language="php",
        status=PreScanStatus.COMPLETED,
        sink_sites=[site],
        filtered_sites=[site],
    )
    agent.enhancement_result = EnhancementResult(
        enhanced_sites=[EnhancedSite(site=site)],
        call_graph_stats={},
        taint_flow_count=0,
        high_confidence_count=0,
        processing_time_ms=0,
    )

    result = agent._execute_analyze_sink_call_chain({"site_id": site.id})

    assert result["success"] is True
    assert progress_events, "应触发 on_analysis_progress 回调"
    assert progress_events[0]["current_site"]["sink_name"] == site.symbol


def test_tool_failure_result_contains_error_payload():
    """回归：工具失败时，event.result 不应是空字典，应包含错误信息。"""
    agent = UnifiedAuditAgent(
        session_id="test-tool-failure-payload",
        llm_client=_DummyLLMClient(),
        indexer=_DummyIndexer(),
        config=UnifiedAgentConfig(),
    )
    agent._register_code_navigation_tools()

    events = asyncio.run(
        agent._execute_tool_calls([
            ToolCall(id="tc-1", name="read_file", arguments={}),
        ])
    )

    assert len(events) == 1
    assert events[0].status.value == "failed"
    assert isinstance(events[0].result, dict)
    assert events[0].result.get("success") is False
    assert "error" in events[0].result


def test_analyze_entry_to_sink_accepts_alias_arguments():
    """回归：兼容 entry_name/sink_name 参数，避免参数名漂移导致工具不可用。"""
    site = _build_site()
    graph = _DummyCallGraph([
        _DummyNode("n1", "<script:high.php>", "source/high.php", 1),
    ])

    agent = UnifiedAuditAgent(
        session_id="test-entry-sink-alias",
        llm_client=_DummyLLMClient(),
        indexer=_DummyIndexer(),
        call_chain_analyzer=_DummyCallChainAnalyzer(graph),
        config=UnifiedAgentConfig(),
    )
    agent.prescan_result = PreScanResult(
        project_path="dummy",
        language="php",
        status=PreScanStatus.COMPLETED,
        sink_sites=[site],
        filtered_sites=[site],
    )

    result = agent._execute_analyze_entry_to_sink({
        "entry_name": "high.php",
        "sink_name": "shell_exec",
    })

    assert result["success"] is True
    assert result["connected"] is True


def test_chat_retries_when_final_response_is_dsml_markup():
    """回归：最终响应若是 DSML function_calls 文本，应自动重试并返回纯文本。"""
    dsml_text = (
        "<｜DSML｜function_calls>\n"
        "<｜DSML｜invoke name=\"get_site_details\">\n"
        "<｜DSML｜parameter name=\"site_id\" string=\"true\">sink-1</｜DSML｜parameter>\n"
        "</｜DSML｜invoke>\n"
        "</｜DSML｜function_calls>"
    )
    llm = _SeqLLMClient([
        ChatResponse(
            content="",
            model="mock",
            usage={"total_tokens": 1},
            finish_reason="tool_calls",
            tool_calls=[ToolCall(id="tc-1", name="unknown_tool", arguments={})],
        ),
        ChatResponse(
            content=dsml_text,
            model="mock",
            usage={"total_tokens": 1},
            finish_reason="stop",
            tool_calls=None,
        ),
        ChatResponse(
            content="最终结论：存在命令注入风险，需严格白名单校验。",
            model="mock",
            usage={"total_tokens": 1},
            finish_reason="stop",
            tool_calls=None,
        ),
    ])

    agent = UnifiedAuditAgent(
        session_id="test-dsml-final",
        llm_client=llm,
        indexer=_DummyIndexer(),
        config=UnifiedAgentConfig(max_tool_rounds=1, max_tool_calls_per_turn=1),
    )
    # 本用例只覆盖最终响应收敛，不依赖初始化阶段。
    agent._initialized = True

    result = asyncio.run(agent.chat("分析项目安全风险"))

    assert "DSML" not in result.content
    assert "最终结论" in result.content
    assert result.metadata["tool_calls_count"] == 1
    assert llm.calls == 3


def test_chat_small_talk_bypasses_llm_and_tools():
    """回归：纯问候语不应触发 LLM/工具调用。"""
    llm = _NoCallLLMClient()
    agent = UnifiedAuditAgent(
        session_id="test-small-talk",
        llm_client=llm,
        indexer=_DummyIndexer(),
        config=UnifiedAgentConfig(),
    )

    result = asyncio.run(agent.chat("你好"))

    assert llm.calls == 0
    assert result.metadata["interaction_mode"] == "small_talk"
    assert result.metadata["tool_calls_count"] == 0
    assert "你好" in result.content


def test_chat_general_dialog_uses_llm_without_tools():
    """回归：普通对话走 chat_only 模式，允许 LLM 但不携带 tools。"""
    llm = _SeqLLMClient([
        ChatResponse(
            content="我可以先和你确认范围，再开始代码审计。",
            model="mock",
            usage={"total_tokens": 1},
            finish_reason="stop",
            tool_calls=None,
        ),
    ])
    agent = UnifiedAuditAgent(
        session_id="test-chat-only",
        llm_client=llm,
        indexer=_DummyIndexer(),
        config=UnifiedAgentConfig(),
    )

    result = asyncio.run(agent.chat("你能做什么？"))

    assert llm.calls == 1
    assert llm.call_kwargs[0].get("tools") is None
    assert result.metadata["interaction_mode"] == "chat_only"
    assert result.metadata["tool_calls_count"] == 0


def test_chat_audit_request_keeps_tool_mode():
    """回归：明确审计请求仍应进入审计模式，并携带工具定义。"""
    llm = _SeqLLMClient([
        ChatResponse(
            content="收到，我先读取目标文件。",
            model="mock",
            usage={"total_tokens": 1},
            finish_reason="stop",
            tool_calls=None,
        ),
    ])
    agent = UnifiedAuditAgent(
        session_id="test-audit-mode",
        llm_client=llm,
        indexer=_DummyIndexer(),
        config=UnifiedAgentConfig(max_tool_rounds=1),
    )
    agent._initialized = True
    agent._register_code_navigation_tools()

    result = asyncio.run(agent.chat("请分析 source/high.php 的命令注入风险"))

    assert llm.calls == 1
    assert llm.call_kwargs[0].get("tools") is not None
    assert result.metadata["interaction_mode"] == "audit"


def test_chat_stream_small_talk_bypasses_llm_and_tools():
    """回归：流式对话的问候语同样不应触发 LLM/工具调用。"""
    llm = _NoCallLLMClient()
    agent = UnifiedAuditAgent(
        session_id="test-stream-small-talk",
        llm_client=llm,
        indexer=_DummyIndexer(),
        config=UnifiedAgentConfig(stream_chunk_size=8),
    )

    events = asyncio.run(_collect_stream_events(agent.chat_stream("你好")))

    assert llm.calls == 0
    assert events[0]["type"] == "start"
    assert events[-1]["type"] == "message"
    assert events[-1]["data"]["metadata"]["interaction_mode"] == "small_talk"
