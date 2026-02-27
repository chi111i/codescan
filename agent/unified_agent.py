"""
统一审计智能体 - 整合所有代码分析工具

核心特性：
1. 支持 LLM Function Calling 自主调用工具
2. 整合代码导航、调用链分析、变体分析等所有功能
3. 提供统一的对话式审计接口
4. 支持流式响应和工具执行可视化
"""

import asyncio
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable, Union

from llm_client import BaseLLMClient, ChatMessage, ToolCall
from indexer import CodeUnit, CodeIndexer
from serialization import safe_json_dumps

from .tools.manager import AgentToolManager, ToolResult
from .tools.registry import CODE_NAVIGATION_TOOLS, SECURITY_ANALYSIS_TOOLS
from .tools.callchain_tools import (
    get_callchain_tool_definitions,
    create_callchain_executor,
)
from .tools.variant_tools import (
    get_variant_tool_definitions,
    create_variant_executor,
)

# 预扫描和深度增强相关导入
from analyzer.prescan import RuleScanPreprocessor, PreScanConfig, PreScanResult
from analyzer.enhancer import DeepAnalysisEnhancer, EnhancementConfig, EnhancementResult

logger = logging.getLogger(__name__)


def _json_serializer(obj):
    """自定义 JSON 序列化器，处理 datetime 和其他不可序列化类型"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, 'to_dict'):
        return obj.to_dict()
    if hasattr(obj, '__dict__'):
        return obj.__dict__
    return str(obj)


class ToolCallStatus(Enum):
    """工具调用状态"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


@dataclass
class ToolCallEvent:
    """工具调用事件（用于 UI 展示）"""
    id: str
    tool_name: str
    arguments: Dict[str, Any]
    status: ToolCallStatus
    result: Optional[Any] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_ms": self.duration_ms,
        }


@dataclass
class AgentMessage:
    """智能体消息"""
    role: str  # "user", "assistant", "tool"
    content: str
    tool_calls: List[ToolCallEvent] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "tool_calls": [tc.to_dict() for tc in self.tool_calls],
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class UnifiedAgentConfig:
    """统一智能体配置"""
    # LLM 配置
    max_tool_rounds: int = 10  # 工具调用最大循环轮数
    max_tool_calls_per_turn: int = 10  # 单轮内最大工具调用次数
    max_conversation_turns: int = 50  # 最大对话轮数
    temperature: float = 0.1
    max_tokens: int = 4000

    # 工具配置
    enable_code_navigation: bool = True
    enable_call_chain: bool = True
    enable_variant_analysis: bool = True
    enable_security_tools: bool = True

    # 上下文配置
    max_context_tokens: int = 100000  # 最大上下文 token 数
    context_window_messages: int = 20  # 保留的最近消息数

    # 性能优化配置
    enable_parallel_tool_execution: bool = True  # 并行执行工具
    enable_streaming: bool = True  # 启用流式响应
    stream_chunk_size: int = 10  # 流式响应缓冲字符数

    # === 预扫描增强配置 ===
    enable_prescan: bool = True  # 启用规则预扫描
    prescan_risk_levels: List[str] = field(default_factory=lambda: ["high", "critical"])
    enable_deep_enhancement: bool = True  # 启用深度增强分析
    prescan_context_injection: bool = True  # 主动注入预扫描上下文
    max_prescan_sites_in_prompt: int = 20  # 系统提示中最多包含的触发点数

    # === 调试日志配置 ===
    enable_debug_logging: bool = False  # 启用详细调试日志
    log_full_request: bool = False  # 记录完整 LLM 请求（用于调试）
    log_full_response: bool = False  # 记录完整 LLM 响应（用于调试）
    save_requests_to_file: bool = False  # 将请求/响应保存到文件
    debug_log_dir: str = ".audit_data/debug_logs"  # 调试日志目录

    # === 对话历史压缩配置 ===
    enable_history_compression: bool = True  # 启用历史压缩
    history_compression_threshold: int = 10000  # 压缩阈值（字符数）
    history_compression_method: str = "summarize"  # 压缩方式: summarize | truncate
    history_preserve_recent: int = 4  # 始终保留最近 N 条消息
    history_summary_max_tokens: int = 500  # 摘要最大 token 数
    history_summary_temperature: float = 0.3  # 摘要生成温度

    # 回调（支持同步和异步）
    on_tool_call: Optional[Callable[[ToolCallEvent], None]] = None
    on_tool_call_async: Optional[Callable[[ToolCallEvent], Any]] = None  # 异步回调
    on_stream: Optional[Callable[[str], None]] = None
    on_stream_async: Optional[Callable[[str], Any]] = None  # 异步流式回调
    on_prescan_complete: Optional[Callable[[PreScanResult], None]] = None  # 预扫描完成回调
    on_enhancement_complete: Optional[Callable[[EnhancementResult], None]] = None  # 深度增强完成回调

    # === LLM 调用过程回调（用于实时展示） ===
    on_llm_call_start: Optional[Callable[[Dict[str, Any]], Any]] = None  # LLM调用开始: {call_id, messages_count, tools_count}
    on_llm_call_end: Optional[Callable[[Dict[str, Any]], Any]] = None  # LLM调用结束: {call_id, content, tool_calls, usage}
    on_llm_thinking: Optional[Callable[[str], Any]] = None  # LLM思考过程（流式内容）

    # === 漏洞发现回调 ===
    on_finding_reported: Optional[Callable[[Dict[str, Any]], Any]] = None  # 漏洞报告: Finding 数据

    # === 分析进度回调 ===
    on_analysis_progress: Optional[Callable[[Dict[str, Any]], Any]] = None  # 进度: {current, total, current_site}


class UnifiedAuditAgent:
    """统一审计智能体

    整合所有代码分析工具，提供统一的对话式审计接口。
    支持 LLM Function Calling 自主选择和调用工具。

    核心能力：
    1. 代码导航：搜索、读取、浏览代码
    2. 调用链分析：追踪调用关系、污点传播
    3. 变体分析：相似代码检测、模式匹配
    4. 安全分析：漏洞检测、规则匹配

    Usage:
        agent = UnifiedAuditAgent(
            session_id="xxx",
            llm_client=llm_client,
            indexer=indexer,
            config=UnifiedAgentConfig(),
        )

        # 初始化工具
        await agent.initialize()

        # 对话交互
        response = await agent.chat("分析这个项目的认证逻辑")

        # 处理流式响应和工具调用事件
    """

    def __init__(
        self,
        session_id: str,
        llm_client: BaseLLMClient,
        indexer: CodeIndexer,
        config: Optional[UnifiedAgentConfig] = None,
        # 可选的分析器实例
        call_chain_analyzer=None,
        variant_analyzer=None,
        vector_store=None,
        rule_manager=None,  # 规则管理器（可选，用于预扫描）
    ):
        """初始化统一审计智能体

        Args:
            session_id: 会话 ID
            llm_client: LLM 客户端
            indexer: 代码索引器
            config: 配置
            call_chain_analyzer: 调用链分析器（可选）
            variant_analyzer: 变体分析器（可选）
            vector_store: 向量存储（可选）
            rule_manager: 规则管理器（可选，用于预扫描）
        """
        self.session_id = session_id
        self.llm_client = llm_client
        self.indexer = indexer
        self.config = config or UnifiedAgentConfig()

        # 分析器
        self.call_chain_analyzer = call_chain_analyzer
        self.variant_analyzer = variant_analyzer
        self.vector_store = vector_store
        self.rule_manager = rule_manager  # 存储规则管理器引用

        # 工具管理器
        self.tool_manager = AgentToolManager()

        # 对话历史
        self.messages: List[AgentMessage] = []
        self.conversation_history: List[ChatMessage] = []

        # 工具调用历史
        self.tool_call_history: List[ToolCallEvent] = []

        # 状态
        self._initialized = False
        self._is_processing = False

        # 统计
        self.total_llm_calls = 0
        self.total_tool_calls = 0
        self.total_tokens_used = 0

        # === 预扫描和深度增强状态 ===
        self.prescan_result: Optional[PreScanResult] = None
        self.enhancement_result: Optional[EnhancementResult] = None
        self._prescan_context: str = ""  # 缓存的预扫描上下文

        # === 对话历史压缩状态 ===
        self._compressed_history_summary: str = ""  # 压缩后的历史摘要

        # === 主事件循环引用（用于跨线程回调调度） ===
        self._main_loop: Optional[asyncio.AbstractEventLoop] = None

        # === 代码单元 TTL 缓存 ===
        self._code_units_cache: Dict[str, CodeUnit] = {}
        self._code_units_cache_time: float = 0.0
        self._code_units_cache_ttl: float = 60.0  # 60 秒 TTL

        logger.info(f"[UnifiedAgent] 创建会话: {session_id}")

    async def initialize(self):
        """初始化智能体

        注册所有工具并设置执行器。
        """
        if self._initialized:
            return

        # 保存主事件循环引用（用于跨线程回调调度）
        try:
            self._main_loop = asyncio.get_running_loop()
        except RuntimeError:
            self._main_loop = None
            logger.warning("[UnifiedAgent] 无法获取运行中的事件循环")

        logger.info("[UnifiedAgent] 开始初始化...")

        # 获取代码单元 - 使用正确的方法从 indexer 获取
        try:
            all_units = self.indexer.get_all_units()
            code_units = all_units if all_units else []
        except Exception as e:
            logger.warning(f"[UnifiedAgent] 获取代码单元失败: {e}, 使用空列表")
            code_units = []

        # 缓存代码单元用于后续查询
        import time as _time
        self._code_units_cache = {u.id: u for u in code_units}
        self._code_units_cache_time = _time.time()

        # 注册代码导航工具
        if self.config.enable_code_navigation:
            self._register_code_navigation_tools()

        # 注册调用链分析工具
        if self.config.enable_call_chain and self.call_chain_analyzer:
            self._register_call_chain_tools(code_units)

        # 注册变体分析工具
        if self.config.enable_variant_analysis:
            self._register_variant_tools(code_units)

        # 注册安全分析工具
        if self.config.enable_security_tools:
            self._register_security_tools()

        # === 执行预扫描和深度增强 ===
        if self.config.enable_prescan and code_units:
            await self._run_prescan(code_units)

        self._initialized = True

        logger.info(
            f"[UnifiedAgent] 初始化完成，注册了 {self.tool_manager.count()} 个工具"
        )

    def _schedule_async_callback(self, callback: Callable, *args) -> bool:
        """在主事件循环中安全调度异步回调

        用于从线程池中的同步执行器调用异步回调函数。

        Args:
            callback: 异步回调函数
            *args: 回调参数

        Returns:
            bool: 是否成功调度
        """
        if not callback:
            return False

        try:
            result = callback(*args)
            if asyncio.iscoroutine(result):
                if self._main_loop and self._main_loop.is_running():
                    # 使用 call_soon_threadsafe 调度到主事件循环
                    future = asyncio.run_coroutine_threadsafe(result, self._main_loop)
                    # 等待结果（带超时）
                    try:
                        future.result(timeout=5.0)
                        return True
                    except Exception as e:
                        logger.warning(f"[UnifiedAgent] 异步回调执行失败: {e}")
                        return False
                else:
                    # 没有运行中的事件循环，尝试创建新的
                    try:
                        asyncio.run(result)
                        return True
                    except RuntimeError as e:
                        logger.warning(f"[UnifiedAgent] 无法执行异步回调: {e}")
                        return False
            else:
                # 同步回调，直接返回
                return True
        except Exception as e:
            logger.warning(f"[UnifiedAgent] 回调调度失败: {e}")
            return False

    async def _run_prescan(self, code_units: List[CodeUnit]):
        """执行规则预扫描和深度增强分析

        Args:
            code_units: 代码单元列表
        """
        logger.info("[UnifiedAgent] 开始执行规则预扫描...")

        try:
            # 使用传入的 rule_manager，如果没有则跳过预扫描
            if self.rule_manager is None:
                logger.warning("[UnifiedAgent] 未提供 rule_manager，跳过预扫描")
                self._prescan_context = ""
                return

            # 1. 规则预扫描
            prescan_config = PreScanConfig(
                enabled_risk_levels=self.config.prescan_risk_levels,
            )
            preprocessor = RuleScanPreprocessor(self.rule_manager, prescan_config)

            # 获取项目路径
            project_path = self.indexer.project_path if hasattr(self.indexer, 'project_path') else ""

            # 使用线程池执行同步扫描操作，避免阻塞事件循环
            self.prescan_result = await asyncio.to_thread(
                preprocessor.scan,
                code_units=code_units,
                project_path=project_path,
                language=None,  # 自动检测
            )

            logger.info(
                f"[UnifiedAgent] 预扫描完成: "
                f"发现 {len(self.prescan_result.sink_sites)} 个触发点, "
                f"过滤后 {len(self.prescan_result.filtered_sites)} 个"
            )

            # 回调通知
            if self.config.on_prescan_complete:
                self.config.on_prescan_complete(self.prescan_result)

            # 2. 深度增强分析（可选）
            if self.config.enable_deep_enhancement and self.prescan_result.filtered_sites:
                enhance_config = EnhancementConfig(
                    enable_call_chain=self.config.enable_call_chain,
                    enable_taint_analysis=True,
                )
                enhancer = DeepAnalysisEnhancer(self.rule_manager, enhance_config)

                # 使用线程池执行同步增强操作
                self.enhancement_result = await asyncio.to_thread(
                    enhancer.enhance,
                    prescan_result=self.prescan_result,
                    code_units=code_units,
                )

                logger.info(
                    f"[UnifiedAgent] 深度增强完成: "
                    f"高置信度触发点 {self.enhancement_result.high_confidence_count} 个"
                )

                # 生成增强上下文
                self._prescan_context = enhancer.get_context_for_agent(
                    self.enhancement_result,
                    max_sites=self.config.max_prescan_sites_in_prompt,
                )

                # 回调通知
                if self.config.on_enhancement_complete:
                    self.config.on_enhancement_complete(self.enhancement_result)
            else:
                # 仅使用预扫描结果生成上下文
                self._prescan_context = preprocessor.get_context_for_agent(
                    self.prescan_result,
                    max_sites=self.config.max_prescan_sites_in_prompt,
                )

        except Exception as e:
            logger.error(f"[UnifiedAgent] 预扫描失败: {e}")
            self._prescan_context = ""

    def _get_code_units(self) -> Dict[str, 'CodeUnit']:
        """获取代码单元（带 TTL 缓存）

        避免每次工具调用都触发 vector_store.get_all() 重查询。
        缓存 60 秒，超时自动刷新。

        Returns:
            符号 ID 到 CodeUnit 的映射字典
        """
        import time as _time
        now = _time.time()

        # 检查缓存是否有效
        if (self._code_units_cache
                and (now - self._code_units_cache_time) < self._code_units_cache_ttl):
            return self._code_units_cache

        # 刷新缓存
        try:
            all_units = self.indexer.get_all_units() or []
            self._code_units_cache = {u.id: u for u in all_units}
            self._code_units_cache_time = now
            logger.debug(f"[UnifiedAgent] 代码单元缓存已刷新: {len(self._code_units_cache)} 个单元")
        except Exception as e:
            logger.warning(f"[UnifiedAgent] 刷新代码单元缓存失败: {e}")
            # 缓存失效但查询失败时，返回旧缓存（如有）
            if not self._code_units_cache:
                self._code_units_cache = {}

        return self._code_units_cache

    def _invalidate_code_units_cache(self):
        """手动失效代码单元缓存（在索引更新后调用）"""
        self._code_units_cache_time = 0.0
        logger.debug("[UnifiedAgent] 代码单元缓存已失效")

    def _match_symbol(self, query: str, target: str) -> int:
        """分级符号匹配

        匹配优先级（返回值越高越精确）：
        - 3: 完全相等
        - 2: 点分隔后缀匹配（如 "get_user" 匹配 "UserService.get_user"）
        - 1: 包含匹配（如 "get_user" 包含在 "my_get_user_info" 中）
        - 0: 不匹配

        Args:
            query: 查询的符号名
            target: 目标符号名

        Returns:
            匹配等级 (0-3)
        """
        if target == query:
            return 3  # 精确匹配
        if target.endswith(f".{query}") or target.split(".")[-1] == query:
            return 2  # 后缀匹配
        if query in target:
            return 1  # 包含匹配
        return 0  # 不匹配

    def _register_code_navigation_tools(self):
        """注册代码导航工具"""
        # search_code
        self.tool_manager.register_tool(
            name="search_code",
            description="通过语义搜索查找相关代码。适用于：查找与某个概念、功能或漏洞模式相关的代码片段。",
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "搜索查询，描述要查找的代码功能或模式"
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "返回结果数量，默认 5",
                        "default": 5
                    },
                    "language": {
                        "type": "string",
                        "description": "限定编程语言"
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "文件路径模式"
                    }
                },
                "required": ["query"]
            },
            executor=self._execute_search_code,
            category="code_navigation",
        )

        # read_file
        self.tool_manager.register_tool(
            name="read_file",
            description="读取指定文件的内容。可以读取整个文件或指定行范围。",
            parameters={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "文件路径（相对于项目根目录）"
                    },
                    "path": {
                        "type": "string",
                        "description": "file_path 的别名（兼容旧调用）"
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "起始行号（从 1 开始）"
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "结束行号"
                    }
                }
            },
            executor=self._execute_read_file,
            category="code_navigation",
        )

        # read_symbol
        self.tool_manager.register_tool(
            name="read_symbol",
            description="读取指定函数、类或方法的完整定义。",
            parameters={
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "符号名称（函数名、类名、方法名）"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定在特定文件中查找"
                    }
                },
                "required": ["symbol_name"]
            },
            executor=self._execute_read_symbol,
            category="code_navigation",
        )

        # list_files
        self.tool_manager.register_tool(
            name="list_files",
            description="列出项目中的文件和目录结构。",
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "文件匹配模式，如 '**/*.py'",
                        "default": "**/*"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "最大返回数量",
                        "default": 50
                    }
                }
            },
            executor=self._execute_list_files,
            category="code_navigation",
        )

        # get_file_outline
        self.tool_manager.register_tool(
            name="get_file_outline",
            description="获取文件的结构大纲，列出所有类、函数、方法的定义。",
            parameters={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "文件路径"
                    }
                },
                "required": ["file_path"]
            },
            executor=self._execute_get_file_outline,
            category="code_navigation",
        )

        # get_callers - 查找调用者（基础版）
        self.tool_manager.register_tool(
            name="get_callers",
            description="查找谁调用了指定函数（向上追溯调用链）。适用于：找到函数的所有使用位置；追踪数据流入口；分析函数的影响范围。",
            parameters={
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "要查找调用者的函数名"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定在特定文件中查找（可选）"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "最大返回数量",
                        "default": 10
                    }
                },
                "required": ["symbol_name"]
            },
            executor=self._execute_get_callers,
            category="code_navigation",
        )

        # get_callees - 查找被调用者（基础版）
        self.tool_manager.register_tool(
            name="get_callees",
            description="查找指定函数调用了哪些其他函数（向下追溯调用链）。适用于：分析函数依赖；追踪数据流向危险函数；理解函数行为。",
            parameters={
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "要分析的函数名"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定在特定文件中查找（可选）"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "调用链追溯深度（1=直接调用，2=间接调用）",
                        "default": 1
                    }
                },
                "required": ["symbol_name"]
            },
            executor=self._execute_get_callees,
            category="code_navigation",
        )

        # grep_code - 精确代码搜索
        self.tool_manager.register_tool(
            name="grep_code",
            description="精确搜索代码（基于正则/关键词，非语义搜索）。与 search_code（语义搜索）不同，此工具提供精确的字符串/正则匹配，适用于：查找精确的函数调用、变量名、字符串常量、API 路径等。",
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "搜索模式（字符串或正则表达式）"
                    },
                    "file_glob": {
                        "type": "string",
                        "description": "文件过滤模式，如 '*.py', 'src/**/*.js'"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "最大返回结果数",
                        "default": 50
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "匹配行前后的上下文行数",
                        "default": 2
                    },
                    "use_regex": {
                        "type": "boolean",
                        "description": "是否将 pattern 作为正则表达式处理",
                        "default": False
                    },
                    "case_sensitive": {
                        "type": "boolean",
                        "description": "是否区分大小写",
                        "default": True
                    }
                },
                "required": ["pattern"]
            },
            executor=self._execute_grep_code,
            category="code_navigation",
        )

        logger.debug("[UnifiedAgent] 代码导航工具已注册（含 get_callers/get_callees/grep_code）")

    def _register_call_chain_tools(self, code_units: List[CodeUnit]):
        """注册调用链分析工具"""
        if not self.call_chain_analyzer:
            logger.warning("[UnifiedAgent] 调用链分析器未配置，跳过工具注册")
            return

        # 创建执行器
        executor = create_callchain_executor(
            call_chain_analyzer=self.call_chain_analyzer,
            code_units=code_units,
            indexer=self.indexer,
        )

        # 获取工具定义并注册
        tool_defs = get_callchain_tool_definitions()
        executors = executor.get_executors()

        self.tool_manager.register_many(
            tools=tool_defs,
            executors=executors,
            category="call_chain",
        )

        logger.debug(f"[UnifiedAgent] 调用链工具已注册: {len(tool_defs)} 个")

    def _register_variant_tools(self, code_units: List[CodeUnit]):
        """注册变体分析工具"""
        # 创建执行器
        executor = create_variant_executor(
            variant_analyzer=self.variant_analyzer,
            vector_store=self.vector_store,
            embedding_client=self.llm_client,  # 使用 LLM 客户端的嵌入功能
            code_units=code_units,
        )

        # 获取工具定义并注册
        tool_defs = get_variant_tool_definitions()
        executors = executor.get_executors()

        self.tool_manager.register_many(
            tools=tool_defs,
            executors=executors,
            category="variant_analysis",
        )

        logger.debug(f"[UnifiedAgent] 变体分析工具已注册: {len(tool_defs)} 个")

    def _register_security_tools(self):
        """注册安全分析工具"""
        # === 报告发现（核心工具 - 用于逐个输出漏洞） ===
        self.tool_manager.register_tool(
            name="report_finding",
            description="报告一个安全发现。当你确认发现安全漏洞时，必须使用此工具立即报告，而不是等到最后总结。每发现一个漏洞就调用一次。",
            parameters={
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "严重程度: critical(紧急), high(高危), medium(中危), low(低危), info(信息)"
                    },
                    "title": {
                        "type": "string",
                        "description": "漏洞标题，简洁明了（如：SQL注入漏洞、命令执行漏洞）"
                    },
                    "vulnerability_type": {
                        "type": "string",
                        "description": "漏洞类型（如：sql_injection, command_injection, xss, file_read, file_write, ssrf, idor, auth_bypass）"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "漏洞所在文件路径"
                    },
                    "line_number": {
                        "type": "integer",
                        "description": "漏洞所在行号"
                    },
                    "description": {
                        "type": "string",
                        "description": "漏洞详细描述，包括成因和影响"
                    },
                    "code_evidence": {
                        "type": "string",
                        "description": "漏洞代码证据（相关代码片段）"
                    },
                    "attack_scenario": {
                        "type": "string",
                        "description": "攻击场景说明（如何利用此漏洞，不含具体payload）"
                    },
                    "fix_suggestion": {
                        "type": "string",
                        "description": "修复建议"
                    },
                    "confidence": {
                        "type": "number",
                        "description": "置信度 0.0-1.0，表示对此发现的确信程度",
                        "minimum": 0.0,
                        "maximum": 1.0
                    }
                },
                "required": ["severity", "title", "vulnerability_type", "file_path", "description"]
            },
            executor=self._execute_report_finding,
            category="finding_management",
        )

        # 确认发现
        self.tool_manager.register_tool(
            name="confirm_finding",
            description="确认一个安全发现为真实漏洞。",
            parameters={
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "发现 ID"
                    },
                    "notes": {
                        "type": "string",
                        "description": "确认备注"
                    }
                },
                "required": ["finding_id"]
            },
            executor=self._execute_confirm_finding,
            category="finding_management",
        )

        # 拒绝发现
        self.tool_manager.register_tool(
            name="reject_finding",
            description="拒绝一个安全发现（标记为误报）。",
            parameters={
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "发现 ID"
                    },
                    "reason": {
                        "type": "string",
                        "description": "拒绝原因"
                    }
                },
                "required": ["finding_id"]
            },
            executor=self._execute_reject_finding,
            category="finding_management",
        )

        # 索引项目
        self.tool_manager.register_tool(
            name="index_project",
            description="索引或重新索引项目代码。在分析新项目或代码有更新时使用。",
            parameters={
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "目标路径（相对或绝对）"
                    },
                    "languages": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "要索引的编程语言列表"
                    },
                    "force_reindex": {
                        "type": "boolean",
                        "description": "是否强制重新索引",
                        "default": False
                    }
                }
            },
            executor=self._execute_index_project,
            category="project",
        )

        # === 预扫描结果查询工具 ===
        self.tool_manager.register_tool(
            name="get_prescan_summary",
            description="获取规则预扫描结果摘要，包括发现的危险函数触发点统计、风险等级分布和类别分布。",
            parameters={
                "type": "object",
                "properties": {}
            },
            executor=self._execute_get_prescan_summary,
            category="prescan",
        )

        # list_security_rules - 列出安全检测规则（重命名避免与 variant_tools 的 list_vuln_patterns 冲突）
        self.tool_manager.register_tool(
            name="list_security_rules",
            description="列出可用的安全检测规则和 Sink 模式。可以按漏洞类型或风险等级过滤，帮助了解系统支持检测哪些安全问题。",
            parameters={
                "type": "object",
                "properties": {
                    "vuln_type": {
                        "type": "string",
                        "description": "过滤漏洞类型: sql_injection, command_injection, xss, file_read, file_write, ssrf, deserialization 等"
                    },
                    "risk_level": {
                        "type": "string",
                        "description": "过滤风险等级: critical, high, medium, low",
                        "enum": ["critical", "high", "medium", "low"]
                    },
                    "language": {
                        "type": "string",
                        "description": "过滤编程语言: python, php, javascript, java, go 等"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "返回数量限制，默认 50",
                        "default": 50
                    }
                }
            },
            executor=self._execute_list_security_rules,
            category="prescan",
        )

        self.tool_manager.register_tool(
            name="get_prescan_sites",
            description="获取预扫描发现的危险函数触发点列表。可以按风险等级或类别过滤。",
            parameters={
                "type": "object",
                "properties": {
                    "risk_level": {
                        "type": "string",
                        "description": "过滤风险等级: critical, high, medium, low",
                        "enum": ["critical", "high", "medium", "low"]
                    },
                    "category": {
                        "type": "string",
                        "description": "过滤 Sink 类别: command_exec, code_exec, sql_injection, file_read, file_write, ssrf, deserialization"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "返回数量限制，默认 20",
                        "default": 20
                    }
                }
            },
            executor=self._execute_get_prescan_sites,
            category="prescan",
        )

        self.tool_manager.register_tool(
            name="get_site_details",
            description="获取单个预扫描触发点的详细信息，包括调用链分析和污点分析结果。",
            parameters={
                "type": "object",
                "properties": {
                    "site_id": {
                        "type": "string",
                        "description": "触发点 ID（如 sink-0001）"
                    }
                },
                "required": ["site_id"]
            },
            executor=self._execute_get_site_details,
            category="prescan",
        )

        # === 深度调用链分析工具 ===
        self.tool_manager.register_tool(
            name="analyze_sink_call_chain",
            description="""分析指定 Sink 触发点的完整调用链。从入口点到危险函数的完整调用路径，包括：
- 所有调用者层级
- 入口点识别（HTTP 路由、API 端点等）
- 污点传播路径分析
- 消毒函数检测
使用此工具深入理解用户输入如何到达危险函数。""",
            parameters={
                "type": "object",
                "properties": {
                    "site_id": {
                        "type": "string",
                        "description": "预扫描触发点 ID（如 sink-0001），或直接使用 symbol_name"
                    },
                    "symbol_name": {
                        "type": "string",
                        "description": "函数/方法名（如果不使用 site_id）"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定在特定文件中（可选）"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "最大调用链深度，默认 10",
                        "default": 10
                    },
                    "include_code": {
                        "type": "boolean",
                        "description": "是否包含各节点的代码片段",
                        "default": True
                    }
                }
            },
            executor=self._execute_analyze_sink_call_chain,
            category="deep_analysis",
        )

        self.tool_manager.register_tool(
            name="find_similar_sinks",
            description="""使用向量检索查找与指定 Sink 相似的代码模式。用于：
- 发现变体漏洞
- 查找相似的危险代码模式
- 批量识别同类安全问题""",
            parameters={
                "type": "object",
                "properties": {
                    "site_id": {
                        "type": "string",
                        "description": "预扫描触发点 ID 作为查询模式"
                    },
                    "code_pattern": {
                        "type": "string",
                        "description": "代码模式描述（如果不使用 site_id）"
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "返回相似结果数量，默认 10",
                        "default": 10
                    },
                    "min_similarity": {
                        "type": "number",
                        "description": "最小相似度阈值（0-1），默认 0.7",
                        "default": 0.7
                    }
                }
            },
            executor=self._execute_find_similar_sinks,
            category="deep_analysis",
        )

        self.tool_manager.register_tool(
            name="analyze_entry_to_sink",
            description="""分析从指定入口点到 Sink 的完整数据流路径。综合调用链和污点分析，给出可利用性评估。""",
            parameters={
                "type": "object",
                "properties": {
                    "entry_point": {
                        "type": "string",
                        "description": "入口点函数名（如 'handle_upload'）"
                    },
                    "entry_name": {
                        "type": "string",
                        "description": "entry_point 的别名（兼容旧调用）"
                    },
                    "sink_site_id": {
                        "type": "string",
                        "description": "目标 Sink 触发点 ID"
                    },
                    "site_id": {
                        "type": "string",
                        "description": "sink_site_id 的别名（兼容旧调用）"
                    },
                    "sink_name": {
                        "type": "string",
                        "description": "Sink 函数名（若未提供 sink_site_id，将尝试按名称自动匹配）"
                    },
                    "include_intermediate_code": {
                        "type": "boolean",
                        "description": "是否包含中间节点代码",
                        "default": True
                    }
                }
            },
            executor=self._execute_analyze_entry_to_sink,
            category="deep_analysis",
        )

        # === 污点分析工具 ===
        self.tool_manager.register_tool(
            name="analyze_taint_path",
            description="""分析从输入源（Source）到危险函数（Sink）的污点传播路径。
用于追踪用户输入如何流向危险函数，判断是否存在可利用的数据流。""",
            parameters={
                "type": "object",
                "properties": {
                    "source_symbol": {
                        "type": "string",
                        "description": "污点源函数名（如 'request.get_json'）"
                    },
                    "sink_symbol": {
                        "type": "string",
                        "description": "危险函数名（如 'cursor.execute'）"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "最大路径深度",
                        "default": 10
                    }
                }
            },
            executor=self._execute_analyze_taint_path,
            category="security_analysis",
        )

        # === 认证检查工具 ===
        self.tool_manager.register_tool(
            name="check_auth",
            description="检查指定函数是否有认证和授权检查。用于发现缺少权限验证的敏感操作。",
            parameters={
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "要检查的函数名"
                    },
                    "check_type": {
                        "type": "string",
                        "description": "检查类型",
                        "enum": ["authentication", "authorization", "both"],
                        "default": "both"
                    }
                },
                "required": ["symbol_name"]
            },
            executor=self._execute_check_auth,
            category="security_analysis",
        )

        # === 入口点发现工具 ===
        self.tool_manager.register_tool(
            name="find_entry_points",
            description="查找项目的入口点（HTTP 路由、API 端点等）。用于发现可被外部访问的函数。",
            parameters={
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "description": "框架类型",
                        "enum": ["flask", "django", "fastapi", "express", "spring", "auto"]
                    },
                    "include_internal": {
                        "type": "boolean",
                        "description": "是否包含内部 API",
                        "default": False
                    }
                }
            },
            executor=self._execute_find_entry_points,
            category="security_analysis",
        )

        logger.debug("[UnifiedAgent] 安全分析工具已注册（含污点分析/认证检查/入口点发现）")

    # ============ 核心对话接口 ============

    async def chat(self, user_message: str) -> AgentMessage:
        """与智能体对话

        支持 LLM 自主选择和调用工具。

        Args:
            user_message: 用户消息

        Returns:
            AgentMessage: 智能体响应（包含工具调用记录）
        """
        if self._is_processing:
            return AgentMessage(
                role="assistant",
                content="正在处理上一个请求，请稍候...",
                metadata={"error": "busy"},
            )

        interaction_mode = self._route_user_message(user_message)
        self._is_processing = True
        logger.info(f"[UnifiedAgent] 收到消息: {user_message[:50]}... (mode={interaction_mode})")

        try:
            # 闲聊/普通对话模式：不进入工具循环
            if interaction_mode != "audit":
                return await self._handle_chat_only_turn(
                    user_message=user_message,
                    interaction_mode=interaction_mode,
                )

            # 审计模式：按原有流程进行工具调用
            if not self._initialized:
                await self.initialize()

            # 添加用户消息
            user_msg = AgentMessage(role="user", content=user_message)
            self.messages.append(user_msg)

            # 构建 LLM 消息
            messages = self._build_llm_messages(user_message)

            # 获取工具定义
            tools = self.tool_manager.get_tools_for_llm()

            # 多轮工具调用循环
            tool_calls_this_turn: List[ToolCallEvent] = []
            final_response = ""

            for turn in range(self.config.max_tool_rounds):
                # 调用 LLM
                response = await self._call_llm_with_tools(messages, tools)
                self.total_llm_calls += 1

                # 检查是否有工具调用
                if response.tool_calls:
                    # 截断为单轮最大工具调用数
                    executed_calls = response.tool_calls[:self.config.max_tool_calls_per_turn]
                    # 执行工具调用
                    tool_results = await self._execute_tool_calls(executed_calls)
                    tool_calls_this_turn.extend(tool_results)

                    # 将截断后的工具调用和结果添加到消息
                    messages.append(ChatMessage(
                        role="assistant",
                        content=response.content or "",
                        tool_calls=executed_calls,
                    ))

                    for tc, result in zip(executed_calls, tool_results):
                        messages.append(ChatMessage(
                            role="tool",
                            content=safe_json_dumps(result.result or {"error": result.error}),
                            tool_call_id=tc.id,
                        ))
                else:
                    # 没有工具调用，获取最终响应
                    final_response = await self._ensure_plain_final_response(
                        messages=messages,
                        candidate_response=response.content or "",
                    )
                    break

            # 如果循环结束仍有工具调用，再获取一次最终响应（不传 tools 强制文本输出）
            if not final_response and tool_calls_this_turn:
                final_resp = await self._call_llm_with_tools(messages, None)
                self.total_llm_calls += 1
                final_response = await self._ensure_plain_final_response(
                    messages=messages,
                    candidate_response=final_resp.content or "",
                )

            # 构建响应消息
            assistant_msg = AgentMessage(
                role="assistant",
                content=final_response,
                tool_calls=tool_calls_this_turn,
                metadata={
                    "llm_calls": self.total_llm_calls,
                    "tool_calls_count": len(tool_calls_this_turn),
                    "interaction_mode": "audit",
                },
            )

            self.messages.append(assistant_msg)

            # 更新对话历史
            self.conversation_history.append(ChatMessage(role="user", content=user_message))
            self.conversation_history.append(ChatMessage(role="assistant", content=final_response))

            # 裁剪历史
            self._trim_conversation_history()

            # 检查并压缩历史
            await self._compress_conversation_history()

            return assistant_msg

        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            error_type = type(e).__name__
            error_msg = str(e)

            logger.error(f"[UnifiedAgent] 对话失败: {error_type}: {error_msg}")
            logger.error(f"[UnifiedAgent] 错误堆栈:\n{error_trace}")

            # 构建详细错误信息供前端展示
            detailed_error = f"{error_type}: {error_msg}"

            return AgentMessage(
                role="assistant",
                content=f"处理请求时发生错误: {detailed_error}",
                metadata={
                    "error": detailed_error,
                    "error_type": error_type,
                    "error_trace": error_trace,
                },
            )

        finally:
            self._is_processing = False

    async def chat_stream(self, user_message: str):
        """流式对话（生成器）

        实现真正的流式响应，在 LLM 生成过程中实时返回内容块。
        支持工具调用的实时状态推送。

        Args:
            user_message: 用户消息

        Yields:
            Dict: 事件对象
                - {"type": "start", "data": {}}  # 开始处理
                - {"type": "tool_call_start", "data": {...}}  # 工具调用开始
                - {"type": "tool_call_end", "data": {...}}  # 工具调用结束
                - {"type": "chunk", "content": "..."}  # 内容块
                - {"type": "message", "data": {...}}  # 完整消息
        """
        if self._is_processing:
            yield {"type": "error", "data": {"error": "正在处理上一个请求，请稍候..."}}
            return

        interaction_mode = self._route_user_message(user_message)
        self._is_processing = True
        yield {"type": "start", "data": {"timestamp": datetime.now().isoformat()}}
        logger.info(f"[UnifiedAgent] 收到流式消息: {user_message[:50]}... (mode={interaction_mode})")

        try:
            # 闲聊/普通对话模式：不进入工具循环
            if interaction_mode != "audit":
                assistant_msg = await self._handle_chat_only_turn(
                    user_message=user_message,
                    interaction_mode=interaction_mode,
                )
                chunk_size = self.config.stream_chunk_size
                for i in range(0, len(assistant_msg.content), chunk_size):
                    yield {"type": "chunk", "content": assistant_msg.content[i:i+chunk_size]}
                    await asyncio.sleep(0)
                yield {"type": "message", "data": assistant_msg.to_dict()}
                return

            if not self._initialized:
                await self.initialize()

            # 添加用户消息
            user_msg = AgentMessage(role="user", content=user_message)
            self.messages.append(user_msg)

            # 构建 LLM 消息
            messages = self._build_llm_messages(user_message)
            tools = self.tool_manager.get_tools_for_llm()

            # 多轮工具调用循环
            tool_calls_this_turn: List[ToolCallEvent] = []
            final_response = ""

            for turn in range(self.config.max_tool_rounds):
                response = await self._call_llm_with_tools(messages, tools)
                self.total_llm_calls += 1

                if response.tool_calls:
                    # 截断为单轮最大工具调用数
                    executed_calls = response.tool_calls[:self.config.max_tool_calls_per_turn]
                    # 执行工具调用（带实时推送）
                    for tc in executed_calls:
                        event = ToolCallEvent(
                            id=tc.id,
                            tool_name=tc.name,
                            arguments=tc.arguments if isinstance(tc.arguments, dict) else {},
                            status=ToolCallStatus.RUNNING,
                            started_at=datetime.now(),
                        )
                        yield {"type": "tool_call_start", "data": event.to_dict()}

                        try:
                            result = await self.tool_manager.execute(tc.name, event.arguments)
                            event.status = ToolCallStatus.SUCCESS if result.success else ToolCallStatus.FAILED
                            event.result = result.data if result.success else {
                                "success": False,
                                "error": result.error or "工具执行失败",
                            }
                            event.error = result.error
                            event.finished_at = datetime.now()
                            event.duration_ms = result.duration_ms
                            self.total_tool_calls += 1
                        except Exception as e:
                            event.status = ToolCallStatus.FAILED
                            event.error = str(e)
                            event.result = {"success": False, "error": str(e)}
                            event.finished_at = datetime.now()

                        yield {"type": "tool_call_end", "data": event.to_dict()}
                        tool_calls_this_turn.append(event)
                        self.tool_call_history.append(event)

                    # 将截断后的工具调用和结果添加到消息
                    messages.append(ChatMessage(
                        role="assistant",
                        content=response.content or "",
                        tool_calls=executed_calls,
                    ))

                    for tc, event in zip(executed_calls, tool_calls_this_turn[-len(executed_calls):]):
                        messages.append(ChatMessage(
                            role="tool",
                            content=safe_json_dumps(event.result or {"error": event.error}),
                            tool_call_id=tc.id,
                        ))
                else:
                    # 没有工具调用，直接使用已有响应内容分块返回（不再重复调用 LLM）
                    final_response = await self._ensure_plain_final_response(
                        messages=messages,
                        candidate_response=response.content or "",
                    )
                    chunk_size = self.config.stream_chunk_size
                    for i in range(0, len(final_response), chunk_size):
                        yield {"type": "chunk", "content": final_response[i:i+chunk_size]}
                        await asyncio.sleep(0)
                    break

            # 如果循环结束仍有工具调用，再获取一次最终响应（不传 tools 强制文本输出）
            if not final_response and tool_calls_this_turn:
                final_resp = await self._call_llm_with_tools(messages, None)
                self.total_llm_calls += 1
                final_response = await self._ensure_plain_final_response(
                    messages=messages,
                    candidate_response=final_resp.content or "",
                )
                # 分块返回
                chunk_size = self.config.stream_chunk_size
                for i in range(0, len(final_response), chunk_size):
                    yield {"type": "chunk", "content": final_response[i:i+chunk_size]}
                    await asyncio.sleep(0)

            # 构建最终消息
            assistant_msg = AgentMessage(
                role="assistant",
                content=final_response,
                tool_calls=tool_calls_this_turn,
                metadata={
                    "llm_calls": self.total_llm_calls,
                    "tool_calls_count": len(tool_calls_this_turn),
                    "interaction_mode": "audit",
                },
            )

            self.messages.append(assistant_msg)
            self.conversation_history.append(ChatMessage(role="user", content=user_message))
            self.conversation_history.append(ChatMessage(role="assistant", content=final_response))
            self._trim_conversation_history()

            # 检查并压缩历史
            await self._compress_conversation_history()

            yield {"type": "message", "data": assistant_msg.to_dict()}

        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            error_type = type(e).__name__
            error_msg = str(e)

            logger.error(f"[UnifiedAgent] 流式对话失败: {error_type}: {error_msg}")
            logger.error(f"[UnifiedAgent] 错误堆栈:\n{error_trace}")

            yield {
                "type": "error",
                "data": {
                    "error": f"{error_type}: {error_msg}",
                    "error_type": error_type,
                    "error_trace": error_trace,
                }
            }

        finally:
            self._is_processing = False

    async def _stream_final_response(self, messages: List[ChatMessage], tools: List[Dict[str, Any]]):
        """使用 LLM 获取最终响应并分块返回（内部方法，当前未被调用）"""
        try:
            # 使用统一封装调用 LLM（不传 tools 强制文本输出）
            response = await self._call_llm_with_tools(messages, None)
            self.total_llm_calls += 1

            # 分块返回完整响应
            content = await self._ensure_plain_final_response(
                messages=messages,
                candidate_response=response.content or "",
            )
            chunk_size = self.config.stream_chunk_size
            for i in range(0, len(content), chunk_size):
                yield {"type": "chunk", "content": content[i:i+chunk_size]}
                await asyncio.sleep(0)

        except Exception as e:
            logger.warning(f"[UnifiedAgent] 流式响应失败: {e}")
            yield {"type": "chunk", "content": f"响应生成失败: {e}"}

    def _route_user_message(self, user_message: str) -> str:
        """路由用户消息：audit | chat_only | small_talk"""
        if self._is_audit_intent_message(user_message) or self._is_followup_audit_message(user_message):
            return "audit"
        if self._is_small_talk_message(user_message):
            return "small_talk"
        return "chat_only"

    def _is_audit_intent_message(self, user_message: str) -> bool:
        """判断消息是否明确要求进入审计流程。"""
        text = (user_message or "").strip().lower()
        if not text:
            return False

        audit_keywords = (
            "分析", "审计", "扫描", "检查", "排查", "漏洞", "风险", "触发点", "调用链", "污点",
            "修复", "复现", "命令注入", "sql注入", "xss", "rce", "ssrf", "idor", "鉴权",
            "sink", "entry", "taint", "finding", "report_finding", "call chain",
            "analyze", "audit", "scan", "review", "security", "vulnerability", "vuln",
        )
        return any(keyword in text for keyword in audit_keywords)

    def _is_followup_audit_message(self, user_message: str) -> bool:
        """判断是否为审计过程中的跟进指令（如“继续”）。"""
        text = (user_message or "").strip().lower()
        if not text:
            return False

        # 只有存在审计上下文时，才把“继续/下一步”视为审计意图
        has_audit_context = any(
            m.role == "assistant" and m.metadata.get("tool_calls_count", 0) > 0
            for m in reversed(self.messages[-10:])
        ) or bool(self.tool_call_history)
        if not has_audit_context:
            return False

        non_audit_hints = ("聊天", "闲聊", "打招呼")
        if any(hint in text for hint in non_audit_hints):
            return False

        followup_keywords = (
            "继续", "接着", "下一步", "下一个", "展开", "详细", "继续分析", "继续审计", "再看",
        )
        return any(keyword in text for keyword in followup_keywords)

    def _is_small_talk_message(self, user_message: str) -> bool:
        """识别问候/寒暄类消息，避免直接触发全量审计。"""
        text = (user_message or "").strip()
        if not text:
            return True

        normalized = re.sub(r"[\s\u3000`~!@#$%^&*()_+\-=\[\]{}|;:'\",.<>/?，。！？、；：“”‘’（）【】《》]+", "", text.lower())
        greetings = {
            "你好", "您好", "嗨", "哈喽", "hello", "hi", "hey",
            "在吗", "在不在", "有人吗", "早上好", "中午好", "下午好", "晚上好", "早安", "晚安",
            "谢谢", "感谢", "thanks", "thankyou", "thx",
        }

        if normalized in greetings:
            return True

        if len(normalized) <= 6 and (
            normalized.startswith("你好")
            or normalized.startswith("您好")
            or normalized.startswith("hello")
            or normalized.startswith("hi")
        ):
            return True

        return False

    def _build_small_talk_response(self, user_message: str) -> str:
        """生成轻量寒暄回复。"""
        text = (user_message or "").lower()
        if any(word in text for word in ("谢谢", "感谢", "thanks", "thx")):
            return "不客气。我在这边，随时可以继续审计。"
        return (
            "你好，我在。你可以像和普通 LLM 对话一样下指令，我会按需审计代码。"
            "例如：分析 source/high.php、继续上一个触发点、只检查命令注入。"
        )

    def _build_chat_only_messages(self, user_message: str) -> List[ChatMessage]:
        """构建纯对话消息（禁用工具），用于需求澄清或普通问答。"""
        system_prompt = (
            "你是代码安全审计助手。当前处于对话模式：\n"
            "1) 先回答用户当前问题，不要主动发起全量审计流程。\n"
            "2) 不要输出 DSML/function_calls/invoke/parameter/XML 标签。\n"
            "3) 如果用户尚未明确审计目标，请用一句话引导其提供文件、漏洞类型或入口点。\n"
            "4) 使用中文，简洁直接。"
        )
        messages: List[ChatMessage] = [ChatMessage(role="system", content=system_prompt)]
        messages.extend(self.conversation_history[-6:])
        messages.append(ChatMessage(role="user", content=user_message))
        return messages

    async def _record_dialogue_turn(self, user_message: str, assistant_message: str, compress: bool = True):
        """记录对话轮次并维护历史。"""
        self.conversation_history.append(ChatMessage(role="user", content=user_message))
        self.conversation_history.append(ChatMessage(role="assistant", content=assistant_message))
        self._trim_conversation_history()
        if compress:
            await self._compress_conversation_history()

    async def _handle_chat_only_turn(self, user_message: str, interaction_mode: str) -> AgentMessage:
        """处理非审计消息（small_talk/chat_only）。"""
        user_msg = AgentMessage(role="user", content=user_message)
        self.messages.append(user_msg)

        if interaction_mode == "small_talk":
            final_response = self._build_small_talk_response(user_message)
        else:
            messages = self._build_chat_only_messages(user_message)
            response = await self._call_llm_with_tools(messages, None)
            self.total_llm_calls += 1
            final_response = await self._ensure_plain_final_response(
                messages=messages,
                candidate_response=response.content or "",
            )
            final_response = self._strip_tool_markup(final_response).strip()
            if not final_response:
                final_response = "请告诉我你想审计的目标（文件、漏洞类型或入口点），我再开始分析。"

        assistant_msg = AgentMessage(
            role="assistant",
            content=final_response,
            metadata={
                "llm_calls": self.total_llm_calls,
                "tool_calls_count": 0,
                "interaction_mode": interaction_mode,
            },
        )
        self.messages.append(assistant_msg)

        # small_talk 不触发历史压缩，避免额外消耗
        await self._record_dialogue_turn(
            user_message=user_message,
            assistant_message=final_response,
            compress=(interaction_mode != "small_talk"),
        )
        return assistant_msg

    def _is_tool_markup_response(self, text: str) -> bool:
        """判断响应是否为 DSML/函数调用标记文本（而非可展示结论）。"""
        if not text:
            return False

        lower = text.lower()
        # 常见 OpenAI 兼容层“文本化工具调用”标记
        if "dsml" in lower and "function_calls" in lower:
            return True
        if "<｜dsml｜invoke" in lower or "<|dsml|invoke" in lower:
            return True
        if "invoke name=" in lower and "function_calls" in lower:
            return True
        return False

    def _strip_tool_markup(self, text: str) -> str:
        """移除 DSML 工具调用标记，保留可展示自然语言。"""
        if not text:
            return ""

        # 先移除完整 function_calls 块
        cleaned = re.sub(
            r"<[｜|]?DSML[｜|]?function_calls>[\s\S]*?</[｜|]?DSML[｜|]?function_calls>",
            "",
            text,
            flags=re.IGNORECASE,
        )

        # 再做逐行兜底过滤，防止部分标签残留
        blocked_tokens = (
            "DSML",
            "function_calls",
            "invoke name=",
            "parameter name=",
            "</invoke>",
            "</parameter>",
        )
        kept_lines = []
        for line in cleaned.splitlines():
            if any(token in line for token in blocked_tokens):
                continue
            kept_lines.append(line)

        return "\n".join(kept_lines).strip()

    async def _ensure_plain_final_response(
        self,
        messages: List[ChatMessage],
        candidate_response: str,
    ) -> str:
        """确保最终响应是可展示纯文本，避免 DSML/function_calls 泄漏到前端。"""
        if not self._is_tool_markup_response(candidate_response):
            return candidate_response

        logger.warning("[UnifiedAgent] 检测到文本化工具调用标记，尝试转为纯文本最终结论")

        # 首先尝试本地清洗（避免额外消耗）
        stripped = self._strip_tool_markup(candidate_response)
        if stripped:
            return stripped

        # 清洗后为空时，补一次“无工具总结”重试
        retry_prompt = (
            "你上一条回复误输出了工具调用标记。"
            "请基于已获得信息直接给出最终分析结论，"
            "禁止输出任何 DSML/function_calls/invoke/parameter/XML 标签。"
        )
        retry_messages = list(messages)
        retry_messages.append(ChatMessage(role="assistant", content=candidate_response))
        retry_messages.append(ChatMessage(role="user", content=retry_prompt))

        try:
            retry_resp = await self._call_llm_with_tools(retry_messages, None)
            self.total_llm_calls += 1
            retry_content = self._strip_tool_markup(retry_resp.content or "")
            if retry_content:
                return retry_content
        except Exception as e:
            logger.warning(f"[UnifiedAgent] 纯文本重试失败: {e}")

        return "工具调用已完成，但模型未返回可展示的最终文本。请重试或缩小分析范围。"

    def _build_llm_messages(self, user_message: str) -> List[ChatMessage]:
        """构建 LLM 消息列表

        集成对话历史压缩：
        1. 如果有压缩摘要，注入到系统提示中
        2. 只携带最近的对话历史
        """
        messages = []

        # 系统提示
        system_prompt = self._build_system_prompt()

        # === 注入压缩的历史摘要 ===
        if self._compressed_history_summary:
            system_prompt += f"""

## 📜 对话历史摘要

以下是之前对话的压缩摘要，请参考这些信息保持上下文连贯：

{self._compressed_history_summary}
"""

        messages.append(ChatMessage(role="system", content=system_prompt))

        # 最近的对话历史
        recent_history = self.conversation_history[-self.config.context_window_messages:]
        messages.extend(recent_history)

        # 当前用户消息
        messages.append(ChatMessage(role="user", content=user_message))

        return messages

    def _build_system_prompt(self) -> str:
        """构建系统提示"""
        # 获取工具摘要
        tool_summary = self.tool_manager.get_tool_summary()

        # 基础提示
        base_prompt = f"""你是一名资深安全工程师和代码审计专家。你正在使用一个智能代码审计系统，可以通过各种工具来分析代码。

## 你的能力

你可以使用以下工具来完成代码审计任务：

{tool_summary}

## 工作流程

### 智能决策循环

你是一个自主的安全分析智能体，应按以下循环进行分析：

```
┌─────────────────────────────────────────────────────────────────┐
│  观察 → 思考 → 行动 → 观察 → ...（循环直到完成）                 │
└─────────────────────────────────────────────────────────────────┘

Step 1: 观察预扫描结果，识别高优先级触发点
Step 2: 对每个触发点，使用深度分析工具获取完整上下文
Step 3: 基于上下文判断是否为真实漏洞
Step 4: 如确认漏洞，使用 find_similar_sinks 查找变体
Step 5: 输出结构化发现报告
```

### 分析阶段

1. **理解阶段**：阅读预扫描结果，理解代码库结构
2. **深度分析**：使用 `analyze_sink_call_chain` 获取调用链上下文
3. **可利用性评估**：使用 `analyze_entry_to_sink` 判断攻击路径
4. **变体发现**：使用 `find_similar_sinks` 批量检测同类问题
5. **结果输出**：结构化报告每个确认的安全问题

## 重要原则

1. **工具优先**：遇到需要查看代码、追踪调用链、查找相似代码等任务时，优先使用工具
2. **循序渐进**：可以多次调用工具，逐步深入分析
3. **证据导向**：所有安全判断都应基于工具返回的代码证据
4. **谨慎判断**：对于不确定的问题，明确说明需要进一步验证

## 安全分析重点

- 认证与授权是否正确、完整
- 访问控制是否可被绕过
- 业务流程是否可被跳过或篡改
- 用户输入是否经过适当验证
- 危险函数调用是否安全

## 🔍 深度分析工具使用策略

### 核心分析工作流

1. **预扫描触发点 → 深度调用链分析**
   - 当预扫描发现危险函数触发点时，使用 `analyze_sink_call_chain` 分析完整调用链
   - 该工具会返回：所有调用者、入口点、调用深度、污点传播路径

2. **相似代码发现 → 批量变体检测**
   - 确认一个漏洞后，使用 `find_similar_sinks` 查找相似代码模式
   - 可发现：同类漏洞变体、复制粘贴的危险代码、未被规则覆盖的变种

3. **入口点 → Sink 完整链路分析**
   - 使用 `analyze_entry_to_sink` 分析从 HTTP 入口到危险函数的完整数据流
   - 可判断：是否有消毒函数、数据流是否可控、漏洞可利用性

### 工具选择决策树

```
发现 Sink 触发点
  │
  ├─→ 需要了解调用链？ → analyze_sink_call_chain
  │     └─→ 返回入口点列表 → 选择关键入口点
  │
  ├─→ 需要查找变体？ → find_similar_sinks
  │     └─→ 返回相似代码 → 逐个验证
  │
  └─→ 需要分析可利用性？ → analyze_entry_to_sink
        └─→ 返回完整路径 + 消毒检测 → 判断风险等级
```

### 最佳实践

1. **优先使用深度分析工具**：面对预扫描结果，先用深度工具获取完整上下文
2. **链级思考**：不要只看单个函数，要看整条调用链上的所有节点
3. **证据收集**：每个发现都要有调用链路径作为证据
4. **批量检测**：确认一个漏洞后，立即使用 `find_similar_sinks` 查找变体

## 🚨 漏洞报告要求（必须遵守）

### 核心规则：发现即报告

**当你确认发现安全漏洞时，必须立即调用 `report_finding` 工具报告，不要等到分析完成后才报告！**

### 工作流程

```
分析触发点 → 确认是漏洞 → 立即调用 report_finding → 继续分析下一个
                 ↓
              不是漏洞 → 跳过，继续分析下一个
```

### report_finding 调用示例

当发现 SQL 注入漏洞时：
```json
{{
  "severity": "high",
  "title": "SQL注入漏洞",
  "vulnerability_type": "sql_injection",
  "file_path": "login.php",
  "line_number": 45,
  "description": "用户输入未经过滤直接拼接到SQL查询中",
  "code_evidence": "$query = \"SELECT * FROM users WHERE username='\" . $_POST['user'] . \"'\";",
  "attack_scenario": "攻击者可通过构造恶意输入获取数据库中的敏感数据",
  "fix_suggestion": "使用参数化查询或预处理语句",
  "confidence": 0.95
}}
```

### 严重程度判断标准

- **critical**: RCE、任意文件读写、反序列化漏洞
- **high**: SQL注入、SSRF、认证绕过、敏感信息泄露
- **medium**: XSS、CSRF、不安全的会话管理
- **low**: 信息泄露、弱加密、日志注入
- **info**: 最佳实践建议、配置优化

## ⚠️ 工具调用格式要求（严格遵守）

调用工具时，**必须**遵循以下规则：

1. **参数类型**：
   - 字符串参数用双引号包裹
   - 整数参数直接使用数字，不要用引号
   - 布尔参数使用 `true` 或 `false`（小写）

2. **必填参数**：每个工具的 `required` 字段列出的参数必须提供

3. **参数格式示例**：
   ```json
   {{
     "query": "用户认证",
     "top_k": 5,
     "language": "python"
   }}
   ```

4. **常见错误避免**：
   - ❌ 不要在整数参数中使用引号：`"top_k": "5"`
   - ✅ 正确写法：`"top_k": 5`
   - ❌ 不要遗漏必填参数
   - ❌ 不要使用未定义的参数名

## 输出格式要求

1. **发现安全问题时**，使用以下结构化格式：

```
### 🔴 [严重程度] 问题标题

**位置**：`文件路径:行号`

**问题描述**：
简要说明发现的安全问题

**代码证据**：
```代码语言
相关代码片段
```

**风险分析**：
- 攻击场景说明
- 潜在影响

**修复建议**：
具体的修复方案
```

2. **分析过程中**，简要说明你的思路和下一步计划

3. **不确定时**，明确标注"需要进一步验证"

## 交互策略（必须遵守）

1. 如果用户仅问候/寒暄（例如“你好”），先简短回复，不要直接开始项目审计。
2. 只有当用户明确提出审计需求（如“分析/扫描/检查/继续分析”）时，才进入工具调用流程。
3. 如果用户意图不明确，先用一句话澄清目标范围（文件、漏洞类型或入口点），再执行审计。

## 会话信息

- 会话 ID: {self.session_id}
- 已索引代码单元: {len(self._get_code_units())}
- 可用工具数: {self.tool_manager.count()}
"""

        # === 注入预扫描上下文 ===
        if self.config.prescan_context_injection and self._prescan_context:
            base_prompt += f"""

## 📋 规则预扫描结果（自动检测的危险函数触发点）

系统已对代码库进行规则扫描，发现以下高危触发点供优先分析：

{self._prescan_context}

### 🎯 推荐分析流程

1. **深度调用链分析**（首选）
   ```
   analyze_sink_call_chain(site_id="sink-0001")
   ```
   返回完整调用链、入口点、污点路径，一次调用获取所有上下文。

2. **入口点到 Sink 链路分析**
   ```
   analyze_entry_to_sink(entry_point="<script:high.php>", sink_site_id="sink-xxxx")
   ```
   分析数据如何从 HTTP 入口流向危险函数，评估可利用性。

3. **变体发现**
   ```
   find_similar_sinks(code_snippet="os.system(user_input)", top_k=10)
   ```
   确认一个漏洞后，查找代码库中的相似模式。

4. **补充工具**
   - `read_file` - 查看特定代码行
   - `get_callers`/`get_callees` - 单跳调用关系
   - `analyze_taint_path` - 污点传播分析
"""

        base_prompt += "\n使用中文回复。"
        return base_prompt

    async def _call_llm_with_tools(
        self,
        messages: List[ChatMessage],
        tools: List[Dict[str, Any]],
    ):
        """调用 LLM（支持工具调用）

        增强日志记录：记录完整的请求和响应信息用于调试。
        """
        call_id = f"llm-{self.total_llm_calls + 1}"
        timestamp = datetime.now().isoformat()

        # === 请求日志 ===
        logger.info(f"[UnifiedAgent][{call_id}] 开始 LLM 调用")
        tools_count = len(tools) if tools else 0
        print(f"[{timestamp}] [UnifiedAgent][{call_id}] 开始 LLM 调用: messages={len(messages)}, tools={tools_count}")  # 强制输出
        logger.info(f"[UnifiedAgent][{call_id}] 请求参数: messages={len(messages)}, tools={tools_count}, temp={self.config.temperature}, max_tokens={self.config.max_tokens}")

        # === 触发 LLM 调用开始回调 ===
        if self.config.on_llm_call_start:
            try:
                # 获取最后一条用户消息作为当前问题摘要
                last_user_msg = ""
                for m in reversed(messages):
                    if m.role == "user":
                        last_user_msg = (m.content or "")[:200]
                        break

                start_event = {
                    "type": "llm_call_start",
                    "call_id": call_id,
                    "session_id": self.session_id,
                    "messages_count": len(messages),
                    "tools_count": tools_count,
                    "timestamp": timestamp,
                    "current_question": last_user_msg,
                }
                result = self.config.on_llm_call_start(start_event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.warning(f"[UnifiedAgent][{call_id}] on_llm_call_start 回调失败: {e}")

        # 记录消息摘要（避免日志过长）
        for i, msg in enumerate(messages):
            role = msg.role
            content_preview = (msg.content or "")[:200] + ("..." if len(msg.content or "") > 200 else "")
            tool_calls_info = f", tool_calls={len(msg.tool_calls)}" if hasattr(msg, 'tool_calls') and msg.tool_calls else ""
            logger.debug(f"[UnifiedAgent][{call_id}] msg[{i}] role={role}{tool_calls_info}: {content_preview}")

        # === 完整请求记录（用于调试） ===
        request_data = None
        if self.config.log_full_request or self.config.save_requests_to_file:
            request_data = {
                "call_id": call_id,
                "timestamp": timestamp,
                "session_id": self.session_id,
                "messages": [
                    {
                        "role": m.role,
                        "content": m.content,
                        "tool_calls": [{"id": tc.id, "name": tc.name, "arguments": tc.arguments} for tc in (m.tool_calls or [])] if hasattr(m, 'tool_calls') and m.tool_calls else None,
                        "tool_call_id": getattr(m, 'tool_call_id', None),
                    }
                    for m in messages
                ],
                "tools": tools,
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
            }
            if self.config.log_full_request:
                logger.info(f"[UnifiedAgent][{call_id}] 完整请求:\n{safe_json_dumps(request_data, indent=2)}")

        try:
            # 使用 asyncio.to_thread 包装同步调用
            response = await asyncio.to_thread(
                self.llm_client.chat_completion,
                messages=messages,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                tools=tools if tools else None,
            )

            # === 响应日志 ===
            response_content = response.content or ""
            content_preview = response_content[:300] + ("..." if len(response_content) > 300 else "")
            tool_calls_count = len(response.tool_calls) if response.tool_calls else 0
            usage_info = response.usage if response.usage else {}

            logger.info(f"[UnifiedAgent][{call_id}] LLM 响应成功: content_len={len(response_content)}, tool_calls={tool_calls_count}, usage={usage_info}")
            print(f"[{datetime.now().isoformat()}] [UnifiedAgent][{call_id}] LLM 响应成功: content_len={len(response_content)}, tool_calls={tool_calls_count}, tokens={usage_info.get('total_tokens', 'N/A')}")  # 强制输出
            logger.info(f"[UnifiedAgent][{call_id}] 响应内容预览: {content_preview}")

            if response.tool_calls:
                for tc in response.tool_calls:
                    args_preview = safe_json_dumps(tc.arguments)[:200] if tc.arguments else "{}"
                    logger.debug(f"[UnifiedAgent][{call_id}] tool_call: {tc.name}({args_preview})")

            # === 完整响应记录（用于调试） ===
            response_data = None
            if self.config.log_full_response or self.config.save_requests_to_file:
                response_data = {
                    "call_id": call_id,
                    "timestamp": datetime.now().isoformat(),
                    "content": response_content,
                    "tool_calls": [
                        {"id": tc.id, "name": tc.name, "arguments": tc.arguments}
                        for tc in (response.tool_calls or [])
                    ] if response.tool_calls else None,
                    "usage": usage_info,
                    "finish_reason": getattr(response, 'finish_reason', None),
                }
                if self.config.log_full_response:
                    logger.info(f"[UnifiedAgent][{call_id}] 完整响应:\n{safe_json_dumps(response_data, indent=2)}")

            # === 保存到文件 ===
            if self.config.save_requests_to_file and request_data:
                await self._save_debug_log(call_id, request_data, response_data)

            # === 触发 LLM 调用结束回调 ===
            if self.config.on_llm_call_end:
                try:
                    # 构建工具调用列表（用于前端展示）
                    tool_calls_data = []
                    if response.tool_calls:
                        for tc in response.tool_calls:
                            tool_calls_data.append({
                                "id": tc.id,
                                "name": tc.name,
                                "arguments": tc.arguments,
                            })

                    end_event = {
                        "type": "llm_call_end",
                        "call_id": call_id,
                        "session_id": self.session_id,
                        "content": response_content,
                        "content_preview": content_preview,
                        "tool_calls": tool_calls_data,
                        "tool_calls_count": tool_calls_count,
                        "usage": usage_info,
                        "timestamp": datetime.now().isoformat(),
                        "has_more_tool_calls": tool_calls_count > 0,
                    }
                    result = self.config.on_llm_call_end(end_event)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception as e:
                    logger.warning(f"[UnifiedAgent][{call_id}] on_llm_call_end 回调失败: {e}")

            # 更新统计
            if response.usage:
                self.total_tokens_used += response.usage.get("total_tokens", 0)

            return response

        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"[UnifiedAgent][{call_id}] LLM 调用失败: {type(e).__name__}: {e}")
            logger.error(f"[UnifiedAgent][{call_id}] 错误堆栈:\n{error_trace}")

            # 记录导致错误的请求信息（用于调试）
            try:
                request_dump = {
                    "messages_count": len(messages),
                    "messages_roles": [m.role for m in messages],
                    "tools_count": len(tools),
                    "temperature": self.config.temperature,
                    "max_tokens": self.config.max_tokens,
                }
                logger.error(f"[UnifiedAgent][{call_id}] 失败请求摘要: {safe_json_dumps(request_dump)}")

                # 如果启用了完整日志，也记录完整请求
                if request_data:
                    error_data = {
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                        "error_trace": error_trace,
                    }
                    await self._save_debug_log(call_id, request_data, error_data, is_error=True)
            except Exception:
                pass

            raise

    async def _execute_tool_calls(self, tool_calls: List[ToolCall]) -> List[ToolCallEvent]:
        """执行工具调用（支持并行执行优化）"""
        if not tool_calls:
            return []

        # 创建所有事件对象
        events = []
        for tc in tool_calls:
            tool_name = tc.name
            arguments = tc.arguments if isinstance(tc.arguments, dict) else {}
            event = ToolCallEvent(
                id=tc.id,
                tool_name=tool_name,
                arguments=arguments,
                status=ToolCallStatus.RUNNING,
                started_at=datetime.now(),
            )
            events.append((tc, event))

            # 异步通知回调（开始状态）
            await self._notify_tool_call(event)
            logger.info(f"[UnifiedAgent] 执行工具: {tool_name}")

        # 根据配置决定串行或并行执行
        if self.config.enable_parallel_tool_execution and len(tool_calls) > 1:
            # 并行执行所有工具
            results = await self._execute_tools_parallel(events)
        else:
            # 串行执行
            results = await self._execute_tools_sequential(events)

        return results

    async def _execute_tools_parallel(self, events: List[tuple]) -> List[ToolCallEvent]:
        """并行执行多个工具"""
        async def execute_single(tc_event_pair):
            tc, event = tc_event_pair
            try:
                result = await self.tool_manager.execute(event.tool_name, event.arguments)
                event.status = ToolCallStatus.SUCCESS if result.success else ToolCallStatus.FAILED
                event.result = result.data if result.success else {
                    "success": False,
                    "error": result.error or "工具执行失败",
                }
                event.error = result.error
                event.finished_at = datetime.now()
                event.duration_ms = result.duration_ms
                self.total_tool_calls += 1
            except Exception as e:
                logger.error(f"[UnifiedAgent] 工具执行失败 {event.tool_name}: {e}")
                event.status = ToolCallStatus.FAILED
                event.error = str(e)
                event.result = {"success": False, "error": str(e)}
                event.finished_at = datetime.now()

            # 异步通知回调（完成状态）
            await self._notify_tool_call(event)
            self.tool_call_history.append(event)
            return event

        # 并行执行所有工具
        results = await asyncio.gather(*[execute_single(pair) for pair in events], return_exceptions=True)

        # 处理异常结果
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                event = events[i][1]
                event.status = ToolCallStatus.FAILED
                event.error = str(result)
                event.result = {"success": False, "error": str(result)}
                event.finished_at = datetime.now()
                final_results.append(event)
            else:
                final_results.append(result)

        return final_results

    async def _execute_tools_sequential(self, events: List[tuple]) -> List[ToolCallEvent]:
        """串行执行工具"""
        results = []
        for tc, event in events:
            try:
                result = await self.tool_manager.execute(event.tool_name, event.arguments)
                event.status = ToolCallStatus.SUCCESS if result.success else ToolCallStatus.FAILED
                event.result = result.data if result.success else {
                    "success": False,
                    "error": result.error or "工具执行失败",
                }
                event.error = result.error
                event.finished_at = datetime.now()
                event.duration_ms = result.duration_ms
                self.total_tool_calls += 1
            except Exception as e:
                logger.error(f"[UnifiedAgent] 工具执行失败 {event.tool_name}: {e}")
                event.status = ToolCallStatus.FAILED
                event.error = str(e)
                event.result = {"success": False, "error": str(e)}
                event.finished_at = datetime.now()

            # 异步通知回调（完成状态）
            await self._notify_tool_call(event)
            results.append(event)
            self.tool_call_history.append(event)

        return results

    async def _notify_tool_call(self, event: ToolCallEvent):
        """通知工具调用事件（支持同步和异步回调）"""
        # 异步回调优先
        if self.config.on_tool_call_async:
            try:
                await self.config.on_tool_call_async(event)
            except Exception as e:
                logger.warning(f"[UnifiedAgent] 异步回调失败: {e}")
        # 同步回调
        elif self.config.on_tool_call:
            try:
                self.config.on_tool_call(event)
            except Exception as e:
                logger.warning(f"[UnifiedAgent] 同步回调失败: {e}")

    def _trim_conversation_history(self):
        """裁剪对话历史"""
        max_messages = self.config.context_window_messages * 2
        if len(self.conversation_history) > max_messages:
            self.conversation_history = self.conversation_history[-max_messages:]

    # ============ 对话历史压缩 ============

    def _calculate_history_chars(self) -> int:
        """计算对话历史的总字符数

        Returns:
            对话历史的总字符数
        """
        total = 0
        for msg in self.conversation_history:
            total += len(msg.content or "")
        # 包含已压缩的摘要
        total += len(self._compressed_history_summary)
        return total

    def _should_compress_history(self) -> bool:
        """判断是否需要压缩对话历史

        Returns:
            True 如果需要压缩
        """
        if not self.config.enable_history_compression:
            return False

        # 计算当前历史字符数
        total_chars = self._calculate_history_chars()

        # 超过阈值则需要压缩
        return total_chars > self.config.history_compression_threshold

    async def _compress_conversation_history(self):
        """压缩对话历史

        根据配置选择压缩策略：
        - summarize: 使用 LLM 生成摘要
        - truncate: 简单截断旧消息
        """
        if not self._should_compress_history():
            return

        preserve_count = self.config.history_preserve_recent
        method = self.config.history_compression_method

        # 历史不足以再压缩时，若摘要本身超限则直接截断以避免反复触发压缩
        if len(self.conversation_history) <= preserve_count:
            if self._compressed_history_summary and len(self._compressed_history_summary) > self.config.history_compression_threshold:
                logger.info(f"[UnifiedAgent] 对话摘要超过阈值，进行截断，当前长度: {len(self._compressed_history_summary)}")
                self._compressed_history_summary = self._compressed_history_summary[: self.config.history_compression_threshold] + "..."
            return

        logger.info(f"[UnifiedAgent] 开始压缩对话历史，当前字符数: {self._calculate_history_chars()}")

        if method == "summarize":
            await self._compress_with_llm_summary(preserve_count)
        else:
            self._compress_with_truncation(preserve_count)

        logger.info(f"[UnifiedAgent] 压缩完成，压缩后字符数: {self._calculate_history_chars()}")

    async def _compress_with_llm_summary(self, preserve_count: int):
        """使用 LLM 生成摘要压缩历史

        Args:
            preserve_count: 保留最近的消息数量
        """
        # 获取需要压缩的旧消息
        if len(self.conversation_history) <= preserve_count:
            return

        old_messages = self.conversation_history[:-preserve_count]
        recent_messages = self.conversation_history[-preserve_count:]

        # 构建摘要请求
        history_text = ""
        for msg in old_messages:
            role_label = "用户" if msg.role == "user" else "助手"
            history_text += f"{role_label}: {msg.content}\n\n"

        # 包含之前的摘要
        if self._compressed_history_summary:
            history_text = f"[之前的对话摘要]\n{self._compressed_history_summary}\n\n[新对话]\n{history_text}"

        summary_prompt = f"""请将以下代码审计对话历史压缩成简洁的摘要，保留关键信息：
1. 分析过的文件和函数
2. 发现的安全问题
3. 重要的审计结论
4. 用户的主要需求

对话历史:
{history_text}

请用不超过 {self.config.history_summary_max_tokens} tokens 的中文生成摘要，保持专业和结构化："""

        try:
            # 调用 LLM 生成摘要
            summary_messages = [
                ChatMessage(role="system", content="你是一个代码安全审计助手，负责将对话历史压缩成简洁的摘要。"),
                ChatMessage(role="user", content=summary_prompt),
            ]

            response = await asyncio.to_thread(
                self.llm_client.chat_completion,
                messages=summary_messages,
                temperature=self.config.history_summary_temperature,
                max_tokens=self.config.history_summary_max_tokens,
            )

            # 更新压缩摘要
            self._compressed_history_summary = response.content or ""

            # 只保留最近的消息
            self.conversation_history = recent_messages

            logger.info(f"[UnifiedAgent] LLM 摘要压缩完成，摘要长度: {len(self._compressed_history_summary)}")

        except Exception as e:
            logger.warning(f"[UnifiedAgent] LLM 摘要压缩失败，回退到截断: {e}")
            self._compress_with_truncation(preserve_count)

    def _compress_with_truncation(self, preserve_count: int):
        """简单截断压缩

        Args:
            preserve_count: 保留最近的消息数量
        """
        if len(self.conversation_history) <= preserve_count:
            return

        # 获取需要压缩的旧消息
        old_messages = self.conversation_history[:-preserve_count]
        recent_messages = self.conversation_history[-preserve_count:]

        # 简单拼接旧消息为摘要
        summary_parts = []
        for msg in old_messages:
            role_label = "用户" if msg.role == "user" else "助手"
            content = msg.content or ""
            # 截断每条消息
            if len(content) > 200:
                content = content[:200] + "..."
            summary_parts.append(f"[{role_label}] {content}")

        # 构建截断摘要
        truncated_summary = "\n".join(summary_parts[-10:])  # 只保留最后 10 条的摘要
        if self._compressed_history_summary:
            self._compressed_history_summary = f"{self._compressed_history_summary}\n---\n{truncated_summary}"
        else:
            self._compressed_history_summary = truncated_summary

        # 更新历史
        self.conversation_history = recent_messages

        logger.info(f"[UnifiedAgent] 截断压缩完成，保留 {len(recent_messages)} 条消息")

    async def _save_debug_log(
        self,
        call_id: str,
        request_data: Dict[str, Any],
        response_data: Optional[Dict[str, Any]],
        is_error: bool = False,
    ):
        """保存调试日志到文件

        Args:
            call_id: 调用 ID
            request_data: 请求数据
            response_data: 响应数据（或错误数据）
            is_error: 是否为错误日志
        """
        import os

        try:
            log_dir = self.config.debug_log_dir
            os.makedirs(log_dir, exist_ok=True)

            # 生成文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            suffix = "_error" if is_error else ""
            filename = f"{self.session_id}_{call_id}_{timestamp}{suffix}.json"
            filepath = os.path.join(log_dir, filename)

            # 构建完整日志
            log_data = {
                "session_id": self.session_id,
                "call_id": call_id,
                "timestamp": datetime.now().isoformat(),
                "is_error": is_error,
                "request": request_data,
                "response": response_data,
            }

            # 异步写入文件
            await asyncio.to_thread(
                self._write_json_file,
                filepath,
                log_data,
            )

            logger.debug(f"[UnifiedAgent][{call_id}] 调试日志已保存: {filepath}")

        except Exception as e:
            logger.warning(f"[UnifiedAgent][{call_id}] 保存调试日志失败: {e}")

    def _write_json_file(self, filepath: str, data: Dict[str, Any]):
        """同步写入 JSON 文件（供 asyncio.to_thread 调用）"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(safe_json_dumps(data, indent=2))

    # ============ 工具执行器 ============

    def _execute_search_code(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行代码搜索"""
        query = args.get("query", "")
        top_k = args.get("top_k", 5)
        language = args.get("language")
        file_pattern = args.get("file_pattern")

        if not query:
            return {"success": False, "error": "query 是必需参数"}

        if not self.vector_store:
            return {"success": False, "error": "向量存储未配置"}

        try:
            # 生成查询向量
            embed_response = self.llm_client.embed([query])
            if not embed_response or not embed_response.embeddings or not embed_response.embeddings[0]:
                return {"success": False, "error": "无法生成嵌入向量"}

            # 搜索 - 使用正确的参数名 query_embedding
            results = self.vector_store.search(
                query_embedding=embed_response.embeddings[0],
                top_k=top_k * 2,  # 预留过滤空间
            )

            # 过滤和格式化
            code_results = []
            for r in results:
                metadata = r.metadata or {}

                # 语言过滤
                if language and metadata.get("language") != language:
                    continue

                # 文件模式过滤
                if file_pattern:
                    import fnmatch
                    if not fnmatch.fnmatch(metadata.get("file_path", ""), file_pattern):
                        continue

                code_results.append({
                    "file_path": metadata.get("file_path", ""),
                    "symbol": metadata.get("symbol", ""),
                    "language": metadata.get("language", ""),
                    "line_start": metadata.get("line_start", 0),
                    "line_end": metadata.get("line_end", 0),
                    "score": round(r.score, 3),
                    "code_preview": (metadata.get("code") or "")[:500],
                })

                if len(code_results) >= top_k:
                    break

            # 回退：当向量检索无结果时，使用本地字符串匹配兜底
            if not code_results:
                import fnmatch

                query_lower = query.lower()
                for unit in self._get_code_units().values():
                    # 语言过滤
                    if language and unit.language != language:
                        continue

                    # 文件模式过滤
                    if file_pattern:
                        normalized_fp = unit.file_path.replace("\\", "/")
                        if not (
                            fnmatch.fnmatch(Path(normalized_fp).name, file_pattern)
                            or fnmatch.fnmatch(normalized_fp, file_pattern)
                        ):
                            continue

                    haystack = f"{unit.symbol}\n{unit.file_path}\n{unit.code}".lower()
                    if query_lower not in haystack:
                        continue

                    code_results.append({
                        "file_path": unit.file_path,
                        "symbol": unit.symbol,
                        "language": unit.language,
                        "line_start": unit.span.start_line,
                        "line_end": unit.span.end_line,
                        "score": 0.0,
                        "code_preview": (unit.code or "")[:500],
                        "source": "fallback_text_match",
                    })
                    if len(code_results) >= top_k:
                        break

            return {
                "success": True,
                "results": code_results,
                "total": len(code_results),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_read_file(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行文件读取"""
        file_path = args.get("file_path") or args.get("path") or ""
        start_line = args.get("start_line")
        end_line = args.get("end_line")

        if not file_path:
            return {"success": False, "error": "file_path 是必需参数"}

        # 安全校验：拒绝绝对路径和明显的路径遍历
        if os.path.isabs(file_path) or ".." in file_path.replace("\\", "/").split("/"):
            return {"success": False, "error": "安全限制：仅允许项目内的相对路径，禁止绝对路径和路径遍历"}

        try:
            content = self.indexer.read_file(
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
            )

            if content is None:
                return {"success": False, "error": f"文件不存在: {file_path}"}

            return {
                "success": True,
                "file_path": file_path,
                "content": content,
                "start_line": start_line or 1,
                "end_line": end_line,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_read_symbol(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行符号读取"""
        symbol_name = args.get("symbol_name", "")
        file_path = args.get("file_path")

        if not symbol_name:
            return {"success": False, "error": "symbol_name 是必需参数"}

        try:
            # 在代码单元中查找（使用缓存 + 分级匹配）
            all_units = self._get_code_units()
            scored_units = []
            for unit in all_units.values():
                match_level = self._match_symbol(symbol_name, unit.symbol)
                if match_level > 0:
                    if file_path and file_path not in unit.file_path:
                        continue
                    scored_units.append((match_level, unit))

            if not scored_units:
                return {"success": False, "error": f"未找到符号: {symbol_name}"}

            # 按匹配精确度排序，精确匹配优先
            scored_units.sort(key=lambda x: x[0], reverse=True)
            matching_units = [u for _, u in scored_units]
            unit = matching_units[0]
            return {
                "success": True,
                "symbol": unit.symbol,
                "file_path": unit.file_path,
                "language": unit.language,
                "line_start": unit.span.start_line,
                "line_end": unit.span.end_line,
                "code": unit.code,
                "calls": unit.calls,
                "total_matches": len(matching_units),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_list_files(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行文件列表"""
        pattern = args.get("pattern", "**/*")
        max_results = args.get("max_results", 50)

        try:
            files = self.indexer.list_files(pattern=pattern, max_results=max_results)

            return {
                "success": True,
                "files": files,
                "total": len(files),
                "pattern": pattern,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_get_file_outline(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行获取文件大纲"""
        file_path = args.get("file_path", "")

        if not file_path:
            return {"success": False, "error": "file_path 是必需参数"}

        try:
            # 从代码单元中提取该文件的符号（使用缓存）
            all_units = self._get_code_units()
            symbols = []
            for unit in all_units.values():
                if unit.file_path == file_path or file_path in unit.file_path:
                    symbols.append({
                        "name": unit.symbol,
                        "type": unit.unit_type.value,
                        "line_start": unit.span.start_line,
                        "line_end": unit.span.end_line,
                    })

            # 按行号排序
            symbols.sort(key=lambda x: x["line_start"])

            return {
                "success": True,
                "file_path": file_path,
                "symbols": symbols,
                "total": len(symbols),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_get_callers(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行获取调用者 - 基础版本

        查找谁调用了指定函数。支持通过 symbol_name 查找，
        可选限定文件路径和最大返回数量。
        """
        symbol_name = args.get("symbol_name", "")
        file_path = args.get("file_path")
        max_results = args.get("max_results", 10)

        if not symbol_name:
            return {"success": False, "error": "symbol_name 是必需参数"}

        try:
            # 首先在代码单元中查找目标符号（使用缓存）
            target_units = []
            for unit in self._get_code_units().values():
                match_level = self._match_symbol(symbol_name, unit.symbol)
                if match_level > 0:
                    if file_path and file_path not in unit.file_path:
                        continue
                    target_units.append((match_level, unit))

            # 按匹配等级排序（精确匹配优先）
            target_units.sort(key=lambda x: x[0], reverse=True)
            target_units = [u for _, u in target_units]

            if not target_units:
                return {
                    "success": False,
                    "error": f"未找到符号: {symbol_name}",
                    "hint": "请确认函数名称正确，或尝试使用部分名称搜索"
                }

            # 如果有调用链分析器，使用调用图查找
            callers_result = []

            if self.call_chain_analyzer and hasattr(self.call_chain_analyzer, 'call_graph'):
                call_graph = self.call_chain_analyzer.call_graph
                if call_graph:
                    for unit in target_units:
                        caller_nodes = call_graph.get_callers(unit.id)
                        for caller in caller_nodes[:max_results]:
                            callers_result.append({
                                "name": caller.name,
                                "qualified_name": caller.qualified_name,
                                "file_path": caller.file_path,
                                "line_start": caller.line_start,
                                "line_end": caller.line_end,
                                "node_type": caller.node_type.value if hasattr(caller.node_type, 'value') else str(caller.node_type),
                            })

            # 如果调用图没有结果，回退到代码单元的 calls 字段反向查找
            if not callers_result:
                for unit in self._get_code_units().values():
                    if unit.calls:
                        for call in unit.calls:
                            # 使用分级匹配替代模糊包含匹配
                            if self._match_symbol(symbol_name, call) >= 2 or call == symbol_name:
                                callers_result.append({
                                    "name": unit.symbol,
                                    "file_path": unit.file_path,
                                    "line_start": unit.span.start_line,
                                    "line_end": unit.span.end_line,
                                    "called_as": call,
                                })
                                if len(callers_result) >= max_results:
                                    break
                    if len(callers_result) >= max_results:
                        break

            return {
                "success": True,
                "symbol_name": symbol_name,
                "callers": callers_result[:max_results],
                "total": len(callers_result),
            }

        except Exception as e:
            logger.error(f"[UnifiedAgent] get_callers 执行失败: {e}")
            return {"success": False, "error": str(e)}

    def _execute_get_callees(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行获取被调用者 - 基础版本

        查找指定函数调用了哪些其他函数。支持通过 symbol_name 查找，
        可选限定文件路径和调用深度。
        """
        symbol_name = args.get("symbol_name", "")
        file_path = args.get("file_path")
        max_depth = args.get("max_depth", 1)

        if not symbol_name:
            return {"success": False, "error": "symbol_name 是必需参数"}

        try:
            # 使用缓存获取所有代码单元
            all_units = self._get_code_units()

            # 首先查找目标符号（分级匹配）
            scored_targets = []
            for unit in all_units.values():
                match_level = self._match_symbol(symbol_name, unit.symbol)
                if match_level > 0:
                    if file_path and file_path not in unit.file_path:
                        continue
                    scored_targets.append((match_level, unit))

            if not scored_targets:
                return {
                    "success": False,
                    "error": f"未找到符号: {symbol_name}",
                    "hint": "请确认函数名称正确，或尝试使用部分名称搜索"
                }

            scored_targets.sort(key=lambda x: x[0], reverse=True)
            target_units = [u for _, u in scored_targets]

            # 构建 symbol 快速查找字典（用于 callee 解析）
            unit_by_symbol: Dict[str, Any] = {}
            unit_by_short: Dict[str, list] = {}
            for unit in all_units.values():
                unit_by_symbol[unit.symbol] = unit
                short = unit.symbol.split(".")[-1]
                if short not in unit_by_short:
                    unit_by_short[short] = []
                unit_by_short[short].append(unit)

            def _resolve_callee(call_name: str):
                """从缓存字典中解析 callee 对应的代码单元"""
                # 精确匹配
                if call_name in unit_by_symbol:
                    return unit_by_symbol[call_name]
                # 短名匹配
                short = call_name.split(".")[-1]
                candidates = unit_by_short.get(short, [])
                if len(candidates) == 1:
                    return candidates[0]
                # 后缀匹配
                for c in candidates:
                    if c.symbol.endswith(f".{call_name}"):
                        return c
                return None

            # 收集所有被调用的函数
            callees_result = []
            seen_names = set()

            # 递归收集 callees
            def _collect_callees(units, depth, visited):
                """递归收集指定深度的 callees"""
                if depth > max_depth or depth > 5:  # 硬上限 5 层
                    return
                next_level_units = []
                for unit in units:
                    if unit.symbol in visited:
                        continue
                    visited.add(unit.symbol)
                    if not unit.calls:
                        continue
                    for call in unit.calls:
                        if call in seen_names:
                            continue
                        seen_names.add(call)
                        found_unit = _resolve_callee(call)
                        callee_info = {
                            "name": call,
                            "called_from": unit.symbol,
                            "source_file": unit.file_path,
                            "source_line": unit.span.start_line,
                            "depth": depth,
                        }
                        if found_unit:
                            callee_info.update({
                                "file_path": found_unit.file_path,
                                "line_start": found_unit.span.start_line,
                                "line_end": found_unit.span.end_line,
                                "is_internal": True,
                            })
                            next_level_units.append(found_unit)
                        else:
                            callee_info["is_internal"] = False
                        callees_result.append(callee_info)
                # 递归下一层
                if next_level_units and depth < max_depth:
                    _collect_callees(next_level_units, depth + 1, visited)

            _collect_callees(target_units, 1, set())

            # 如果有调用链分析器，补充调用图中的额外信息
            if self.call_chain_analyzer and hasattr(self.call_chain_analyzer, 'call_graph'):
                call_graph = self.call_chain_analyzer.call_graph
                if call_graph:
                    for unit in target_units:
                        callee_nodes = call_graph.get_callees(unit.id)
                        for callee in callee_nodes:
                            if callee.name not in seen_names:
                                seen_names.add(callee.name)
                                callees_result.append({
                                    "name": callee.name,
                                    "qualified_name": callee.qualified_name,
                                    "file_path": callee.file_path,
                                    "line_start": callee.line_start,
                                    "line_end": callee.line_end,
                                    "node_type": callee.node_type.value if hasattr(callee.node_type, 'value') else str(callee.node_type),
                                    "depth": 1,
                                    "source": "call_graph",
                                })

            return {
                "success": True,
                "symbol_name": symbol_name,
                "callees": callees_result,
                "total": len(callees_result),
                "max_depth": max_depth,
            }

        except Exception as e:
            logger.error(f"[UnifiedAgent] get_callees 执行失败: {e}")
            return {"success": False, "error": str(e)}

    def _execute_grep_code(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行精确代码搜索

        调用 CodeReader.grep_code() 进行正则/关键词搜索。
        """
        pattern = args.get("pattern", "")
        if not pattern:
            return {"success": False, "error": "pattern 是必需参数"}

        try:
            # 通过 code_reader 执行搜索
            if hasattr(self.indexer, 'code_reader') and self.indexer.code_reader:
                result = self.indexer.code_reader.grep_code(
                    pattern=pattern,
                    file_glob=args.get("file_glob"),
                    max_results=args.get("max_results", 50),
                    context_lines=args.get("context_lines", 2),
                    use_regex=args.get("use_regex", False),
                    case_sensitive=args.get("case_sensitive", True),
                )
                return result
            else:
                return {
                    "success": False,
                    "error": "CodeReader 未初始化",
                    "hint": "请确保项目已完成索引。",
                }

        except Exception as e:
            logger.error(f"[UnifiedAgent] grep_code 执行失败: {e}")
            return {"success": False, "error": str(e)}

    def _execute_report_finding(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行报告发现 - 保存漏洞并通过回调通知前端"""
        import uuid as uuid_module

        try:
            # 生成发现 ID
            finding_id = f"finding-{uuid_module.uuid4().hex[:8]}"

            # 提取参数
            finding_data = {
                "id": finding_id,
                "session_id": self.session_id,
                "severity": args.get("severity", "medium"),
                "title": args.get("title", "未命名发现"),
                "vulnerability_type": args.get("vulnerability_type", "unknown"),
                "file_path": args.get("file_path", ""),
                "line_number": args.get("line_number"),
                "description": args.get("description", ""),
                "code_evidence": args.get("code_evidence", ""),
                "attack_scenario": args.get("attack_scenario", ""),
                "fix_suggestion": args.get("fix_suggestion", ""),
                "confidence": args.get("confidence", 0.8),
                "status": "pending",  # pending, confirmed, rejected
                "reported_at": datetime.now().isoformat(),
            }

            # 存储到发现列表（内存）
            if not hasattr(self, '_findings'):
                self._findings: List[Dict[str, Any]] = []
            self._findings.append(finding_data)

            logger.info(f"[UnifiedAgent] 报告发现: {finding_data['title']} ({finding_data['severity']}) - {finding_data['file_path']}")

            # 触发回调通知前端（使用安全的跨线程调度）
            if self.config.on_finding_reported:
                self._schedule_async_callback(self.config.on_finding_reported, finding_data)

            return {
                "success": True,
                "finding_id": finding_id,
                "message": f"发现已记录: {finding_data['title']}",
                "severity": finding_data['severity'],
                "file_path": finding_data['file_path'],
            }

        except Exception as e:
            logger.error(f"[UnifiedAgent] 报告发现失败: {e}")
            return {"success": False, "error": str(e)}

    def _execute_confirm_finding(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行确认发现"""
        finding_id = args.get("finding_id", "")
        notes = args.get("notes", "")

        if not finding_id:
            return {"success": False, "error": "finding_id 是必需参数"}

        # 查找并更新发现状态
        if not hasattr(self, '_findings'):
            return {"success": False, "error": "没有可用的发现记录"}

        for finding in self._findings:
            if finding.get("id") == finding_id:
                finding["status"] = "confirmed"
                finding["notes"] = notes
                finding["updated_at"] = datetime.now().isoformat()

                # 通过回调通知前端
                if self.finding_callback:
                    self._schedule_async_callback(
                        self.finding_callback,
                        {"type": "finding_updated", "finding": finding}
                    )

                return {
                    "success": True,
                    "finding_id": finding_id,
                    "status": "confirmed",
                    "notes": notes,
                }

        return {
            "success": False,
            "error": f"未找到发现 ID: {finding_id}",
            "hint": "请确认发现 ID 是否正确",
        }

    def _execute_reject_finding(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行拒绝发现"""
        finding_id = args.get("finding_id", "")
        reason = args.get("reason", "")

        if not finding_id:
            return {"success": False, "error": "finding_id 是必需参数"}

        # 查找并更新发现状态
        if not hasattr(self, '_findings'):
            return {"success": False, "error": "没有可用的发现记录"}

        for finding in self._findings:
            if finding.get("id") == finding_id:
                finding["status"] = "rejected"
                finding["reason"] = reason
                finding["updated_at"] = datetime.now().isoformat()

                # 通过回调通知前端
                if self.finding_callback:
                    self._schedule_async_callback(
                        self.finding_callback,
                        {"type": "finding_updated", "finding": finding}
                    )

                return {
                    "success": True,
                    "finding_id": finding_id,
                    "status": "rejected",
                    "reason": reason,
                }

        return {
            "success": False,
            "error": f"未找到发现 ID: {finding_id}",
            "hint": "请确认发现 ID 是否正确",
        }

    def _execute_index_project(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行项目索引

        安全限制：只允许索引会话绑定的目标项目目录，防止意外索引其他目录
        """
        target_path = args.get("target_path")
        languages = args.get("languages")
        force_reindex = args.get("force_reindex", False)

        # 获取会话绑定的项目路径
        allowed_project_path = getattr(self.indexer, 'project_path', None)

        # 安全验证：限制只能索引会话绑定的目标项目
        if not allowed_project_path:
            return {
                "success": False,
                "error": "会话未绑定目标项目，无法执行索引操作。请先创建会话并指定目标项目。"
            }

        # 规范化路径进行比较
        import os
        allowed_normalized = os.path.normpath(os.path.abspath(allowed_project_path)).lower()

        # 如果未指定 target_path，使用会话绑定的项目路径
        if not target_path:
            target_path = allowed_project_path
        else:
            target_normalized = os.path.normpath(os.path.abspath(target_path)).lower()

            # 检查请求的路径是否在允许的项目目录内
            # BUG #5 Fix: 追加 os.sep 防止同前缀目录绕过（如 /project vs /project-evil）
            if not (target_normalized == allowed_normalized
                    or target_normalized.startswith(allowed_normalized + os.sep)):
                return {
                    "success": False,
                    "error": f"安全限制：只允许索引会话绑定的目标项目 '{allowed_project_path}'，"
                             f"不允许索引 '{target_path}'。"
                }

        try:
            # 执行索引
            self.indexer.index_directory(
                target_path=target_path,
            )

            # 索引更新后清除代码单元缓存
            self._invalidate_code_units_cache()

            return {
                "success": True,
                "target_path": target_path,
                "code_units_count": len(self._get_code_units()),
                "languages": languages,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    # ============ 状态查询 ============

    def get_session_state(self) -> Dict[str, Any]:
        """获取会话状态"""
        return {
            "session_id": self.session_id,
            "initialized": self._initialized,
            "is_processing": self._is_processing,
            "messages_count": len(self.messages),
            "tool_calls_count": len(self.tool_call_history),
            "total_llm_calls": self.total_llm_calls,
            "total_tool_calls": self.total_tool_calls,
            "total_tokens_used": self.total_tokens_used,
            "available_tools": self.tool_manager.get_all_names(),
        }

    def get_messages(self) -> List[Dict[str, Any]]:
        """获取所有消息"""
        return [m.to_dict() for m in self.messages]

    def get_tool_call_history(self) -> List[Dict[str, Any]]:
        """获取工具调用历史"""
        return [tc.to_dict() for tc in self.tool_call_history]

    def clear_history(self):
        """清空对话历史"""
        self.messages.clear()
        self.conversation_history.clear()
        self.tool_call_history.clear()
        self.total_llm_calls = 0
        self.total_tool_calls = 0
        self.total_tokens_used = 0
        self.prescan_result = None
        self.enhancement_result = None
        self._prescan_context = ""
        self._is_processing = False
        self._compressed_history_summary = ""
        logger.info(f"[UnifiedAgent] 已清空会话 {self.session_id} 的历史")

    # ============ 预扫描工具执行器 ============

    def _execute_get_prescan_summary(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """获取预扫描结果摘要"""
        if not self.prescan_result:
            return {
                "success": False,
                "error": "预扫描未执行或无结果",
            }

        result = self.prescan_result
        summary = {
            "success": True,
            "total_units_scanned": result.total_units_scanned,
            "total_sites_found": len(result.sink_sites),
            "filtered_sites_count": len(result.filtered_sites),
            "risk_summary": result.risk_summary.to_dict(),
            "category_summaries": [cs.to_dict() for cs in result.category_summaries],
            "scan_duration_ms": result.scan_duration_ms,
        }

        # 添加深度增强摘要
        if self.enhancement_result:
            summary["enhancement"] = {
                "high_confidence_count": self.enhancement_result.high_confidence_count,
                "call_graph_stats": self.enhancement_result.call_graph_stats,
                "taint_flow_count": self.enhancement_result.taint_flow_count,
            }

        return summary

    def _execute_list_security_rules(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """列出可用的安全检测规则和 Sink 模式"""
        vuln_type = args.get("vuln_type")
        risk_level = args.get("risk_level")
        language = args.get("language")
        limit = args.get("limit", 50)

        try:
            # 从规则管理器获取所有规则
            if not self.rule_manager:
                return {
                    "success": False,
                    "error": "规则管理器未初始化"
                }

            all_rules = self.rule_manager.get_all_rules()

            # 过滤规则
            filtered_rules = []
            for rule in all_rules:
                # 按漏洞类型过滤
                if vuln_type:
                    rule_category = getattr(rule, 'category', '') or ''
                    rule_vuln_type = getattr(rule, 'vulnerability_type', '') or ''
                    if vuln_type.lower() not in rule_category.lower() and vuln_type.lower() not in rule_vuln_type.lower():
                        continue

                # 按风险等级过滤
                if risk_level:
                    rule_risk = getattr(rule, 'risk_level', '') or ''
                    if isinstance(rule_risk, str):
                        if rule_risk.lower() != risk_level.lower():
                            continue
                    elif hasattr(rule_risk, 'value'):
                        if rule_risk.value.lower() != risk_level.lower():
                            continue

                # 按语言过滤
                if language:
                    rule_languages = getattr(rule, 'languages', []) or []
                    if language.lower() not in [l.lower() for l in rule_languages]:
                        continue

                filtered_rules.append(rule)

            # 截取
            filtered_rules = filtered_rules[:limit]

            # 构建返回结果
            patterns = []
            for rule in filtered_rules:
                pattern_info = {
                    "id": getattr(rule, 'id', '') or getattr(rule, 'rule_id', ''),
                    "name": getattr(rule, 'name', '') or getattr(rule, 'title', ''),
                    "type": getattr(rule, 'type', '') or '',
                    "category": getattr(rule, 'category', '') or '',
                    "risk_level": str(getattr(rule, 'risk_level', '')) if hasattr(rule, 'risk_level') else '',
                    "description": getattr(rule, 'description', '') or '',
                    "languages": getattr(rule, 'languages', []) or [],
                    "patterns": getattr(rule, 'patterns', []) or [],
                }
                # 处理 risk_level 枚举值
                if hasattr(pattern_info["risk_level"], 'value'):
                    pattern_info["risk_level"] = pattern_info["risk_level"].value
                patterns.append(pattern_info)

            # 统计信息
            stats = {
                "total_rules": len(all_rules),
                "filtered_count": len(patterns),
                "by_type": {},
                "by_risk_level": {},
            }

            for rule in all_rules:
                # 统计类型
                rule_type = getattr(rule, 'type', 'unknown') or 'unknown'
                if hasattr(rule_type, 'value'):
                    rule_type = rule_type.value
                stats["by_type"][rule_type] = stats["by_type"].get(rule_type, 0) + 1

                # 统计风险等级
                rule_risk = getattr(rule, 'risk_level', 'unknown') or 'unknown'
                if hasattr(rule_risk, 'value'):
                    rule_risk = rule_risk.value
                stats["by_risk_level"][str(rule_risk)] = stats["by_risk_level"].get(str(rule_risk), 0) + 1

            return {
                "success": True,
                "patterns": patterns,
                "stats": stats,
            }

        except Exception as e:
            logger.error(f"[UnifiedAgent] list_vuln_patterns 执行失败: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def _execute_get_prescan_sites(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """获取预扫描触发点列表"""
        if not self.prescan_result:
            return {
                "success": False,
                "error": "预扫描未执行或无结果",
            }

        risk_level = args.get("risk_level")
        category = args.get("category")
        limit = args.get("limit", 20)

        sites = self.prescan_result.filtered_sites

        # 过滤
        if risk_level:
            sites = [s for s in sites if s.risk_level.value == risk_level]
        if category:
            sites = [s for s in sites if s.sink_category.value == category]

        # 截取
        sites = sites[:limit]

        return {
            "success": True,
            "sites": [
                {
                    "id": s.id,
                    "file_path": s.file_path,
                    "line_start": s.line_start,
                    "line_end": s.line_end,
                    "symbol": s.symbol,
                    "risk_level": s.risk_level.value,
                    "sink_category": s.sink_category.value,
                    "matched_patterns": s.matched_patterns,
                    "confidence": s.confidence,
                    "call_snippet": s.call_snippet[:200] if s.call_snippet else "",
                }
                for s in sites
            ],
            "total": len(sites),
        }

    def _execute_get_site_details(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """获取单个触发点详情"""
        site_id = args.get("site_id", "")
        if not site_id:
            return {"success": False, "error": "site_id 是必需参数"}

        if not self.prescan_result:
            return {"success": False, "error": "预扫描未执行或无结果"}

        # 查找触发点
        site = None
        for s in self.prescan_result.filtered_sites:
            if s.id == site_id:
                site = s
                break

        if not site:
            return {"success": False, "error": f"未找到触发点: {site_id}"}

        result = {
            "success": True,
            "site": site.to_dict(),
        }

        # 添加深度增强信息
        if self.enhancement_result:
            for enhanced in self.enhancement_result.enhanced_sites:
                if enhanced.site.id == site_id:
                    result["enhancement"] = {
                        "enhanced_score": enhanced.enhanced_score,
                        "priority_rank": enhanced.priority_rank,
                        "analysis_notes": enhanced.analysis_notes,
                    }
                    if enhanced.call_chain_info:
                        result["call_chain"] = enhanced.call_chain_info.to_dict()
                    if enhanced.taint_info:
                        result["taint_info"] = enhanced.taint_info.to_dict()
                    break

        return result

    # ============ 深度分析工具执行器 ============

    def _execute_analyze_sink_call_chain(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """分析 Sink 触发点的完整调用链"""
        site_id = args.get("site_id")
        symbol_name = args.get("symbol_name")
        file_path = args.get("file_path")
        max_depth = args.get("max_depth", 10)
        include_code = args.get("include_code", True)

        # 获取目标 site 或 symbol
        target_site = None
        target_symbol = symbol_name

        if site_id and self.prescan_result:
            # 计算当前分析进度
            total_sites = len(self.prescan_result.filtered_sites)
            current_index = 0
            for i, s in enumerate(self.prescan_result.filtered_sites):
                if s.id == site_id:
                    target_site = s
                    target_symbol = s.symbol
                    file_path = file_path or s.file_path
                    current_index = i + 1
                    break

            # 触发分析进度回调（使用安全的跨线程调度）
            if target_site and self.config.on_analysis_progress:
                # 兼容旧字段 sink_name（历史对象）和当前字段 symbol（SinkCallSite）
                sink_name = getattr(target_site, "sink_name", None) or target_site.symbol
                progress_data = {
                    "current": current_index,
                    "total": total_sites,
                    "current_site": {
                        "id": site_id,
                        "sink_name": sink_name,
                        "file_path": target_site.file_path,
                        "line": target_site.line_start,
                    },
                }
                self._schedule_async_callback(self.config.on_analysis_progress, progress_data)

            if not target_site:
                return {"success": False, "error": f"未找到触发点: {site_id}"}

        if not target_symbol:
            return {"success": False, "error": "需要提供 site_id 或 symbol_name"}

        # 如果有深度增强结果，直接返回
        if target_site and self.enhancement_result:
            for enhanced in self.enhancement_result.enhanced_sites:
                if enhanced.site.id == site_id:
                    result = {
                        "success": True,
                        "symbol": target_symbol,
                        "file_path": target_site.file_path,
                        "line": target_site.line_start,
                        "risk_level": target_site.risk_level.value,
                        "sink_category": target_site.sink_category.value,
                    }
                    if enhanced.call_chain_info:
                        result["call_chain"] = enhanced.call_chain_info.to_dict()
                    if enhanced.taint_info:
                        result["taint_info"] = enhanced.taint_info.to_dict()
                    result["enhanced_score"] = enhanced.enhanced_score
                    result["analysis_notes"] = enhanced.analysis_notes

                    # 如果需要代码，添加相关代码
                    if include_code and enhanced.call_chain_info:
                        result["caller_code"] = self._get_caller_code(
                            enhanced.call_chain_info.callers[:5]
                        )
                    return result

        # 没有增强结果，使用 call_chain_analyzer
        if not self.call_chain_analyzer:
            return {"success": False, "error": "调用链分析器未配置"}

        try:
            # 查找节点
            nodes = self.call_chain_analyzer.call_graph.get_nodes_by_name(target_symbol)
            if file_path:
                nodes = [n for n in nodes if file_path in n.file_path]

            if not nodes:
                return {"success": False, "error": f"未找到符号: {target_symbol}"}

            node = nodes[0]
            callers = self._collect_call_chain(node.id, max_depth, include_code)
            entry_points = self._find_reachable_entry_points(node.id, max_depth)

            return {
                "success": True,
                "symbol": node.qualified_name,
                "file_path": node.file_path,
                "line": node.line_start,
                "callers": callers,
                "entry_points": entry_points,
                "call_chain_depth": len(callers),
                "has_entry_point": len(entry_points) > 0,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_find_similar_sinks(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """查找与指定 Sink 相似的代码模式"""
        site_id = args.get("site_id")
        code_pattern = args.get("code_pattern")
        top_k = args.get("top_k", 10)
        min_similarity = args.get("min_similarity", 0.7)

        # 获取查询代码
        query_code = code_pattern
        if site_id and self.prescan_result:
            for s in self.prescan_result.filtered_sites:
                if s.id == site_id:
                    query_code = s.call_snippet or s.symbol
                    break

        if not query_code:
            return {"success": False, "error": "需要提供 site_id 或 code_pattern"}

        if not self.vector_store:
            return {"success": False, "error": "向量存储未配置"}

        try:
            # 生成查询向量
            embed_response = self.llm_client.embed([query_code])
            if not embed_response or not embed_response.embeddings or not embed_response.embeddings[0]:
                return {"success": False, "error": "无法生成嵌入向量"}

            # 搜索相似代码
            results = self.vector_store.search(
                query_embedding=embed_response.embeddings[0],
                top_k=top_k * 2,
            )

            # 过滤和格式化
            similar_codes = []
            for r in results:
                if r.score < min_similarity:
                    continue

                metadata = r.metadata or {}
                similar_codes.append({
                    "file_path": metadata.get("file_path", ""),
                    "symbol": metadata.get("symbol", ""),
                    "line_start": metadata.get("line_start", 0),
                    "line_end": metadata.get("line_end", 0),
                    "similarity": round(r.score, 3),
                    "code_preview": (metadata.get("code") or "")[:300],
                    "language": metadata.get("language", ""),
                })

                if len(similar_codes) >= top_k:
                    break

            # 标记哪些是已知的 Sink
            if self.prescan_result:
                known_sinks = {s.symbol for s in self.prescan_result.filtered_sites}
                for item in similar_codes:
                    item["is_known_sink"] = item["symbol"] in known_sinks

            return {
                "success": True,
                "query_pattern": query_code[:100],
                "similar_codes": similar_codes,
                "total": len(similar_codes),
                "potential_variants": len([c for c in similar_codes if c.get("is_known_sink", False)]),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_analyze_entry_to_sink(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """分析从入口点到 Sink 的完整数据流路径"""
        entry_point = args.get("entry_point") or args.get("entry_name") or ""
        sink_site_id = args.get("sink_site_id") or args.get("site_id") or ""
        sink_name = args.get("sink_name") or ""
        include_intermediate_code = args.get("include_intermediate_code", True)

        if not entry_point:
            return {"success": False, "error": "entry_point 是必需参数（兼容别名: entry_name）"}

        # 获取 Sink 信息
        sink_site = None
        if self.prescan_result:
            if sink_site_id:
                for s in self.prescan_result.filtered_sites:
                    if s.id == sink_site_id:
                        sink_site = s
                        break

            # 兼容：仅提供 sink_name 时，尝试自动匹配触发点
            if not sink_site and sink_name:
                sink_name_lower = sink_name.lower()
                for s in self.prescan_result.filtered_sites:
                    snippet = (s.call_snippet or "").lower()
                    patterns = [p.lower() for p in (s.matched_patterns or [])]
                    if (
                        sink_name_lower == s.symbol.lower()
                        or sink_name_lower in snippet
                        or any(sink_name_lower in p for p in patterns)
                    ):
                        sink_site = s
                        break

        if not sink_site:
            if sink_site_id:
                return {"success": False, "error": f"未找到 Sink 触发点: {sink_site_id}"}
            return {"success": False, "error": "未找到 Sink 触发点，请提供 sink_site_id（或可匹配的 sink_name）"}

        if not self.call_chain_analyzer:
            return {"success": False, "error": "调用链分析器未配置"}

        try:
            # 查找入口点和 Sink 节点
            entry_nodes = self.call_chain_analyzer.call_graph.get_nodes_by_name(entry_point)
            # 兼容：当 entry_point 传的是文件名（如 high.php）时，尝试映射到脚本符号
            if not entry_nodes and entry_point.lower().endswith(".php"):
                script_symbol = f"<script:{Path(entry_point).name}>"
                entry_nodes = self.call_chain_analyzer.call_graph.get_nodes_by_name(script_symbol)
            sink_nodes = self.call_chain_analyzer.call_graph.get_nodes_by_name(sink_site.symbol)

            if not entry_nodes:
                return {"success": False, "error": f"未找到入口点: {entry_point}"}
            if not sink_nodes:
                return {"success": False, "error": f"未找到 Sink 节点: {sink_site.symbol}"}

            entry_node = entry_nodes[0]
            sink_node = sink_nodes[0]

            # 查找路径
            paths = self._find_paths_between(entry_node.id, sink_node.id, max_depth=15)

            if not paths:
                return {
                    "success": True,
                    "connected": False,
                    "message": f"未找到从 {entry_point} 到 {sink_site.symbol} 的调用路径",
                    "entry_point": {
                        "name": entry_node.qualified_name,
                        "file": entry_node.file_path,
                        "line": entry_node.line_start,
                    },
                    "sink": {
                        "name": sink_node.qualified_name,
                        "file": sink_node.file_path,
                        "line": sink_node.line_start,
                        "risk_level": sink_site.risk_level.value,
                    },
                }

            # 格式化路径
            formatted_paths = []
            for path in paths[:5]:  # 最多返回 5 条路径
                path_nodes = []
                for node_id in path:
                    node = self.call_chain_analyzer.call_graph.get_node(node_id)
                    if node:
                        node_info = {
                            "name": node.qualified_name,
                            "file": node.file_path,
                            "line": node.line_start,
                            "type": node.node_type.value,
                        }
                        if include_intermediate_code:
                            code = self._get_node_code(node)
                            if code:
                                node_info["code"] = code[:500]
                        path_nodes.append(node_info)
                formatted_paths.append({
                    "length": len(path_nodes),
                    "nodes": path_nodes,
                })

            # 检查是否有消毒函数
            has_sanitizer = False
            sanitizers = []
            for path in formatted_paths:
                for node in path["nodes"]:
                    if node.get("type") == "sanitizer":
                        has_sanitizer = True
                        sanitizers.append(node["name"])

            return {
                "success": True,
                "connected": True,
                "entry_point": {
                    "name": entry_node.qualified_name,
                    "file": entry_node.file_path,
                    "line": entry_node.line_start,
                },
                "sink": {
                    "name": sink_node.qualified_name,
                    "file": sink_node.file_path,
                    "line": sink_node.line_start,
                    "risk_level": sink_site.risk_level.value,
                    "category": sink_site.sink_category.value,
                },
                "paths": formatted_paths,
                "total_paths": len(paths),
                "shortest_path_length": min(len(p) for p in paths),
                "has_sanitizer": has_sanitizer,
                "sanitizers": list(set(sanitizers)),
                "exploitability": "high" if not has_sanitizer else "low",
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_analyze_taint_path(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """分析污点传播路径 - 从 Source 到 Sink

        追踪用户输入如何传播到危险函数调用点。
        """
        source_symbol = args.get("source_symbol", "")
        sink_symbol = args.get("sink_symbol", "")
        max_depth = args.get("max_depth", 10)

        try:
            # 如果没有调用链分析器，返回提示信息
            if not self.call_chain_analyzer:
                return {
                    "success": False,
                    "error": "调用链分析器未配置，无法进行污点分析",
                    "hint": "请先运行预扫描或确保项目已索引"
                }

            results = {
                "success": True,
                "source": source_symbol or "(all sources)",
                "sink": sink_symbol or "(all sinks)",
                "paths": [],
                "summary": {
                    "total_paths": 0,
                    "high_risk_paths": 0,
                    "sanitized_paths": 0,
                }
            }

            # 获取 Source 和 Sink 节点
            source_nodes = []
            sink_nodes = []

            if source_symbol:
                source_nodes = self.call_chain_analyzer.call_graph.get_nodes_by_name(source_symbol)
            else:
                # 获取所有 Source 类型节点
                source_nodes = self.call_chain_analyzer.call_graph.get_sources()

            if sink_symbol:
                sink_nodes = self.call_chain_analyzer.call_graph.get_nodes_by_name(sink_symbol)
            else:
                # 获取所有 Sink 类型节点
                sink_nodes = self.call_chain_analyzer.call_graph.get_sinks()

            if not source_nodes:
                return {
                    "success": True,
                    "message": f"未找到 Source: {source_symbol or '任意'}",
                    "paths": [],
                }

            if not sink_nodes:
                return {
                    "success": True,
                    "message": f"未找到 Sink: {sink_symbol or '任意'}",
                    "paths": [],
                }

            # 查找 Source -> Sink 路径
            for source in source_nodes[:5]:  # 限制 Source 数量
                for sink in sink_nodes[:10]:  # 限制 Sink 数量
                    paths = self._find_paths_between(source.id, sink.id, max_depth=max_depth)
                    for path in paths[:3]:  # 每对限制 3 条路径
                        path_info = {
                            "source": {
                                "name": source.qualified_name,
                                "file": source.file_path,
                                "line": source.line_start,
                            },
                            "sink": {
                                "name": sink.qualified_name,
                                "file": sink.file_path,
                                "line": sink.line_start,
                            },
                            "length": len(path),
                            "nodes": [],
                            "has_sanitizer": False,
                        }

                        # 填充路径节点
                        for node_id in path:
                            node = self.call_chain_analyzer.call_graph.get_node(node_id)
                            if node:
                                path_info["nodes"].append({
                                    "name": node.qualified_name,
                                    "type": node.node_type.value,
                                })
                                if node.node_type.value == "sanitizer":
                                    path_info["has_sanitizer"] = True

                        results["paths"].append(path_info)
                        results["summary"]["total_paths"] += 1
                        if not path_info["has_sanitizer"]:
                            results["summary"]["high_risk_paths"] += 1
                        else:
                            results["summary"]["sanitized_paths"] += 1

            return results

        except Exception as e:
            logger.error(f"[UnifiedAgent] analyze_taint_path 执行失败: {e}")
            return {"success": False, "error": str(e)}

    def _execute_check_auth(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """检查函数是否有认证和授权检查

        分析函数代码，检测是否包含认证/授权相关的检查逻辑。
        """
        symbol_name = args.get("symbol_name", "")
        check_type = args.get("check_type", "both")

        if not symbol_name:
            return {"success": False, "error": "symbol_name 是必需参数"}

        try:
            # 查找目标函数（使用缓存 + 分级匹配）
            all_units = self._get_code_units()
            best_match = None
            best_level = 0
            for unit in all_units.values():
                match_level = self._match_symbol(symbol_name, unit.symbol)
                if match_level > best_level:
                    best_level = match_level
                    best_match = unit

            target_unit = best_match

            if not target_unit:
                return {
                    "success": False,
                    "error": f"未找到符号: {symbol_name}",
                }

            code = target_unit.code or ""

            # 认证相关关键词
            auth_patterns = [
                "login", "authenticate", "is_authenticated", "require_login",
                "@login_required", "session", "jwt", "token", "bearer",
                "credentials", "password", "user_id", "current_user",
            ]

            # 授权相关关键词
            authz_patterns = [
                "authorize", "is_authorized", "permission", "role", "access",
                "@permission_required", "@role_required", "can_", "has_permission",
                "check_permission", "is_admin", "is_owner", "belongs_to",
            ]

            results = {
                "success": True,
                "symbol": symbol_name,
                "file_path": target_unit.file_path,
                "line_range": f"{target_unit.span.start_line}-{target_unit.span.end_line}",
                "checks": {
                    "authentication": {
                        "found": False,
                        "patterns": [],
                    },
                    "authorization": {
                        "found": False,
                        "patterns": [],
                    },
                },
                "risk_assessment": "unknown",
            }

            code_lower = code.lower()

            # 检查认证
            if check_type in ["authentication", "both"]:
                for pattern in auth_patterns:
                    if pattern.lower() in code_lower:
                        results["checks"]["authentication"]["found"] = True
                        results["checks"]["authentication"]["patterns"].append(pattern)

            # 检查授权
            if check_type in ["authorization", "both"]:
                for pattern in authz_patterns:
                    if pattern.lower() in code_lower:
                        results["checks"]["authorization"]["found"] = True
                        results["checks"]["authorization"]["patterns"].append(pattern)

            # 风险评估
            has_auth = results["checks"]["authentication"]["found"]
            has_authz = results["checks"]["authorization"]["found"]

            if has_auth and has_authz:
                results["risk_assessment"] = "low"
                results["assessment_reason"] = "函数包含认证和授权检查"
            elif has_auth:
                results["risk_assessment"] = "medium"
                results["assessment_reason"] = "函数包含认证检查，但可能缺少授权检查"
            elif has_authz:
                results["risk_assessment"] = "medium"
                results["assessment_reason"] = "函数包含授权检查，但可能缺少认证检查"
            else:
                results["risk_assessment"] = "high"
                results["assessment_reason"] = "未发现认证或授权检查，可能存在越权风险"

            return results

        except Exception as e:
            logger.error(f"[UnifiedAgent] check_auth 执行失败: {e}")
            return {"success": False, "error": str(e)}

    def _execute_find_entry_points(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """查找项目的入口点

        识别 HTTP 路由、API 端点等可被外部访问的函数。
        """
        framework = args.get("framework", "auto")
        include_internal = args.get("include_internal", False)

        try:
            # 框架特定的入口点模式
            framework_patterns = {
                "flask": [
                    r"@app\.route", r"@blueprint\.route", r"@.*\.route",
                    r"add_url_rule",
                ],
                "django": [
                    r"def\s+\w+\(request", r"class\s+\w+View",
                    r"path\(", r"url\(",
                ],
                "fastapi": [
                    r"@app\.(get|post|put|delete|patch)", r"@router\.(get|post|put|delete|patch)",
                    r"@.*\.(get|post|put|delete|patch)",
                ],
                "express": [
                    r"app\.(get|post|put|delete|patch)", r"router\.(get|post|put|delete|patch)",
                ],
                "spring": [
                    r"@(Get|Post|Put|Delete|Patch)Mapping", r"@RequestMapping",
                ],
            }

            # 通用入口点模式
            generic_patterns = [
                r"def\s+(handle|process|api|endpoint|route|controller|handler|service)",
                r"class\s+\w+(Controller|Handler|View|API|Endpoint)",
            ]

            import re

            entry_points = []

            # 确定要使用的模式
            patterns = []
            if framework == "auto":
                # 使用所有模式
                for fw_patterns in framework_patterns.values():
                    patterns.extend(fw_patterns)
                patterns.extend(generic_patterns)
            elif framework in framework_patterns:
                patterns = framework_patterns[framework] + generic_patterns
            else:
                patterns = generic_patterns

            # 遍历代码单元查找入口点（使用缓存）
            all_units = self._get_code_units()
            for unit in all_units.values():
                is_entry_point = False
                matched_pattern = None

                code = unit.code or ""

                for pattern in patterns:
                    if re.search(pattern, code, re.IGNORECASE):
                        is_entry_point = True
                        matched_pattern = pattern
                        break

                # 检查符号名是否匹配入口点命名模式
                entry_name_patterns = [
                    "handle", "process", "api", "endpoint", "route",
                    "controller", "handler", "view", "service",
                ]
                for name_pattern in entry_name_patterns:
                    if name_pattern in unit.symbol.lower():
                        is_entry_point = True
                        matched_pattern = f"name contains '{name_pattern}'"
                        break

                if is_entry_point:
                    # 过滤内部 API
                    if not include_internal:
                        internal_markers = ["_internal", "_private", "__", "test_", "_test"]
                        if any(marker in unit.symbol.lower() for marker in internal_markers):
                            continue

                    entry_points.append({
                        "name": unit.symbol,
                        "file_path": unit.file_path,
                        "line_start": unit.span.start_line,
                        "line_end": unit.span.end_line,
                        "matched_pattern": matched_pattern,
                        "language": unit.language,
                    })

            # 如果有调用链分析器，也获取其识别的入口点
            if self.call_chain_analyzer:
                call_graph_entries = self.call_chain_analyzer.call_graph.get_entry_points()
                for node in call_graph_entries:
                    if not any(ep["name"] == node.qualified_name for ep in entry_points):
                        entry_points.append({
                            "name": node.qualified_name,
                            "file_path": node.file_path,
                            "line_start": node.line_start,
                            "line_end": node.line_end,
                            "matched_pattern": "call_graph_entry_point",
                            "language": node.language,
                        })

            return {
                "success": True,
                "framework": framework,
                "include_internal": include_internal,
                "entry_points": entry_points,
                "total": len(entry_points),
            }

        except Exception as e:
            logger.error(f"[UnifiedAgent] find_entry_points 执行失败: {e}")
            return {"success": False, "error": str(e)}

    def _collect_call_chain(self, node_id: str, max_depth: int, include_code: bool) -> List[Dict[str, Any]]:
        """收集调用链信息"""
        if not self.call_chain_analyzer:
            return []

        chain = []
        visited = {node_id}
        queue = [(node_id, 0)]

        while queue and len(chain) < 30:
            current_id, depth = queue.pop(0)
            if depth >= max_depth:
                continue

            for caller in self.call_chain_analyzer.call_graph.get_callers(current_id):
                if caller.id in visited:
                    continue

                visited.add(caller.id)
                queue.append((caller.id, depth + 1))

                caller_info = {
                    "name": caller.qualified_name,
                    "file": caller.file_path,
                    "line": caller.line_start,
                    "depth": depth + 1,
                    "type": caller.node_type.value,
                }

                if include_code:
                    code = self._get_node_code(caller)
                    if code:
                        caller_info["code"] = code[:500]

                chain.append(caller_info)

        return chain

    def _find_reachable_entry_points(self, node_id: str, max_depth: int) -> List[Dict[str, Any]]:
        """查找可达的入口点"""
        if not self.call_chain_analyzer:
            return []

        from analyzer.call_chain import NodeType

        entry_points = []
        visited = set()

        def dfs(current_id: str, depth: int):
            if current_id in visited or depth > max_depth:
                return
            visited.add(current_id)

            node = self.call_chain_analyzer.call_graph.get_node(current_id)
            if node and node.node_type == NodeType.ENTRY_POINT:
                entry_points.append({
                    "name": node.qualified_name,
                    "file": node.file_path,
                    "line": node.line_start,
                    "decorators": node.metadata.get("decorators", []),
                })

            for caller in self.call_chain_analyzer.call_graph.get_callers(current_id):
                dfs(caller.id, depth + 1)

        dfs(node_id, 0)
        return entry_points

    def _find_paths_between(self, start_id: str, end_id: str, max_depth: int = 15) -> List[List[str]]:
        """查找两个节点之间的所有路径"""
        if not self.call_chain_analyzer:
            return []

        paths = []
        visited = set()

        def dfs(current_id: str, path: List[str], depth: int):
            if depth > max_depth or len(paths) >= 10:
                return

            if current_id == end_id:
                paths.append(path.copy())
                return

            visited.add(current_id)

            for callee in self.call_chain_analyzer.call_graph.get_callees(current_id):
                if callee.id not in visited:
                    path.append(callee.id)
                    dfs(callee.id, path, depth + 1)
                    path.pop()

            visited.remove(current_id)

        dfs(start_id, [start_id], 0)
        return paths

    def _get_node_code(self, node) -> Optional[str]:
        """获取节点的代码"""
        if hasattr(self, '_code_units_cache') and self._code_units_cache:
            for unit in self._code_units_cache.values():
                # 匹配逻辑：文件路径必须匹配，符号可以是完整名或简短名
                if unit.file_path == node.file_path:
                    # 尝试多种匹配方式
                    node_name = getattr(node, 'name', '') or ''
                    qualified_name = getattr(node, 'qualified_name', '') or ''
                    if (unit.symbol == node_name or
                        unit.symbol == qualified_name or
                        qualified_name.endswith('.' + unit.symbol) or
                        node_name == unit.symbol):
                        return unit.code
        return None

    def _get_caller_code(self, callers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """获取调用者的代码片段"""
        result = []
        for caller in callers:
            code = None
            caller_name = caller.get("name", "")
            caller_file = caller.get("file", "")

            if hasattr(self, '_code_units_cache') and self._code_units_cache:
                for unit in self._code_units_cache.values():
                    if unit.file_path == caller_file:
                        # 尝试多种匹配方式
                        if (unit.symbol == caller_name or
                            caller_name.endswith('.' + unit.symbol) or
                            caller_name == unit.symbol):
                            code = unit.code
                            break
            if code:
                result.append({
                    "name": caller_name,
                    "file": caller_file,
                    "code": code[:500],
                })
        return result


def create_unified_agent(
    session_id: str,
    llm_client: BaseLLMClient,
    indexer: CodeIndexer,
    config: Optional[UnifiedAgentConfig] = None,
    **kwargs,
) -> UnifiedAuditAgent:
    """创建统一审计智能体（工厂函数）

    Args:
        session_id: 会话 ID
        llm_client: LLM 客户端
        indexer: 代码索引器
        config: 配置
        **kwargs: 传递给 UnifiedAuditAgent 的其他参数

    Returns:
        UnifiedAuditAgent 实例
    """
    return UnifiedAuditAgent(
        session_id=session_id,
        llm_client=llm_client,
        indexer=indexer,
        config=config,
        **kwargs,
    )
