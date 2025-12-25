"""
交互式审计会话管理器

负责：
1. 创建和管理审计会话
2. 维护会话状态
3. 会话持久化
4. 会话清理
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any

from config import AuditConfig
from llm_client import BaseLLMClient
from indexer import CodeIndexer, CodeUnit
from rules import RuleManager

from .sink_scanner import SinkCallScanner, SinkCallSite
from .chain_context import ChainContextCollector, ChainContext
from .call_chain import CallChainAnalyzer
from .interactive_agent import InteractiveAuditAgent

logger = logging.getLogger(__name__)


class SessionStatus(Enum):
    """会话状态"""
    INITIALIZING = "initializing"  # 初始化中
    READY = "ready"                # 就绪
    ANALYZING = "analyzing"        # 分析中
    PAUSED = "paused"              # 暂停
    COMPLETED = "completed"        # 完成
    ERROR = "error"                # 错误


@dataclass
class SessionInfo:
    """会话信息"""
    session_id: str
    target_path: str
    status: SessionStatus
    created_at: datetime
    updated_at: datetime

    # 统计信息
    code_units_count: int = 0
    sink_sites_count: int = 0
    chain_contexts_count: int = 0
    pending_findings_count: int = 0
    confirmed_findings_count: int = 0
    rejected_findings_count: int = 0

    # 配置
    languages: List[str] = field(default_factory=list)
    max_chain_depth: int = 5

    # 错误信息
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_path": self.target_path,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "code_units_count": self.code_units_count,
            "sink_sites_count": self.sink_sites_count,
            "chain_contexts_count": self.chain_contexts_count,
            "pending_findings_count": self.pending_findings_count,
            "confirmed_findings_count": self.confirmed_findings_count,
            "rejected_findings_count": self.rejected_findings_count,
            "languages": self.languages,
            "max_chain_depth": self.max_chain_depth,
            "error_message": self.error_message,
        }


class InteractiveSessionManager:
    """交互式审计会话管理器

    负责创建、管理和清理交互式审计会话。
    """

    def __init__(
        self,
        config: AuditConfig,
        llm_client: BaseLLMClient,
        indexer: CodeIndexer,
        rule_manager: RuleManager,
        max_sessions: int = 10,
        session_timeout_hours: int = 24,
    ):
        """
        Args:
            config: 审计配置
            llm_client: LLM 客户端
            indexer: 代码索引器
            rule_manager: 规则管理器
            max_sessions: 最大并发会话数
            session_timeout_hours: 会话超时时间（小时）
        """
        self.config = config
        self.llm_client = llm_client
        self.indexer = indexer
        self.rule_manager = rule_manager
        self.max_sessions = max_sessions
        self.session_timeout = timedelta(hours=session_timeout_hours)

        # 会话存储
        self._sessions: Dict[str, InteractiveAuditAgent] = {}
        self._session_info: Dict[str, SessionInfo] = {}

        # 线程安全锁（用于保护会话字典的并发访问）
        self._lock = asyncio.Lock()

        # 组件
        self.sink_scanner = SinkCallScanner(rule_manager)
        self.call_chain_analyzer = CallChainAnalyzer(rule_manager)

        logger.info(
            f"[SessionManager] 初始化: max_sessions={max_sessions}, "
            f"timeout={session_timeout_hours}h"
        )

    async def create_session(
        self,
        target_path: str,
        languages: Optional[List[str]] = None,
        max_chain_depth: int = 5,
        skip_index: bool = True,
    ) -> SessionInfo:
        """创建新的审计会话

        Args:
            target_path: 目标路径
            languages: 限定语言列表
            max_chain_depth: 最大调用链深度
            skip_index: 是否跳过向量索引（直接解析）

        Returns:
            SessionInfo

        Raises:
            ValueError: 会话数超限或目标路径不存在
        """
        # 使用锁保护会话数检查和创建
        async with self._lock:
            # 检查会话数限制
            if len(self._sessions) >= self.max_sessions:
                # 尝试清理过期会话
                self._cleanup_expired_sessions()
                if len(self._sessions) >= self.max_sessions:
                    raise ValueError(f"会话数已达上限 ({self.max_sessions})")

            # 验证目标路径
            target = Path(target_path)
            if not target.exists():
                raise ValueError(f"目标路径不存在: {target_path}")

            # 生成会话 ID
            session_id = f"interactive-{uuid.uuid4().hex[:8]}"

            # 创建会话信息
            now = datetime.now()
            info = SessionInfo(
                session_id=session_id,
                target_path=str(target),
                status=SessionStatus.INITIALIZING,
                created_at=now,
                updated_at=now,
                languages=languages or [],
                max_chain_depth=max_chain_depth,
            )
            self._session_info[session_id] = info

        logger.info(f"[SessionManager] 创建会话 {session_id}: {target_path}")

        try:
            # 异步初始化会话（不持有锁，允许其他操作）
            agent = await self._initialize_session(
                session_id=session_id,
                target_path=str(target),
                languages=languages,
                max_chain_depth=max_chain_depth,
                skip_index=skip_index,
            )

            # 使用锁保护会话添加
            async with self._lock:
                self._sessions[session_id] = agent

                # 更新状态
                info.status = SessionStatus.READY
                info.code_units_count = len(agent.code_units)
                info.sink_sites_count = len(agent.sink_sites)
                info.chain_contexts_count = len(agent.chain_contexts)
                info.updated_at = datetime.now()

            logger.info(
                f"[SessionManager] 会话 {session_id} 就绪: "
                f"{info.code_units_count} 代码单元, "
                f"{info.sink_sites_count} sink sites, "
                f"{info.chain_contexts_count} 调用链"
            )

            return info

        except Exception as e:
            # 使用锁保护状态更新
            async with self._lock:
                info.status = SessionStatus.ERROR
                info.error_message = str(e)
                info.updated_at = datetime.now()
            logger.error(f"[SessionManager] 会话 {session_id} 初始化失败: {e}")
            raise

    async def _initialize_session(
        self,
        session_id: str,
        target_path: str,
        languages: Optional[List[str]],
        max_chain_depth: int,
        skip_index: bool,
    ) -> InteractiveAuditAgent:
        """初始化会话（异步）

        Args:
            session_id: 会话 ID
            target_path: 目标路径
            languages: 语言列表
            max_chain_depth: 最大调用链深度
            skip_index: 是否跳过索引

        Returns:
            InteractiveAuditAgent
        """
        # 1. 解析代码
        logger.info(f"[SessionManager] 会话 {session_id}: 解析代码...")

        if skip_index:
            # 直接解析，不使用向量索引
            code_units = await asyncio.to_thread(
                self.indexer.parse_directory_without_index,
                target_path,
                languages,
            )
        else:
            # 使用向量索引
            await asyncio.to_thread(
                self.indexer.index_directory,
                target_path,
            )
            code_units = await asyncio.to_thread(
                self.indexer.get_all_units,
            )
            if languages:
                code_units = [u for u in code_units if u.language in languages]

        logger.info(f"[SessionManager] 会话 {session_id}: 解析了 {len(code_units)} 个代码单元")

        # 2. 扫描 sink sites
        logger.info(f"[SessionManager] 会话 {session_id}: 扫描危险函数...")
        language = languages[0] if languages else None
        sink_sites = self.sink_scanner.scan(code_units, language)
        logger.info(f"[SessionManager] 会话 {session_id}: 发现 {len(sink_sites)} 个 sink sites")

        # 3. 构建调用图
        logger.info(f"[SessionManager] 会话 {session_id}: 构建调用图...")
        call_graph = await asyncio.to_thread(
            self.call_chain_analyzer.build_call_graph,
            code_units,
        )
        logger.info(
            f"[SessionManager] 会话 {session_id}: 调用图 "
            f"{len(call_graph.nodes)} 节点, {len(call_graph.edges)} 边"
        )

        # 4. 收集调用链上下文
        logger.info(f"[SessionManager] 会话 {session_id}: 收集调用链上下文...")
        context_collector = ChainContextCollector(
            call_chain_analyzer=self.call_chain_analyzer,
            code_units=code_units,
        )
        chain_contexts = context_collector.collect_contexts_batch(
            sink_sites=sink_sites,
            max_depth=max_chain_depth,
        )
        logger.info(f"[SessionManager] 会话 {session_id}: 收集了 {len(chain_contexts)} 个调用链上下文")

        # 5. 创建 Agent
        agent = InteractiveAuditAgent(
            session_id=session_id,
            llm_client=self.llm_client,
            target_path=target_path,
            code_units=code_units,
            sink_sites=sink_sites,
            chain_contexts=chain_contexts,
        )

        return agent

    def get_session(self, session_id: str) -> Optional[InteractiveAuditAgent]:
        """获取会话

        Args:
            session_id: 会话 ID

        Returns:
            InteractiveAuditAgent 或 None
        """
        agent = self._sessions.get(session_id)
        if agent:
            # 更新访问时间
            info = self._session_info.get(session_id)
            if info:
                info.updated_at = datetime.now()
        return agent

    def get_session_info(self, session_id: str) -> Optional[SessionInfo]:
        """获取会话信息

        Args:
            session_id: 会话 ID

        Returns:
            SessionInfo 或 None
        """
        info = self._session_info.get(session_id)
        if info and session_id in self._sessions:
            # 同步 agent 状态
            agent = self._sessions[session_id]
            info.pending_findings_count = len(agent.pending_findings)
            info.confirmed_findings_count = len(agent.confirmed_findings)
            info.rejected_findings_count = len(agent.rejected_findings)
        return info

    def list_sessions(self) -> List[SessionInfo]:
        """列出所有会话

        Returns:
            SessionInfo 列表
        """
        result = []
        for session_id, info in self._session_info.items():
            # 同步状态
            if session_id in self._sessions:
                agent = self._sessions[session_id]
                info.pending_findings_count = len(agent.pending_findings)
                info.confirmed_findings_count = len(agent.confirmed_findings)
                info.rejected_findings_count = len(agent.rejected_findings)
            result.append(info)

        # 按创建时间排序
        result.sort(key=lambda x: x.created_at, reverse=True)
        return result

    async def delete_session(self, session_id: str) -> bool:
        """删除会话

        Args:
            session_id: 会话 ID

        Returns:
            是否成功
        """
        async with self._lock:
            return self._delete_session_unlocked(session_id)

    def _delete_session_unlocked(self, session_id: str) -> bool:
        """删除会话（内部方法，不加锁，需要在锁内调用）

        Args:
            session_id: 会话 ID

        Returns:
            是否成功
        """
        if session_id not in self._sessions:
            return False

        del self._sessions[session_id]
        if session_id in self._session_info:
            del self._session_info[session_id]

        logger.info(f"[SessionManager] 删除会话: {session_id}")
        return True

    def update_session_status(
        self,
        session_id: str,
        status: SessionStatus,
        error_message: Optional[str] = None,
    ):
        """更新会话状态

        Args:
            session_id: 会话 ID
            status: 新状态
            error_message: 错误信息
        """
        info = self._session_info.get(session_id)
        if info:
            info.status = status
            info.updated_at = datetime.now()
            if error_message:
                info.error_message = error_message

    def _cleanup_expired_sessions(self):
        """清理过期会话（内部方法，需要在锁内调用）"""
        now = datetime.now()
        expired = []

        for session_id, info in self._session_info.items():
            if now - info.updated_at > self.session_timeout:
                expired.append(session_id)

        for session_id in expired:
            self._delete_session_unlocked(session_id)
            logger.info(f"[SessionManager] 清理过期会话: {session_id}")

    async def cleanup_all(self):
        """清理所有会话"""
        async with self._lock:
            session_ids = list(self._sessions.keys())
            for session_id in session_ids:
                self._delete_session_unlocked(session_id)
        logger.info(f"[SessionManager] 清理了 {len(session_ids)} 个会话")

    # ========== 会话操作代理方法 ==========

    async def analyze_selection(
        self,
        session_id: str,
        selected_chain_ids: List[str] = None,
        selected_unit_ids: List[str] = None,
        focus_areas: Optional[List[str]] = None,
        custom_prompt: Optional[str] = None,
    ):
        """分析选择的内容（代理方法）"""
        agent = self.get_session(session_id)
        if not agent:
            raise ValueError(f"会话不存在: {session_id}")

        self.update_session_status(session_id, SessionStatus.ANALYZING)

        try:
            result = await agent.analyze_selection(
                selected_chain_ids=selected_chain_ids,
                selected_unit_ids=selected_unit_ids,
                focus_areas=focus_areas,
                custom_prompt=custom_prompt,
            )
            self.update_session_status(session_id, SessionStatus.READY)
            return result
        except Exception as e:
            self.update_session_status(session_id, SessionStatus.ERROR, str(e))
            raise

    async def chat(self, session_id: str, message: str):
        """与 LLM 对话（代理方法）"""
        agent = self.get_session(session_id)
        if not agent:
            raise ValueError(f"会话不存在: {session_id}")

        return await agent.chat(message)

    async def dig_deeper(
        self,
        session_id: str,
        finding_id: str,
        direction: str = "expand",
    ):
        """深入分析（代理方法）"""
        agent = self.get_session(session_id)
        if not agent:
            raise ValueError(f"会话不存在: {session_id}")

        return await agent.dig_deeper(finding_id, direction)

    async def summarize(self, session_id: str):
        """生成总结（代理方法）"""
        agent = self.get_session(session_id)
        if not agent:
            raise ValueError(f"会话不存在: {session_id}")

        return await agent.summarize()

    def stop_analysis(self, session_id: str):
        """停止分析（代理方法）"""
        agent = self.get_session(session_id)
        if not agent:
            raise ValueError(f"会话不存在: {session_id}")

        self.update_session_status(session_id, SessionStatus.PAUSED)
        return agent.stop_analysis()

    def confirm_finding(self, session_id: str, finding_id: str, notes: str = "") -> bool:
        """确认发现（代理方法）"""
        agent = self.get_session(session_id)
        if not agent:
            raise ValueError(f"会话不存在: {session_id}")

        return agent.confirm_finding(finding_id, notes)

    def reject_finding(self, session_id: str, finding_id: str, reason: str = "") -> bool:
        """拒绝发现（代理方法）"""
        agent = self.get_session(session_id)
        if not agent:
            raise ValueError(f"会话不存在: {session_id}")

        return agent.reject_finding(finding_id, reason)

    def get_findings(self, session_id: str) -> Dict[str, List]:
        """获取所有发现（代理方法）"""
        agent = self.get_session(session_id)
        if not agent:
            raise ValueError(f"会话不存在: {session_id}")

        return agent.get_all_findings()

    def list_chain_contexts(self, session_id: str) -> List[Dict]:
        """列出调用链上下文（代理方法）"""
        agent = self.get_session(session_id)
        if not agent:
            raise ValueError(f"会话不存在: {session_id}")

        return agent.list_chain_contexts()

    def list_code_units(self, session_id: str) -> List[Dict]:
        """列出代码单元（代理方法）"""
        agent = self.get_session(session_id)
        if not agent:
            raise ValueError(f"会话不存在: {session_id}")

        return agent.list_code_units()

    def list_sink_sites(self, session_id: str) -> List[Dict]:
        """列出 sink sites（代理方法）"""
        agent = self.get_session(session_id)
        if not agent:
            raise ValueError(f"会话不存在: {session_id}")

        return agent.list_sink_sites()

    def get_chain_context_detail(self, session_id: str, chain_id: str) -> Optional[Dict]:
        """获取调用链详情"""
        agent = self.get_session(session_id)
        if not agent:
            return None

        ctx = agent.get_chain_context(chain_id)
        if not ctx:
            return None

        return {
            "id": chain_id,
            "sink_site": {
                "id": ctx.sink_site.id,
                "symbol": ctx.sink_site.symbol,
                "file_path": ctx.sink_site.file_path,
                "line_start": ctx.sink_site.line_start,
                "line_end": ctx.sink_site.line_end,
                "sink_category": ctx.sink_site.sink_category.value,
                "risk_level": ctx.sink_site.risk_level.value,
                "call_snippet": ctx.sink_site.call_snippet,
            },
            "chain_nodes": [
                {
                    "symbol": node.symbol,
                    "qualified_name": node.qualified_name,
                    "file_path": node.file_path,
                    "line_start": node.line_start,
                    "line_end": node.line_end,
                    "node_type": node.node_type,
                    "code": node.code,
                    "is_sink": node.is_sink,
                }
                for node in ctx.chain_nodes
            ],
            "entry_point": {
                "symbol": ctx.entry_point.symbol,
                "qualified_name": ctx.entry_point.qualified_name,
                "file_path": ctx.entry_point.file_path,
                "line_start": ctx.entry_point.line_start,
            } if ctx.entry_point else None,
            "chain_length": ctx.chain_length,
            "has_user_input": ctx.has_user_input,
            "sanitizers_on_path": ctx.sanitizers_on_path,
            "risk_level": ctx.risk_level,
            "confidence": ctx.confidence,
            "prompt_text": ctx.to_prompt_text(),
        }

    def get_code_unit_detail(self, session_id: str, unit_id: str) -> Optional[Dict]:
        """获取代码单元详情"""
        agent = self.get_session(session_id)
        if not agent:
            return None

        unit = agent.get_code_unit(unit_id)
        if not unit:
            return None

        return {
            "id": unit.id,
            "language": unit.language,
            "file_path": unit.file_path,
            "symbol": unit.symbol,
            "unit_type": unit.unit_type.value,
            "signature": unit.signature,
            "span": {
                "start_line": unit.span.start_line,
                "end_line": unit.span.end_line,
                "start_col": unit.span.start_col,
                "end_col": unit.span.end_col,
            },
            "code": unit.code,
            "docstring": unit.docstring,
            "calls": unit.calls,
            "parent_class": unit.parent_class,
            "decorators": unit.decorators,
            "imports": unit.imports,
        }
