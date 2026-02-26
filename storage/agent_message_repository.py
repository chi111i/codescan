"""
智能审计消息仓库 - 消息 CRUD 操作

功能：
- 创建/查询消息
- 按会话获取消息历史
- 分页和增量查询
"""

import json
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field, asdict

from serialization import safe_json_dumps

from .database import DatabaseManager

logger = logging.getLogger(__name__)


@dataclass
class AgentMessage:
    """智能审计消息数据模型"""
    session_id: str
    role: str  # user/assistant/system/tool
    content: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    metadata: Optional[Dict[str, Any]] = None
    tokens_used: int = 0
    id: Optional[int] = None
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentMessage':
        """从字典创建实例"""
        if isinstance(data.get('tool_calls'), str):
            try:
                data['tool_calls'] = json.loads(data['tool_calls'])
            except (json.JSONDecodeError, TypeError):
                data['tool_calls'] = None

        if isinstance(data.get('metadata'), str):
            try:
                data['metadata'] = json.loads(data['metadata'])
            except (json.JSONDecodeError, TypeError):
                data['metadata'] = None

        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class AgentMessageRepository:
    """智能审计消息仓库"""

    def __init__(self, db: Optional[DatabaseManager] = None):
        """初始化仓库

        Args:
            db: 数据库管理器实例，默认使用单例
        """
        self.db = db or DatabaseManager()

    def create(
        self,
        session_id: str,
        role: str,
        content: Optional[str] = None,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tokens_used: int = 0
    ) -> AgentMessage:
        """创建消息

        Args:
            session_id: 会话 ID
            role: 角色 (user/assistant/system/tool)
            content: 消息内容
            tool_calls: 工具调用列表
            metadata: 额外元数据
            tokens_used: 使用的 Token 数

        Returns:
            创建的消息对象
        """
        now = datetime.now().isoformat()
        # tool_calls / metadata 可能包含 datetime/path/enum 等不可直接 JSON 序列化的对象
        tool_calls_json = safe_json_dumps(tool_calls, ensure_ascii=False) if tool_calls else None
        metadata_json = safe_json_dumps(metadata, ensure_ascii=False) if metadata else None

        sql = """
        INSERT INTO agent_messages (
            session_id, role, content, tool_calls, metadata, tokens_used, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            session_id,
            role,
            content,
            tool_calls_json,
            metadata_json,
            tokens_used,
            now
        )

        self.db.execute(sql, params)

        # 获取插入的 ID
        result = self.db.fetch_one("SELECT last_insert_rowid() as id")
        msg_id = result['id'] if result else None

        logger.debug(f"创建消息: session={session_id}, role={role}, id={msg_id}")

        return AgentMessage(
            id=msg_id,
            session_id=session_id,
            role=role,
            content=content,
            tool_calls=tool_calls,
            metadata=metadata,
            tokens_used=tokens_used,
            created_at=now
        )

    def get_by_session(
        self,
        session_id: str,
        limit: int = 100,
        offset: int = 0
    ) -> List[AgentMessage]:
        """获取会话的消息列表

        Args:
            session_id: 会话 ID
            limit: 返回数量限制
            offset: 偏移量

        Returns:
            消息列表（按时间正序）
        """
        sql = """
        SELECT * FROM agent_messages
        WHERE session_id = ?
        ORDER BY created_at ASC
        LIMIT ? OFFSET ?
        """
        rows = self.db.fetch_all(sql, (session_id, limit, offset))
        return [AgentMessage.from_dict(row) for row in rows]

    def get_latest(
        self,
        session_id: str,
        since_id: int = 0,
        limit: int = 50
    ) -> List[AgentMessage]:
        """获取会话最新消息（增量查询）

        Args:
            session_id: 会话 ID
            since_id: 从此 ID 之后的消息
            limit: 返回数量限制

        Returns:
            新消息列表
        """
        sql = """
        SELECT * FROM agent_messages
        WHERE session_id = ? AND id > ?
        ORDER BY created_at ASC
        LIMIT ?
        """
        rows = self.db.fetch_all(sql, (session_id, since_id, limit))
        return [AgentMessage.from_dict(row) for row in rows]

    def get_last_n(self, session_id: str, n: int = 10) -> List[AgentMessage]:
        """获取会话最后 N 条消息

        Args:
            session_id: 会话 ID
            n: 消息数量

        Returns:
            消息列表（按时间正序）
        """
        sql = """
        SELECT * FROM (
            SELECT * FROM agent_messages
            WHERE session_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        ) sub ORDER BY created_at ASC
        """
        rows = self.db.fetch_all(sql, (session_id, n))
        return [AgentMessage.from_dict(row) for row in rows]

    def count_by_session(self, session_id: str) -> int:
        """获取会话消息数量

        Args:
            session_id: 会话 ID

        Returns:
            消息数量
        """
        sql = "SELECT COUNT(*) as cnt FROM agent_messages WHERE session_id = ?"
        result = self.db.fetch_one(sql, (session_id,))
        return result['cnt'] if result else 0

    def delete_by_session(self, session_id: str) -> int:
        """删除会话的所有消息

        Args:
            session_id: 会话 ID

        Returns:
            删除的消息数量
        """
        count = self.count_by_session(session_id)
        sql = "DELETE FROM agent_messages WHERE session_id = ?"
        self.db.execute(sql, (session_id,))
        logger.info(f"删除会话 {session_id} 的 {count} 条消息")
        return count

    def get_first_user_message(self, session_id: str) -> Optional[AgentMessage]:
        """获取会话的第一条用户消息

        用于生成会话标题

        Args:
            session_id: 会话 ID

        Returns:
            第一条用户消息或 None
        """
        sql = """
        SELECT * FROM agent_messages
        WHERE session_id = ? AND role = 'user'
        ORDER BY created_at ASC
        LIMIT 1
        """
        row = self.db.fetch_one(sql, (session_id,))
        return AgentMessage.from_dict(row) if row else None

    def get_tool_calls_count(self, session_id: str) -> int:
        """获取会话的工具调用次数（统计实际 tool_call 条目数，而非消息数）

        Args:
            session_id: 会话 ID

        Returns:
            工具调用次数
        """
        sql = """
        SELECT COALESCE(SUM(json_array_length(tool_calls)), 0) as cnt
        FROM agent_messages
        WHERE session_id = ? AND tool_calls IS NOT NULL AND tool_calls != '[]'
        """
        result = self.db.fetch_one(sql, (session_id,))
        return result['cnt'] if result else 0

    def get_total_tokens(self, session_id: str) -> int:
        """获取会话的总 Token 使用量

        Args:
            session_id: 会话 ID

        Returns:
            总 Token 数
        """
        sql = "SELECT SUM(tokens_used) as total FROM agent_messages WHERE session_id = ?"
        result = self.db.fetch_one(sql, (session_id,))
        return result['total'] or 0 if result else 0

    def create_batch(self, messages: List[AgentMessage]) -> int:
        """批量创建消息

        Args:
            messages: 消息列表

        Returns:
            创建的消息数量
        """
        if not messages:
            return 0

        now = datetime.now().isoformat()
        sql = """
        INSERT INTO agent_messages (
            session_id, role, content, tool_calls, metadata, tokens_used, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        params_list = []
        for msg in messages:
            tool_calls_json = safe_json_dumps(msg.tool_calls, ensure_ascii=False) if msg.tool_calls else None
            metadata_json = safe_json_dumps(msg.metadata, ensure_ascii=False) if msg.metadata else None
            params_list.append((
                msg.session_id,
                msg.role,
                msg.content,
                tool_calls_json,
                metadata_json,
                msg.tokens_used,
                msg.created_at or now
            ))

        self.db.execute_many(sql, params_list)
        logger.info(f"批量创建 {len(messages)} 条消息")
        return len(messages)
