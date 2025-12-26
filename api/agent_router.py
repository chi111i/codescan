"""统一智能体 API 路由

提供统一的智能审计入口，整合所有分析工具。

主要功能：
1. 会话管理（创建、获取、删除、恢复）
2. 对话交互（支持工具调用）
3. WebSocket 实时通信
4. 工具和状态查询
5. 会话和消息持久化
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Query

from serialization import to_jsonable, fast_safe_json_dumps, fast_json_loads

from .schemas_agent import (
    # 请求模型
    CreateUnifiedSessionRequest,
    UnifiedChatRequest,
    IndexProjectRequest,
    # 响应模型
    UnifiedSessionInfoSchema,
    UnifiedChatResponseSchema,
    AgentMessageSchema,
    ToolCallEventSchema,
    ToolDefinitionSchema,
    SessionStatsSchema,
    TokenBreakdownSchema,
    # 枚举
    UnifiedSessionStatus,
    ToolCallStatusEnum,
    WSEventType,
    WSEvent,
)
from .schemas import APIResponse
from storage import (
    AgentSessionRepository,
    AgentMessageRepository,
    AgentSession,
    AgentMessage,
)

logger = logging.getLogger(__name__)

# 创建路由器
router = APIRouter(prefix="/api/agent", tags=["unified-agent"])

# 内存中的活跃会话（智能体实例）
_active_agents: Dict[str, Any] = {}
_ws_connections: Dict[str, WebSocket] = {}

# 数据库仓库（延迟初始化）
_session_repo: Optional[AgentSessionRepository] = None
_message_repo: Optional[AgentMessageRepository] = None


def get_session_repo() -> AgentSessionRepository:
    """获取会话仓库"""
    global _session_repo
    if _session_repo is None:
        _session_repo = AgentSessionRepository()
    return _session_repo


def get_message_repo() -> AgentMessageRepository:
    """获取消息仓库"""
    global _message_repo
    if _message_repo is None:
        _message_repo = AgentMessageRepository()
    return _message_repo


# ============ 依赖注入 ============

def get_app_state():
    """获取应用状态"""
    from .main import app_state
    return app_state


def get_active_session(session_id: str) -> Dict[str, Any]:
    """获取内存中的活跃会话"""
    if session_id not in _active_agents:
        raise HTTPException(status_code=404, detail=f"会话不在活跃状态: {session_id}")
    return _active_agents[session_id]


async def _generate_session_title(llm_client, first_message: str) -> str:
    """使用 LLM 生成会话标题"""
    from llm_client import ChatMessage
    try:
        prompt = f"""根据以下用户的第一条消息，生成一个简短的会话标题（不超过20个字符）。
只返回标题文本，不要任何其他内容。

用户消息：{first_message[:200]}"""

        response = await asyncio.to_thread(
            llm_client.chat_completion,
            messages=[ChatMessage(role="user", content=prompt)],
            temperature=0.3,
            max_tokens=50,
        )

        title = (response.content or "").strip() if hasattr(response, 'content') else ""
        if title:
            return title[:50]
    except Exception as e:
        logger.warning(f"生成标题失败: {e}")

    # 回退：使用消息前20字符
    return first_message[:20] + ("..." if len(first_message) > 20 else "")


# ============ 会话管理 ============

@router.post("/session/create", response_model=APIResponse)
async def create_session(request: CreateUnifiedSessionRequest):
    """创建统一智能体会话

    初始化智能体并索引目标代码。
    """
    app_state = get_app_state()

    # 检查组件
    if not app_state.config or not app_state.llm_client or not app_state.indexer:
        raise HTTPException(status_code=500, detail="系统组件未完全初始化")

    try:
        # 生成会话 ID
        session_id = f"unified-{uuid.uuid4().hex[:8]}"

        # 导入统一智能体
        from agent import UnifiedAuditAgent, UnifiedAgentConfig, create_unified_agent

        # 创建配置
        agent_config = UnifiedAgentConfig(
            enable_call_chain=request.enable_call_chain,
            enable_variant_analysis=request.enable_variant_analysis,
            # === 预扫描配置 ===
            enable_prescan=request.enable_prescan,
            prescan_risk_levels=request.prescan_risk_levels,
            enable_deep_enhancement=request.enable_deep_enhancement,
        )

        # 获取可选的分析器
        call_chain_analyzer = None
        variant_analyzer = None

        # 如果有调用链分析器，获取它
        if hasattr(app_state, 'call_chain_analyzer'):
            call_chain_analyzer = app_state.call_chain_analyzer

        # 创建智能体
        agent = create_unified_agent(
            session_id=session_id,
            llm_client=app_state.llm_client,
            indexer=app_state.indexer,
            config=agent_config,
            call_chain_analyzer=call_chain_analyzer,
            variant_analyzer=variant_analyzer,
            vector_store=app_state.vector_store if hasattr(app_state, 'vector_store') else None,
        )

        # 【重要】先索引目标代码，然后再初始化智能体
        # 这样智能体初始化时可以获取到代码单元，进行预扫描
        if request.target_path:
            logger.info(f"[Session {session_id}] 阶段1/3: 开始索引目标代码 - {request.target_path}")
            import time
            start_time = time.time()
            await asyncio.to_thread(
                app_state.indexer.index_directory,
                target_path=request.target_path,
            )
            elapsed = time.time() - start_time
            logger.info(f"[Session {session_id}] 阶段1/3: 索引完成，耗时 {elapsed:.1f}s")

        # 初始化智能体（此时 indexer 中已有代码单元）
        logger.info(f"[Session {session_id}] 阶段2/3: 开始初始化智能体...")
        await agent.initialize()
        logger.info(f"[Session {session_id}] 阶段2/3: 智能体初始化完成")

        logger.info(f"[Session {session_id}] 阶段3/3: 保存会话状态...")
        now = datetime.now()
        config_dict = {
            "enable_call_chain": request.enable_call_chain,
            "enable_variant_analysis": request.enable_variant_analysis,
            "languages": request.languages,
            # === 预扫描配置 ===
            "enable_prescan": request.enable_prescan,
            "prescan_risk_levels": request.prescan_risk_levels,
            "enable_deep_enhancement": request.enable_deep_enhancement,
        }

        # 存储到数据库
        session_repo = get_session_repo()
        db_session = session_repo.create(
            session_id=session_id,
            target_path=request.target_path or "",
            config=config_dict,
            title=None,  # 标题在第一次对话后生成
        )

        # 存储到内存
        _active_agents[session_id] = {
            "agent": agent,
            "target_path": request.target_path,
            "created_at": now,
            "updated_at": now,
            "status": UnifiedSessionStatus.READY,
            "config": config_dict,
        }
        logger.info(f"[Session {session_id}] 阶段3/3: 会话就绪，可用工具 {agent.tool_manager.count()} 个")

        # 构建响应
        session_info = UnifiedSessionInfoSchema(
            session_id=session_id,
            target_path=request.target_path,
            status=UnifiedSessionStatus.READY,
            created_at=now,
            updated_at=now,
            available_tools=agent.tool_manager.get_all_names(),
            enable_call_chain=request.enable_call_chain,
            enable_variant_analysis=request.enable_variant_analysis,
        )

        return APIResponse(
            success=True,
            message=f"会话创建成功，可用工具: {agent.tool_manager.count()} 个",
            data=session_info.model_dump(mode='json'),
        )

    except Exception as e:
        logger.error(f"创建会话失败: {e}")
        raise HTTPException(status_code=500, detail=f"创建会话失败: {str(e)}")


@router.get("/session/{session_id}", response_model=APIResponse)
async def get_session(session_id: str):
    """获取会话信息"""
    # 先检查活跃会话
    if session_id in _active_agents:
        session = _active_agents[session_id]
        agent = session["agent"]
        state = agent.get_session_state()

        session_info = UnifiedSessionInfoSchema(
            session_id=session_id,
            target_path=session["target_path"],
            status=session["status"],
            created_at=session["created_at"],
            updated_at=session["updated_at"],
            messages_count=state.get("messages_count", 0),
            tool_calls_count=state.get("tool_calls_count", 0),
            total_llm_calls=state.get("total_llm_calls", 0),
            total_tokens_used=state.get("total_tokens_used", 0),
            available_tools=state.get("available_tools", []),
            enable_call_chain=session["config"].get("enable_call_chain", True),
            enable_variant_analysis=session["config"].get("enable_variant_analysis", True),
        )
    else:
        # 从数据库获取
        session_repo = get_session_repo()
        db_session = session_repo.get(session_id)
        if not db_session:
            raise HTTPException(status_code=404, detail=f"会话不存在: {session_id}")

        config = db_session.config or {}
        session_info = UnifiedSessionInfoSchema(
            session_id=session_id,
            target_path=db_session.target_path,
            status=UnifiedSessionStatus.ARCHIVED,  # 未激活的显示为已归档
            title=db_session.title,
            created_at=datetime.fromisoformat(db_session.created_at) if db_session.created_at else datetime.now(),
            updated_at=datetime.fromisoformat(db_session.updated_at) if db_session.updated_at else datetime.now(),
            messages_count=db_session.messages_count,
            tool_calls_count=db_session.tool_calls_count,
            total_tokens_used=db_session.total_tokens_used,
            enable_call_chain=config.get("enable_call_chain", True),
            enable_variant_analysis=config.get("enable_variant_analysis", True),
        )

    return APIResponse(
        success=True,
        message="获取成功",
        data=session_info.model_dump(mode='json'),
    )


@router.post("/session/{session_id}/restore", response_model=APIResponse)
async def restore_session(session_id: str):
    """恢复历史会话

    从数据库加载会话和消息历史，重新创建智能体实例。
    """
    # 如果已在活跃状态，直接返回
    if session_id in _active_agents:
        session = _active_agents[session_id]
        return APIResponse(
            success=True,
            message="会话已处于活跃状态",
            data={"session_id": session_id, "status": session["status"].value},
        )

    # 从数据库获取会话
    session_repo = get_session_repo()
    db_session = session_repo.get(session_id)
    if not db_session:
        raise HTTPException(status_code=404, detail=f"会话不存在: {session_id}")

    app_state = get_app_state()
    if not app_state.config or not app_state.llm_client or not app_state.indexer:
        raise HTTPException(status_code=500, detail="系统组件未完全初始化")

    try:
        # 导入统一智能体
        from agent import UnifiedAuditAgent, UnifiedAgentConfig, create_unified_agent

        config = db_session.config or {}

        # 创建配置
        agent_config = UnifiedAgentConfig(
            enable_call_chain=config.get("enable_call_chain", True),
            enable_variant_analysis=config.get("enable_variant_analysis", True),
        )

        # 获取可选的分析器
        call_chain_analyzer = None
        if hasattr(app_state, 'call_chain_analyzer'):
            call_chain_analyzer = app_state.call_chain_analyzer

        # 创建智能体
        agent = create_unified_agent(
            session_id=session_id,
            llm_client=app_state.llm_client,
            indexer=app_state.indexer,
            config=agent_config,
            call_chain_analyzer=call_chain_analyzer,
            variant_analyzer=None,
            vector_store=app_state.vector_store if hasattr(app_state, 'vector_store') else None,
        )

        # 【重要】先重新索引目标代码（如果有），再初始化智能体
        if db_session.target_path:
            logger.info(f"[Session] 恢复会话时重新索引: {db_session.target_path}")
            await asyncio.to_thread(
                app_state.indexer.index_directory,
                target_path=db_session.target_path,
            )

        # 初始化智能体（此时 indexer 中已有代码单元）
        await agent.initialize()

        # 加载历史消息到智能体
        message_repo = get_message_repo()
        history_messages = message_repo.get_by_session(session_id, limit=100)

        # 恢复消息历史到智能体
        from agent.unified_agent import AgentMessage
        from llm_client import ChatMessage
        for msg in history_messages:
            # 恢复智能体消息对象
            agent_msg = AgentMessage(
                role=msg.role,
                content=msg.content,
                timestamp=datetime.fromisoformat(msg.created_at) if msg.created_at else datetime.now(),
            )
            agent.messages.append(agent_msg)
            # 恢复 LLM 对话历史
            agent.conversation_history.append(ChatMessage(
                role=msg.role,
                content=msg.content,
            ))

        now = datetime.now()

        # 存储到内存
        _active_agents[session_id] = {
            "agent": agent,
            "target_path": db_session.target_path,
            "created_at": datetime.fromisoformat(db_session.created_at) if db_session.created_at else now,
            "updated_at": now,
            "status": UnifiedSessionStatus.READY,
            "config": config,
        }

        # 更新数据库状态
        session_repo.update(session_id, status="active")

        return APIResponse(
            success=True,
            message=f"会话已恢复，加载了 {len(history_messages)} 条历史消息",
            data={
                "session_id": session_id,
                "status": UnifiedSessionStatus.READY.value,
                "messages_count": len(history_messages),
                "target_path": db_session.target_path,
                "title": db_session.title,
            },
        )

    except Exception as e:
        logger.error(f"恢复会话失败: {e}")
        raise HTTPException(status_code=500, detail=f"恢复会话失败: {str(e)}")


@router.delete("/session/{session_id}", response_model=APIResponse)
async def delete_session(session_id: str):
    """删除会话"""
    session_repo = get_session_repo()
    message_repo = get_message_repo()

    # 如果在活跃状态，先清理内存
    if session_id in _active_agents:
        session = _active_agents[session_id]
        agent = session["agent"]
        agent.clear_history()
        del _active_agents[session_id]

    # 关闭 WebSocket 连接
    if session_id in _ws_connections:
        try:
            await _ws_connections[session_id].close()
        except Exception as e:
            logger.debug(f"关闭 WebSocket 连接时出错（可忽略）: {e}")
        del _ws_connections[session_id]

    # 从数据库删除（级联删除消息）
    if session_repo.exists(session_id):
        message_repo.delete_by_session(session_id)
        session_repo.delete(session_id)

    return APIResponse(
        success=True,
        message="会话已删除",
        data={"session_id": session_id},
    )


@router.get("/sessions", response_model=APIResponse)
async def list_sessions(
    status: Optional[str] = Query(None, description="状态筛选: active/completed/archived"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """列出所有会话（从数据库）"""
    session_repo = get_session_repo()

    # 从数据库获取会话列表
    db_sessions = session_repo.list_all(status=status, limit=limit, offset=offset)
    total = session_repo.count(status=status)

    sessions = []
    for db_session in db_sessions:
        # 检查是否在活跃状态
        is_active = db_session.session_id in _active_agents
        current_status = "active" if is_active else db_session.status

        sessions.append({
            "session_id": db_session.session_id,
            "target_path": db_session.target_path,
            "status": current_status,
            "title": db_session.title,
            "created_at": db_session.created_at,
            "updated_at": db_session.updated_at,
            "last_message_at": db_session.last_message_at,
            "messages_count": db_session.messages_count,
            "tool_calls_count": db_session.tool_calls_count,
            "total_tokens_used": db_session.total_tokens_used,
            "is_active": is_active,
        })

    return APIResponse(
        success=True,
        message=f"共 {total} 个会话",
        data={"sessions": sessions, "total": total, "limit": limit, "offset": offset},
    )


@router.get("/sessions/active", response_model=APIResponse)
async def list_active_sessions():
    """列出所有活跃会话（仅内存中的）"""
    sessions = []
    for sid, session in _active_agents.items():
        agent = session["agent"]
        state = agent.get_session_state()

        sessions.append({
            "session_id": sid,
            "target_path": session["target_path"],
            "status": session["status"].value,
            "created_at": session["created_at"].isoformat(),
            "updated_at": session["updated_at"].isoformat(),
            "messages_count": state.get("messages_count", 0),
            "tool_calls_count": len(agent.tool_call_history),
        })

    return APIResponse(
        success=True,
        message=f"共 {len(sessions)} 个活跃会话",
        data={"sessions": sessions, "total": len(sessions)},
    )


# ============ 对话交互 ============

@router.post("/session/{session_id}/chat", response_model=APIResponse)
async def chat(session_id: str, request: UnifiedChatRequest):
    """与智能体对话

    智能体会自主选择和调用工具来完成任务。
    """
    print(f"[DEBUG] ===== 收到 chat 请求: session={session_id} =====")  # 强制打印
    logger.info(f"[Chat] 收到对话请求: session={session_id}, message_len={len(request.message)}")
    session = get_active_session(session_id)
    agent = session["agent"]
    app_state = get_app_state()

    # 更新状态
    session["status"] = UnifiedSessionStatus.PROCESSING
    session["updated_at"] = datetime.now()

    message_repo = get_message_repo()
    session_repo = get_session_repo()

    try:
        # 保存用户消息到数据库
        logger.info(f"[Chat] 保存用户消息到数据库...")
        message_repo.create(
            session_id=session_id,
            role="user",
            content=request.message,
        )

        # 检查是否需要生成标题（第一条消息）
        db_session = session_repo.get(session_id)
        if db_session and not db_session.title:
            # 异步生成标题
            logger.info(f"[Chat] 生成会话标题...")
            title = await _generate_session_title(app_state.llm_client, request.message)
            session_repo.set_title(session_id, title)
            logger.info(f"[Chat] 标题已生成: {title}")

        # 调用智能体
        logger.info(f"[Chat] 开始调用智能体 chat()...")
        response = await agent.chat(request.message)
        logger.info(f"[Chat] 智能体响应完成, content_len={len(response.content or '')}, tool_calls={len(response.tool_calls)}")

        # 更新状态
        session["status"] = UnifiedSessionStatus.IDLE

        # 转换工具调用
        tool_calls = []
        tool_calls_data = []
        for tc in response.tool_calls:
            tool_call_schema = ToolCallEventSchema(
                id=tc.id,
                tool_name=tc.tool_name,
                arguments=to_jsonable(tc.arguments),
                status=ToolCallStatusEnum(tc.status.value),
                result=to_jsonable(tc.result),
                error=tc.error,
                started_at=tc.started_at,
                finished_at=tc.finished_at,
                duration_ms=tc.duration_ms,
            )
            tool_calls.append(tool_call_schema)
            tool_calls_data.append(tool_call_schema.model_dump(mode='json'))

        # 保存助手消息到数据库
        message_repo.create(
            session_id=session_id,
            role="assistant",
            content=response.content,
            tool_calls=tool_calls_data if tool_calls_data else None,
            metadata=to_jsonable(response.metadata),
        )

        # 更新会话统计
        session_repo.increment_stats(
            session_id=session_id,
            messages_delta=2,  # 用户消息 + 助手消息
            tool_calls_delta=len(tool_calls),
        )

        message_schema = AgentMessageSchema(
            role=response.role,
            content=response.content,
            tool_calls=tool_calls,
            timestamp=response.timestamp,
            metadata=to_jsonable(response.metadata),
        )

        chat_response = UnifiedChatResponseSchema(
            message=message_schema,
            session_status=session["status"],
            tool_calls_count=len(tool_calls),
        )

        return APIResponse(
            success=True,
            message=f"对话完成，调用了 {len(tool_calls)} 个工具",
            data=chat_response.model_dump(mode='json'),
        )

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        error_type = type(e).__name__
        logger.error(f"对话失败: {error_type}: {e}")
        logger.error(f"错误堆栈:\n{error_trace}")
        session["status"] = UnifiedSessionStatus.ERROR
        raise HTTPException(status_code=500, detail=f"对话失败: {error_type}: {str(e)}")


@router.get("/session/{session_id}/messages", response_model=APIResponse)
async def get_messages(session_id: str, limit: int = 50, offset: int = 0):
    """获取会话消息历史（从数据库）"""
    message_repo = get_message_repo()
    session_repo = get_session_repo()

    # 验证会话存在
    if not session_repo.exists(session_id):
        raise HTTPException(status_code=404, detail=f"会话不存在: {session_id}")

    messages = message_repo.get_by_session(session_id, limit=limit, offset=offset)
    total = message_repo.count_by_session(session_id)

    # 转换为字典列表
    messages_data = [msg.to_dict() for msg in messages]

    return APIResponse(
        success=True,
        message=f"共 {total} 条消息",
        data={"messages": messages_data, "total": total, "limit": limit, "offset": offset},
    )


@router.get("/session/{session_id}/tool-calls", response_model=APIResponse)
async def get_tool_calls(session_id: str, limit: int = 100):
    """获取工具调用历史"""
    # 优先从活跃会话获取
    if session_id in _active_agents:
        session = _active_agents[session_id]
        agent = session["agent"]
        tool_calls = agent.get_tool_call_history()[-limit:]

        return APIResponse(
            success=True,
            message=f"共 {len(tool_calls)} 次工具调用",
            data={"tool_calls": tool_calls, "total": len(agent.tool_call_history)},
        )

    # 从数据库消息中提取工具调用
    message_repo = get_message_repo()
    messages = message_repo.get_by_session(session_id, limit=500)

    tool_calls = []
    for msg in messages:
        if msg.tool_calls:
            tool_calls.extend(msg.tool_calls)

    return APIResponse(
        success=True,
        message=f"共 {len(tool_calls)} 次工具调用",
        data={"tool_calls": tool_calls[-limit:], "total": len(tool_calls)},
    )


@router.post("/session/{session_id}/clear-history", response_model=APIResponse)
async def clear_history(session_id: str):
    """清空会话历史"""
    session_repo = get_session_repo()
    message_repo = get_message_repo()

    # 验证会话存在
    if not session_repo.exists(session_id):
        raise HTTPException(status_code=404, detail=f"会话不存在: {session_id}")

    # 清理内存中的智能体历史
    if session_id in _active_agents:
        session = _active_agents[session_id]
        agent = session["agent"]
        agent.clear_history()
        session["updated_at"] = datetime.now()

    # 清理数据库消息
    deleted_count = message_repo.delete_by_session(session_id)

    # 重置会话统计
    session_repo.update_stats(session_id, 0, 0, 0)

    return APIResponse(
        success=True,
        message=f"已清空 {deleted_count} 条历史消息",
        data={"session_id": session_id, "deleted_count": deleted_count},
    )


# ============ 工具查询 ============

@router.get("/session/{session_id}/tools", response_model=APIResponse)
async def get_tools(session_id: str, category: Optional[str] = None):
    """获取可用工具列表"""
    session = get_active_session(session_id)
    agent = session["agent"]

    if category:
        tools = agent.tool_manager.get_tools_by_category(category)
    else:
        tools = agent.tool_manager.get_tools_for_llm()

    # 简化输出
    tool_list = []
    for tool in tools:
        func = tool.get("function") or {}
        description = func.get("description") or ""
        definition = agent.tool_manager.get_tool(func.get("name", ""))
        tool_list.append({
            "name": func.get("name", ""),
            "description": description[:200] if description else "",
            "category": definition.category if definition else "general",
        })

    return APIResponse(
        success=True,
        message=f"共 {len(tool_list)} 个工具",
        data={"tools": tool_list, "total": len(tool_list)},
    )


@router.get("/session/{session_id}/stats", response_model=APIResponse)
async def get_stats(session_id: str):
    """获取会话统计"""
    # 优先从活跃会话获取
    if session_id in _active_agents:
        session = _active_agents[session_id]
        agent = session["agent"]
        state = agent.get_session_state()

        stats = SessionStatsSchema(
            messages_count=len(agent.messages),
            tool_calls_count=len(agent.tool_call_history),
            total_llm_calls=state.get("total_llm_calls", 0),
            total_tokens_used=state.get("total_tokens_used", 0),
        )
    else:
        # 从数据库获取
        session_repo = get_session_repo()
        db_session = session_repo.get(session_id)
        if not db_session:
            raise HTTPException(status_code=404, detail=f"会话不存在: {session_id}")

        stats = SessionStatsSchema(
            messages_count=db_session.messages_count,
            tool_calls_count=db_session.tool_calls_count,
            total_llm_calls=0,
            total_tokens_used=db_session.total_tokens_used,
        )

    return APIResponse(
        success=True,
        message="获取成功",
        data=stats.model_dump(mode='json'),
    )


# ============ 项目操作 ============

@router.post("/session/{session_id}/index", response_model=APIResponse)
async def index_project(session_id: str, request: IndexProjectRequest):
    """索引或重新索引项目"""
    session = get_active_session(session_id)
    app_state = get_app_state()

    target_path = request.target_path or session["target_path"]

    try:
        # 执行索引
        await asyncio.to_thread(
            app_state.indexer.index_directory,
            target_path=target_path,
        )

        code_units_count = len(app_state.indexer.code_units) if app_state.indexer.code_units else 0

        return APIResponse(
            success=True,
            message=f"索引完成，共 {code_units_count} 个代码单元",
            data={
                "target_path": target_path,
                "code_units_count": code_units_count,
                "languages": request.languages,
            },
        )

    except Exception as e:
        logger.error(f"索引失败: {e}")
        raise HTTPException(status_code=500, detail=f"索引失败: {str(e)}")


# ============ WebSocket ============


async def _safe_send_json(websocket: WebSocket, data: Any):
    """安全发送 JSON 数据 (使用 orjson 加速)"""
    await websocket.send_text(fast_safe_json_dumps(data))


@router.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    """WebSocket 实时通信

    支持：
    - 工具调用实时状态
    - 流式响应
    - 心跳检测
    """
    await websocket.accept()
    _ws_connections[session_id] = websocket

    logger.info(f"WebSocket 连接已建立: {session_id}")

    # 发送连接成功事件
    await _safe_send_json(websocket,
        WSEvent(
            type=WSEventType.CONNECTED,
            session_id=session_id,
            data={"message": "连接成功"},
        ).model_dump(mode='json')
    )

    try:
        while True:
            # 接收消息 (使用 orjson 加速反序列化)
            raw_data = await websocket.receive_text()
            data = fast_json_loads(raw_data)
            msg_type = data.get("type", "")

            if msg_type == "ping":
                await _safe_send_json(websocket,
                    WSEvent(
                        type=WSEventType.PONG,
                        session_id=session_id,
                    ).model_dump(mode='json')
                )

            elif msg_type == "chat":
                # 处理聊天消息
                message = data.get("message", "")
                use_stream = data.get("stream", True)  # 默认使用流式

                if not message:
                    continue

                if session_id not in _active_agents:
                    await _safe_send_json(websocket,
                        WSEvent(
                            type=WSEventType.ERROR,
                            session_id=session_id,
                            data={"error": f"会话未激活: {session_id}"},
                        ).model_dump(mode='json')
                    )
                    continue

                agent = _active_agents[session_id]["agent"]

                if use_stream:
                    # 使用流式响应
                    try:
                        async for event in agent.chat_stream(message):
                            event_type = event.get("type", "")

                            if event_type == "start":
                                # 开始处理
                                pass
                            elif event_type == "tool_call_start":
                                await _safe_send_json(websocket,
                                    WSEvent(
                                        type=WSEventType.TOOL_CALL_START,
                                        session_id=session_id,
                                        data=event.get("data", {}),
                                    ).model_dump(mode='json')
                                )
                            elif event_type == "tool_call_end":
                                await _safe_send_json(websocket,
                                    WSEvent(
                                        type=WSEventType.TOOL_CALL_END,
                                        session_id=session_id,
                                        data=event.get("data", {}),
                                    ).model_dump(mode='json')
                                )
                            elif event_type == "chunk":
                                # 发送内容块
                                await _safe_send_json(websocket,
                                    WSEvent(
                                        type=WSEventType.MESSAGE_CHUNK,
                                        session_id=session_id,
                                        data={"content": event.get("content", "")},
                                    ).model_dump(mode='json')
                                )
                            elif event_type == "message":
                                # 发送完成消息
                                await _safe_send_json(websocket,
                                    WSEvent(
                                        type=WSEventType.MESSAGE_COMPLETE,
                                        session_id=session_id,
                                        data=event.get("data", {}),
                                    ).model_dump(mode='json')
                                )
                            elif event_type == "error":
                                await _safe_send_json(websocket,
                                    WSEvent(
                                        type=WSEventType.ERROR,
                                        session_id=session_id,
                                        data=event.get("data", {}),
                                    ).model_dump(mode='json')
                                )
                    except Exception as e:
                        import traceback
                        error_trace = traceback.format_exc()
                        logger.error(f"流式响应失败: {type(e).__name__}: {e}")
                        logger.error(f"错误堆栈:\n{error_trace}")
                        await _safe_send_json(websocket,
                            WSEvent(
                                type=WSEventType.ERROR,
                                session_id=session_id,
                                data={
                                    "error": f"{type(e).__name__}: {str(e)}",
                                    "error_type": type(e).__name__,
                                    "error_trace": error_trace,
                                },
                            ).model_dump(mode='json')
                        )
                else:
                    # 非流式响应（保持向后兼容）
                    response = await agent.chat(message)
                    await _safe_send_json(websocket,
                        WSEvent(
                            type=WSEventType.MESSAGE_COMPLETE,
                            session_id=session_id,
                            data=response.to_dict(),
                        ).model_dump(mode='json')
                    )

    except WebSocketDisconnect:
        logger.info(f"WebSocket 连接断开: {session_id}")
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"WebSocket 错误: {type(e).__name__}: {e}")
        logger.error(f"错误堆栈:\n{error_trace}")
        # 尝试发送错误消息，但连接可能已断开
        try:
            await _safe_send_json(websocket,
                WSEvent(
                    type=WSEventType.ERROR,
                    session_id=session_id,
                    data={
                        "error": f"{type(e).__name__}: {str(e)}",
                        "error_type": type(e).__name__,
                        "error_trace": error_trace,
                    },
                ).model_dump(mode='json')
            )
        except Exception:
            logger.debug(f"无法发送错误消息到 WebSocket (可能已断开): {session_id}")
    finally:
        if session_id in _ws_connections:
            try:
                await _ws_connections[session_id].close()
            except Exception as e:
                logger.debug(f"关闭 WebSocket 连接时出错（可忽略）: {e}")
            del _ws_connections[session_id]


async def broadcast_to_session(session_id: str, event: WSEvent):
    """向会话广播消息"""
    if session_id in _ws_connections:
        try:
            await _safe_send_json(_ws_connections[session_id], event.model_dump(mode='json'))
        except Exception as e:
            logger.warning(f"广播失败: {e}")
