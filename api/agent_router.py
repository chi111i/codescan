"""统一智能体 API 路由

提供统一的智能审计入口，整合所有分析工具。

主要功能：
1. 会话管理（创建、获取、删除）
2. 对话交互（支持工具调用）
3. WebSocket 实时通信
4. 工具和状态查询
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Optional, Dict, Any

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

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

logger = logging.getLogger(__name__)

# 创建路由器
router = APIRouter(prefix="/api/agent", tags=["unified-agent"])

# 会话存储
_unified_sessions: Dict[str, Any] = {}
_ws_connections: Dict[str, WebSocket] = {}


# ============ 依赖注入 ============

def get_app_state():
    """获取应用状态"""
    from .main import app_state
    return app_state


def get_or_create_session(session_id: str):
    """获取或验证会话"""
    if session_id not in _unified_sessions:
        raise HTTPException(status_code=404, detail=f"会话不存在: {session_id}")
    return _unified_sessions[session_id]


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
        config = UnifiedAgentConfig(
            enable_call_chain=request.enable_call_chain,
            enable_variant_analysis=request.enable_variant_analysis,
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
            config=config,
            call_chain_analyzer=call_chain_analyzer,
            variant_analyzer=variant_analyzer,
            vector_store=app_state.vector_store if hasattr(app_state, 'vector_store') else None,
        )

        # 初始化智能体
        await agent.initialize()

        # 索引目标代码
        if request.target_path:
            app_state.indexer.index_directory(
                target_path=request.target_path,
            )

        # 存储会话
        _unified_sessions[session_id] = {
            "agent": agent,
            "target_path": request.target_path,
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "status": UnifiedSessionStatus.READY,
            "config": {
                "enable_call_chain": request.enable_call_chain,
                "enable_variant_analysis": request.enable_variant_analysis,
                "languages": request.languages,
            },
        }

        # 构建响应
        session_info = UnifiedSessionInfoSchema(
            session_id=session_id,
            target_path=request.target_path,
            status=UnifiedSessionStatus.READY,
            created_at=_unified_sessions[session_id]["created_at"],
            updated_at=_unified_sessions[session_id]["updated_at"],
            available_tools=agent.tool_manager.get_all_names(),
            enable_call_chain=request.enable_call_chain,
            enable_variant_analysis=request.enable_variant_analysis,
        )

        return APIResponse(
            success=True,
            message=f"会话创建成功，可用工具: {agent.tool_manager.count()} 个",
            data=session_info.model_dump(),
        )

    except Exception as e:
        logger.error(f"创建会话失败: {e}")
        raise HTTPException(status_code=500, detail=f"创建会话失败: {str(e)}")


@router.get("/session/{session_id}", response_model=APIResponse)
async def get_session(session_id: str):
    """获取会话信息"""
    session = get_or_create_session(session_id)
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

    return APIResponse(
        success=True,
        message="获取成功",
        data=session_info.model_dump(),
    )


@router.delete("/session/{session_id}", response_model=APIResponse)
async def delete_session(session_id: str):
    """删除会话"""
    if session_id not in _unified_sessions:
        raise HTTPException(status_code=404, detail=f"会话不存在: {session_id}")

    # 清理智能体
    session = _unified_sessions[session_id]
    agent = session["agent"]
    agent.clear_history()

    # 删除会话
    del _unified_sessions[session_id]

    # 关闭 WebSocket 连接
    if session_id in _ws_connections:
        try:
            await _ws_connections[session_id].close()
        except:
            pass
        del _ws_connections[session_id]

    return APIResponse(
        success=True,
        message="会话已删除",
        data={"session_id": session_id},
    )


@router.get("/sessions", response_model=APIResponse)
async def list_sessions():
    """列出所有会话"""
    sessions = []
    for sid, session in _unified_sessions.items():
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
        message=f"共 {len(sessions)} 个会话",
        data={"sessions": sessions, "total": len(sessions)},
    )


# ============ 对话交互 ============

@router.post("/session/{session_id}/chat", response_model=APIResponse)
async def chat(session_id: str, request: UnifiedChatRequest):
    """与智能体对话

    智能体会自主选择和调用工具来完成任务。
    """
    session = get_or_create_session(session_id)
    agent = session["agent"]

    # 更新状态
    session["status"] = UnifiedSessionStatus.PROCESSING
    session["updated_at"] = datetime.now()

    try:
        # 调用智能体
        response = await agent.chat(request.message)

        # 更新状态
        session["status"] = UnifiedSessionStatus.IDLE

        # 转换响应
        tool_calls = [
            ToolCallEventSchema(
                id=tc.id,
                tool_name=tc.tool_name,
                arguments=tc.arguments,
                status=ToolCallStatusEnum(tc.status.value),
                result=tc.result,
                error=tc.error,
                started_at=tc.started_at,
                finished_at=tc.finished_at,
                duration_ms=tc.duration_ms,
            )
            for tc in response.tool_calls
        ]

        message_schema = AgentMessageSchema(
            role=response.role,
            content=response.content,
            tool_calls=tool_calls,
            timestamp=response.timestamp,
            metadata=response.metadata,
        )

        chat_response = UnifiedChatResponseSchema(
            message=message_schema,
            session_status=session["status"],
            tool_calls_count=len(tool_calls),
        )

        return APIResponse(
            success=True,
            message=f"对话完成，调用了 {len(tool_calls)} 个工具",
            data=chat_response.model_dump(),
        )

    except Exception as e:
        logger.error(f"对话失败: {e}")
        session["status"] = UnifiedSessionStatus.ERROR
        raise HTTPException(status_code=500, detail=f"对话失败: {str(e)}")


@router.get("/session/{session_id}/messages", response_model=APIResponse)
async def get_messages(session_id: str, limit: int = 50):
    """获取会话消息历史"""
    session = get_or_create_session(session_id)
    agent = session["agent"]

    messages = agent.get_messages()[-limit:]

    return APIResponse(
        success=True,
        message=f"共 {len(messages)} 条消息",
        data={"messages": messages, "total": len(agent.messages)},
    )


@router.get("/session/{session_id}/tool-calls", response_model=APIResponse)
async def get_tool_calls(session_id: str, limit: int = 100):
    """获取工具调用历史"""
    session = get_or_create_session(session_id)
    agent = session["agent"]

    tool_calls = agent.get_tool_call_history()[-limit:]

    return APIResponse(
        success=True,
        message=f"共 {len(tool_calls)} 次工具调用",
        data={"tool_calls": tool_calls, "total": len(agent.tool_call_history)},
    )


@router.post("/session/{session_id}/clear-history", response_model=APIResponse)
async def clear_history(session_id: str):
    """清空会话历史"""
    session = get_or_create_session(session_id)
    agent = session["agent"]

    agent.clear_history()
    session["updated_at"] = datetime.now()

    return APIResponse(
        success=True,
        message="历史已清空",
        data={"session_id": session_id},
    )


# ============ 工具查询 ============

@router.get("/session/{session_id}/tools", response_model=APIResponse)
async def get_tools(session_id: str, category: Optional[str] = None):
    """获取可用工具列表"""
    session = get_or_create_session(session_id)
    agent = session["agent"]

    if category:
        tools = agent.tool_manager.get_tools_by_category(category)
    else:
        tools = agent.tool_manager.get_tools_for_llm()

    # 简化输出
    tool_list = []
    for tool in tools:
        func = tool.get("function", {})
        definition = agent.tool_manager.get_tool(func.get("name", ""))
        tool_list.append({
            "name": func.get("name", ""),
            "description": func.get("description", "")[:200],
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
    session = get_or_create_session(session_id)
    agent = session["agent"]

    state = agent.get_session_state()

    stats = SessionStatsSchema(
        messages_count=len(agent.messages),
        tool_calls_count=len(agent.tool_call_history),
        total_llm_calls=state.get("total_llm_calls", 0),
        total_tokens_used=state.get("total_tokens_used", 0),
    )

    return APIResponse(
        success=True,
        message="获取成功",
        data=stats.model_dump(),
    )


# ============ 项目操作 ============

@router.post("/session/{session_id}/index", response_model=APIResponse)
async def index_project(session_id: str, request: IndexProjectRequest):
    """索引或重新索引项目"""
    session = get_or_create_session(session_id)
    app_state = get_app_state()

    target_path = request.target_path or session["target_path"]

    try:
        # 执行索引
        app_state.indexer.index_directory(
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
    await websocket.send_json(
        WSEvent(
            type=WSEventType.CONNECTED,
            session_id=session_id,
            data={"message": "连接成功"},
        ).model_dump()
    )

    try:
        while True:
            # 接收消息
            data = await websocket.receive_json()
            msg_type = data.get("type", "")

            if msg_type == "ping":
                await websocket.send_json(
                    WSEvent(
                        type=WSEventType.PONG,
                        session_id=session_id,
                    ).model_dump()
                )

            elif msg_type == "chat":
                # 处理聊天消息
                message = data.get("message", "")
                if message and session_id in _unified_sessions:
                    agent = _unified_sessions[session_id]["agent"]

                    # 设置工具调用回调
                    async def on_tool_call(event):
                        await websocket.send_json(
                            WSEvent(
                                type=WSEventType.TOOL_CALL_START if event.status.value == "running" else WSEventType.TOOL_CALL_END,
                                session_id=session_id,
                                data=event.to_dict(),
                            ).model_dump()
                        )

                    # 调用智能体
                    response = await agent.chat(message)

                    # 发送完成消息
                    await websocket.send_json(
                        WSEvent(
                            type=WSEventType.MESSAGE_COMPLETE,
                            session_id=session_id,
                            data=response.to_dict(),
                        ).model_dump()
                    )

    except WebSocketDisconnect:
        logger.info(f"WebSocket 连接断开: {session_id}")
    except Exception as e:
        logger.error(f"WebSocket 错误: {e}")
        await websocket.send_json(
            WSEvent(
                type=WSEventType.ERROR,
                session_id=session_id,
                data={"error": str(e)},
            ).model_dump()
        )
    finally:
        if session_id in _ws_connections:
            del _ws_connections[session_id]


async def broadcast_to_session(session_id: str, event: WSEvent):
    """向会话广播消息"""
    if session_id in _ws_connections:
        try:
            await _ws_connections[session_id].send_json(event.model_dump())
        except Exception as e:
            logger.warning(f"广播失败: {e}")
