"""交互式代码审计 API 路由

提供交互式、可对话、可选择的代码审计功能。

主要功能：
1. 会话管理（创建、获取、删除会话）
2. 代码浏览（代码单元、调用链、sink sites）
3. LLM 交互（分析、对话、深入分析、总结）
4. 发现管理（确认、拒绝、备注）
5. WebSocket 实时通信
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Depends

from serialization import to_jsonable

from .schemas_interactive import (
    # 请求模型
    CreateSessionRequest,
    AnalyzeSelectionRequest,
    ChatRequest,
    DigDeeperRequest,
    ConfirmFindingRequest,
    RejectFindingRequest,
    UpdateFindingNotesRequest,
    # 响应模型
    SessionInfoSchema,
    AgentResponseSchema,
    ChainContextSchema,
    CodeUnitBriefSchema,
    CodeUnitDetailSchema,
    SinkSiteBriefSchema,
    FindingsGroupSchema,
    SessionListItemSchema,
    InteractiveFindingSchema,
    EvidenceSchema,
    SinkSiteSchema,
    ChainNodeSchema,
    # 枚举
    InteractiveSessionStatus,
    InteractiveFindingStatus,
    AgentResponseTypeEnum,
)
from .schemas import APIResponse

logger = logging.getLogger(__name__)

# 创建路由器
router = APIRouter(prefix="/api/interactive", tags=["interactive"])


# ============ 依赖注入 ============

def get_session_manager():
    """获取会话管理器（依赖注入）"""
    from .main import app_state

    if app_state.interactive_session_manager is None:
        raise HTTPException(status_code=500, detail="交互式会话管理器未初始化")
    return app_state.interactive_session_manager


# ============ 会话管理 ============

@router.post("/session/start", response_model=APIResponse)
async def create_session(request: CreateSessionRequest):
    """创建新的交互式审计会话

    1. 解析目标代码
    2. 扫描危险函数触发点
    3. 构建调用图
    4. 收集调用链上下文
    """
    from .main import app_state

    # 检查组件是否初始化
    if not app_state.config or not app_state.llm_client or not app_state.indexer or not app_state.rule_manager:
        raise HTTPException(status_code=500, detail="系统组件未完全初始化")

    # 延迟初始化交互式会话管理器
    if app_state.interactive_session_manager is None:
        from analyzer import InteractiveSessionManager
        app_state.interactive_session_manager = InteractiveSessionManager(
            config=app_state.config,
            llm_client=app_state.llm_client,
            indexer=app_state.indexer,
            rule_manager=app_state.rule_manager,
            max_sessions=10,
            session_timeout_hours=24,
        )
        logger.info("交互式会话管理器已初始化")

    try:
        # 创建会话（异步）
        session_info = await app_state.interactive_session_manager.create_session(
            target_path=request.target_path,
            languages=request.languages,
            max_chain_depth=request.max_chain_depth,
            skip_index=request.skip_index,
        )

        return APIResponse(
            success=True,
            message=f"会话创建成功，发现 {session_info.sink_sites_count} 个危险函数触发点",
            data=SessionInfoSchema(
                session_id=session_info.session_id,
                target_path=session_info.target_path,
                status=InteractiveSessionStatus(session_info.status.value),
                created_at=session_info.created_at,
                updated_at=session_info.updated_at,
                code_units_count=session_info.code_units_count,
                sink_sites_count=session_info.sink_sites_count,
                chain_contexts_count=session_info.chain_contexts_count,
                pending_findings_count=session_info.pending_findings_count,
                confirmed_findings_count=session_info.confirmed_findings_count,
                rejected_findings_count=session_info.rejected_findings_count,
                languages=session_info.languages,
                max_chain_depth=session_info.max_chain_depth,
                error_message=session_info.error_message,
            ).model_dump(),
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"创建会话失败: {e}")
        raise HTTPException(status_code=500, detail=f"创建会话失败: {str(e)}")


@router.get("/session/{session_id}", response_model=APIResponse)
async def get_session(session_id: str):
    """获取会话信息"""
    session_manager = get_session_manager()

    session_info = session_manager.get_session_info(session_id)
    if not session_info:
        raise HTTPException(status_code=404, detail=f"会话不存在: {session_id}")

    return APIResponse(
        success=True,
        message="获取成功",
        data=SessionInfoSchema(
            session_id=session_info.session_id,
            target_path=session_info.target_path,
            status=InteractiveSessionStatus(session_info.status.value),
            created_at=session_info.created_at,
            updated_at=session_info.updated_at,
            code_units_count=session_info.code_units_count,
            sink_sites_count=session_info.sink_sites_count,
            chain_contexts_count=session_info.chain_contexts_count,
            pending_findings_count=session_info.pending_findings_count,
            confirmed_findings_count=session_info.confirmed_findings_count,
            rejected_findings_count=session_info.rejected_findings_count,
            languages=session_info.languages,
            max_chain_depth=session_info.max_chain_depth,
            error_message=session_info.error_message,
        ).model_dump(),
    )


@router.delete("/session/{session_id}", response_model=APIResponse)
async def delete_session(session_id: str):
    """删除会话"""
    session_manager = get_session_manager()

    if await session_manager.delete_session(session_id):
        return APIResponse(
            success=True,
            message="会话已删除",
            data={"session_id": session_id},
        )
    else:
        raise HTTPException(status_code=404, detail=f"会话不存在: {session_id}")


@router.get("/sessions", response_model=APIResponse)
async def list_sessions():
    """列出所有会话"""
    session_manager = get_session_manager()

    sessions = session_manager.list_sessions()
    session_list = [
        SessionListItemSchema(
            session_id=s.session_id,
            target_path=s.target_path,
            status=InteractiveSessionStatus(s.status.value),
            created_at=s.created_at,
            updated_at=s.updated_at,
            code_units_count=s.code_units_count,
            pending_findings_count=s.pending_findings_count,
            confirmed_findings_count=s.confirmed_findings_count,
        ).model_dump()
        for s in sessions
    ]

    return APIResponse(
        success=True,
        message=f"共 {len(session_list)} 个会话",
        data={"sessions": session_list, "total": len(session_list)},
    )


# ============ 代码浏览 ============

@router.get("/session/{session_id}/code-units", response_model=APIResponse)
async def list_code_units(session_id: str, limit: int = 200):
    """获取会话的代码单元列表"""
    session_manager = get_session_manager()

    try:
        units = session_manager.list_code_units(session_id)
        return APIResponse(
            success=True,
            message=f"共 {len(units)} 个代码单元",
            data={
                "code_units": units[:limit],
                "total": len(units),
            },
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/session/{session_id}/code-units/{unit_id}", response_model=APIResponse)
async def get_code_unit_detail(session_id: str, unit_id: str):
    """获取代码单元详情"""
    session_manager = get_session_manager()

    detail = session_manager.get_code_unit_detail(session_id, unit_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"代码单元不存在: {unit_id}")

    return APIResponse(
        success=True,
        message="获取成功",
        data=detail,
    )


@router.get("/session/{session_id}/sink-sites", response_model=APIResponse)
async def list_sink_sites(session_id: str, limit: int = 200):
    """获取会话的 sink sites 列表"""
    session_manager = get_session_manager()

    try:
        sites = session_manager.list_sink_sites(session_id)
        return APIResponse(
            success=True,
            message=f"共 {len(sites)} 个 sink sites",
            data={
                "sink_sites": sites[:limit],
                "total": len(sites),
            },
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/session/{session_id}/chain-contexts", response_model=APIResponse)
async def list_chain_contexts(session_id: str, limit: int = 100):
    """获取会话的调用链上下文列表"""
    session_manager = get_session_manager()

    try:
        contexts = session_manager.list_chain_contexts(session_id)
        return APIResponse(
            success=True,
            message=f"共 {len(contexts)} 个调用链上下文",
            data={
                "chain_contexts": contexts[:limit],
                "total": len(contexts),
            },
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/session/{session_id}/chain-contexts/{chain_id}", response_model=APIResponse)
async def get_chain_context_detail(session_id: str, chain_id: str):
    """获取调用链上下文详情"""
    session_manager = get_session_manager()

    detail = session_manager.get_chain_context_detail(session_id, chain_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"调用链上下文不存在: {chain_id}")

    return APIResponse(
        success=True,
        message="获取成功",
        data=detail,
    )


# ============ LLM 交互 ============

@router.post("/analyze", response_model=APIResponse)
async def analyze_selection(request: AnalyzeSelectionRequest):
    """分析用户选择的内容

    用户可以选择调用链和/或代码单元，LLM 将对选中内容进行安全分析。
    """
    session_manager = get_session_manager()

    try:
        result = await session_manager.analyze_selection(
            session_id=request.session_id,
            selected_chain_ids=request.selected_chain_ids,
            selected_unit_ids=request.selected_unit_ids,
            focus_areas=request.focus_areas,
            custom_prompt=request.custom_prompt,
        )

        # 转换发现为 schema
        findings_schemas = [_convert_finding_to_schema(f) for f in result.findings]

        return APIResponse(
            success=True,
            message=f"分析完成，发现 {len(findings_schemas)} 个问题",
            data=AgentResponseSchema(
                response_type=AgentResponseTypeEnum(result.response_type.value),
                content=result.content,
                findings=findings_schemas,
                suggestions=result.suggestions,
                metadata=result.metadata,
                error=result.error,
            ).model_dump(),
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"分析失败: {e}")
        raise HTTPException(status_code=500, detail=f"分析失败: {str(e)}")


@router.post("/chat", response_model=APIResponse)
async def chat_with_llm(request: ChatRequest):
    """与 LLM 对话

    在当前会话上下文中与 LLM 进行对话交互。
    """
    session_manager = get_session_manager()

    try:
        result = await session_manager.chat(
            session_id=request.session_id,
            message=request.message,
        )

        findings_schemas = [_convert_finding_to_schema(f) for f in result.findings]

        return APIResponse(
            success=True,
            message="对话成功",
            data=AgentResponseSchema(
                response_type=AgentResponseTypeEnum(result.response_type.value),
                content=result.content,
                findings=findings_schemas,
                suggestions=result.suggestions,
                metadata=result.metadata,
                error=result.error,
            ).model_dump(),
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"对话失败: {e}")
        raise HTTPException(status_code=500, detail=f"对话失败: {str(e)}")


@router.post("/dig-deeper", response_model=APIResponse)
async def dig_deeper(request: DigDeeperRequest):
    """深入分析某个发现

    方向选项：
    - expand: 扩展分析（更多上下文）
    - trace_source: 追踪数据源
    - trace_sink: 追踪数据汇
    - verify: 验证可利用性
    """
    session_manager = get_session_manager()

    try:
        result = await session_manager.dig_deeper(
            session_id=request.session_id,
            finding_id=request.finding_id,
            direction=request.direction,
        )

        findings_schemas = [_convert_finding_to_schema(f) for f in result.findings]

        return APIResponse(
            success=True,
            message="深入分析完成",
            data=AgentResponseSchema(
                response_type=AgentResponseTypeEnum(result.response_type.value),
                content=result.content,
                findings=findings_schemas,
                suggestions=result.suggestions,
                metadata=result.metadata,
                error=result.error,
            ).model_dump(),
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"深入分析失败: {e}")
        raise HTTPException(status_code=500, detail=f"深入分析失败: {str(e)}")


@router.post("/session/{session_id}/summarize", response_model=APIResponse)
async def summarize_session(session_id: str):
    """生成会话总结报告"""
    session_manager = get_session_manager()

    try:
        result = await session_manager.summarize(session_id)

        return APIResponse(
            success=True,
            message="总结生成完成",
            data=AgentResponseSchema(
                response_type=AgentResponseTypeEnum(result.response_type.value),
                content=result.content,
                findings=[],
                suggestions=result.suggestions,
                metadata=result.metadata,
                error=result.error,
            ).model_dump(),
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"生成总结失败: {e}")
        raise HTTPException(status_code=500, detail=f"生成总结失败: {str(e)}")


@router.post("/session/{session_id}/stop", response_model=APIResponse)
async def stop_analysis(session_id: str):
    """停止当前分析"""
    session_manager = get_session_manager()

    try:
        result = session_manager.stop_analysis(session_id)

        return APIResponse(
            success=True,
            message="分析已停止",
            data={
                "session_id": session_id,
                "status": result.metadata.get("status", "paused"),
                "metadata": result.metadata,
            },
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ============ 发现管理 ============

@router.get("/session/{session_id}/findings", response_model=APIResponse)
async def get_findings(session_id: str):
    """获取所有发现（按状态分组）"""
    session_manager = get_session_manager()

    try:
        findings_dict = session_manager.get_findings(session_id)

        result = FindingsGroupSchema(
            pending=[_convert_finding_to_schema(f) for f in findings_dict.get("pending", [])],
            confirmed=[_convert_finding_to_schema(f) for f in findings_dict.get("confirmed", [])],
            rejected=[_convert_finding_to_schema(f) for f in findings_dict.get("rejected", [])],
        )

        return APIResponse(
            success=True,
            message=f"共 {len(result.pending) + len(result.confirmed) + len(result.rejected)} 个发现",
            data=result.model_dump(),
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/session/{session_id}/findings/{finding_id}/confirm", response_model=APIResponse)
async def confirm_finding(session_id: str, finding_id: str, request: ConfirmFindingRequest):
    """确认发现"""
    session_manager = get_session_manager()

    try:
        success = session_manager.confirm_finding(session_id, finding_id, request.notes)
        if success:
            return APIResponse(
                success=True,
                message="发现已确认",
                data={"finding_id": finding_id, "status": "confirmed"},
            )
        else:
            raise HTTPException(status_code=404, detail=f"发现不存在或已处理: {finding_id}")

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/session/{session_id}/findings/{finding_id}/reject", response_model=APIResponse)
async def reject_finding(session_id: str, finding_id: str, request: RejectFindingRequest):
    """拒绝发现"""
    session_manager = get_session_manager()

    try:
        success = session_manager.reject_finding(session_id, finding_id, request.reason)
        if success:
            return APIResponse(
                success=True,
                message="发现已拒绝",
                data={"finding_id": finding_id, "status": "rejected"},
            )
        else:
            raise HTTPException(status_code=404, detail=f"发现不存在或已处理: {finding_id}")

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/session/{session_id}/findings/{finding_id}/notes", response_model=APIResponse)
async def update_finding_notes(session_id: str, finding_id: str, request: UpdateFindingNotesRequest):
    """更新发现备注"""
    session_manager = get_session_manager()

    agent = session_manager.get_session(session_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"会话不存在: {session_id}")

    success = agent.update_finding_notes(finding_id, request.notes)
    if success:
        return APIResponse(
            success=True,
            message="备注已更新",
            data={"finding_id": finding_id},
        )
    else:
        raise HTTPException(status_code=404, detail=f"发现不存在: {finding_id}")


# ============ WebSocket ============

# 存储 WebSocket 连接
_interactive_ws_connections: dict = {}


@router.websocket("/ws/{session_id}")
async def websocket_interactive(websocket: WebSocket, session_id: str):
    """交互式审计 WebSocket 连接

    支持实时通信：
    - LLM 响应流
    - 分析进度
    - 新发现通知
    """
    await websocket.accept()
    _interactive_ws_connections[session_id] = websocket

    logger.info(f"WebSocket 连接已建立: {session_id}")

    try:
        while True:
            # 接收客户端消息
            data = await websocket.receive_json()
            msg_type = data.get("type", "")

            if msg_type == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "session_id": session_id,
                    "timestamp": datetime.now().isoformat(),
                })

            elif msg_type == "get_status":
                # 返回会话状态
                from .main import app_state
                if app_state.interactive_session_manager:
                    info = app_state.interactive_session_manager.get_session_info(session_id)
                    if info:
                        await websocket.send_json({
                            "type": "status",
                            "session_id": session_id,
                            "status": info.status.value,
                            "pending_findings": info.pending_findings_count,
                            "confirmed_findings": info.confirmed_findings_count,
                            "timestamp": datetime.now().isoformat(),
                        })

    except WebSocketDisconnect:
        logger.info(f"WebSocket 连接断开: {session_id}")
    except Exception as e:
        logger.error(f"WebSocket 错误: {e}")
    finally:
        if session_id in _interactive_ws_connections:
            del _interactive_ws_connections[session_id]


async def broadcast_to_session(session_id: str, message: dict):
    """向会话广播消息"""
    if session_id in _interactive_ws_connections:
        ws = _interactive_ws_connections[session_id]
        try:
            await ws.send_json(to_jsonable(message))
        except Exception as e:
            logger.warning(f"WebSocket 广播失败: {e}")


# ============ 辅助函数 ============

def _convert_finding_to_schema(finding) -> InteractiveFindingSchema:
    """将 InteractiveFinding 转换为 schema"""
    evidence_list = []
    if hasattr(finding, 'evidence') and finding.evidence:
        for e in finding.evidence:
            evidence_list.append(EvidenceSchema(
                file_path=e.file_path,
                line_start=e.line_start,
                line_end=e.line_end,
                code_snippet=e.code_snippet if hasattr(e, 'code_snippet') else "",
                description=e.description if hasattr(e, 'description') else "",
            ))

    return InteractiveFindingSchema(
        id=finding.id,
        title=finding.title,
        category=finding.category,
        severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
        confidence=finding.confidence,
        file_path=finding.file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        symbol=finding.symbol,
        summary=finding.summary,
        details=finding.details,
        evidence=evidence_list,
        attack_scenario=finding.attack_scenario,
        fix_suggestion=finding.fix_suggestion,
        status=InteractiveFindingStatus(finding.status.value),
        user_notes=finding.user_notes,
        confirmed_at=finding.confirmed_at,
        rejected_reason=finding.rejected_reason,
        source_chain_id=finding.source_chain_id,
        source_sink_site_id=finding.source_sink_site_id,
    )
