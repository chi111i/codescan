"""FastAPI 主应用 - 代码安全审计 API"""

import sys
import uuid
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# 设置项目路径
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import load_config, AuditConfig
from llm_client import create_llm_client, BaseLLMClient
from indexer import CodeIndexer, create_vector_store, BaseVectorStore
from rules import create_rule_manager, RuleManager
from analyzer import (
    SecurityAnalyzer,
    CallChainAnalyzer,
    HighRiskVulnDetector,
    VulnType,
)
from .schemas import (
    ScanRequest, IndexRequest, SearchRequest, CallGraphRequest,
    ScanResultSchema, IndexResultSchema, SearchResultSchema,
    StatsSchema, RuleListSchema, RuleSchema,
    FindingSchema, VulnFindingSchema, TaintPathSchema,
    CallGraphStatsSchema, CodeUnitSchema, CodeSpanSchema,
    ScanStatus, SeverityLevel, VulnTypeEnum,
    APIResponse, ErrorResponse,
)

logger = logging.getLogger(__name__)

# ============ 全局状态 ============

class AppState:
    """应用状态管理"""
    def __init__(self):
        self.config: Optional[AuditConfig] = None
        self.llm_client: Optional[BaseLLMClient] = None
        self.vector_store: Optional[BaseVectorStore] = None
        self.indexer: Optional[CodeIndexer] = None
        self.rule_manager: Optional[RuleManager] = None

        # 扫描任务状态
        self.scan_tasks: Dict[str, ScanResultSchema] = {}

        # WebSocket 连接
        self.websocket_connections: Dict[str, WebSocket] = {}

    def initialize(self, config_path: Optional[str] = None):
        """初始化组件"""
        self.config = load_config(config_path=config_path)
        self.llm_client = create_llm_client(self.config.llm)
        self.vector_store = create_vector_store(self.config.vector_store)
        self.indexer = CodeIndexer(self.config, self.llm_client, self.vector_store)
        self.rule_manager = create_rule_manager(self.config.rules)
        logger.info("API 组件初始化完成")


app_state = AppState()


# ============ 生命周期 ============

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时初始化
    try:
        app_state.initialize()
        logger.info("API 服务启动")
    except Exception as e:
        logger.error(f"初始化失败: {e}")

    yield

    # 关闭时清理
    logger.info("API 服务关闭")


# ============ 创建应用 ============

def create_app() -> FastAPI:
    """创建 FastAPI 应用"""

    application = FastAPI(
        title="代码安全审计 API",
        description="LLM 驱动的代码安全审计工具 API",
        version="1.0.0",
        lifespan=lifespan,
    )

    # CORS 配置
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    return application


app = create_app()


# ============ 静态文件 ============

# 前端静态文件目录
FRONTEND_DIR = PROJECT_ROOT / "frontend" / "dist"

if FRONTEND_DIR.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")


@app.get("/")
async def serve_frontend():
    """提供前端页面"""
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "代码安全审计 API", "docs": "/docs"}


# ============ 健康检查 ============

@app.get("/api/health")
async def health_check():
    """健康检查"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "llm_client": app_state.llm_client is not None,
            "vector_store": app_state.vector_store is not None,
            "indexer": app_state.indexer is not None,
            "rule_manager": app_state.rule_manager is not None,
        }
    }


# ============ 索引接口 ============

@app.post("/api/index", response_model=APIResponse)
async def index_project(request: IndexRequest, background_tasks: BackgroundTasks):
    """索引项目代码"""
    if not app_state.indexer:
        raise HTTPException(status_code=500, detail="索引器未初始化")

    target_path = Path(request.target_path)
    if not target_path.exists():
        raise HTTPException(status_code=400, detail=f"目标路径不存在: {request.target_path}")

    try:
        if request.clear_existing:
            app_state.indexer.clear_index()

        count = app_state.indexer.index_directory(str(target_path))
        stats = app_state.indexer.get_stats()

        result = IndexResultSchema(
            target_path=str(target_path),
            total_files=count,
            total_units=stats["total_units"],
            languages={},
            indexed_at=datetime.now(),
        )

        return APIResponse(
            success=True,
            message=f"索引完成，共 {count} 个代码单元",
            data=result.model_dump(),
        )

    except Exception as e:
        logger.error(f"索引失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/index/stats", response_model=APIResponse)
async def get_index_stats():
    """获取索引统计"""
    if not app_state.indexer:
        raise HTTPException(status_code=500, detail="索引器未初始化")

    stats = app_state.indexer.get_stats()

    # 获取语言分布
    all_units = app_state.indexer.get_all_units(limit=10000)
    lang_counts = {}
    type_counts = {}

    for unit in all_units:
        lang_counts[unit.language] = lang_counts.get(unit.language, 0) + 1
        type_counts[unit.unit_type.value] = type_counts.get(unit.unit_type.value, 0) + 1

    return APIResponse(
        success=True,
        message="获取统计成功",
        data=StatsSchema(
            total_units=stats["total_units"],
            collection_name=stats["collection_name"],
            languages=lang_counts,
            unit_types=type_counts,
        ).model_dump(),
    )


# ============ 搜索接口 ============

@app.post("/api/search", response_model=APIResponse)
async def search_code(request: SearchRequest):
    """搜索代码"""
    if not app_state.indexer:
        raise HTTPException(status_code=500, detail="索引器未初始化")

    try:
        results = app_state.indexer.search(
            query=request.query,
            top_k=request.top_k,
            language=request.language,
            file_pattern=request.file_pattern,
        )

        # 转换为 schema
        code_units = []
        for unit in results:
            code_units.append(CodeUnitSchema(
                id=unit.id,
                language=unit.language,
                file_path=unit.file_path,
                symbol=unit.symbol,
                unit_type=unit.unit_type.value,
                signature=unit.signature,
                span=CodeSpanSchema(
                    start_line=unit.span.start_line,
                    end_line=unit.span.end_line,
                    start_col=unit.span.start_col,
                    end_col=unit.span.end_col,
                ),
                code=unit.code,
                docstring=unit.docstring,
                calls=unit.calls,
                parent_class=unit.parent_class,
                decorators=unit.decorators,
                imports=unit.imports,
            ))

        return APIResponse(
            success=True,
            message=f"找到 {len(code_units)} 个结果",
            data=SearchResultSchema(
                query=request.query,
                total=len(code_units),
                results=code_units,
            ).model_dump(),
        )

    except Exception as e:
        logger.error(f"搜索失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============ 扫描接口 ============

async def run_scan_task(scan_id: str, request: ScanRequest):
    """执行扫描任务（后台）"""
    task = app_state.scan_tasks[scan_id]

    try:
        target_path = Path(request.target_path)

        # 更新状态：索引中
        task.status = ScanStatus.INDEXING
        task.current_step = "正在索引代码..."
        task.progress = 0.1
        await broadcast_scan_progress(scan_id, task)

        # 检查是否需要重新索引
        stats = app_state.indexer.get_stats()
        if stats["total_units"] == 0 or request.reindex:
            app_state.indexer.index_directory(str(target_path))

        stats = app_state.indexer.get_stats()
        task.total_units = stats["total_units"]
        task.progress = 0.2
        await broadcast_scan_progress(scan_id, task)

        # 更新状态：分析中
        task.status = ScanStatus.ANALYZING
        task.current_step = "正在分析代码..."
        task.progress = 0.3
        await broadcast_scan_progress(scan_id, task)

        # 获取代码单元
        code_units = app_state.indexer.get_all_units()

        # 按语言过滤
        if request.languages:
            code_units = [u for u in code_units if u.language in request.languages]

        all_findings = []
        all_vuln_findings = []

        # 执行安全分析
        task.current_step = "执行安全规则扫描..."
        task.progress = 0.4
        await broadcast_scan_progress(scan_id, task)

        analyzer = SecurityAnalyzer(
            app_state.config,
            app_state.llm_client,
            app_state.indexer,
            app_state.rule_manager,
        )

        findings = analyzer.analyze(
            language=request.languages[0] if request.languages else None,
            max_candidates=request.max_issues,
        )

        for f in findings:
            # 从证据中提取代码片段
            code_snippet = None
            if f.evidence and len(f.evidence) > 0:
                code_snippet = f.evidence[0].code_snippet if hasattr(f.evidence[0], 'code_snippet') else None

            # 转换证据为字典列表
            evidence_list = []
            for e in f.evidence:
                evidence_list.append({
                    "file_path": e.file_path,
                    "line_start": e.line_start,
                    "line_end": e.line_end,
                    "code_snippet": e.code_snippet,
                    "description": e.description,
                })

            all_findings.append(FindingSchema(
                id=f.id,
                title=f.title,
                file_path=f.file_path,
                line_start=f.line_start,
                line_end=f.line_end,
                symbol=f.symbol,
                severity=SeverityLevel(f.severity.value),
                confidence=f.confidence,
                category=f.category if isinstance(f.category, str) else str(f.category),
                summary=f.summary,
                details=f.details,
                evidence=evidence_list,
                attack_scenario=f.attack_scenario,
                fix_suggestion=f.fix_suggestion,
                code_snippet=code_snippet,
                notes=f.notes,
                rule_id=f.rule_ids[0] if f.rule_ids else None,
                cwe_ids=f.cwe_ids,
            ))

        task.progress = 0.6
        await broadcast_scan_progress(scan_id, task)

        # 执行高危漏洞扫描
        if request.use_llm:
            task.current_step = "执行高危漏洞扫描..."
            task.progress = 0.7
            await broadcast_scan_progress(scan_id, task)

            vuln_detector = HighRiskVulnDetector(app_state.llm_client, app_state.rule_manager)

            # 转换漏洞类型
            vuln_types = None
            if request.vuln_types:
                type_map = {
                    VulnTypeEnum.RCE: VulnType.RCE,
                    VulnTypeEnum.COMMAND_INJECTION: VulnType.COMMAND_INJECTION,
                    VulnTypeEnum.FILE_READ: VulnType.FILE_READ,
                    VulnTypeEnum.FILE_WRITE: VulnType.FILE_WRITE,
                    VulnTypeEnum.SQL_INJECTION: VulnType.SQL_INJECTION,
                    VulnTypeEnum.SSRF: VulnType.SSRF,
                    VulnTypeEnum.DESERIALIZATION: VulnType.DESERIALIZATION,
                    VulnTypeEnum.AUTH_BYPASS: VulnType.AUTH_BYPASS,
                    VulnTypeEnum.IDOR: VulnType.IDOR,
                    VulnTypeEnum.LOGIC_FLAW: VulnType.LOGIC_FLAW,
                }
                vuln_types = [type_map.get(t) for t in request.vuln_types if t in type_map]

            vuln_findings = vuln_detector.detect_vulnerabilities(
                code_units,
                vuln_types=vuln_types,
                use_llm=request.use_llm,
            )

            for vf in vuln_findings:
                all_vuln_findings.append(VulnFindingSchema(
                    id=vf.id,
                    name=vf.name,
                    vuln_type=VulnTypeEnum(vf.vuln_type.value),
                    severity=SeverityLevel(vf.severity.value),
                    confidence=vf.confidence,
                    file_path=vf.file_path,
                    line_start=vf.line_start,
                    line_end=vf.line_end,
                    function_name=vf.function_name,
                    description=vf.description,
                    attack_scenario=vf.attack_scenario,
                    fix_suggestion=vf.fix_suggestion,
                    code_snippet=vf.code_snippet,
                    llm_analysis=vf.llm_analysis,
                    needs_manual_review=vf.needs_manual_review,
                    review_notes=vf.review_notes,
                ))

        task.progress = 0.8
        await broadcast_scan_progress(scan_id, task)

        # 执行逻辑漏洞扫描
        if request.scan_logic and request.use_llm:
            task.current_step = "执行业务逻辑漏洞扫描..."
            task.progress = 0.85
            await broadcast_scan_progress(scan_id, task)

            vuln_detector = HighRiskVulnDetector(app_state.llm_client, app_state.rule_manager)
            logic_findings = vuln_detector.detect_logic_vulnerabilities(code_units)

            for vf in logic_findings:
                all_vuln_findings.append(VulnFindingSchema(
                    id=vf.id,
                    name=vf.name,
                    vuln_type=VulnTypeEnum(vf.vuln_type.value),
                    severity=SeverityLevel(vf.severity.value),
                    confidence=vf.confidence,
                    file_path=vf.file_path,
                    line_start=vf.line_start,
                    line_end=vf.line_end,
                    function_name=vf.function_name,
                    description=vf.description,
                    attack_scenario=vf.attack_scenario,
                    fix_suggestion=vf.fix_suggestion,
                    code_snippet=vf.code_snippet,
                    llm_analysis=vf.llm_analysis,
                    needs_manual_review=vf.needs_manual_review,
                    review_notes=vf.review_notes,
                ))

        task.progress = 0.9
        await broadcast_scan_progress(scan_id, task)

        # 调用链分析
        task.current_step = "执行调用链分析..."
        chain_analyzer = CallChainAnalyzer(app_state.rule_manager)
        call_graph = chain_analyzer.build_call_graph(code_units)
        taint_paths = chain_analyzer.find_taint_paths(max_depth=10, max_paths=50)

        # 构建统计
        task.call_graph_stats = CallGraphStatsSchema(
            total_nodes=len(call_graph.nodes),
            total_edges=len(call_graph.edges),
            entry_points=len(call_graph.get_entry_points()),
            sources=len(call_graph.get_sources()),
            sinks=len(call_graph.get_sinks()),
            sanitizers=len(call_graph.get_sanitizers()),
        )

        # 转换污点路径
        for tp in taint_paths[:20]:  # 限制数量
            task.taint_paths.append(TaintPathSchema(
                source_node=tp.source_node,
                sink_node=tp.sink_node,
                path=tp.path,
                is_sanitized=tp.is_sanitized,
                sanitizers=tp.sanitizers,
                risk_level=tp.risk_level,
                confidence=tp.confidence,
                description=tp.description,
            ))

        # 完成
        task.status = ScanStatus.COMPLETED
        task.completed_at = datetime.now()
        task.findings = all_findings
        task.vuln_findings = all_vuln_findings
        task.progress = 1.0
        task.current_step = "扫描完成"
        await broadcast_scan_progress(scan_id, task)

    except Exception as e:
        logger.error(f"扫描任务失败: {e}")
        task.status = ScanStatus.FAILED
        task.error_message = str(e)
        task.current_step = f"错误: {e}"
        await broadcast_scan_progress(scan_id, task)


async def broadcast_scan_progress(scan_id: str, task: ScanResultSchema):
    """广播扫描进度"""
    if scan_id in app_state.websocket_connections:
        ws = app_state.websocket_connections[scan_id]
        try:
            await ws.send_json({
                "type": "progress",
                "scan_id": scan_id,
                "status": task.status.value,
                "progress": task.progress,
                "current_step": task.current_step,
                "findings_count": len(task.findings),
                "vuln_count": len(task.vuln_findings),
            })
        except Exception as e:
            logger.warning(f"WebSocket 发送失败: {e}")


@app.post("/api/scan", response_model=APIResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """开始扫描任务"""
    if not app_state.indexer:
        raise HTTPException(status_code=500, detail="索引器未初始化")

    target_path = Path(request.target_path)
    if not target_path.exists():
        raise HTTPException(status_code=400, detail=f"目标路径不存在: {request.target_path}")

    # 创建扫描任务
    scan_id = str(uuid.uuid4())[:8]
    task = ScanResultSchema(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        target_path=str(target_path),
        started_at=datetime.now(),
        current_step="准备中...",
    )
    app_state.scan_tasks[scan_id] = task

    # 启动后台任务
    background_tasks.add_task(run_scan_task, scan_id, request)

    return APIResponse(
        success=True,
        message="扫描任务已创建",
        data={"scan_id": scan_id},
    )


@app.get("/api/scan/{scan_id}", response_model=APIResponse)
async def get_scan_result(scan_id: str):
    """获取扫描结果"""
    if scan_id not in app_state.scan_tasks:
        raise HTTPException(status_code=404, detail="扫描任务不存在")

    task = app_state.scan_tasks[scan_id]
    return APIResponse(
        success=True,
        message="获取成功",
        data=task.model_dump(),
    )


@app.get("/api/scan/{scan_id}/findings", response_model=APIResponse)
async def get_scan_findings(scan_id: str):
    """获取扫描发现"""
    if scan_id not in app_state.scan_tasks:
        raise HTTPException(status_code=404, detail="扫描任务不存在")

    task = app_state.scan_tasks[scan_id]
    return APIResponse(
        success=True,
        message=f"共 {len(task.findings) + len(task.vuln_findings)} 个发现",
        data={
            "findings": [f.model_dump() for f in task.findings],
            "vuln_findings": [f.model_dump() for f in task.vuln_findings],
        },
    )


@app.get("/api/scans", response_model=APIResponse)
async def list_scans():
    """列出所有扫描任务"""
    tasks = []
    for scan_id, task in app_state.scan_tasks.items():
        tasks.append({
            "scan_id": scan_id,
            "status": task.status.value,
            "target_path": task.target_path,
            "started_at": task.started_at.isoformat(),
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
            "findings_count": len(task.findings),
            "vuln_count": len(task.vuln_findings),
            "progress": task.progress,
        })

    return APIResponse(
        success=True,
        message=f"共 {len(tasks)} 个扫描任务",
        data=tasks,
    )


# ============ 调用图接口 ============

@app.post("/api/callgraph", response_model=APIResponse)
async def analyze_callgraph(request: CallGraphRequest):
    """分析调用图"""
    if not app_state.indexer:
        raise HTTPException(status_code=500, detail="索引器未初始化")

    try:
        # 获取代码单元
        code_units = app_state.indexer.get_all_units()

        # 构建调用图
        chain_analyzer = CallChainAnalyzer(app_state.rule_manager)
        call_graph = chain_analyzer.build_call_graph(code_units)

        result = {
            "stats": CallGraphStatsSchema(
                total_nodes=len(call_graph.nodes),
                total_edges=len(call_graph.edges),
                entry_points=len(call_graph.get_entry_points()),
                sources=len(call_graph.get_sources()),
                sinks=len(call_graph.get_sinks()),
                sanitizers=len(call_graph.get_sanitizers()),
            ).model_dump(),
            "taint_paths": [],
            "dangerous_chains": [],
        }

        # 查找污点路径
        if request.find_taint:
            taint_paths = chain_analyzer.find_taint_paths(
                max_depth=request.max_depth,
                max_paths=100,
            )

            for tp in taint_paths[:50]:
                result["taint_paths"].append(TaintPathSchema(
                    source_node=tp.source_node,
                    sink_node=tp.sink_node,
                    path=tp.path,
                    is_sanitized=tp.is_sanitized,
                    sanitizers=tp.sanitizers,
                    risk_level=tp.risk_level,
                    confidence=tp.confidence,
                    description=tp.description,
                ).model_dump())

        # 查找危险调用链
        dangerous_chains = chain_analyzer.find_dangerous_chains()
        result["dangerous_chains"] = dangerous_chains[:50]

        return APIResponse(
            success=True,
            message="调用图分析完成",
            data=result,
        )

    except Exception as e:
        logger.error(f"调用图分析失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============ 规则接口 ============

@app.get("/api/rules", response_model=APIResponse)
async def list_rules(
    language: Optional[str] = None,
    category: Optional[str] = None,
):
    """列出安全规则"""
    if not app_state.rule_manager:
        raise HTTPException(status_code=500, detail="规则管理器未初始化")

    rules = app_state.rule_manager.all_rules()

    if language:
        rules = [r for r in rules if language in r.languages]
    if category:
        rules = [r for r in rules if r.category.value == category]

    rule_schemas = []
    for r in rules:
        rule_schemas.append(RuleSchema(
            id=r.id,
            name=r.name,
            rule_type=r.rule_type.value,
            category=r.category.value,
            risk_level=r.risk_level.value,
            languages=r.languages,
            patterns=r.patterns,
            description=r.description,
            fix_suggestion=r.fix_suggestion,
        ))

    return APIResponse(
        success=True,
        message=f"共 {len(rule_schemas)} 条规则",
        data=RuleListSchema(total=len(rule_schemas), rules=rule_schemas).model_dump(),
    )


@app.get("/api/rules/{rule_id}", response_model=APIResponse)
async def get_rule(rule_id: str):
    """获取单个规则"""
    if not app_state.rule_manager:
        raise HTTPException(status_code=500, detail="规则管理器未初始化")

    rule = app_state.rule_manager.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="规则不存在")

    return APIResponse(
        success=True,
        message="获取成功",
        data=RuleSchema(
            id=rule.id,
            name=rule.name,
            rule_type=rule.rule_type.value,
            category=rule.category.value,
            risk_level=rule.risk_level.value,
            languages=rule.languages,
            patterns=rule.patterns,
            description=rule.description,
            fix_suggestion=rule.fix_suggestion,
        ).model_dump(),
    )


# ============ WebSocket ============

@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    """WebSocket 实时扫描进度"""
    await websocket.accept()
    app_state.websocket_connections[scan_id] = websocket

    try:
        while True:
            # 保持连接，等待消息
            data = await websocket.receive_text()

            # 返回当前状态
            if scan_id in app_state.scan_tasks:
                task = app_state.scan_tasks[scan_id]
                await websocket.send_json({
                    "type": "status",
                    "scan_id": scan_id,
                    "status": task.status.value,
                    "progress": task.progress,
                    "current_step": task.current_step,
                })

    except WebSocketDisconnect:
        if scan_id in app_state.websocket_connections:
            del app_state.websocket_connections[scan_id]


# ============ 代码单元接口 ============

@app.get("/api/units", response_model=APIResponse)
async def list_code_units(
    language: Optional[str] = None,
    file_path: Optional[str] = None,
    limit: int = 100,
):
    """列出代码单元"""
    if not app_state.indexer:
        raise HTTPException(status_code=500, detail="索引器未初始化")

    if language:
        units = app_state.indexer.get_units_by_language(language, limit=limit)
    elif file_path:
        units = app_state.indexer.get_units_by_file(file_path)
    else:
        units = app_state.indexer.get_all_units(limit=limit)

    code_units = []
    for unit in units[:limit]:
        code_units.append(CodeUnitSchema(
            id=unit.id,
            language=unit.language,
            file_path=unit.file_path,
            symbol=unit.symbol,
            unit_type=unit.unit_type.value,
            signature=unit.signature,
            span=CodeSpanSchema(
                start_line=unit.span.start_line,
                end_line=unit.span.end_line,
                start_col=unit.span.start_col,
                end_col=unit.span.end_col,
            ),
            code=unit.code,
            docstring=unit.docstring,
            calls=unit.calls,
            parent_class=unit.parent_class,
            decorators=unit.decorators,
            imports=unit.imports,
        ))

    return APIResponse(
        success=True,
        message=f"共 {len(code_units)} 个代码单元",
        data=code_units,
    )


@app.get("/api/units/{unit_id}", response_model=APIResponse)
async def get_code_unit(unit_id: str):
    """获取单个代码单元"""
    if not app_state.indexer:
        raise HTTPException(status_code=500, detail="索引器未初始化")

    unit = app_state.indexer.get_unit(unit_id)
    if not unit:
        raise HTTPException(status_code=404, detail="代码单元不存在")

    return APIResponse(
        success=True,
        message="获取成功",
        data=CodeUnitSchema(
            id=unit.id,
            language=unit.language,
            file_path=unit.file_path,
            symbol=unit.symbol,
            unit_type=unit.unit_type.value,
            signature=unit.signature,
            span=CodeSpanSchema(
                start_line=unit.span.start_line,
                end_line=unit.span.end_line,
                start_col=unit.span.start_col,
                end_col=unit.span.end_col,
            ),
            code=unit.code,
            docstring=unit.docstring,
            calls=unit.calls,
            parent_class=unit.parent_class,
            decorators=unit.decorators,
            imports=unit.imports,
        ).model_dump(),
    )


# ============ 启动入口 ============

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
