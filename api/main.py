"""FastAPI 主应用 - 代码安全审计 API"""

import sys
import uuid
import asyncio
import logging
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List
from contextlib import asynccontextmanager


def setup_logging():
    """配置日志系统 - 确保所有模块日志正确输出到终端

    注意: 此函数会在 uvicorn reload 后被重新调用，确保日志配置一致
    """
    import io

    # 创建格式化器
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # 创建控制台处理器（使用 stderr + UTF-8 编码以避免 Windows 终端乱码）
    # 在 Windows 上强制使用 UTF-8 编码
    if sys.platform == 'win32':
        # 尝试设置控制台编码为 UTF-8
        try:
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
        except Exception:
            pass  # 如果失败则使用默认编码

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)

    # 配置根 logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # 清除已有处理器，避免重复
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # 添加控制台处理器
    root_logger.addHandler(console_handler)

    # 设置第三方库日志级别（减少噪音）
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
    logging.getLogger("watchfiles").setLevel(logging.WARNING)

    # 确保本项目模块日志输出
    for module in ["llm_client", "agent", "analyzer", "indexer", "api", "rules", "config", "prompts"]:
        module_logger = logging.getLogger(module)
        module_logger.setLevel(logging.INFO)
        module_logger.propagate = True  # 确保传播到根 logger

    # 输出启动信息
    root_logger.info("日志系统初始化完成")


# 在模块加载时立即配置日志
setup_logging()

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.middleware.base import BaseHTTPMiddleware

# 设置项目路径
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import load_config, AuditConfig, save_user_config
from llm_client import create_llm_client, BaseLLMClient
from indexer import CodeIndexer, create_vector_store, BaseVectorStore
from rules import create_rule_manager, RuleManager
from analyzer import (
    SecurityAnalyzer,
    CallChainAnalyzer,
    HighRiskVulnDetector,
    VulnType,
)
from storage import (
    DatabaseManager,
    ScanRepository,
    FindingRepository,
    InteractionRepository,
    ScanTask,
    ScanFinding,
)

from serialization import to_jsonable
from .schemas import (
    ScanRequest, IndexRequest, SearchRequest, CallGraphRequest,
    ScanResultSchema, IndexResultSchema, SearchResultSchema,
    StatsSchema, RuleListSchema, RuleSchema,
    FindingSchema, VulnFindingSchema, TaintPathSchema,
    CallGraphStatsSchema, CodeUnitSchema, CodeSpanSchema,
    ScanStatus, SeverityLevel, VulnTypeEnum,
    APIResponse, ErrorResponse,
)
from pydantic import BaseModel

logger = logging.getLogger(__name__)


# ============ HTTP 请求日志中间件 ============

class HTTPLoggingMiddleware(BaseHTTPMiddleware):
    """HTTP 请求日志中间件 - 记录所有 HTTP 请求和响应"""

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        method = request.method
        path = request.url.path
        query = str(request.url.query) if request.url.query else ""

        # 排除健康检查、OPTIONS 预检请求等高频端点的日志
        skip_logging = path in ["/api/health", "/favicon.ico"] or method == "OPTIONS"

        if not skip_logging:
            log_msg = f"[HTTP] {method} {path}"
            if query:
                log_msg += f"?{query[:100]}"
            logger.info(log_msg)

        # 执行请求
        response = await call_next(request)

        # 计算耗时
        duration = time.time() - start_time

        if not skip_logging:
            logger.info(f"[HTTP] {method} {path} -> {response.status_code} ({duration:.3f}s)")

        return response

# ============ 全局状态 ============

class AppState:
    """应用状态管理"""
    def __init__(self):
        self.config: Optional[AuditConfig] = None
        self.llm_client: Optional[BaseLLMClient] = None
        self.vector_store: Optional[BaseVectorStore] = None
        self.indexer: Optional[CodeIndexer] = None
        self.rule_manager: Optional[RuleManager] = None

        # 数据库与仓库
        self.db: Optional[DatabaseManager] = None
        self.scan_repo: Optional[ScanRepository] = None
        self.finding_repo: Optional[FindingRepository] = None
        self.interaction_repo: Optional[InteractionRepository] = None

        # 内存中的扫描任务状态（用于实时进度追踪）
        self.scan_tasks: Dict[str, ScanResultSchema] = {}

        # WebSocket 连接
        self.websocket_connections: Dict[str, WebSocket] = {}

        # 交互式审计会话管理器（延迟初始化）
        self.interactive_session_manager = None

        # ============ 缓存机制 ============
        # 统计信息缓存（避免每次请求都遍历）
        self._stats_cache: Optional[Dict] = None
        self._stats_cache_time: float = 0
        self._stats_cache_ttl: float = 30.0  # 缓存 30 秒

    def get_cached_stats(self) -> Optional[Dict]:
        """获取缓存的统计信息（如果未过期）"""
        if self._stats_cache and (time.time() - self._stats_cache_time < self._stats_cache_ttl):
            return self._stats_cache
        return None

    def set_stats_cache(self, stats: Dict):
        """设置统计信息缓存"""
        self._stats_cache = stats
        self._stats_cache_time = time.time()

    def invalidate_stats_cache(self):
        """使统计信息缓存失效"""
        self._stats_cache = None

    def initialize(self, config_path: Optional[str] = None):
        """初始化组件（同步版本，内部使用）"""
        self.config = load_config(config_path=config_path)
        self.llm_client = create_llm_client(self.config.llm)
        # 传递嵌入向量维度，确保与嵌入模型输出一致
        self.vector_store = create_vector_store(
            self.config.vector_store,
            embedding_dim=self.config.llm.embedding_dim
        )
        self.indexer = CodeIndexer(self.config, self.llm_client, self.vector_store)
        self.rule_manager = create_rule_manager(self.config.rules)

        # 初始化数据库和仓库
        self.db = DatabaseManager()
        self.scan_repo = ScanRepository(self.db)
        self.finding_repo = FindingRepository(self.db)
        self.interaction_repo = InteractionRepository(self.db)

        # 注册交互日志回调（用于 WebSocket 实时推送）
        self.interaction_repo.add_callback(queue_interaction_broadcast)

        logger.info("API 组件初始化完成（含数据库）")

    async def initialize_async(self, config_path: Optional[str] = None):
        """异步初始化组件（避免阻塞事件循环）"""
        await asyncio.to_thread(self.initialize, config_path)


app_state = AppState()


# ============ 生命周期 ============

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时异步初始化（不阻塞事件循环）
    try:
        await app_state.initialize_async()
        logger.info("API 服务启动")
        print(f"[INIT] rule_manager 已初始化: {app_state.rule_manager is not None}")
        if app_state.rule_manager:
            print(f"[INIT] 规则总数: {app_state.rule_manager.count()}")
    except Exception as e:
        import traceback
        logger.error(f"初始化失败: {e}")
        print(f"[INIT ERROR] 初始化失败: {e}")
        print(f"[INIT ERROR] 堆栈: {traceback.format_exc()}")
        # 不要 re-raise，让服务器继续运行但记录错误

    # 启动后台任务处理交互日志广播队列
    broadcast_task = asyncio.create_task(process_interaction_broadcast_queue())

    yield

    # 关闭时清理
    broadcast_task.cancel()
    try:
        await broadcast_task
    except asyncio.CancelledError:
        pass

    # 关闭 LLM 客户端 HTTP 连接
    if app_state.llm_client:
        try:
            app_state.llm_client.close()
            logger.info("LLM 客户端已关闭")
        except Exception as e:
            logger.warning(f"关闭 LLM 客户端失败: {e}")

    # 关闭索引器资源（向量存储、嵌入缓存、文件追踪器）
    if app_state.indexer:
        try:
            await app_state.indexer.aclose()
            logger.info("索引器资源已关闭")
        except Exception as e:
            logger.warning(f"关闭索引器失败: {e}")

    # 关闭所有嵌入缓存（单例模式）
    try:
        from indexer.embedding_cache import close_all_caches
        close_all_caches()
        logger.info("嵌入缓存已关闭")
    except Exception as e:
        logger.warning(f"关闭嵌入缓存失败: {e}")

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
        max_age=86400,  # 预检请求缓存 1 天，减少跨域请求开销
    )

    # GZip 压缩中间件（压缩较大响应，减少传输延迟）
    application.add_middleware(
        GZipMiddleware,
        minimum_size=1024,  # 仅压缩 > 1KB 的响应
    )

    # HTTP 请求日志中间件
    application.add_middleware(HTTPLoggingMiddleware)

    return application


app = create_app()

# 注册交互式审计路由
from .interactive_router import router as interactive_router
app.include_router(interactive_router)

# 注册统一智能体路由
from .agent_router import router as agent_router
app.include_router(agent_router)

# 注册代码属性图路由
from .graph_router import router as graph_router
app.include_router(graph_router)

# 注册变体分析路由
from .variant_router import router as variant_router
app.include_router(variant_router)


# ============ 静态文件 ============

# 前端静态文件目录
FRONTEND_DIR = PROJECT_ROOT / "frontend" / "dist"

# 只有当 assets 目录确实存在时才挂载
assets_dir = FRONTEND_DIR / "assets"
if assets_dir.exists():
    app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")


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

        # 索引完成后使统计缓存失效
        app_state.invalidate_stats_cache()

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
    """获取索引统计（带缓存，避免频繁遍历）"""
    if not app_state.indexer:
        raise HTTPException(status_code=500, detail="索引器未初始化")

    # 尝试使用缓存
    cached = app_state.get_cached_stats()
    if cached:
        return APIResponse(
            success=True,
            message="获取统计成功（缓存）",
            data=cached,
        )

    # 缓存未命中，计算统计信息
    stats = app_state.indexer.get_stats()

    # 使用异步线程避免阻塞
    def compute_distribution():
        all_units = app_state.indexer.get_all_units(limit=10000)
        lang_counts = {}
        type_counts = {}
        for unit in all_units:
            lang_counts[unit.language] = lang_counts.get(unit.language, 0) + 1
            type_counts[unit.unit_type.value] = type_counts.get(unit.unit_type.value, 0) + 1
        return lang_counts, type_counts

    lang_counts, type_counts = await asyncio.to_thread(compute_distribution)

    result_data = StatsSchema(
        total_units=stats["total_units"],
        collection_name=stats["collection_name"],
        languages=lang_counts,
        unit_types=type_counts,
    ).model_dump()

    # 设置缓存
    app_state.set_stats_cache(result_data)

    return APIResponse(
        success=True,
        message="获取统计成功",
        data=result_data,
    )


@app.delete("/api/index", response_model=APIResponse)
async def clear_index():
    """清空索引（删除并重建向量集合）"""
    if not app_state.indexer:
        raise HTTPException(status_code=500, detail="索引器未初始化")

    try:
        app_state.indexer.clear_index()
        # 使统计缓存失效
        app_state.invalidate_stats_cache()
        logger.info("索引已清空并重建")
        return APIResponse(
            success=True,
            message="索引已清空，向量集合已用新维度重建",
            data={"embedding_dim": app_state.config.llm.embedding_dim},
        )
    except Exception as e:
        logger.error(f"清空索引失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============ 缓存接口 ============

@app.get("/api/cache/stats", response_model=APIResponse)
async def get_cache_stats():
    """获取嵌入缓存统计信息"""
    if not app_state.indexer:
        raise HTTPException(status_code=500, detail="索引器未初始化")

    try:
        if app_state.indexer.cached_generator:
            stats = app_state.indexer.cached_generator.get_stats()
            return APIResponse(
                success=True,
                message="获取缓存统计成功",
                data=stats,
            )
        else:
            return APIResponse(
                success=True,
                message="缓存未启用",
                data={
                    "total_entries": 0,
                    "cache_size_mb": 0,
                    "cache_enabled": False,
                },
            )
    except Exception as e:
        logger.error(f"获取缓存统计失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/cache", response_model=APIResponse)
async def clear_cache():
    """清空嵌入缓存"""
    if not app_state.indexer:
        raise HTTPException(status_code=500, detail="索引器未初始化")

    try:
        if app_state.indexer.embedding_cache:
            app_state.indexer.embedding_cache.clear()
            logger.info("嵌入缓存已清空")
            return APIResponse(
                success=True,
                message="嵌入缓存已清空",
                data={"cleared": True},
            )
        else:
            return APIResponse(
                success=True,
                message="缓存未启用",
                data={"cleared": False},
            )
    except Exception as e:
        logger.error(f"清空缓存失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/cache/cleanup", response_model=APIResponse)
async def cleanup_expired_cache():
    """清理过期的嵌入缓存"""
    if not app_state.indexer:
        raise HTTPException(status_code=500, detail="索引器未初始化")

    try:
        cleaned_count = app_state.indexer.cleanup_cache()
        logger.info(f"清理了 {cleaned_count} 个过期缓存条目")
        return APIResponse(
            success=True,
            message=f"清理了 {cleaned_count} 个过期缓存条目",
            data={"cleaned_count": cleaned_count},
        )
    except Exception as e:
        logger.error(f"清理过期缓存失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


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
    """执行扫描任务（后台）

    注意：耗时的同步操作使用 asyncio.to_thread() 放到线程池执行，
    避免阻塞事件循环影响其他请求。
    """
    print(f"[SCAN] 进入 run_scan_task, scan_id={scan_id}")  # 直接打印确保可见
    logger.warning(f"[SCAN] 开始执行扫描任务 {scan_id}")  # 使用 warning 级别确保可见

    task = app_state.scan_tasks[scan_id]

    try:
        target_path = Path(request.target_path)
        print(f"[SCAN] 目标路径: {target_path}, skip_index={request.skip_index}, use_llm={request.use_llm}")
        logger.warning(f"开始扫描任务 {scan_id}, 目标路径: {target_path}")

        # 检查 LLM 配置
        if not app_state.config.llm.api_key:
            logger.error("扫描任务失败: LLM API Key 未配置")
            task.status = ScanStatus.FAILED
            task.error_message = "LLM API Key 未配置，请先在设置中配置 API Key"
            task.current_step = "错误: API Key 未配置"
            await broadcast_scan_progress(scan_id, task)
            return

        logger.info(f"LLM 配置: model={app_state.config.llm.model}, base_url={app_state.config.llm.base_url}")

        # 更新状态：索引中
        task.status = ScanStatus.INDEXING
        task.progress = 0.1
        await broadcast_scan_progress(scan_id, task)

        # 根据 skip_index 选项决定是否使用向量索引
        if request.skip_index:
            # 小项目模式：直接解析文件，跳过向量索引
            task.current_step = "正在解析代码（跳过索引）..."
            logger.info(f"扫描任务 {scan_id}: 使用直接解析模式（跳过向量索引）")

            # 使用线程池执行同步的解析操作
            code_units = await asyncio.to_thread(
                app_state.indexer.parse_directory_without_index,
                str(target_path),
                request.languages
            )
            task.total_units = len(code_units)
        else:
            # 正常模式：使用向量索引
            task.current_step = "正在索引代码..."
            logger.info(f"扫描任务 {scan_id}: 开始索引代码")

            # 检查是否需要重新索引
            stats = await asyncio.to_thread(app_state.indexer.get_stats)
            if stats["total_units"] == 0 or request.reindex:
                logger.info(f"扫描任务 {scan_id}: 索引目录 {target_path}")
                # 使用线程池执行同步的索引操作
                await asyncio.to_thread(app_state.indexer.index_directory, str(target_path))

            stats = await asyncio.to_thread(app_state.indexer.get_stats)
            task.total_units = stats["total_units"]

            # 获取代码单元
            code_units = await asyncio.to_thread(app_state.indexer.get_all_units)

            # 按语言过滤
            if request.languages:
                code_units = [u for u in code_units if u.language in request.languages]

        task.progress = 0.2
        await broadcast_scan_progress(scan_id, task)

        # 广播代码解析完成的详细信息
        await broadcast_analysis_detail(scan_id, "parse_complete", {
            "total_units": len(code_units),
            "message": f"代码解析完成，共 {len(code_units)} 个代码单元"
        })

        print(f"[SCAN] 代码解析完成，共 {len(code_units)} 个代码单元")
        logger.warning(f"扫描任务 {scan_id}: 代码解析完成，共 {len(code_units)} 个代码单元")

        # 更新状态：分析中
        task.status = ScanStatus.ANALYZING
        task.current_step = "正在分析代码..."
        task.progress = 0.3
        await broadcast_scan_progress(scan_id, task)

        all_findings = []
        all_vuln_findings = []

        # 执行安全分析
        task.current_step = "执行安全规则扫描..."
        task.progress = 0.4
        await broadcast_scan_progress(scan_id, task)
        print(f"[SCAN] 开始安全规则扫描，代码单元数: {len(code_units)}")
        logger.warning(f"扫描任务 {scan_id}: 开始安全规则扫描，代码单元数: {len(code_units)}")

        # 记录分析开始
        if app_state.interaction_repo:
            app_state.interaction_repo.log_thinking(
                scan_id, f"开始安全规则扫描，共 {len(code_units)} 个代码单元"
            )

        # 检查 rule_manager 是否已初始化
        if app_state.rule_manager is None:
            logger.error("rule_manager 未初始化！请检查启动日志")
            print("[SCAN ERROR] rule_manager 未初始化！")
            task.status = ScanStatus.FAILED
            task.error_message = "规则管理器未初始化，请重启服务器"
            task.current_step = "错误: 规则管理器未初始化"
            await broadcast_scan_progress(scan_id, task)
            return

        print(f"[SCAN] rule_manager 规则数: {app_state.rule_manager.count()}")

        analyzer = SecurityAnalyzer(
            app_state.config,
            app_state.llm_client,
            app_state.indexer,
            app_state.rule_manager,
            interaction_repo=app_state.interaction_repo,
            scan_id=scan_id,
        )

        print(f"[SCAN] 调用 SecurityAnalyzer.analyze()")
        logger.warning(f"扫描任务 {scan_id}: 调用 SecurityAnalyzer.analyze()")

        # 根据配置选择分析模式
        analysis_mode = "链级分析" if request.use_chain_analysis else "简单分析"
        logger.info(f"扫描任务 {scan_id}: 使用 {analysis_mode} 模式")

        # 记录分析模式
        if app_state.interaction_repo:
            app_state.interaction_repo.log_thinking(
                scan_id, f"使用 {analysis_mode} 模式进行安全分析"
            )

        # 转换用户选择的漏洞类型为字符串列表
        vuln_type_strs = None
        if request.vuln_types:
            vuln_type_strs = [vt.value for vt in request.vuln_types]
            logger.info(f"扫描任务 {scan_id}: 用户选择的漏洞类型: {vuln_type_strs}")

        # 创建线程安全的进度回调
        import queue
        progress_queue = queue.Queue()

        def analysis_progress_callback(progress: float, step: str):
            """线程安全的进度回调，将进度更新放入队列"""
            progress_queue.put((progress, step))

        # 启动一个协程来处理进度队列
        async def process_progress_updates():
            """异步处理进度更新队列"""
            while True:
                try:
                    # 非阻塞地检查队列
                    try:
                        progress, step = progress_queue.get_nowait()
                        task.progress = progress
                        task.current_step = step
                        await broadcast_scan_progress(scan_id, task)
                    except queue.Empty:
                        pass
                    await asyncio.sleep(0.1)  # 100ms 轮询间隔
                except asyncio.CancelledError:
                    # 处理剩余的队列项
                    while not progress_queue.empty():
                        try:
                            progress, step = progress_queue.get_nowait()
                            task.progress = progress
                            task.current_step = step
                            await broadcast_scan_progress(scan_id, task)
                        except queue.Empty:
                            break
                    break
                except Exception as e:
                    logger.warning(f"Progress update error: {e}")
                    await asyncio.sleep(0.1)

        # 启动进度处理任务
        progress_task = asyncio.create_task(process_progress_updates())

        # 使用线程池执行同步的分析操作（可能调用 LLM）
        # 始终传递 code_units 使用直接分析模式，避免依赖不可靠的向量搜索
        try:
            findings = await asyncio.to_thread(
                analyzer.analyze,
                request.languages[0] if request.languages else None,  # language
                None,  # file_pattern
                request.max_issues,  # max_candidates
                2,  # max_workers
                None,  # use_agent
                code_units,  # code_units - 直接传递代码单元进行模式匹配
                request.use_chain_analysis,  # use_chain_analysis - 是否使用链级分析
                request.max_chain_depth,  # max_chain_depth - 最大调用链深度
                vuln_type_strs,  # vuln_types - 用户选择的漏洞类型
                30,  # max_llm_calls - 最大 LLM 调用次数
                analysis_progress_callback,  # progress_callback - 进度回调
            )
        finally:
            # 停止进度处理任务
            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                pass
        logger.info(f"扫描任务 {scan_id}: 安全规则扫描完成，发现 {len(findings)} 个问题")

        # 记录分析结果
        if app_state.interaction_repo:
            app_state.interaction_repo.log_analysis(
                scan_id,
                f"安全规则扫描完成，发现 {len(findings)} 个安全问题",
            )

        # 广播发现的问题数量
        await broadcast_analysis_detail(scan_id, "scan_progress", {
            "phase": "security_scan_complete",
            "findings_count": len(findings),
            "message": f"安全规则扫描完成，发现 {len(findings)} 个问题"
        })

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

            # 使用线程池执行同步的漏洞检测操作
            vuln_findings = await asyncio.to_thread(
                vuln_detector.detect_vulnerabilities,
                code_units,
                vuln_types,
                request.use_llm,
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
            # 使用线程池执行同步的逻辑漏洞检测
            logic_findings = await asyncio.to_thread(
                vuln_detector.detect_logic_vulnerabilities,
                code_units
            )

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
        # 使用线程池执行同步的调用链分析
        call_graph = await asyncio.to_thread(
            chain_analyzer.build_call_graph,
            code_units
        )
        taint_paths = await asyncio.to_thread(
            chain_analyzer.find_taint_paths,
            10,  # max_depth
            50   # max_paths
        )

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

        # 保存扫描结果到数据库
        await save_scan_results_to_db(scan_id, task, all_findings, all_vuln_findings)

    except Exception as e:
        logger.error(f"扫描任务失败: {e}")
        task.status = ScanStatus.FAILED
        task.error_message = str(e)
        task.current_step = f"错误: {e}"
        await broadcast_scan_progress(scan_id, task)

        # 更新数据库中的失败状态
        if app_state.scan_repo:
            try:
                app_state.scan_repo.update_status(
                    scan_id, "failed",
                    error_message=str(e)
                )
            except Exception as db_err:
                logger.error(f"更新数据库状态失败: {db_err}")


async def broadcast_scan_progress(scan_id: str, task: ScanResultSchema):
    """广播扫描进度

    发送详细的进度信息到前端，支持大型项目的实时反馈。
    """
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
                "total_units": task.total_units,
                "timestamp": datetime.now().isoformat(),
            })
        except Exception as e:
            logger.warning(f"WebSocket 发送失败: {e}")


async def broadcast_llm_stream(scan_id: str, content: str, is_done: bool = False):
    """广播 LLM 流式响应

    实时发送 LLM 生成的内容到前端。

    Args:
        scan_id: 扫描 ID
        content: LLM 生成的内容（增量）
        is_done: 是否完成
    """
    if scan_id in app_state.websocket_connections:
        ws = app_state.websocket_connections[scan_id]
        try:
            await ws.send_json({
                "type": "llm_stream",
                "scan_id": scan_id,
                "content": content,
                "is_done": is_done,
                "timestamp": datetime.now().isoformat(),
            })
        except Exception as e:
            logger.warning(f"WebSocket LLM 流发送失败: {e}")


async def broadcast_analysis_detail(scan_id: str, detail_type: str, data: dict):
    """广播分析详情

    发送分析过程中的详细信息，如正在分析的文件、发现的问题等。

    Args:
        scan_id: 扫描 ID
        detail_type: 详情类型 (analyzing_file, found_issue, chain_analysis, etc.)
        data: 详情数据
    """
    if scan_id in app_state.websocket_connections:
        ws = app_state.websocket_connections[scan_id]
        try:
            await ws.send_json({
                "type": "analysis_detail",
                "scan_id": scan_id,
                "detail_type": detail_type,
                "data": data,
                "timestamp": datetime.now().isoformat(),
            })
        except Exception as e:
            logger.warning(f"WebSocket 分析详情发送失败: {e}")


# 用于存储待广播的交互日志
_pending_interactions = []


def queue_interaction_broadcast(interaction):
    """将交互日志加入广播队列

    这是一个同步函数，作为 InteractionRepository 的回调。
    交互日志会被加入队列，由异步任务进行广播。

    Args:
        interaction: LLMInteraction 对象
    """
    _pending_interactions.append(interaction)


async def broadcast_interaction(interaction):
    """广播交互日志到 WebSocket

    Args:
        interaction: LLMInteraction 对象
    """
    scan_id = interaction.scan_id
    if scan_id in app_state.websocket_connections:
        ws = app_state.websocket_connections[scan_id]
        try:
            # Starlette WebSocket.send_json 内部直接 json.dumps，
            # interaction 里可能包含 datetime/path 等对象，需先转为 JSON 兼容类型。
            await ws.send_json({
                "type": "interaction",
                "scan_id": scan_id,
                "data": to_jsonable(interaction.to_timeline_event()),
            })
        except Exception as e:
            logger.warning(f"WebSocket 广播交互日志失败: {e}")


async def process_interaction_broadcast_queue():
    """后台任务：处理交互日志广播队列

    该任务在应用启动时创建，持续运行直到应用关闭。
    从 _pending_interactions 队列中取出交互日志并广播到 WebSocket。
    """
    global _pending_interactions

    logger.info("交互日志广播队列处理任务已启动")

    while True:
        try:
            # 检查队列中是否有待处理的交互日志
            if _pending_interactions:
                # 取出所有待处理的交互日志
                interactions_to_broadcast = _pending_interactions[:]
                _pending_interactions = []

                # 广播每个交互日志
                for interaction in interactions_to_broadcast:
                    await broadcast_interaction(interaction)

            # 短暂休眠，避免 CPU 空转
            await asyncio.sleep(0.1)

        except asyncio.CancelledError:
            logger.info("交互日志广播队列处理任务已停止")
            raise
        except Exception as e:
            logger.error(f"处理交互日志广播队列时出错: {e}")
            await asyncio.sleep(1)  # 出错后稍长休眠


async def save_scan_results_to_db(
    scan_id: str,
    task: ScanResultSchema,
    findings: List[FindingSchema],
    vuln_findings: List[VulnFindingSchema]
):
    """将扫描结果保存到数据库"""
    if not app_state.scan_repo or not app_state.finding_repo:
        logger.warning("数据库仓库未初始化，跳过保存")
        return

    try:
        # 更新扫描任务状态
        app_state.scan_repo.update_status(
            scan_id,
            status="completed",
            progress=1.0,
            current_step="扫描完成"
        )

        # 保存安全发现
        db_findings = []
        for f in findings:
            db_findings.append(ScanFinding(
                id=f.id,
                scan_id=scan_id,
                finding_type="security",
                title=f.title,
                file_path=f.file_path,
                line_start=f.line_start,
                line_end=f.line_end,
                symbol=f.symbol,
                severity=f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                confidence=f.confidence,
                category=f.category,
                summary=f.summary,
                details=f.details,
                evidence=f.evidence,
                attack_scenario=f.attack_scenario,
                fix_suggestion=f.fix_suggestion,
                code_snippet=f.code_snippet,
                cwe_ids=f.cwe_ids,
                notes=f.notes,
            ))

        # 保存漏洞发现
        for vf in vuln_findings:
            db_findings.append(ScanFinding(
                id=vf.id,
                scan_id=scan_id,
                finding_type="vuln",
                name=vf.name,
                vuln_type=vf.vuln_type.value if hasattr(vf.vuln_type, 'value') else str(vf.vuln_type),
                file_path=vf.file_path,
                line_start=vf.line_start,
                line_end=vf.line_end,
                symbol=vf.function_name,
                severity=vf.severity.value if hasattr(vf.severity, 'value') else str(vf.severity),
                confidence=vf.confidence,
                description=vf.description,
                attack_scenario=vf.attack_scenario,
                fix_suggestion=vf.fix_suggestion,
                code_snippet=vf.code_snippet,
                needs_manual_review=vf.needs_manual_review,
                notes=vf.review_notes,
            ))

        if db_findings:
            app_state.finding_repo.create_many(db_findings)
            logger.info(f"扫描 {scan_id} 的 {len(db_findings)} 个发现已保存到数据库")

    except Exception as e:
        logger.error(f"保存扫描结果到数据库失败: {e}")


@app.post("/api/scan", response_model=APIResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """开始扫描任务"""
    print(f"[API] 收到扫描请求: {request.target_path}")

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

    # 在数据库中创建扫描任务记录
    if app_state.scan_repo:
        try:
            db_task = ScanTask(
                scan_id=scan_id,
                target_path=str(target_path),
                status="pending",
                progress=0.0,
                current_step="准备中...",
                started_at=datetime.now().isoformat(),
                config={
                    "languages": request.languages,
                    "use_llm": request.use_llm,
                    "skip_index": request.skip_index,
                    "use_chain_analysis": request.use_chain_analysis,
                }
            )
            app_state.scan_repo.create(db_task)
            logger.info(f"扫描任务 {scan_id} 已保存到数据库")
        except Exception as e:
            logger.error(f"保存扫描任务到数据库失败: {e}")

    # 启动后台任务 - 使用 asyncio.create_task 替代 background_tasks
    # BackgroundTasks 对异步函数支持有问题
    print(f"[API] 创建扫描任务 {scan_id}")
    asyncio.create_task(run_scan_task(scan_id, request))

    return APIResponse(
        success=True,
        message="扫描任务已创建",
        data={"scan_id": scan_id},
    )


@app.get("/api/scan/{scan_id}", response_model=APIResponse)
async def get_scan_result(scan_id: str):
    """获取扫描结果"""
    # 先从内存中查找（正在进行的任务）
    if scan_id in app_state.scan_tasks:
        task = app_state.scan_tasks[scan_id]
        return APIResponse(
            success=True,
            message="获取成功",
            data=task.model_dump(),
        )

    # 从数据库中查找历史记录
    if app_state.scan_repo:
        db_task = app_state.scan_repo.get_by_id(scan_id)
        if db_task:
            # 获取发现统计
            finding_stats = {}
            findings_list = []
            vuln_findings_list = []

            if app_state.finding_repo:
                finding_stats = app_state.finding_repo.get_stats(scan_id)
                # 加载实际的发现数据
                db_findings = app_state.finding_repo.get_by_scan_id(scan_id, limit=200)
                for f in db_findings:
                    f_dict = f.to_dict()
                    if f.finding_type == "security":
                        findings_list.append(f_dict)
                    else:
                        vuln_findings_list.append(f_dict)

            return APIResponse(
                success=True,
                message="获取成功（历史记录）",
                data={
                    "scan_id": db_task.scan_id,
                    "status": db_task.status,
                    "target_path": db_task.target_path,
                    "progress": db_task.progress,
                    "current_step": db_task.current_step,
                    "started_at": db_task.started_at,
                    "completed_at": db_task.completed_at,
                    "total_units": db_task.total_units,
                    "error_message": db_task.error_message,
                    "findings_count": finding_stats.get("total", 0),
                    "findings_stats": finding_stats,
                    "findings": findings_list,
                    "vuln_findings": vuln_findings_list,
                },
            )

    raise HTTPException(status_code=404, detail="扫描任务不存在")


@app.get("/api/scan/{scan_id}/findings", response_model=APIResponse)
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    """获取扫描发现（支持分页和过滤）"""
    # 先从内存中查找（正在进行的任务）
    if scan_id in app_state.scan_tasks:
        task = app_state.scan_tasks[scan_id]
        findings = [f.model_dump() for f in task.findings]
        vuln_findings = [f.model_dump() for f in task.vuln_findings]

        # 简单过滤（内存中的数据）
        if severity:
            findings = [f for f in findings if f.get("severity") == severity]
            vuln_findings = [vf for vf in vuln_findings if vf.get("severity") == severity]

        return APIResponse(
            success=True,
            message=f"共 {len(findings) + len(vuln_findings)} 个发现",
            data={
                "findings": findings[offset:offset+limit],
                "vuln_findings": vuln_findings[offset:offset+limit],
                "total": len(findings) + len(vuln_findings),
                "limit": limit,
                "offset": offset,
            },
        )

    # 从数据库中查找
    if app_state.finding_repo:
        db_findings = app_state.finding_repo.get_by_scan_id(
            scan_id,
            severity=severity,
            category=category,
            limit=limit,
            offset=offset,
        )
        if db_findings or app_state.scan_repo.get_by_id(scan_id):
            # 分离 security 和 vuln 类型
            findings = [f.to_dict() for f in db_findings if f.finding_type == "security"]
            vuln_findings = [f.to_dict() for f in db_findings if f.finding_type == "vuln"]
            total = app_state.finding_repo.count(scan_id=scan_id)

            return APIResponse(
                success=True,
                message=f"共 {total} 个发现（数据库）",
                data={
                    "findings": findings,
                    "vuln_findings": vuln_findings,
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                },
            )

    raise HTTPException(status_code=404, detail="扫描任务不存在")


@app.get("/api/scans", response_model=APIResponse)
async def list_scans(
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    """列出所有扫描任务（内存 + 数据库）"""
    tasks = []
    seen_ids = set()

    # 先添加内存中的任务（正在进行的）
    for scan_id, task in app_state.scan_tasks.items():
        if status and task.status.value != status:
            continue
        tasks.append({
            "scan_id": scan_id,
            "status": task.status.value,
            "target_path": task.target_path,
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
            "findings_count": len(task.findings),
            "vuln_count": len(task.vuln_findings),
            "progress": task.progress,
            "source": "memory",
        })
        seen_ids.add(scan_id)

    # 添加数据库中的历史记录
    if app_state.scan_repo:
        db_tasks = app_state.scan_repo.list_all(status=status, limit=limit, offset=offset)
        for db_task in db_tasks:
            if db_task.scan_id not in seen_ids:
                # 获取发现数量
                finding_count = 0
                if app_state.finding_repo:
                    finding_count = app_state.finding_repo.count(scan_id=db_task.scan_id)

                tasks.append({
                    "scan_id": db_task.scan_id,
                    "status": db_task.status,
                    "target_path": db_task.target_path,
                    "started_at": db_task.started_at,
                    "completed_at": db_task.completed_at,
                    "findings_count": finding_count,
                    "vuln_count": 0,  # 数据库中合并存储
                    "progress": db_task.progress,
                    "source": "database",
                })

    # 按创建时间排序（最新的在前）
    tasks.sort(key=lambda x: x.get("started_at") or "", reverse=True)

    return APIResponse(
        success=True,
        message=f"共 {len(tasks)} 个扫描任务",
        data={
            "tasks": tasks[offset:offset+limit] if offset > 0 else tasks[:limit],
            "total": len(tasks),
            "limit": limit,
            "offset": offset,
        },
    )


# ============ 交互日志接口 ============

@app.get("/api/scan/{scan_id}/interactions", response_model=APIResponse)
async def get_scan_interactions(
    scan_id: str,
    interaction_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    """获取扫描任务的 LLM 交互日志

    用于实时展示 LLM 分析过程
    """
    if not app_state.interaction_repo:
        raise HTTPException(status_code=500, detail="交互日志仓库未初始化")

    interactions = app_state.interaction_repo.get_by_scan_id(
        scan_id,
        interaction_type=interaction_type,
        limit=limit,
        offset=offset,
    )

    return APIResponse(
        success=True,
        message=f"共 {len(interactions)} 条交互记录",
        data={
            "interactions": [i.to_dict() for i in interactions],
            "total": len(interactions),
            "limit": limit,
            "offset": offset,
        },
    )


@app.get("/api/scan/{scan_id}/timeline", response_model=APIResponse)
async def get_scan_timeline(scan_id: str, limit: int = 100):
    """获取扫描任务的时间线（用于前端展示）"""
    if not app_state.interaction_repo:
        raise HTTPException(status_code=500, detail="交互日志仓库未初始化")

    timeline = app_state.interaction_repo.get_timeline(scan_id, limit)

    return APIResponse(
        success=True,
        message=f"共 {len(timeline)} 条时间线记录",
        data={
            "timeline": timeline,
            "total": len(timeline),
        },
    )


@app.get("/api/scan/{scan_id}/interactions/latest", response_model=APIResponse)
async def get_latest_interactions(
    scan_id: str,
    since_id: Optional[int] = None,
    limit: int = 50,
):
    """获取最新交互记录（用于实时更新）

    Args:
        scan_id: 扫描任务 ID
        since_id: 上次获取的最后一个 ID，获取该 ID 之后的记录
        limit: 返回数量限制
    """
    if not app_state.interaction_repo:
        raise HTTPException(status_code=500, detail="交互日志仓库未初始化")

    interactions = app_state.interaction_repo.get_latest(
        scan_id,
        since_id=since_id,
        limit=limit,
    )

    return APIResponse(
        success=True,
        message=f"获取到 {len(interactions)} 条新记录",
        data={
            "interactions": [i.to_dict() for i in interactions],
            "last_id": interactions[-1].id if interactions else since_id,
        },
    )


@app.get("/api/scan/{scan_id}/stats", response_model=APIResponse)
async def get_scan_stats(scan_id: str):
    """获取扫描任务的统计信息"""
    stats = {}

    # 获取交互统计
    if app_state.interaction_repo:
        stats["interactions"] = app_state.interaction_repo.get_stats(scan_id)

    # 获取发现统计
    if app_state.finding_repo:
        stats["findings"] = app_state.finding_repo.get_stats(scan_id)

    return APIResponse(
        success=True,
        message="获取统计成功",
        data=stats,
    )


# ============ 调用图接口 ============

@app.post("/api/callgraph", response_model=APIResponse)
async def analyze_callgraph(request: CallGraphRequest):
    """分析调用图"""
    if not app_state.indexer:
        raise HTTPException(status_code=500, detail="索引器未初始化")

    try:
        # 获取代码单元（使用线程池）
        code_units = await asyncio.to_thread(app_state.indexer.get_all_units)

        # 构建调用图（使用线程池）
        chain_analyzer = CallChainAnalyzer(app_state.rule_manager)
        call_graph = await asyncio.to_thread(
            chain_analyzer.build_call_graph,
            code_units
        )

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

        # 查找污点路径（使用线程池）
        if request.find_taint:
            taint_paths = await asyncio.to_thread(
                chain_analyzer.find_taint_paths,
                request.max_depth,
                100,  # max_paths
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

        # 查找危险调用链（使用线程池）
        dangerous_chains = await asyncio.to_thread(
            chain_analyzer.find_dangerous_chains
        )
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


# ============ 配置接口 ============

class LLMSettingsRequest(BaseModel):
    """LLM 配置请求"""
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    embedding_model: Optional[str] = None
    embedding_base_url: Optional[str] = None
    embedding_api_key: Optional[str] = None
    embedding_dim: Optional[int] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None


class SettingsRequest(BaseModel):
    """配置更新请求"""
    llm: Optional[LLMSettingsRequest] = None
    scan_mode: Optional[str] = None
    target_path: Optional[str] = None


@app.get("/api/settings", response_model=APIResponse)
async def get_settings():
    """获取当前配置"""
    if not app_state.config:
        raise HTTPException(status_code=500, detail="配置未初始化")

    # 返回配置（遮蔽敏感信息）
    config = app_state.config

    # 安全地获取 API Key 前缀
    def mask_key(key: str) -> str:
        if not key:
            return ""
        if len(key) <= 8:
            return "****"
        return key[:4] + "****" + key[-4:]

    return APIResponse(
        success=True,
        message="获取配置成功",
        data={
            "llm": {
                "base_url": config.llm.base_url,
                "api_key_masked": mask_key(config.llm.api_key),
                "api_key_configured": bool(config.llm.api_key),
                "model": config.llm.model,
                "embedding_model": config.llm.embedding_model,
                "embedding_base_url": config.llm.embedding_base_url,
                "embedding_api_key_configured": bool(config.llm.embedding_api_key),
                "embedding_dim": config.llm.embedding_dim,
                "temperature": config.llm.temperature,
                "max_tokens": config.llm.max_tokens,
            },
            "scan": {
                "mode": config.scan.mode,
                "target_path": config.scan.target_path,
                "languages": config.scan.languages,
            },
            "vector_store": {
                "provider": config.vector_store.provider,
                "host": config.vector_store.host,
                "port": config.vector_store.port,
            },
        },
    )


@app.post("/api/settings", response_model=APIResponse)
async def update_settings(request: SettingsRequest):
    """更新配置并重新初始化 LLM 客户端"""
    if not app_state.config:
        raise HTTPException(status_code=500, detail="配置未初始化")

    logger.info(f"收到配置更新请求")

    updated_fields = []

    # 更新 LLM 配置
    if request.llm:
        llm_config = app_state.config.llm

        if request.llm.base_url is not None:
            llm_config.base_url = request.llm.base_url
            updated_fields.append("llm.base_url")
            logger.info(f"更新 LLM base_url: {request.llm.base_url}")

        if request.llm.api_key is not None:
            llm_config.api_key = request.llm.api_key
            updated_fields.append("llm.api_key")
            logger.info(f"更新 LLM api_key: {'已配置' if request.llm.api_key else '未配置'}")

        if request.llm.model is not None:
            llm_config.model = request.llm.model
            updated_fields.append("llm.model")
            logger.info(f"更新 LLM model: {request.llm.model}")

        if request.llm.embedding_model is not None:
            llm_config.embedding_model = request.llm.embedding_model
            updated_fields.append("llm.embedding_model")

        if request.llm.embedding_base_url is not None:
            llm_config.embedding_base_url = request.llm.embedding_base_url
            updated_fields.append("llm.embedding_base_url")

        if request.llm.embedding_api_key is not None:
            llm_config.embedding_api_key = request.llm.embedding_api_key
            updated_fields.append("llm.embedding_api_key")

        if request.llm.embedding_dim is not None:
            old_dim = llm_config.embedding_dim
            llm_config.embedding_dim = request.llm.embedding_dim
            updated_fields.append("llm.embedding_dim")

            # 如果维度变化，需要重新创建 vector_store 和 indexer
            if old_dim != request.llm.embedding_dim:
                logger.info(f"嵌入维度变化: {old_dim} -> {request.llm.embedding_dim}，重建向量存储...")
                try:
                    # 重新创建 vector_store（会使用新维度）
                    app_state.vector_store = create_vector_store(
                        app_state.config.vector_store,
                        embedding_dim=request.llm.embedding_dim
                    )
                    # 清空旧集合并用新维度重建
                    app_state.vector_store.clear()
                    # 重新创建 indexer
                    app_state.indexer = CodeIndexer(
                        app_state.config,
                        app_state.llm_client,
                        app_state.vector_store
                    )
                    logger.info("向量存储和索引器已用新维度重建")
                except Exception as e:
                    logger.error(f"重建向量存储失败: {e}")
                    raise HTTPException(status_code=500, detail=f"重建向量存储失败: {e}")

        if request.llm.temperature is not None:
            llm_config.temperature = request.llm.temperature
            updated_fields.append("llm.temperature")

        if request.llm.max_tokens is not None:
            llm_config.max_tokens = request.llm.max_tokens
            updated_fields.append("llm.max_tokens")

        # 重新创建 LLM 客户端
        try:
            logger.info("重新初始化 LLM 客户端...")
            app_state.llm_client = create_llm_client(llm_config)
            logger.info("LLM 客户端重新初始化成功")
        except Exception as e:
            logger.error(f"重新初始化 LLM 客户端失败: {e}")
            raise HTTPException(status_code=500, detail=f"LLM 客户端初始化失败: {e}")

    # 更新扫描配置
    if request.scan_mode is not None:
        app_state.config.scan.mode = request.scan_mode
        updated_fields.append("scan.mode")

    if request.target_path is not None:
        app_state.config.scan.target_path = request.target_path
        updated_fields.append("scan.target_path")

    # 持久化配置到本地文件
    if updated_fields:
        config_to_save = {}
        if request.llm:
            config_to_save["llm"] = {}
            if request.llm.base_url is not None:
                config_to_save["llm"]["base_url"] = request.llm.base_url
            if request.llm.api_key is not None:
                config_to_save["llm"]["api_key"] = request.llm.api_key
            if request.llm.model is not None:
                config_to_save["llm"]["model"] = request.llm.model
            if request.llm.embedding_model is not None:
                config_to_save["llm"]["embedding_model"] = request.llm.embedding_model
            if request.llm.embedding_base_url is not None:
                config_to_save["llm"]["embedding_base_url"] = request.llm.embedding_base_url
            if request.llm.embedding_api_key is not None:
                config_to_save["llm"]["embedding_api_key"] = request.llm.embedding_api_key
            if request.llm.embedding_dim is not None:
                config_to_save["llm"]["embedding_dim"] = request.llm.embedding_dim
            if request.llm.temperature is not None:
                config_to_save["llm"]["temperature"] = request.llm.temperature
            if request.llm.max_tokens is not None:
                config_to_save["llm"]["max_tokens"] = request.llm.max_tokens

        if request.scan_mode is not None:
            if "scan" not in config_to_save:
                config_to_save["scan"] = {}
            config_to_save["scan"]["mode"] = request.scan_mode

        if request.target_path is not None:
            if "scan" not in config_to_save:
                config_to_save["scan"] = {}
            config_to_save["scan"]["target_path"] = request.target_path

        # 保存到文件
        if save_user_config(config_to_save):
            logger.info(f"配置已持久化到本地文件")
        else:
            logger.warning("配置持久化失败，但内存配置已更新")

    return APIResponse(
        success=True,
        message=f"配置已更新并保存: {', '.join(updated_fields)}" if updated_fields else "无配置变更",
        data={"updated_fields": updated_fields},
    )


@app.post("/api/settings/test-connection", response_model=APIResponse)
async def test_llm_connection():
    """测试 LLM 连接"""
    if not app_state.llm_client:
        raise HTTPException(status_code=500, detail="LLM 客户端未初始化")

    if not app_state.config.llm.api_key:
        return APIResponse(
            success=False,
            message="API Key 未配置",
            data={"error": "API Key 未配置，请先在设置中配置 API Key"},
        )

    try:
        from llm_client import ChatMessage

        logger.info("测试 LLM 连接...")

        # 发送简单测试请求
        response = app_state.llm_client.chat_completion(
            messages=[
                ChatMessage(role="user", content="Say 'Connection test successful' in one sentence.")
            ],
            max_tokens=50,
            temperature=0,
        )

        logger.info(f"LLM 连接测试成功: {response.content[:100] if response.content else 'No content'}")

        return APIResponse(
            success=True,
            message="LLM 连接测试成功",
            data={
                "model": response.model,
                "response": response.content[:200] if response.content else "",
                "usage": response.usage,
            },
        )
    except Exception as e:
        logger.error(f"LLM 连接测试失败: {e}")
        return APIResponse(
            success=False,
            message=f"LLM 连接测试失败: {str(e)}",
            data={"error": str(e)},
        )


@app.post("/api/settings/test-embedding", response_model=APIResponse)
async def test_embedding_connection():
    """测试嵌入模型连接"""
    if not app_state.llm_client:
        raise HTTPException(status_code=500, detail="LLM 客户端未初始化")

    # 检查嵌入模型配置
    llm_config = app_state.config.llm
    embedding_api_key = llm_config.embedding_api_key or llm_config.api_key

    if not embedding_api_key:
        return APIResponse(
            success=False,
            message="嵌入模型 API Key 未配置",
            data={"error": "嵌入模型 API Key 未配置，请先配置"},
        )

    try:
        logger.info("测试嵌入模型连接...")

        # 发送简单测试请求
        test_text = ["This is a test for embedding model connection."]
        response = app_state.llm_client.embed(test_text)

        if response.embeddings and len(response.embeddings) > 0:
            embedding_dim = len(response.embeddings[0])
            logger.info(f"嵌入模型连接测试成功: 维度={embedding_dim}")

            return APIResponse(
                success=True,
                message="嵌入模型连接测试成功",
                data={
                    "model": llm_config.embedding_model,
                    "embedding_dim": embedding_dim,
                    "configured_dim": llm_config.embedding_dim,
                    "dim_match": embedding_dim == llm_config.embedding_dim,
                },
            )
        else:
            return APIResponse(
                success=False,
                message="嵌入模型返回空结果",
                data={"error": "嵌入模型返回空结果"},
            )

    except Exception as e:
        logger.error(f"嵌入模型连接测试失败: {e}")
        return APIResponse(
            success=False,
            message=f"嵌入模型连接测试失败: {str(e)}",
            data={"error": str(e)},
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
