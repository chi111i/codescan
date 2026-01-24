"""FastAPI 主应用 - 代码安全审计 API"""

import sys
import os

# ============ 早期 UTF-8 编码设置 ============
# 必须在任何其他模块导入之前设置，确保中文日志正确显示
os.environ['PYTHONUNBUFFERED'] = '1'
os.environ['PYTHONIOENCODING'] = 'utf-8'

if sys.platform == 'win32':
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleOutputCP(65001)  # UTF-8 code page
    except Exception:
        pass

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', line_buffering=True)
    except Exception:
        pass
if hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8', line_buffering=True)
    except Exception:
        pass

# ============ 其他导入 ============
import uuid
import asyncio
import logging
import time
import queue
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List, Any
from contextlib import asynccontextmanager


class FlushingStreamHandler(logging.StreamHandler):
    """自动刷新的 StreamHandler，解决 Windows 上 uvicorn reload 子进程日志不显示问题"""

    def emit(self, record):
        super().emit(record)
        self.flush()


def setup_logging():
    """配置日志系统 - 确保所有模块日志正确输出到终端

    注意: 此函数设计为幂等，多次调用不会重复添加 handler

    Windows uvicorn --reload 子进程日志问题的解决方案:
    1. 使用 sys.stdout 而非 sys.stderr（Windows 终端对 stdout 处理更好）
    2. 使用自定义 FlushingStreamHandler 每次日志后立即刷新
    3. 设置环境变量禁用 Python 输出缓冲
    4. 设置 Windows 终端为 UTF-8 编码
    """
    import os
    import io

    # 禁用 Python 输出缓冲
    os.environ['PYTHONUNBUFFERED'] = '1'
    os.environ['PYTHONIOENCODING'] = 'utf-8'

    # Windows 特殊处理：设置 stdout/stderr 为 UTF-8 编码和无缓冲模式
    if sys.platform == 'win32':
        try:
            # 尝试设置 Windows 控制台为 UTF-8 模式
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleOutputCP(65001)  # UTF-8 code page
        except Exception:
            pass

    # 重新配置 stdout/stderr 为 UTF-8 编码
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8', line_buffering=True)
        except Exception:
            pass
    if hasattr(sys.stderr, 'reconfigure'):
        try:
            sys.stderr.reconfigure(encoding='utf-8', line_buffering=True)
        except Exception:
            pass

    # 创建格式化器
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # 配置根 logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # 幂等检查：如果已经有 FlushingStreamHandler，则跳过添加
    has_flushing_handler = any(
        isinstance(h, FlushingStreamHandler) for h in root_logger.handlers
    )

    if not has_flushing_handler:
        # 清除已有处理器（仅在首次配置时）
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # 使用 sys.stdout 替代 sys.stderr（Windows 对 stdout 的子进程继承更可靠）
        # 并使用自动刷新的 Handler 确保日志立即显示
        console_handler = FlushingStreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)

        # 添加控制台处理器
        root_logger.addHandler(console_handler)

        # 输出启动信息（仅首次）
        root_logger.info("Logging system initialized")

    # 设置第三方库日志级别（减少噪音）- 每次都设置以确保一致性
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("watchfiles").setLevel(logging.WARNING)

    # 确保 uvicorn（含 reload worker）日志统一走根 logger 的控制台处理器
    # 关键：清除 uvicorn 自带的 handler，强制 propagate 到根 logger
    for uvicorn_logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(uvicorn_logger_name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.setLevel(logging.INFO)
        uvicorn_logger.propagate = True

    # 确保本项目模块日志输出
    for module in ["llm_client", "agent", "analyzer", "indexer", "api", "rules", "config", "prompts"]:
        module_logger = logging.getLogger(module)
        module_logger.setLevel(logging.INFO)
        module_logger.propagate = True  # 确保传播到根 logger


# 注意：不在模块导入时调用 setup_logging()
# uvicorn --reload 模式下会在 worker 进程中重新配置日志，覆盖这里的设置
# 改为仅在 lifespan（worker 启动后）中调用，确保日志配置生效
#
# 如果需要在导入时输出启动日志，使用 print() 而非 logger

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
    SinkCallScanner,
    SinkCallSite,
    CallGraph,
    FunctionCallingAdapter,
    FCAdapterConfig,
    FCSecurityTools,
    FCToolCall,
    FCToolStatus,
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
    SelectedAnalysisRequest,
    ScanResultSchema, IndexResultSchema, SearchResultSchema,
    StatsSchema, RuleListSchema, RuleSchema,
    FindingSchema, VulnFindingSchema, TaintPathSchema,
    CallGraphStatsSchema, CodeUnitSchema, CodeSpanSchema,
    CallGraphNodeSchema, CallGraphEdgeSchema, CallChainSchema,
    ScanStatus, SeverityLevel, VulnTypeEnum,
    IndexStatus, IndexProgressSchema,
    SinkCallSiteSchema, SinkSitesResponseSchema, SinkCategoryEnum,
    ToolCallSchema, FCAnalysisProgressSchema,
    APIResponse, ErrorResponse,
)
from pydantic import BaseModel

logger = logging.getLogger(__name__)


# ============ HTTP 请求日志中间件 ============

class HTTPLoggingMiddleware(BaseHTTPMiddleware):
    """HTTP 请求日志中间件 - 记录所有 HTTP 请求和响应"""

    async def dispatch(self, request: Request, call_next):
        import sys as _sys
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
            # 诊断：使用 stderr.write 强制输出（无缓冲）
            _sys.stderr.write(f"[HTTP-DEBUG] {log_msg}\n")
            _sys.stderr.flush()

        # 执行请求
        response = await call_next(request)

        # 计算耗时
        duration = time.time() - start_time

        if not skip_logging:
            log_msg = f"[HTTP] {method} {path} -> {response.status_code} ({duration:.3f}s)"
            logger.info(log_msg)
            # 诊断：使用 stderr.write 强制输出（无缓冲）
            _sys.stderr.write(f"[HTTP-DEBUG] {log_msg}\n")
            _sys.stderr.flush()

        return response


# ============ SPA 回退中间件 ============

class SPAFallbackMiddleware(BaseHTTPMiddleware):
    """SPA 回退中间件 - 处理前端路由的直接访问或刷新

    对于非 API/WebSocket/静态资源的 GET 请求，返回 index.html，
    让前端路由器（Vue Router）处理实际路由。
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method

        # 只处理 GET 请求
        if method != "GET":
            return await call_next(request)

        # 排除：API 路由、WebSocket、静态资源、根路径
        excluded_prefixes = ("/api/", "/ws/", "/assets/", "/docs", "/openapi", "/redoc")
        if path == "/" or any(path.startswith(prefix) for prefix in excluded_prefixes):
            return await call_next(request)

        # 排除：文件扩展名请求（如 .js, .css, .svg, .ico）
        if "." in path.split("/")[-1]:
            return await call_next(request)

        # 尝试正常路由
        response = await call_next(request)

        # 如果返回 404，尝试返回 index.html
        if response.status_code == 404:
            frontend_dir = Path(__file__).parent.parent / "frontend" / "dist"
            index_file = frontend_dir / "index.html"
            if index_file.exists():
                return FileResponse(index_file)

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

        # 索引任务 WebSocket 连接（分离于扫描）
        self.index_ws_connections: Dict[str, WebSocket] = {}

        # 索引任务状态
        self.index_tasks: Dict[str, IndexProgressSchema] = {}

        # 后台任务跟踪（用于优雅关闭）
        self.background_tasks: Dict[str, asyncio.Task] = {}

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
    # 重新配置日志系统（uvicorn 启动后会覆盖模块级配置）
    setup_logging()

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

    # 启动后台任务处理 FC 事件广播队列
    fc_broadcast_task = asyncio.create_task(process_fc_event_queue())

    yield

    # 关闭时清理
    logger.info("开始优雅关闭...")

    # 1. 取消并等待所有后台扫描任务
    if app_state.background_tasks:
        logger.info(f"取消 {len(app_state.background_tasks)} 个后台任务...")
        for task_id, task in list(app_state.background_tasks.items()):
            if not task.done():
                task.cancel()
        # 等待所有任务完成（带超时）
        if app_state.background_tasks:
            pending = [t for t in app_state.background_tasks.values() if not t.done()]
            if pending:
                done, still_pending = await asyncio.wait(pending, timeout=10.0)
                if still_pending:
                    logger.warning(f"{len(still_pending)} 个任务未能在超时内完成")
                for task in still_pending:
                    task.cancel()
        app_state.background_tasks.clear()
        logger.info("后台任务已清理")

    # 2. 取消广播任务
    broadcast_task.cancel()
    try:
        await broadcast_task
    except asyncio.CancelledError:
        pass

    # 2.1 取消 FC 广播任务
    fc_broadcast_task.cancel()
    try:
        await fc_broadcast_task
    except asyncio.CancelledError:
        pass

    # 3. 关闭 LLM 客户端 HTTP 连接
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

    # 4. 关闭数据库连接
    if app_state.db:
        try:
            app_state.db.close_all()
            logger.info("数据库连接已关闭")
        except Exception as e:
            logger.warning(f"关闭数据库连接失败: {e}")

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

    # SPA 回退中间件（处理前端路由直接访问）
    application.add_middleware(SPAFallbackMiddleware)

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


# ============ WebSocket 广播辅助函数 ============


async def _safe_ws_send(
    ws: WebSocket,
    message: dict,
    connection_id: str,
    connection_pool: dict,
    context: str = "广播"
) -> bool:
    """安全地发送 WebSocket 消息，处理断开连接并清理连接池

    H-4 修复: 统一处理 WebSocketDisconnect 异常，防止连接泄漏

    Args:
        ws: WebSocket 连接对象
        message: 要发送的消息
        connection_id: 连接标识（scan_id / index_id / session_id）
        connection_pool: 连接池字典
        context: 日志上下文描述

    Returns:
        bool: 发送是否成功
    """
    try:
        await ws.send_json(message)
        return True
    except WebSocketDisconnect:
        # 客户端已断开，清理连接
        if connection_id in connection_pool:
            del connection_pool[connection_id]
            logger.info(f"[{context}] 客户端断开，已清理连接: {connection_id}")
        return False
    except Exception as e:
        # 其他异常（如连接已关闭），也尝试清理
        if connection_id in connection_pool:
            # 检查是否是连接关闭相关的异常
            error_msg = str(e).lower()
            if "closed" in error_msg or "disconnect" in error_msg or "connection" in error_msg:
                del connection_pool[connection_id]
                logger.info(f"[{context}] 连接异常断开，已清理: {connection_id}")
            else:
                logger.warning(f"[{context}] WebSocket 发送失败 ({connection_id}): {e}")
        return False


# ============ 索引接口 ============


async def broadcast_index_progress(index_id: str, progress: IndexProgressSchema):
    """广播索引进度到 WebSocket"""
    if index_id in app_state.index_ws_connections:
        ws = app_state.index_ws_connections[index_id]
        await _safe_ws_send(
            ws,
            {
                "type": "index_progress",
                "index_id": index_id,
                "status": progress.status.value,
                "progress": progress.progress,
                "current_step": progress.current_step,
                "total_files": progress.total_files,
                "processed_files": progress.processed_files,
                "total_units": progress.total_units,
                "processed_units": progress.processed_units,
                "embedding_progress": progress.embedding_progress,
                "error_message": progress.error_message,
            },
            index_id,
            app_state.index_ws_connections,
            "索引进度"
        )


async def run_index_task(index_id: str, target_path: Path, clear_existing: bool):
    """后台执行索引任务（支持定期进度广播）"""
    progress = app_state.index_tasks.get(index_id)
    if not progress:
        return

    # 定期广播控制
    last_broadcast_time = time.time()
    broadcast_interval = 0.5  # 每 0.5 秒广播一次

    async def maybe_broadcast():
        """如果距上次广播超过间隔，则广播进度"""
        nonlocal last_broadcast_time
        now = time.time()
        if now - last_broadcast_time >= broadcast_interval:
            last_broadcast_time = now
            await broadcast_index_progress(index_id, progress)

    try:
        progress.status = IndexStatus.SCANNING
        progress.current_step = "扫描文件..."
        progress.started_at = datetime.now()
        await broadcast_index_progress(index_id, progress)

        if clear_existing and app_state.indexer:
            app_state.indexer.clear_index()

        if not app_state.indexer:
            raise Exception("索引器未初始化")

        # 用于线程安全的进度更新队列
        progress_queue = asyncio.Queue()

        # 解析阶段进度回调（在线程池中执行）
        def on_parse_progress(processed: int, total: int):
            progress.processed_files = processed
            progress.total_files = total
            progress.progress = 0.1 + 0.3 * (processed / max(total, 1))
            progress.current_step = f"解析文件: {processed}/{total}"
            # 将广播请求放入队列
            try:
                progress_queue.put_nowait(("parse", processed, total))
            except asyncio.QueueFull:
                pass  # 忽略队列满的情况

        # 嵌入阶段进度回调
        def on_embed_progress(processed: int, total: int, msg: str = ""):
            progress.processed_units = processed
            progress.total_units = total
            progress.embedding_progress = processed / max(total, 1)
            progress.progress = 0.4 + 0.5 * (processed / max(total, 1))
            progress.current_step = msg or f"生成嵌入: {processed}/{total}"
            try:
                progress_queue.put_nowait(("embed", processed, total))
            except asyncio.QueueFull:
                pass

        # 启动进度广播协程
        async def progress_broadcaster():
            """定期从队列读取进度并广播"""
            while True:
                try:
                    # 等待进度更新，超时后检查是否需要广播
                    await asyncio.wait_for(progress_queue.get(), timeout=broadcast_interval)
                    await maybe_broadcast()
                except asyncio.TimeoutError:
                    # 超时，检查是否需要广播（即使没有新进度）
                    await maybe_broadcast()
                except asyncio.CancelledError:
                    break

        # 启动广播任务
        broadcaster_task = asyncio.create_task(progress_broadcaster())

        try:
            # 阶段1: 解析文件
            progress.status = IndexStatus.PARSING
            progress.progress = 0.1
            await broadcast_index_progress(index_id, progress)

            # 使用线程池执行同步的索引操作
            count = await asyncio.to_thread(
                app_state.indexer.index_directory,
                str(target_path),
                on_parse_progress,
                on_embed_progress  # 传递嵌入回调
            )

            # 获取统计
            stats = await asyncio.to_thread(app_state.indexer.get_stats)

            # 完成
            progress.status = IndexStatus.COMPLETED
            progress.progress = 1.0
            progress.current_step = "索引完成"
            progress.total_units = stats.get("total_units", count)
            progress.processed_units = progress.total_units
            progress.completed_at = datetime.now()
            await broadcast_index_progress(index_id, progress)

            # 使统计缓存失效
            app_state.invalidate_stats_cache()

        finally:
            # 取消广播任务
            broadcaster_task.cancel()
            try:
                await broadcaster_task
            except asyncio.CancelledError:
                pass

    except Exception as e:
        import traceback
        logger.error(f"索引任务失败: {e}\n{traceback.format_exc()}")
        progress.status = IndexStatus.FAILED
        progress.error_message = str(e)
        progress.current_step = f"错误: {e}"
        await broadcast_index_progress(index_id, progress)


@app.post("/api/index", response_model=APIResponse)
async def index_project(request: IndexRequest, background_tasks: BackgroundTasks):
    """索引项目代码（同步模式，兼容旧接口）"""
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


@app.post("/api/index/async", response_model=APIResponse)
async def index_project_async(request: IndexRequest):
    """异步索引项目代码（后台执行，WebSocket 推送进度）

    返回 index_id，客户端可通过 /ws/index/{index_id} 接收进度更新
    """
    if not app_state.indexer:
        raise HTTPException(status_code=500, detail="索引器未初始化")

    target_path = Path(request.target_path)
    if not target_path.exists():
        raise HTTPException(status_code=400, detail=f"目标路径不存在: {request.target_path}")

    # 生成索引任务 ID
    index_id = str(uuid.uuid4())

    # 创建进度跟踪对象
    progress = IndexProgressSchema(
        index_id=index_id,
        target_path=str(target_path),
        status=IndexStatus.PENDING,
        progress=0.0,
        current_step="等待开始...",
    )
    app_state.index_tasks[index_id] = progress

    # 启动后台任务
    task = asyncio.create_task(run_index_task(index_id, target_path, request.clear_existing))
    app_state.background_tasks[f"index_{index_id}"] = task

    return APIResponse(
        success=True,
        message="索引任务已创建",
        data={"index_id": index_id, "target_path": str(target_path)},
    )


@app.get("/api/index/{index_id}/progress", response_model=APIResponse)
async def get_index_progress(index_id: str):
    """获取索引任务进度"""
    progress = app_state.index_tasks.get(index_id)
    if not progress:
        raise HTTPException(status_code=404, detail="索引任务不存在")

    return APIResponse(
        success=True,
        message="获取进度成功",
        data=progress.model_dump(),
    )


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
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"扫描任务失败: {e}\n{error_trace}")
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
        message = {
            "type": "progress",
            "scan_id": scan_id,
            "status": task.status.value,
            "progress": task.progress,
            "current_step": task.current_step,
            "findings_count": len(task.findings),
            "vuln_count": len(task.vuln_findings),
            "total_units": task.total_units,
            "target_path": task.target_path,
            "timestamp": datetime.now().isoformat(),
        }
        success = await _safe_ws_send(
            ws, message, scan_id,
            app_state.websocket_connections, "扫描进度"
        )

        # 如果是完成或失败状态，给前端一点时间处理消息
        if success and task.status.value in ("completed", "failed"):
            import asyncio
            await asyncio.sleep(0.1)  # 100ms 延迟确保消息被处理


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
        await _safe_ws_send(
            ws,
            {
                "type": "llm_stream",
                "scan_id": scan_id,
                "content": content,
                "is_done": is_done,
                "timestamp": datetime.now().isoformat(),
            },
            scan_id,
            app_state.websocket_connections,
            "LLM流"
        )


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
        await _safe_ws_send(
            ws,
            {
                "type": "analysis_detail",
                "scan_id": scan_id,
                "detail_type": detail_type,
                "data": data,
                "timestamp": datetime.now().isoformat(),
            },
            scan_id,
            app_state.websocket_connections,
            "分析详情"
        )


async def broadcast_fc_tool_call(
    scan_id: str,
    sink_symbol: str,
    tool_call: Dict[str, Any],
    status: str = "running"
):
    """广播 Function Calling 工具调用事件

    实时发送 LLM 工具调用信息到前端，用于展示分析过程。

    Args:
        scan_id: 扫描 ID
        sink_symbol: 当前分析的触发点符号
        tool_call: 工具调用信息，包含 id, tool_name, arguments, result 等
        status: 工具调用状态 (pending, running, success, failed)
    """
    if scan_id in app_state.websocket_connections:
        ws = app_state.websocket_connections[scan_id]
        await _safe_ws_send(
            ws,
            {
                "type": "fc_tool_call",
                "scan_id": scan_id,
                "sink_symbol": sink_symbol,
                "tool_call": to_jsonable(tool_call),
                "status": status,
                "timestamp": datetime.now().isoformat(),
            },
            scan_id,
            app_state.websocket_connections,
            "FC工具调用"
        )


async def broadcast_fc_progress(
    scan_id: str,
    sink_symbol: str,
    current_turn: int,
    total_tool_calls: int,
    tool_calls: List[Dict[str, Any]],
    status: str = "analyzing"
):
    """广播 Function Calling 分析进度

    发送 FC 模式下的分析进度信息。

    Args:
        scan_id: 扫描 ID
        sink_symbol: 当前分析的触发点符号
        current_turn: 当前对话轮次
        total_tool_calls: 总工具调用次数
        tool_calls: 工具调用历史列表
        status: 分析状态 (analyzing, completed, failed)
    """
    if scan_id in app_state.websocket_connections:
        ws = app_state.websocket_connections[scan_id]
        await _safe_ws_send(
            ws,
            {
                "type": "fc_progress",
                "scan_id": scan_id,
                "sink_symbol": sink_symbol,
                "current_turn": current_turn,
                "total_tool_calls": total_tool_calls,
                "tool_calls": to_jsonable(tool_calls[-10:]),  # 只发送最近 10 条
                "status": status,
                "timestamp": datetime.now().isoformat(),
            },
            scan_id,
            app_state.websocket_connections,
            "FC进度"
        )


async def broadcast_fc_finding(scan_id: str, finding: Dict[str, Any]):
    """广播 Function Calling 模式发现的新结果

    当 LLM 通过 report_finding 工具报告发现时推送。

    Args:
        scan_id: 扫描 ID
        finding: 发现结果
    """
    if scan_id in app_state.websocket_connections:
        ws = app_state.websocket_connections[scan_id]
        await _safe_ws_send(
            ws,
            {
                "type": "fc_finding",
                "scan_id": scan_id,
                "finding": to_jsonable(finding),
                "timestamp": datetime.now().isoformat(),
            },
            scan_id,
            app_state.websocket_connections,
            "FC发现"
        )


async def broadcast_fc_llm_thinking(scan_id: str, sink_symbol: str, message: str):
    """广播 LLM 思考状态消息

    当 LLM 开始新一轮分析或有中间思考内容时推送。

    Args:
        scan_id: 扫描 ID
        sink_symbol: 当前分析的 sink 符号
        message: 思考状态消息
    """
    if scan_id in app_state.websocket_connections:
        ws = app_state.websocket_connections[scan_id]
        await _safe_ws_send(
            ws,
            {
                "type": "fc_llm_thinking",
                "scan_id": scan_id,
                "sink_symbol": sink_symbol,
                "message": message,
                "timestamp": datetime.now().isoformat(),
            },
            scan_id,
            app_state.websocket_connections,
            "LLM思考"
        )


# FC 事件队列（用于从同步代码中安全发送事件）
_pending_fc_events: queue.Queue = queue.Queue()


def queue_fc_event(event_type: str, scan_id: str, data: Dict[str, Any]):
    """将 FC 事件加入广播队列

    这是一个同步函数，可从 analyzer 线程中调用。

    Args:
        event_type: 事件类型 (tool_call, progress, finding)
        scan_id: 扫描 ID
        data: 事件数据
    """
    _pending_fc_events.put_nowait({
        "event_type": event_type,
        "scan_id": scan_id,
        "data": data,
    })


async def process_fc_event_queue():
    """后台任务：处理 FC 事件广播队列"""
    logger.info("FC 事件广播队列处理任务已启动")

    while True:
        try:
            events_to_broadcast = []
            while True:
                try:
                    event = _pending_fc_events.get_nowait()
                    events_to_broadcast.append(event)
                except queue.Empty:
                    break

            for event in events_to_broadcast:
                event_type = event["event_type"]
                scan_id = event["scan_id"]
                data = event["data"]

                if event_type == "tool_call":
                    await broadcast_fc_tool_call(
                        scan_id,
                        data.get("sink_symbol", ""),
                        data.get("tool_call", {}),
                        data.get("status", "running"),
                    )
                elif event_type == "progress":
                    await broadcast_fc_progress(
                        scan_id,
                        data.get("sink_symbol", ""),
                        data.get("current_turn", 0),
                        data.get("total_tool_calls", 0),
                        data.get("tool_calls", []),
                        data.get("status", "analyzing"),
                    )
                elif event_type == "finding":
                    await broadcast_fc_finding(scan_id, data.get("finding", {}))
                elif event_type == "llm_thinking":
                    await broadcast_fc_llm_thinking(
                        scan_id,
                        data.get("sink_symbol", ""),
                        data.get("message", ""),
                    )

            await asyncio.sleep(0.05)

        except asyncio.CancelledError:
            logger.info("FC 事件广播队列处理任务已停止")
            raise
        except Exception as e:
            logger.error(f"处理 FC 事件广播队列时出错: {e}")
            await asyncio.sleep(1)


# 用于存储待广播的交互日志（使用线程安全队列避免竞态条件）
_pending_interactions: queue.Queue = queue.Queue()


def queue_interaction_broadcast(interaction):
    """将交互日志加入广播队列

    这是一个同步函数，作为 InteractionRepository 的回调。
    交互日志会被加入队列，由异步任务进行广播。

    注意：使用 queue.Queue 确保线程安全，因为此函数可能从
    工作线程（如 asyncio.to_thread）中调用。

    Args:
        interaction: LLMInteraction 对象
    """
    _pending_interactions.put_nowait(interaction)


async def broadcast_interaction(interaction):
    """广播交互日志到 WebSocket

    Args:
        interaction: LLMInteraction 对象
    """
    scan_id = interaction.scan_id
    if scan_id in app_state.websocket_connections:
        ws = app_state.websocket_connections[scan_id]
        # Starlette WebSocket.send_json 内部直接 json.dumps，
        # interaction 里可能包含 datetime/path 等对象，需先转为 JSON 兼容类型。
        await _safe_ws_send(
            ws,
            {
                "type": "interaction",
                "scan_id": scan_id,
                "data": to_jsonable(interaction.to_timeline_event()),
            },
            scan_id,
            app_state.websocket_connections,
            "交互日志"
        )


async def process_interaction_broadcast_queue():
    """后台任务：处理交互日志广播队列

    该任务在应用启动时创建，持续运行直到应用关闭。
    从 _pending_interactions 队列中取出交互日志并广播到 WebSocket。

    使用 queue.Queue.get() 的非阻塞模式配合 asyncio.sleep() 实现
    异步友好的队列消费。
    """
    logger.info("交互日志广播队列处理任务已启动")

    while True:
        try:
            # 批量处理队列中的所有待处理项
            interactions_to_broadcast = []
            while True:
                try:
                    interaction = _pending_interactions.get_nowait()
                    interactions_to_broadcast.append(interaction)
                except queue.Empty:
                    break

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
            await asyncio.sleep(1)


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
            await asyncio.to_thread(app_state.scan_repo.create, db_task)
            logger.info(f"扫描任务 {scan_id} 已保存到数据库")
        except Exception as e:
            logger.error(f"保存扫描任务到数据库失败: {e}")

    # 启动后台任务 - 使用 asyncio.create_task 替代 background_tasks
    # BackgroundTasks 对异步函数支持有问题
    print(f"[API] 创建扫描任务 {scan_id}")
    task = asyncio.create_task(run_scan_task(scan_id, request))
    app_state.background_tasks[scan_id] = task

    # 任务完成后自动清理
    def cleanup_task(t):
        app_state.background_tasks.pop(scan_id, None)
    task.add_done_callback(cleanup_task)

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
        db_task = await asyncio.to_thread(app_state.scan_repo.get_by_id, scan_id)
        if db_task:
            # 获取发现统计
            finding_stats = {}
            findings_list = []
            vuln_findings_list = []

            if app_state.finding_repo:
                finding_stats = await asyncio.to_thread(app_state.finding_repo.get_stats, scan_id)
                # 加载实际的发现数据
                db_findings = await asyncio.to_thread(
                    app_state.finding_repo.get_by_scan_id, scan_id, 200
                )
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
        db_findings = await asyncio.to_thread(
            app_state.finding_repo.get_by_scan_id,
            scan_id,
            severity,
            category,
            limit,
            offset,
        )
        scan_exists = await asyncio.to_thread(app_state.scan_repo.get_by_id, scan_id) if app_state.scan_repo else None
        if db_findings or scan_exists:
            # 分离 security 和 vuln 类型
            findings = [f.to_dict() for f in db_findings if f.finding_type == "security"]
            vuln_findings = [f.to_dict() for f in db_findings if f.finding_type == "vuln"]
            total = await asyncio.to_thread(app_state.finding_repo.count, scan_id)

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

        # 计算内存中任务的严重性统计
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        all_findings = list(task.findings) + list(task.vuln_findings)
        for f in all_findings:
            sev = getattr(f, 'severity', None) or (f.get('severity') if isinstance(f, dict) else 'medium')
            sev = sev.lower() if isinstance(sev, str) else 'medium'
            if sev == 'critical':
                critical_count += 1
            elif sev == 'high':
                high_count += 1
            elif sev == 'medium':
                medium_count += 1
            else:
                low_count += 1

        tasks.append({
            "scan_id": scan_id,
            "status": task.status.value,
            "target_path": task.target_path,
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
            "findings_count": len(task.findings),
            "vuln_count": len(task.vuln_findings),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "progress": task.progress,
            "source": "memory",
        })
        seen_ids.add(scan_id)

    # 添加数据库中的历史记录
    if app_state.scan_repo:
        db_tasks = await asyncio.to_thread(
            app_state.scan_repo.list_all, status, limit, offset
        )
        for db_task in db_tasks:
            if db_task.scan_id not in seen_ids:
                # 获取发现统计（包含严重性分布）
                finding_stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
                if app_state.finding_repo:
                    finding_stats = await asyncio.to_thread(
                        app_state.finding_repo.get_stats, db_task.scan_id
                    )

                tasks.append({
                    "scan_id": db_task.scan_id,
                    "status": db_task.status,
                    "target_path": db_task.target_path,
                    "started_at": db_task.started_at,
                    "completed_at": db_task.completed_at,
                    "findings_count": finding_stats.get("total", 0),
                    "vuln_count": 0,  # 数据库中合并存储
                    "critical_count": finding_stats.get("critical", 0),
                    "high_count": finding_stats.get("high", 0),
                    "medium_count": finding_stats.get("medium", 0),
                    "low_count": finding_stats.get("low", 0),
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


# ============ 触发点扫描接口 ============

@app.get("/api/scan/{scan_id}/sink-sites", response_model=APIResponse)
async def get_sink_sites(
    scan_id: str,
    category: Optional[str] = None,
    risk_level: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
):
    """获取扫描任务的危险函数触发点列表

    此 API 用于展示用户可选择的触发点，供后续深度分析。

    Args:
        scan_id: 扫描任务 ID
        category: 按 Sink 类别过滤 (command_exec, sql_injection, etc.)
        risk_level: 按风险等级过滤 (critical, high, medium, low)
        limit: 返回数量限制
        offset: 偏移量

    Returns:
        触发点列表及统计信息
    """
    if not app_state.indexer or not app_state.rule_manager:
        raise HTTPException(status_code=500, detail="索引器或规则管理器未初始化")

    # 验证扫描任务存在
    scan_exists = scan_id in app_state.scan_tasks
    if not scan_exists and app_state.scan_repo:
        db_task = await asyncio.to_thread(app_state.scan_repo.get_by_id, scan_id)
        scan_exists = db_task is not None

    if not scan_exists:
        raise HTTPException(status_code=404, detail="扫描任务不存在")

    try:
        # 获取扫描任务的目标路径
        target_path = None
        if scan_id in app_state.scan_tasks:
            target_path = app_state.scan_tasks[scan_id].target_path
        elif app_state.scan_repo:
            db_task = await asyncio.to_thread(app_state.scan_repo.get_by_id, scan_id)
            if db_task:
                target_path = db_task.target_path

        if not target_path:
            raise HTTPException(status_code=400, detail="无法获取扫描目标路径")

        # 获取代码单元
        code_units = await asyncio.to_thread(
            app_state.indexer.parse_directory_without_index,
            target_path,
            None  # languages
        )

        if not code_units:
            return APIResponse(
                success=True,
                message="未找到代码单元",
                data={
                    "scan_id": scan_id,
                    "total": 0,
                    "sink_sites": [],
                    "stats": {"total": 0, "by_category": {}, "by_risk_level": {}, "by_file": {}},
                },
            )

        # 使用 SinkCallScanner 扫描触发点
        scanner = SinkCallScanner(app_state.rule_manager)
        sink_sites = await asyncio.to_thread(
            scanner.scan,
            code_units,
            None,  # language
            [category] if category else None  # categories
        )

        # 按风险等级过滤
        if risk_level:
            sink_sites = [s for s in sink_sites if s.risk_level.value == risk_level]

        # 计算统计信息
        stats = {
            "total": len(sink_sites),
            "by_category": {},
            "by_risk_level": {},
            "by_file": {},
        }

        for site in sink_sites:
            # 按类别统计
            cat = site.sink_category.value
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

            # 按风险等级统计
            rl = site.risk_level.value
            stats["by_risk_level"][rl] = stats["by_risk_level"].get(rl, 0) + 1

            # 按文件统计
            fp = site.file_path
            stats["by_file"][fp] = stats["by_file"].get(fp, 0) + 1

        # 按风险等级排序（critical > high > medium > low）
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sink_sites.sort(key=lambda s: (risk_order.get(s.risk_level.value, 5), s.file_path, s.line_start))

        # 分页
        total = len(sink_sites)
        paginated_sites = sink_sites[offset:offset + limit]

        # 转换为 schema
        result_sites = []
        for site in paginated_sites:
            result_sites.append(SinkCallSiteSchema(
                id=site.id,
                unit_id=site.unit_id,
                file_path=site.file_path,
                line_start=site.line_start,
                line_end=site.line_end,
                symbol=site.symbol,
                matched_rule_ids=site.matched_rule_ids,
                call_snippet=site.call_snippet,
                sink_category=SinkCategoryEnum(site.sink_category.value),
                risk_level=site.risk_level.value,
                matched_patterns=site.matched_patterns,
                confidence=site.confidence,
                metadata=site.metadata,
            ).model_dump())

        return APIResponse(
            success=True,
            message=f"找到 {total} 个触发点",
            data={
                "scan_id": scan_id,
                "total": total,
                "sink_sites": result_sites,
                "stats": stats,
                "limit": limit,
                "offset": offset,
            },
        )

    except Exception as e:
        import traceback
        logger.error(f"获取触发点失败: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/{scan_id}/sink-sites/{site_id}/chains", response_model=APIResponse)
async def get_sink_site_chains(
    scan_id: str,
    site_id: str,
    max_depth: int = 10,
    max_chains: int = 20,
    target_path: str = None,  # 新增：支持直接传入目标路径
):
    """获取指定触发点的调用链

    用于用户选择要分析的调用链（两步确认模式）。

    Args:
        scan_id: 扫描任务 ID
        site_id: 触发点 ID
        max_depth: 最大调用链深度
        max_chains: 最大返回调用链数量
        target_path: 目标路径（可选，用于临时 scan_id 场景）

    Returns:
        调用链列表
    """
    if not app_state.indexer or not app_state.rule_manager:
        raise HTTPException(status_code=500, detail="索引器或规则管理器未初始化")

    # 获取扫描任务的目标路径
    resolved_target_path = target_path  # 优先使用传入的 target_path
    if not resolved_target_path:
        if scan_id in app_state.scan_tasks:
            resolved_target_path = app_state.scan_tasks[scan_id].target_path
        elif app_state.scan_repo:
            db_task = await asyncio.to_thread(app_state.scan_repo.get_by_id, scan_id)
            if db_task:
                resolved_target_path = db_task.target_path

    if not resolved_target_path:
        raise HTTPException(status_code=404, detail=f"扫描任务不存在: {scan_id}，请提供 target_path 参数")

    path = Path(resolved_target_path)
    if not path.exists():
        raise HTTPException(status_code=400, detail=f"目标路径不存在: {resolved_target_path}")

    try:
        # 优先使用已索引的代码单元，避免每次重新解析
        stats = await asyncio.to_thread(app_state.indexer.get_stats)
        if stats["total_units"] > 0:
            # 使用已索引的数据
            code_units = await asyncio.to_thread(app_state.indexer.get_all_units)
            logger.debug(f"[chains] 使用已索引数据: {len(code_units)} 个代码单元")
        else:
            # 回退到直接解析
            code_units = await asyncio.to_thread(
                app_state.indexer.parse_directory_without_index,
                str(path),
                None
            )
            logger.debug(f"[chains] 回退到直接解析: {len(code_units)} 个代码单元")

        # 扫描触发点
        scanner = SinkCallScanner(app_state.rule_manager)
        sink_sites = await asyncio.to_thread(
            scanner.scan,
            code_units,
            None,
            None
        )

        # 查找目标触发点
        target_sink = None
        for site in sink_sites:
            if site.id == site_id:
                target_sink = site
                break

        if not target_sink:
            raise HTTPException(status_code=404, detail=f"触发点不存在: {site_id}")

        # 构建调用图
        chain_analyzer = CallChainAnalyzer(app_state.rule_manager)
        await asyncio.to_thread(
            chain_analyzer.build_call_graph,
            code_units
        )

        # 查找调用链
        chains = await asyncio.to_thread(
            chain_analyzer.find_paths_to_sink,
            target_sink.symbol,
            max_depth,
            max_chains
        )

        # 转换为响应格式
        chain_schemas = []
        for idx, chain_path in enumerate(chains):
            chain_id = f"chain-{site_id}-{idx}"
            entry_point = chain_path[0] if chain_path else target_sink.symbol

            # 计算风险分数
            risk_score = 0.5
            if len(chain_path) <= 2:
                risk_score = 0.9  # 短链更危险
            elif len(chain_path) <= 4:
                risk_score = 0.7
            elif len(chain_path) >= 8:
                risk_score = 0.3

            chain_schemas.append({
                "id": chain_id,
                "sink_id": site_id,
                "entry_point": entry_point,
                "path": chain_path,
                "depth": len(chain_path),
                "risk_score": risk_score,
            })

        return APIResponse(
            success=True,
            message=f"找到 {len(chain_schemas)} 条调用链",
            data={
                "scan_id": scan_id,
                "site_id": site_id,
                "sink_symbol": target_sink.symbol,
                "total": len(chain_schemas),
                "chains": chain_schemas[:max_chains]
            },
        )

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        logger.error(f"获取调用链失败: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/sink-sites", response_model=APIResponse)
async def scan_sink_sites(request: ScanRequest):
    """独立触发点扫描（不启动完整扫描）

    仅进行 SinkCallScanner 确定性扫描，返回所有危险函数触发点。
    用于"两步确认"模式的第一步。

    如果 skip_index=False（默认），会同时进行代码向量化索引，
    以支持后续对话审计中的函数调用（如 search_code）。

    Args:
        request: 扫描请求（使用 target_path、languages 和 skip_index）

    Returns:
        触发点列表及统计信息
    """
    if not app_state.indexer or not app_state.rule_manager:
        raise HTTPException(status_code=500, detail="索引器或规则管理器未初始化")

    target_path = Path(request.target_path)
    if not target_path.exists():
        raise HTTPException(status_code=400, detail=f"目标路径不存在: {request.target_path}")

    try:
        # 根据 skip_index 决定是否进行向量化索引
        if request.skip_index:
            # 跳过向量索引，仅解析代码
            logger.info(f"[sink-sites] 使用直接解析模式（跳过向量索引）: {target_path}")
            code_units = await asyncio.to_thread(
                app_state.indexer.parse_directory_without_index,
                str(target_path),
                request.languages
            )
        else:
            # 进行向量化索引（支持后续对话审计的函数调用）
            logger.info(f"[sink-sites] 使用向量索引模式: {target_path}")

            # 检查是否需要索引
            stats = await asyncio.to_thread(app_state.indexer.get_stats)
            if stats["total_units"] == 0 or request.reindex:
                logger.info(f"[sink-sites] 开始索引目录: {target_path}")
                await asyncio.to_thread(
                    app_state.indexer.index_directory,
                    str(target_path)
                )
                logger.info(f"[sink-sites] 索引完成")

            # 获取所有代码单元
            code_units = await asyncio.to_thread(app_state.indexer.get_all_units)

            # 按语言过滤
            if request.languages:
                code_units = [u for u in code_units if u.language in request.languages]

        if not code_units:
            return APIResponse(
                success=True,
                message="未找到代码单元",
                data={
                    "total": 0,
                    "sink_sites": [],
                    "stats": {"total": 0, "by_category": {}, "by_risk_level": {}, "by_file": {}},
                    "code_units_count": 0,
                },
            )

        # 使用 SinkCallScanner 扫描触发点
        scanner = SinkCallScanner(app_state.rule_manager)
        sink_sites = await asyncio.to_thread(
            scanner.scan,
            code_units,
            request.languages[0] if request.languages else None,
            None  # categories
        )

        # 计算统计信息
        stats = {
            "total": len(sink_sites),
            "by_category": {},
            "by_risk_level": {},
            "by_file": {},
        }

        for site in sink_sites:
            cat = site.sink_category.value
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

            rl = site.risk_level.value
            stats["by_risk_level"][rl] = stats["by_risk_level"].get(rl, 0) + 1

            fp = site.file_path
            stats["by_file"][fp] = stats["by_file"].get(fp, 0) + 1

        # 按风险等级排序
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sink_sites.sort(key=lambda s: (risk_order.get(s.risk_level.value, 5), s.file_path, s.line_start))

        # 转换为 schema（限制返回数量避免响应过大）
        max_return = 500
        result_sites = []
        for site in sink_sites[:max_return]:
            result_sites.append(SinkCallSiteSchema(
                id=site.id,
                unit_id=site.unit_id,
                file_path=site.file_path,
                line_start=site.line_start,
                line_end=site.line_end,
                symbol=site.symbol,
                matched_rule_ids=site.matched_rule_ids,
                call_snippet=site.call_snippet,
                sink_category=SinkCategoryEnum(site.sink_category.value),
                risk_level=site.risk_level.value,
                matched_patterns=site.matched_patterns,
                confidence=site.confidence,
                metadata=site.metadata,
            ).model_dump())

        return APIResponse(
            success=True,
            message=f"扫描完成，发现 {len(sink_sites)} 个触发点",
            data={
                "total": len(sink_sites),
                "sink_sites": result_sites,
                "stats": stats,
                "code_units_count": len(code_units),
                "truncated": len(sink_sites) > max_return,
            },
        )

    except Exception as e:
        import traceback
        logger.error(f"触发点扫描失败: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze/selected", response_model=APIResponse)
async def analyze_selected_sinks(request: SelectedAnalysisRequest):
    """对用户选择的触发点进行 LLM 深度分析

    这是"两步确认"模式的第二步：
    1. 用户先通过 POST /api/scan/sink-sites 获取所有触发点
    2. 用户选择感兴趣的触发点后，调用此 API 进行 LLM 分析

    支持 WebSocket 实时进度推送。

    Args:
        request: 包含目标路径和选中的触发点 ID 列表

    Returns:
        创建的扫描任务信息（scan_id）
    """
    if not app_state.indexer or not app_state.rule_manager:
        raise HTTPException(status_code=500, detail="索引器或规则管理器未初始化")

    if not app_state.config.llm.api_key:
        raise HTTPException(status_code=400, detail="LLM API Key 未配置")

    target_path = Path(request.target_path)
    if not target_path.exists():
        raise HTTPException(status_code=400, detail=f"目标路径不存在: {request.target_path}")

    if not request.sink_site_ids:
        raise HTTPException(status_code=400, detail="未选择任何触发点")

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
                    "mode": "selected_analysis",
                    "sink_site_ids": request.sink_site_ids,
                    "use_chain_analysis": request.use_chain_analysis,
                    "max_chain_depth": request.max_chain_depth,
                    "languages": request.languages,
                }
            )
            await asyncio.to_thread(app_state.scan_repo.create, db_task)
        except Exception as e:
            logger.error(f"保存扫描任务到数据库失败: {e}")

    # 启动后台任务
    bg_task = asyncio.create_task(
        run_selected_analysis_task(scan_id, request)
    )
    app_state.background_tasks[scan_id] = bg_task

    # 任务完成后自动清理
    def cleanup_task(t):
        app_state.background_tasks.pop(scan_id, None)
    bg_task.add_done_callback(cleanup_task)

    return APIResponse(
        success=True,
        message=f"选择性分析任务已创建，共 {len(request.sink_site_ids)} 个触发点",
        data={
            "scan_id": scan_id,
            "selected_count": len(request.sink_site_ids),
        },
    )


async def run_selected_analysis_task(scan_id: str, request: SelectedAnalysisRequest):
    """执行选择性分析任务（后台）

    仅分析用户选中的触发点，不进行全量扫描。
    """
    task = app_state.scan_tasks[scan_id]

    try:
        target_path = Path(request.target_path)
        logger.info(f"选择性分析任务 {scan_id}: 开始，目标 {target_path}，选中 {len(request.sink_site_ids)} 个触发点")

        # 更新状态：解析中
        task.status = ScanStatus.INDEXING
        task.current_step = "正在解析代码..."
        task.progress = 0.1
        await broadcast_scan_progress(scan_id, task)

        # 解析代码单元
        code_units = await asyncio.to_thread(
            app_state.indexer.parse_directory_without_index,
            str(target_path),
            request.languages
        )
        task.total_units = len(code_units)
        task.progress = 0.2
        await broadcast_scan_progress(scan_id, task)

        # 使用 SinkCallScanner 扫描所有触发点
        task.current_step = "正在扫描触发点..."
        scanner = SinkCallScanner(app_state.rule_manager)
        all_sink_sites = await asyncio.to_thread(
            scanner.scan,
            code_units,
            request.languages[0] if request.languages else None,
            None
        )

        # 过滤出用户选中的触发点
        selected_ids = set(request.sink_site_ids)
        selected_sites = [s for s in all_sink_sites if s.id in selected_ids]

        if not selected_sites:
            task.status = ScanStatus.COMPLETED
            task.current_step = "未找到匹配的触发点"
            task.progress = 1.0
            task.completed_at = datetime.now()
            await broadcast_scan_progress(scan_id, task)
            return

        logger.info(f"选择性分析任务 {scan_id}: 找到 {len(selected_sites)} 个选中的触发点")
        task.progress = 0.3
        await broadcast_scan_progress(scan_id, task)

        # 更新状态：分析中
        task.status = ScanStatus.ANALYZING
        task.current_step = f"正在分析 {len(selected_sites)} 个触发点..."
        await broadcast_scan_progress(scan_id, task)

        # 创建 SecurityAnalyzer
        analyzer = SecurityAnalyzer(
            app_state.config,
            app_state.llm_client,
            app_state.indexer,
            app_state.rule_manager,
            interaction_repo=app_state.interaction_repo,
            scan_id=scan_id,
        )

        # 设置 Function Calling 模式
        if request.use_function_calling:
            analyzer.use_function_calling = True
            logger.info(f"选择性分析任务 {scan_id}: 使用 Function Calling 模式")
            if app_state.interaction_repo:
                app_state.interaction_repo.log_thinking(
                    scan_id,
                    f"启用 Function Calling 模式，LLM 将主动调用工具进行代码探索"
                )

        # 记录分析开始
        if app_state.interaction_repo:
            app_state.interaction_repo.log_thinking(
                scan_id,
                f"开始选择性分析，共 {len(selected_sites)} 个用户选中的触发点"
            )

        # 进度回调
        progress_queue = queue.Queue()

        def analysis_progress_callback(progress: float, step: str):
            progress_queue.put((progress, step))

        # FC 模式的工具调用回调
        def fc_tool_call_callback(
            sink_symbol: str,
            tool_call: Dict[str, Any],
            status: str = "running"
        ):
            """FC 模式工具调用回调 - 从同步代码中推送事件"""
            queue_fc_event("tool_call", scan_id, {
                "sink_symbol": sink_symbol,
                "tool_call": tool_call,
                "status": status,
            })

        # FC 模式的 LLM 思考状态回调
        current_sink_symbol = {"value": ""}  # 用于跟踪当前分析的 sink

        def fc_llm_thinking_callback(message: str):
            """FC 模式 LLM 思考状态回调 - 推送 LLM 分析状态"""
            queue_fc_event("llm_thinking", scan_id, {
                "sink_symbol": current_sink_symbol["value"],
                "message": message,
            })

        async def process_progress_updates():
            while True:
                try:
                    try:
                        progress, step = progress_queue.get_nowait()
                        task.progress = 0.3 + progress * 0.6
                        task.current_step = step
                        await broadcast_scan_progress(scan_id, task)
                    except queue.Empty:
                        pass
                    await asyncio.sleep(0.1)
                except asyncio.CancelledError:
                    while not progress_queue.empty():
                        try:
                            progress, step = progress_queue.get_nowait()
                            task.progress = 0.3 + progress * 0.6
                            task.current_step = step
                            await broadcast_scan_progress(scan_id, task)
                        except queue.Empty:
                            break
                    break

        # 启动进度处理任务
        progress_task = asyncio.create_task(process_progress_updates())

        try:
            # 调用分析器，传入选中的触发点
            # FC 模式下，将工具调用回调和 LLM 思考回调传递给分析器
            on_tool_call = fc_tool_call_callback if request.use_function_calling else None
            on_llm_thinking = fc_llm_thinking_callback if request.use_function_calling else None

            findings = await asyncio.to_thread(
                analyzer.analyze_selected_sinks,
                selected_sites,
                code_units,
                request.use_chain_analysis,
                request.max_chain_depth,
                request.max_chains_per_sink,
                analysis_progress_callback,
                on_tool_call,  # FC 工具调用回调
                on_llm_thinking,  # FC LLM 思考状态回调
            )
        finally:
            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                pass

        logger.info(f"选择性分析任务 {scan_id}: 完成，发现 {len(findings)} 个问题")

        # 转换 findings 为 schema
        all_findings = []
        for f in findings:
            code_snippet = None
            if f.evidence and len(f.evidence) > 0:
                code_snippet = f.evidence[0].code_snippet if hasattr(f.evidence[0], 'code_snippet') else None

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

        # 完成
        task.status = ScanStatus.COMPLETED
        task.completed_at = datetime.now()
        task.findings = all_findings
        task.progress = 1.0
        task.current_step = "分析完成"
        await broadcast_scan_progress(scan_id, task)

        # 保存扫描结果到数据库
        await save_scan_results_to_db(scan_id, task, all_findings, [])

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"选择性分析任务失败: {e}\n{error_trace}")
        task.status = ScanStatus.FAILED
        task.error_message = str(e)
        task.current_step = f"错误: {e}"
        await broadcast_scan_progress(scan_id, task)

        if app_state.scan_repo:
            try:
                app_state.scan_repo.update_status(
                    scan_id, "failed",
                    error_message=str(e)
                )
            except Exception as db_err:
                logger.error(f"更新数据库状态失败: {db_err}")


# ============ 调用图接口 ============

@app.post("/api/callgraph", response_model=APIResponse)
async def get_call_graph(request: CallGraphRequest):
    """获取项目的调用图数据

    返回适合 Cytoscape.js 可视化的节点和边数据。

    Args:
        request: 包含目标路径和分析参数

    Returns:
        调用图节点和边数据
    """
    if not app_state.indexer or not app_state.rule_manager:
        raise HTTPException(status_code=500, detail="索引器或规则管理器未初始化")

    from analyzer.call_chain import NodeType

    target_path = Path(request.target_path)
    if not target_path.exists():
        raise HTTPException(status_code=400, detail=f"目标路径不存在: {request.target_path}")

    try:
        # 解析代码单元（支持语言过滤）
        code_units = await asyncio.to_thread(
            app_state.indexer.parse_directory_without_index,
            str(target_path),
            request.languages  # 传递语言过滤参数
        )

        # 按语言过滤代码单元
        if request.languages:
            code_units = [u for u in code_units if u.language in request.languages]

        if not code_units:
            return APIResponse(
                success=True,
                message="未找到代码单元",
                data={
                    "nodes": [],
                    "edges": [],
                    "stats": {"total_nodes": 0, "total_edges": 0}
                },
            )

        # 构建调用图
        chain_analyzer = CallChainAnalyzer(app_state.rule_manager)
        call_graph = await asyncio.to_thread(
            chain_analyzer.build_call_graph,
            code_units
        )

        # 扫描触发点以标记 sink 节点（使用相同的语言过滤）
        scanner = SinkCallScanner(app_state.rule_manager)
        language_filter = request.languages[0] if request.languages else None
        sink_sites = await asyncio.to_thread(
            scanner.scan,
            code_units,
            language_filter,
            None
        )
        sink_symbols = {s.symbol for s in sink_sites}

        # 转换为前端格式
        nodes = []
        edges = []

        for node_id, node in call_graph.nodes.items():
            # CallNode 使用 name/qualified_name 属性，不是 symbol
            node_symbol = node.qualified_name or node.name
            is_sink = node_symbol in sink_symbols or node.name in sink_symbols
            # CallNode 使用 node_type 枚举，检查是否是入口点
            is_entry = node.node_type == NodeType.ENTRY_POINT

            node_type = "function"
            if is_entry:
                node_type = "entry_point"
            elif is_sink:
                node_type = "sink"

            nodes.append(CallGraphNodeSchema(
                id=node_id,
                symbol=node_symbol,
                file_path=node.file_path,
                line_start=node.line_start,
                line_end=node.line_end,
                node_type=node_type,
                is_entry_point=is_entry,
                is_sink=is_sink,
                metadata={}
            ).model_dump())

        for edge in call_graph.edges:
            # CallEdge 使用 caller_id/callee_id 属性，不是 caller/callee
            edges.append(CallGraphEdgeSchema(
                source=edge.caller_id,
                target=edge.callee_id,
                call_type=edge.call_type,
                line=None
            ).model_dump())

        # 统计信息
        stats = {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "entry_points": sum(1 for n in nodes if n.get("is_entry_point")),
            "sinks": sum(1 for n in nodes if n.get("is_sink")),
        }

        return APIResponse(
            success=True,
            message=f"调用图构建完成: {len(nodes)} 节点, {len(edges)} 边",
            data={
                "nodes": nodes,
                "edges": edges,
                "stats": stats
            },
        )

    except Exception as e:
        import traceback
        logger.error(f"构建调用图失败: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/callgraph/chains/{sink_id}", response_model=APIResponse)
async def get_call_chains(
    sink_id: str,
    target_path: str,
    max_depth: int = 10,
    max_chains: int = 20,
):
    """获取到达指定触发点的所有调用链

    用于用户选择要分析的调用链。

    Args:
        sink_id: 触发点 ID
        target_path: 目标项目路径
        max_depth: 最大调用链深度
        max_chains: 最大返回调用链数量

    Returns:
        调用链列表
    """
    if not app_state.indexer or not app_state.rule_manager:
        raise HTTPException(status_code=500, detail="索引器或规则管理器未初始化")

    path = Path(target_path)
    if not path.exists():
        raise HTTPException(status_code=400, detail=f"目标路径不存在: {target_path}")

    try:
        # 优先使用已索引的代码单元，避免每次重新解析
        stats = await asyncio.to_thread(app_state.indexer.get_stats)
        if stats["total_units"] > 0:
            # 使用已索引的数据
            code_units = await asyncio.to_thread(app_state.indexer.get_all_units)
            logger.debug(f"[callgraph/chains] 使用已索引数据: {len(code_units)} 个代码单元")
        else:
            # 回退到直接解析
            code_units = await asyncio.to_thread(
                app_state.indexer.parse_directory_without_index,
                str(path),
                None
            )
            logger.debug(f"[callgraph/chains] 回退到直接解析: {len(code_units)} 个代码单元")

        # 扫描触发点
        scanner = SinkCallScanner(app_state.rule_manager)
        sink_sites = await asyncio.to_thread(
            scanner.scan,
            code_units,
            None,
            None
        )

        # 查找目标触发点
        target_sink = None
        for site in sink_sites:
            if site.id == sink_id:
                target_sink = site
                break

        if not target_sink:
            raise HTTPException(status_code=404, detail=f"触发点不存在: {sink_id}")

        # 构建调用图
        chain_analyzer = CallChainAnalyzer(app_state.rule_manager)
        await asyncio.to_thread(
            chain_analyzer.build_call_graph,
            code_units
        )

        # 查找调用链
        chains = await asyncio.to_thread(
            chain_analyzer.find_paths_to_sink,
            target_sink.symbol,
            max_depth,
            max_chains
        )

        # 转换为响应格式
        chain_schemas = []
        for idx, chain_path in enumerate(chains):
            chain_id = f"chain-{sink_id}-{idx}"
            entry_point = chain_path[0] if chain_path else target_sink.symbol

            # 计算风险分数（基于链长度和触发点风险等级）
            risk_score = 0.5
            risk_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}
            risk_score = risk_map.get(target_sink.risk_level.value, 0.5)
            # 链越短越危险
            risk_score *= (1 - len(chain_path) * 0.05)
            risk_score = max(0.1, min(1.0, risk_score))

            chain_schemas.append(CallChainSchema(
                id=chain_id,
                path=chain_path,
                entry_point=entry_point,
                sink=target_sink.symbol,
                depth=len(chain_path),
                risk_score=risk_score
            ).model_dump())

        # 按风险分数排序
        chain_schemas.sort(key=lambda c: c["risk_score"], reverse=True)

        return APIResponse(
            success=True,
            message=f"找到 {len(chain_schemas)} 条调用链",
            data={
                "sink_id": sink_id,
                "sink_symbol": target_sink.symbol,
                "total": len(chain_schemas),
                "chains": chain_schemas[:max_chains]
            },
        )

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        logger.error(f"获取调用链失败: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


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

    interactions = await asyncio.to_thread(
        app_state.interaction_repo.get_by_scan_id,
        scan_id,
        interaction_type,
        limit,
        offset,
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

    timeline = await asyncio.to_thread(
        app_state.interaction_repo.get_timeline, scan_id, limit
    )

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

    interactions = await asyncio.to_thread(
        app_state.interaction_repo.get_latest,
        scan_id,
        since_id,
        limit,
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
        stats["interactions"] = await asyncio.to_thread(
            app_state.interaction_repo.get_stats, scan_id
        )

    # 获取发现统计
    if app_state.finding_repo:
        stats["findings"] = await asyncio.to_thread(
            app_state.finding_repo.get_stats, scan_id
        )

    return APIResponse(
        success=True,
        message="获取统计成功",
        data=stats,
    )


# ============ 调用图接口 ============

@app.post("/api/callgraph/analyze", response_model=APIResponse)
async def analyze_callgraph(request: CallGraphRequest):
    """分析调用图（污点分析和危险调用链）"""
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
    rule_type: Optional[str] = None,
):
    """列出安全规则

    支持过滤参数:
    - language: 按语言过滤 (python/javascript/php 等)
    - category: 按类别过滤 (injection/auth/file 等)
    - rule_type: 按类型过滤 (sink/source/sanitizer/pattern)
    """
    if not app_state.rule_manager:
        raise HTTPException(status_code=500, detail="规则管理器未初始化")

    rules = app_state.rule_manager.all_rules()

    if language:
        rules = [r for r in rules if language in r.languages]
    if category:
        rules = [r for r in rules if r.category.value == category]
    if rule_type:
        rules = [r for r in rules if r.rule_type.value == rule_type]

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
            frameworks=r.frameworks,
            description=r.description,
            example=r.example,
            attack_scenario=r.attack_scenario,
            fix_suggestion=r.fix_suggestion,
            cwe_ids=r.cwe_ids,
            owasp_ids=r.owasp_ids,
            tags=r.tags,
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
            frameworks=rule.frameworks,
            description=rule.description,
            example=rule.example,
            attack_scenario=rule.attack_scenario,
            fix_suggestion=rule.fix_suggestion,
            cwe_ids=rule.cwe_ids,
            owasp_ids=rule.owasp_ids,
            tags=rule.tags,
        ).model_dump(),
    )


@app.get("/api/rules/stats", response_model=APIResponse)
async def get_rules_stats():
    """获取规则统计信息

    返回规则按语言、类别、类型、风险等级的分布统计
    """
    if not app_state.rule_manager:
        raise HTTPException(status_code=500, detail="规则管理器未初始化")

    rules = app_state.rule_manager.all_rules()

    # 统计各维度分布
    by_language: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    by_risk_level: Dict[str, int] = {}

    for rule in rules:
        # 语言统计（一条规则可能支持多语言）
        for lang in rule.languages:
            by_language[lang] = by_language.get(lang, 0) + 1
        # 类别统计
        cat = rule.category.value
        by_category[cat] = by_category.get(cat, 0) + 1
        # 类型统计
        rt = rule.rule_type.value
        by_type[rt] = by_type.get(rt, 0) + 1
        # 风险等级统计
        rl = rule.risk_level.value
        by_risk_level[rl] = by_risk_level.get(rl, 0) + 1

    from api.schemas import RuleStatsSchema
    stats = RuleStatsSchema(
        total=len(rules),
        by_language=by_language,
        by_category=by_category,
        by_type=by_type,
        by_risk_level=by_risk_level,
    )

    return APIResponse(
        success=True,
        message=f"共 {len(rules)} 条规则",
        data=stats.model_dump(),
    )


@app.post("/api/rules/reload", response_model=APIResponse)
async def reload_rules():
    """热更新规则

    清空当前规则并重新加载内置规则和自定义规则目录
    """
    if not app_state.rule_manager:
        raise HTTPException(status_code=500, detail="规则管理器未初始化")

    try:
        result = app_state.rule_manager.reload()
        total = result.get("builtin", 0) + result.get("custom", 0)
        return APIResponse(
            success=True,
            message=f"规则已重新加载：内置 {result.get('builtin', 0)} 条，自定义 {result.get('custom', 0)} 条",
            data={
                "total": total,
                "builtin": result.get("builtin", 0),
                "custom": result.get("custom", 0),
            },
        )
    except Exception as e:
        logger.exception("Failed to reload rules")
        raise HTTPException(status_code=500, detail=f"规则重新加载失败: {str(e)}")


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
        pass  # 正常断开连接
    except Exception as e:
        logger.warning(f"WebSocket 连接异常: {e}")
    finally:
        # 确保清理连接（无论正常断开还是异常）
        if scan_id in app_state.websocket_connections:
            del app_state.websocket_connections[scan_id]


@app.websocket("/ws/index/{index_id}")
async def websocket_index_progress(websocket: WebSocket, index_id: str):
    """WebSocket 实时索引进度"""
    await websocket.accept()
    app_state.index_ws_connections[index_id] = websocket

    try:
        # 如果任务已存在，立即发送当前状态
        if index_id in app_state.index_tasks:
            progress = app_state.index_tasks[index_id]
            await websocket.send_json({
                "type": "index_progress",
                "index_id": index_id,
                "status": progress.status.value,
                "progress": progress.progress,
                "current_step": progress.current_step,
                "total_files": progress.total_files,
                "processed_files": progress.processed_files,
                "total_units": progress.total_units,
                "processed_units": progress.processed_units,
                "embedding_progress": progress.embedding_progress,
            })

        while True:
            # 保持连接，等待消息
            data = await websocket.receive_text()

            # 返回当前状态
            if index_id in app_state.index_tasks:
                progress = app_state.index_tasks[index_id]
                await websocket.send_json({
                    "type": "index_status",
                    "index_id": index_id,
                    "status": progress.status.value,
                    "progress": progress.progress,
                    "current_step": progress.current_step,
                })

    except WebSocketDisconnect:
        pass  # 正常断开连接
    except Exception as e:
        logger.warning(f"索引 WebSocket 连接异常: {e}")
    finally:
        # 确保清理连接
        if index_id in app_state.index_ws_connections:
            del app_state.index_ws_connections[index_id]


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
        log_config=None,  # 禁用 uvicorn 默认日志配置，使用应用自定义配置
    )
