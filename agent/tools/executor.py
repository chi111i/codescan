"""
工具执行器 - 执行 LLM 工具调用并记录日志

提供统一的工具执行接口，支持：
- 工具调用执行
- 执行时间统计
- 日志记录到数据库
"""

import time
import json
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Callable, List

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """工具执行结果"""
    tool_name: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: int = 0

    def to_json(self) -> str:
        """转换为 JSON 字符串"""
        return json.dumps({
            "success": self.success,
            "data": self.data,
            "error": self.error,
        }, ensure_ascii=False)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        if self.success:
            return self.data
        else:
            return {"error": self.error, "success": False}


class ToolExecutor:
    """工具执行器

    统一管理工具的注册和执行，支持日志记录。

    Usage:
        executor = ToolExecutor()
        executor.register("read_file", read_file_func)

        result = executor.execute("read_file", {"file_path": "main.py"})
    """

    def __init__(self, interaction_repo=None, scan_id: Optional[str] = None):
        """初始化执行器

        Args:
            interaction_repo: 交互日志仓库（可选），用于记录工具调用
            scan_id: 当前扫描任务 ID（可选），用于关联日志
        """
        self._executors: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {}
        self._interaction_repo = interaction_repo
        self._scan_id = scan_id

    def set_scan_id(self, scan_id: str):
        """设置扫描任务 ID"""
        self._scan_id = scan_id

    def set_interaction_repo(self, repo):
        """设置交互日志仓库"""
        self._interaction_repo = repo

    def register(
        self,
        name: str,
        executor: Callable[[Dict[str, Any]], Dict[str, Any]],
    ):
        """注册工具执行器

        Args:
            name: 工具名称
            executor: 执行函数，接收参数字典，返回结果字典
        """
        self._executors[name] = executor
        logger.debug(f"注册工具: {name}")

    def register_many(
        self,
        executors: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]],
    ):
        """批量注册工具执行器"""
        for name, executor in executors.items():
            self.register(name, executor)

    def execute(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        log_to_db: bool = True,
    ) -> ToolResult:
        """执行工具

        Args:
            tool_name: 工具名称
            arguments: 工具参数
            log_to_db: 是否记录到数据库

        Returns:
            ToolResult 执行结果
        """
        start_time = time.time()

        executor = self._executors.get(tool_name)
        if not executor:
            result = ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"未知工具: {tool_name}",
            )
        else:
            try:
                data = executor(arguments)
                success = data.get("success", True) if isinstance(data, dict) else True
                result = ToolResult(
                    tool_name=tool_name,
                    success=success,
                    data=data if isinstance(data, dict) else {"result": data},
                )
            except Exception as e:
                logger.error(f"工具执行失败 {tool_name}: {e}")
                result = ToolResult(
                    tool_name=tool_name,
                    success=False,
                    error=str(e),
                )

        # 计算执行时间
        result.duration_ms = int((time.time() - start_time) * 1000)

        # 记录到数据库
        if log_to_db and self._interaction_repo and self._scan_id:
            try:
                self._interaction_repo.log_tool_call(
                    scan_id=self._scan_id,
                    tool_name=tool_name,
                    tool_input=arguments,
                    tool_output=result.to_dict(),
                    duration_ms=result.duration_ms,
                )
            except Exception as e:
                logger.warning(f"记录工具调用日志失败: {e}")

        return result

    def get_available_tools(self) -> List[str]:
        """获取所有可用工具名称"""
        return list(self._executors.keys())

    def has_tool(self, name: str) -> bool:
        """检查工具是否存在"""
        return name in self._executors


class LoggingToolExecutor(ToolExecutor):
    """带详细日志的工具执行器

    在执行工具前后打印详细日志，用于调试。
    """

    def execute(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        log_to_db: bool = True,
    ) -> ToolResult:
        """执行工具并打印日志"""
        logger.info(f"[Tool Call] {tool_name}")
        logger.debug(f"[Tool Args] {json.dumps(arguments, ensure_ascii=False)[:200]}")

        result = super().execute(tool_name, arguments, log_to_db)

        if result.success:
            logger.info(f"[Tool Done] {tool_name} - {result.duration_ms}ms")
        else:
            logger.warning(f"[Tool Fail] {tool_name} - {result.error}")

        return result
