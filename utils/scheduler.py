"""
扫描任务调度器 - 统一管理LLM调用和分析任务

功能：
1. 任务队列管理（内存/持久化）
2. 并发控制和限流
3. 自动重试机制（超时、429错误）
4. 分级模型调用（便宜模型初筛，贵模型精分析）
5. 任务状态追踪和恢复
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Awaitable, Union
from collections import deque
import threading

from llm_client import BaseLLMClient, ChatMessage

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """任务状态"""
    PENDING = "pending"           # 等待执行
    QUEUED = "queued"            # 已入队
    RUNNING = "running"          # 执行中
    COMPLETED = "completed"      # 已完成
    FAILED = "failed"            # 失败
    RETRYING = "retrying"        # 重试中
    CANCELLED = "cancelled"      # 已取消
    TIMEOUT = "timeout"          # 超时


class TaskPriority(Enum):
    """任务优先级"""
    CRITICAL = 0    # 最高优先级（高危漏洞确认）
    HIGH = 1        # 高优先级（中危漏洞分析）
    NORMAL = 2      # 普通优先级
    LOW = 3         # 低优先级（批量解释）


class ModelTier(Enum):
    """模型层级"""
    FAST = "fast"           # 快速/便宜模型（初筛）
    STANDARD = "standard"   # 标准模型（常规分析）
    ADVANCED = "advanced"   # 高级模型（深度分析）


@dataclass
class TaskConfig:
    """任务配置"""
    max_retries: int = 3
    retry_delay_base: float = 1.0      # 重试基础延迟（秒）
    retry_delay_multiplier: float = 2.0  # 重试延迟倍数
    timeout_seconds: float = 120.0
    priority: TaskPriority = TaskPriority.NORMAL
    model_tier: ModelTier = ModelTier.STANDARD


@dataclass
class AnalysisTask:
    """分析任务"""
    id: str
    task_type: str                     # "vulnerability", "taint", "logic", etc.
    payload: Dict[str, Any]           # 任务数据
    config: TaskConfig = field(default_factory=TaskConfig)

    # 状态
    status: TaskStatus = TaskStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    # 执行信息
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    retry_count: int = 0
    execution_time_ms: int = 0

    # 模型调用统计
    model_used: Optional[str] = None
    tokens_used: int = 0
    estimated_cost: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "task_type": self.task_type,
            "payload": self.payload,
            "config": {
                "max_retries": self.config.max_retries,
                "timeout_seconds": self.config.timeout_seconds,
                "priority": self.config.priority.value,
                "model_tier": self.config.model_tier.value,
            },
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "result": self.result,
            "error": self.error,
            "retry_count": self.retry_count,
            "execution_time_ms": self.execution_time_ms,
            "model_used": self.model_used,
            "tokens_used": self.tokens_used,
            "estimated_cost": self.estimated_cost,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisTask":
        config_data = data.get("config", {})
        config = TaskConfig(
            max_retries=config_data.get("max_retries", 3),
            timeout_seconds=config_data.get("timeout_seconds", 120.0),
            priority=TaskPriority(config_data.get("priority", "normal")),
            model_tier=ModelTier(config_data.get("model_tier", "standard")),
        )
        return cls(
            id=data["id"],
            task_type=data["task_type"],
            payload=data["payload"],
            config=config,
            status=TaskStatus(data.get("status", "pending")),
            created_at=data.get("created_at", ""),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            result=data.get("result"),
            error=data.get("error"),
            retry_count=data.get("retry_count", 0),
            execution_time_ms=data.get("execution_time_ms", 0),
            model_used=data.get("model_used"),
            tokens_used=data.get("tokens_used", 0),
            estimated_cost=data.get("estimated_cost", 0.0),
        )


@dataclass
class TieredModelConfig:
    """分级模型配置"""
    fast_model: str = "gpt-3.5-turbo"
    standard_model: str = "gpt-4"
    advanced_model: str = "gpt-4-turbo"

    # 成本估算（每1K tokens）
    fast_cost_per_1k: float = 0.0005
    standard_cost_per_1k: float = 0.03
    advanced_cost_per_1k: float = 0.01

    # 升级阈值
    upgrade_on_uncertainty: float = 0.5  # 置信度低于此值时升级模型


@dataclass
class SchedulerStats:
    """调度器统计"""
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    retried_tasks: int = 0
    cancelled_tasks: int = 0
    total_tokens: int = 0
    total_cost: float = 0.0
    avg_execution_time_ms: float = 0.0
    by_model_tier: Dict[str, int] = field(default_factory=dict)
    by_task_type: Dict[str, int] = field(default_factory=dict)


class TaskQueue:
    """优先级任务队列"""

    def __init__(self):
        self._queues: Dict[int, deque] = {
            p.value: deque() for p in TaskPriority
        }
        self._lock = threading.Lock()
        self._task_map: Dict[str, AnalysisTask] = {}

    def put(self, task: AnalysisTask) -> None:
        """添加任务到队列"""
        with self._lock:
            priority = task.config.priority.value
            self._queues[priority].append(task)
            self._task_map[task.id] = task
            task.status = TaskStatus.QUEUED

    def get(self) -> Optional[AnalysisTask]:
        """获取最高优先级任务"""
        with self._lock:
            for priority in sorted(self._queues.keys()):
                queue = self._queues[priority]
                if queue:
                    task = queue.popleft()
                    return task
        return None

    def peek(self) -> Optional[AnalysisTask]:
        """查看最高优先级任务（不移除）"""
        with self._lock:
            for priority in sorted(self._queues.keys()):
                queue = self._queues[priority]
                if queue:
                    return queue[0]
        return None

    def size(self) -> int:
        """获取队列大小"""
        with self._lock:
            return sum(len(q) for q in self._queues.values())

    def get_task(self, task_id: str) -> Optional[AnalysisTask]:
        """按ID获取任务"""
        with self._lock:
            return self._task_map.get(task_id)

    def remove(self, task_id: str) -> bool:
        """从队列中移除任务"""
        with self._lock:
            if task_id in self._task_map:
                task = self._task_map[task_id]
                priority = task.config.priority.value
                try:
                    self._queues[priority].remove(task)
                except ValueError:
                    pass
                del self._task_map[task_id]
                return True
        return False

    def clear(self) -> None:
        """清空队列"""
        with self._lock:
            for queue in self._queues.values():
                queue.clear()
            self._task_map.clear()


class RateLimiter:
    """简单的速率限制器"""

    def __init__(
        self,
        requests_per_minute: int = 60,
        tokens_per_minute: int = 90000,
    ):
        self.requests_per_minute = requests_per_minute
        self.tokens_per_minute = tokens_per_minute
        self._request_times: deque = deque()
        self._token_counts: deque = deque()
        self._lock = threading.Lock()

    def wait_if_needed(self, estimated_tokens: int = 1000) -> float:
        """等待直到可以发送请求

        Returns:
            等待的秒数
        """
        waited = 0.0
        current_time = time.time()

        with self._lock:
            # 清理过期记录
            cutoff = current_time - 60
            while self._request_times and self._request_times[0] < cutoff:
                self._request_times.popleft()
            while self._token_counts and self._token_counts[0][0] < cutoff:
                self._token_counts.popleft()

            # 检查请求限制
            if len(self._request_times) >= self.requests_per_minute:
                wait_time = self._request_times[0] + 60 - current_time
                if wait_time > 0:
                    waited = wait_time
                    time.sleep(wait_time)

            # 检查token限制
            total_tokens = sum(t[1] for t in self._token_counts)
            if total_tokens + estimated_tokens > self.tokens_per_minute:
                wait_time = self._token_counts[0][0] + 60 - time.time()
                if wait_time > 0:
                    waited = max(waited, wait_time)
                    time.sleep(wait_time)

            # 记录此次请求
            self._request_times.append(time.time())
            self._token_counts.append((time.time(), estimated_tokens))

        return waited

    def record_actual_tokens(self, tokens: int) -> None:
        """记录实际使用的tokens"""
        with self._lock:
            if self._token_counts:
                # 更新最后一条记录
                timestamp = self._token_counts[-1][0]
                self._token_counts[-1] = (timestamp, tokens)


class TaskScheduler:
    """扫描任务调度器"""

    def __init__(
        self,
        llm_client: BaseLLMClient,
        model_config: Optional[TieredModelConfig] = None,
        max_concurrent: int = 5,
        requests_per_minute: int = 60,
        state_dir: Optional[str] = None,
    ):
        self.llm_client = llm_client
        self.model_config = model_config or TieredModelConfig()
        self.max_concurrent = max_concurrent

        # 任务队列
        self.queue = TaskQueue()
        self._running_tasks: Dict[str, AnalysisTask] = {}
        self._completed_tasks: Dict[str, AnalysisTask] = {}

        # 速率限制
        self.rate_limiter = RateLimiter(
            requests_per_minute=requests_per_minute,
        )

        # 统计
        self.stats = SchedulerStats()

        # 状态持久化
        self.state_dir = Path(state_dir) if state_dir else None
        if self.state_dir:
            self.state_dir.mkdir(parents=True, exist_ok=True)

        # 控制
        self._running = False
        self._lock = threading.Lock()
        self._semaphore = threading.Semaphore(max_concurrent)

        # 任务处理器映射
        self._handlers: Dict[str, Callable] = {}

    def register_handler(
        self,
        task_type: str,
        handler: Callable[[AnalysisTask], Dict[str, Any]],
    ) -> None:
        """注册任务处理器"""
        self._handlers[task_type] = handler

    def submit(
        self,
        task_type: str,
        payload: Dict[str, Any],
        config: Optional[TaskConfig] = None,
        task_id: Optional[str] = None,
    ) -> str:
        """提交任务

        Args:
            task_type: 任务类型
            payload: 任务数据
            config: 任务配置
            task_id: 自定义任务ID

        Returns:
            任务ID
        """
        task = AnalysisTask(
            id=task_id or str(uuid.uuid4())[:8],
            task_type=task_type,
            payload=payload,
            config=config or TaskConfig(),
        )

        self.queue.put(task)
        self.stats.total_tasks += 1

        logger.debug(f"Task {task.id} submitted: {task_type}")
        return task.id

    def submit_batch(
        self,
        tasks: List[Dict[str, Any]],
    ) -> List[str]:
        """批量提交任务

        Args:
            tasks: 任务列表，每个任务包含 task_type, payload, config(可选)

        Returns:
            任务ID列表
        """
        task_ids = []
        for task_data in tasks:
            config = None
            if "config" in task_data:
                config = TaskConfig(**task_data["config"])
            task_id = self.submit(
                task_type=task_data["task_type"],
                payload=task_data["payload"],
                config=config,
            )
            task_ids.append(task_id)
        return task_ids

    def _get_model_for_tier(self, tier: ModelTier) -> str:
        """获取对应层级的模型名称"""
        if tier == ModelTier.FAST:
            return self.model_config.fast_model
        elif tier == ModelTier.ADVANCED:
            return self.model_config.advanced_model
        else:
            return self.model_config.standard_model

    def _estimate_cost(self, tokens: int, tier: ModelTier) -> float:
        """估算成本"""
        if tier == ModelTier.FAST:
            rate = self.model_config.fast_cost_per_1k
        elif tier == ModelTier.ADVANCED:
            rate = self.model_config.advanced_cost_per_1k
        else:
            rate = self.model_config.standard_cost_per_1k
        return (tokens / 1000) * rate

    def _execute_task(self, task: AnalysisTask) -> None:
        """执行单个任务"""
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.now().isoformat()
        start_time = time.time()

        try:
            # 获取处理器
            handler = self._handlers.get(task.task_type)
            if not handler:
                raise ValueError(f"No handler for task type: {task.task_type}")

            # 速率限制
            self.rate_limiter.wait_if_needed()

            # 执行任务
            result = handler(task)

            # 更新任务状态
            task.status = TaskStatus.COMPLETED
            task.result = result
            task.completed_at = datetime.now().isoformat()
            task.execution_time_ms = int((time.time() - start_time) * 1000)

            # 更新统计
            self.stats.completed_tasks += 1
            self.stats.total_tokens += task.tokens_used
            self.stats.total_cost += task.estimated_cost

            # 更新平均执行时间
            completed = self.stats.completed_tasks
            avg = self.stats.avg_execution_time_ms
            self.stats.avg_execution_time_ms = (
                avg * (completed - 1) + task.execution_time_ms
            ) / completed

            logger.debug(f"Task {task.id} completed in {task.execution_time_ms}ms")

        except Exception as e:
            error_msg = str(e)
            logger.warning(f"Task {task.id} failed: {error_msg}")

            # 检查是否需要重试
            if self._should_retry(task, e):
                task.retry_count += 1
                task.status = TaskStatus.RETRYING
                self.stats.retried_tasks += 1

                # 计算重试延迟
                delay = (
                    task.config.retry_delay_base *
                    (task.config.retry_delay_multiplier ** (task.retry_count - 1))
                )
                logger.info(f"Task {task.id} will retry in {delay:.1f}s (attempt {task.retry_count})")
                time.sleep(delay)

                # 重新入队
                self.queue.put(task)
            else:
                task.status = TaskStatus.FAILED
                task.error = error_msg
                task.completed_at = datetime.now().isoformat()
                self.stats.failed_tasks += 1

        finally:
            # 从运行中任务移除
            with self._lock:
                if task.id in self._running_tasks:
                    del self._running_tasks[task.id]

            # 添加到已完成任务
            if task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
                self._completed_tasks[task.id] = task

            self._semaphore.release()

    def _should_retry(self, task: AnalysisTask, error: Exception) -> bool:
        """判断是否应该重试"""
        if task.retry_count >= task.config.max_retries:
            return False

        error_str = str(error).lower()

        # 429错误（速率限制）- 应该重试
        if "429" in error_str or "rate limit" in error_str:
            return True

        # 超时 - 应该重试
        if "timeout" in error_str:
            return True

        # 服务器错误 - 应该重试
        if "500" in error_str or "502" in error_str or "503" in error_str:
            return True

        # 其他错误 - 不重试
        return False

    def process_one(self) -> Optional[str]:
        """处理一个任务

        Returns:
            处理的任务ID，如果没有任务返回None
        """
        task = self.queue.get()
        if not task:
            return None

        # 获取信号量
        self._semaphore.acquire()

        # 添加到运行中任务
        with self._lock:
            self._running_tasks[task.id] = task

        # 在新线程中执行
        thread = threading.Thread(target=self._execute_task, args=(task,))
        thread.start()

        return task.id

    def process_all(self, timeout: Optional[float] = None) -> int:
        """处理所有队列中的任务

        Args:
            timeout: 超时时间（秒），None表示无限等待

        Returns:
            处理的任务数量
        """
        processed = 0
        start_time = time.time()

        while True:
            # 检查超时
            if timeout and (time.time() - start_time) > timeout:
                break

            # 处理任务
            task_id = self.process_one()
            if task_id:
                processed += 1
            else:
                # 队列为空，检查是否还有运行中的任务
                with self._lock:
                    if not self._running_tasks:
                        break
                time.sleep(0.1)

        # 等待所有任务完成
        self.wait_all(timeout=timeout)

        return processed

    def wait_all(self, timeout: Optional[float] = None) -> bool:
        """等待所有任务完成

        Args:
            timeout: 超时时间（秒）

        Returns:
            是否所有任务都已完成
        """
        start_time = time.time()

        while True:
            with self._lock:
                if not self._running_tasks and self.queue.size() == 0:
                    return True

            if timeout and (time.time() - start_time) > timeout:
                return False

            time.sleep(0.1)

    def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """获取任务状态"""
        # 检查队列
        task = self.queue.get_task(task_id)
        if task:
            return task.status

        # 检查运行中
        with self._lock:
            if task_id in self._running_tasks:
                return self._running_tasks[task_id].status

        # 检查已完成
        if task_id in self._completed_tasks:
            return self._completed_tasks[task_id].status

        return None

    def get_task_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        """获取任务结果"""
        if task_id in self._completed_tasks:
            task = self._completed_tasks[task_id]
            return task.to_dict()
        return None

    def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        # 只能取消队列中的任务
        task = self.queue.get_task(task_id)
        if task and task.status == TaskStatus.QUEUED:
            self.queue.remove(task_id)
            task.status = TaskStatus.CANCELLED
            self._completed_tasks[task_id] = task
            self.stats.cancelled_tasks += 1
            return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """获取调度器统计"""
        with self._lock:
            running_count = len(self._running_tasks)

        return {
            "total_tasks": self.stats.total_tasks,
            "completed_tasks": self.stats.completed_tasks,
            "failed_tasks": self.stats.failed_tasks,
            "retried_tasks": self.stats.retried_tasks,
            "cancelled_tasks": self.stats.cancelled_tasks,
            "queued_tasks": self.queue.size(),
            "running_tasks": running_count,
            "total_tokens": self.stats.total_tokens,
            "total_cost": round(self.stats.total_cost, 4),
            "avg_execution_time_ms": round(self.stats.avg_execution_time_ms, 2),
            "by_model_tier": self.stats.by_model_tier,
            "by_task_type": self.stats.by_task_type,
        }

    def save_state(self) -> Optional[str]:
        """保存调度器状态

        Returns:
            保存的文件路径
        """
        if not self.state_dir:
            return None

        state = {
            "saved_at": datetime.now().isoformat(),
            "stats": asdict(self.stats),
            "queued_tasks": [],
            "completed_tasks": [],
        }

        # 保存队列中的任务
        for priority, queue in self.queue._queues.items():
            for task in queue:
                state["queued_tasks"].append(task.to_dict())

        # 保存已完成的任务
        for task in self._completed_tasks.values():
            state["completed_tasks"].append(task.to_dict())

        state_path = self.state_dir / "scheduler_state.json"
        with open(state_path, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)

        logger.info(f"Scheduler state saved to {state_path}")
        return str(state_path)

    def load_state(self) -> bool:
        """加载调度器状态

        Returns:
            是否成功加载
        """
        if not self.state_dir:
            return False

        state_path = self.state_dir / "scheduler_state.json"
        if not state_path.exists():
            return False

        try:
            with open(state_path, "r", encoding="utf-8") as f:
                state = json.load(f)

            # 恢复统计
            stats_data = state.get("stats", {})
            self.stats = SchedulerStats(
                total_tasks=stats_data.get("total_tasks", 0),
                completed_tasks=stats_data.get("completed_tasks", 0),
                failed_tasks=stats_data.get("failed_tasks", 0),
                retried_tasks=stats_data.get("retried_tasks", 0),
                cancelled_tasks=stats_data.get("cancelled_tasks", 0),
                total_tokens=stats_data.get("total_tokens", 0),
                total_cost=stats_data.get("total_cost", 0.0),
                avg_execution_time_ms=stats_data.get("avg_execution_time_ms", 0.0),
                by_model_tier=stats_data.get("by_model_tier", {}),
                by_task_type=stats_data.get("by_task_type", {}),
            )

            # 恢复队列中的任务
            for task_data in state.get("queued_tasks", []):
                task = AnalysisTask.from_dict(task_data)
                task.status = TaskStatus.PENDING  # 重置状态
                self.queue.put(task)

            # 恢复已完成的任务
            for task_data in state.get("completed_tasks", []):
                task = AnalysisTask.from_dict(task_data)
                self._completed_tasks[task.id] = task

            logger.info(f"Scheduler state loaded from {state_path}")
            return True

        except Exception as e:
            logger.warning(f"Failed to load scheduler state: {e}")
            return False

    def clear(self) -> None:
        """清空调度器"""
        self.queue.clear()
        self._completed_tasks.clear()
        self.stats = SchedulerStats()
        logger.info("Scheduler cleared")


class TieredAnalysisExecutor:
    """分级分析执行器

    使用分级策略执行LLM分析：
    1. 先用快速模型初筛
    2. 对低置信度或高风险的结果用高级模型精分析
    """

    def __init__(
        self,
        llm_client: BaseLLMClient,
        model_config: Optional[TieredModelConfig] = None,
    ):
        self.llm_client = llm_client
        self.model_config = model_config or TieredModelConfig()

    def analyze_with_tiering(
        self,
        messages: List[ChatMessage],
        initial_tier: ModelTier = ModelTier.FAST,
        upgrade_threshold: float = 0.5,
        force_upgrade_on_high_risk: bool = True,
    ) -> Dict[str, Any]:
        """使用分级策略进行分析

        Args:
            messages: 聊天消息
            initial_tier: 初始模型层级
            upgrade_threshold: 升级阈值（置信度低于此值时升级）
            force_upgrade_on_high_risk: 高风险发现是否强制升级

        Returns:
            分析结果
        """
        # 第一阶段：使用初始层级模型
        model = self._get_model(initial_tier)
        logger.debug(f"Tier 1 analysis with model: {model}")

        result = self._call_llm(messages, model)

        # 检查是否需要升级
        should_upgrade = False

        confidence = result.get("confidence", 1.0)
        if confidence < upgrade_threshold:
            should_upgrade = True
            logger.debug(f"Low confidence ({confidence}), upgrading model")

        if force_upgrade_on_high_risk:
            severity = result.get("severity", "").lower()
            if severity in ("critical", "high"):
                should_upgrade = True
                logger.debug(f"High risk ({severity}), upgrading model")

        # 第二阶段：如果需要，使用高级模型
        if should_upgrade and initial_tier != ModelTier.ADVANCED:
            advanced_model = self._get_model(ModelTier.ADVANCED)
            logger.debug(f"Tier 2 analysis with model: {advanced_model}")

            # 添加第一阶段结果作为上下文
            enhanced_messages = messages.copy()
            enhanced_messages.append(ChatMessage(
                role="assistant",
                content=f"初步分析结果：{json.dumps(result, ensure_ascii=False)}"
            ))
            enhanced_messages.append(ChatMessage(
                role="user",
                content="请基于上述初步分析，进行更深入的安全审计，确认漏洞是否真实存在。"
            ))

            advanced_result = self._call_llm(enhanced_messages, advanced_model)

            # 合并结果
            result["tier1_result"] = result.copy()
            result.update(advanced_result)
            result["model_upgraded"] = True
            result["final_model"] = advanced_model

        return result

    def _get_model(self, tier: ModelTier) -> str:
        """获取模型名称"""
        if tier == ModelTier.FAST:
            return self.model_config.fast_model
        elif tier == ModelTier.ADVANCED:
            return self.model_config.advanced_model
        return self.model_config.standard_model

    def _call_llm(
        self,
        messages: List[ChatMessage],
        model: str,
    ) -> Dict[str, Any]:
        """调用LLM"""
        try:
            response = self.llm_client.chat_completion(
                messages=messages,
                model=model,
                response_format={"type": "json_object"},
                temperature=0.1,
            )

            # 解析JSON响应
            import json
            try:
                return json.loads(response.content)
            except json.JSONDecodeError:
                # 尝试提取JSON
                import re
                match = re.search(r'\{[\s\S]*\}', response.content)
                if match:
                    return json.loads(match.group(0))
                return {"raw_response": response.content, "confidence": 0.3}

        except Exception as e:
            logger.warning(f"LLM call failed: {e}")
            return {"error": str(e), "confidence": 0.0}
