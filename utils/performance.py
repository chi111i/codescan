"""
性能优化与 Token 预算控制模块

功能:
- Token 计数和估算
- Token 预算管理
- 上下文智能截断
- 请求节流和速率限制
- 并发控制
"""

import time
import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, Future

logger = logging.getLogger(__name__)


class TokenEstimator:
    """Token 估算器

    基于启发式规则估算文本的 token 数量
    """

    # 不同语言的平均 token/字符比率
    CHAR_TO_TOKEN_RATIO = {
        "english": 0.25,    # 英文约 4 字符 = 1 token
        "chinese": 0.5,     # 中文约 2 字符 = 1 token
        "code": 0.3,        # 代码约 3.3 字符 = 1 token
        "mixed": 0.35,      # 混合内容
    }

    def __init__(self, default_ratio: float = 0.3):
        """初始化

        Args:
            default_ratio: 默认的字符/token 比率
        """
        self.default_ratio = default_ratio

    def estimate(self, text: str, content_type: str = "mixed") -> int:
        """估算文本的 token 数量

        Args:
            text: 文本内容
            content_type: 内容类型 (english, chinese, code, mixed)

        Returns:
            估算的 token 数量
        """
        if not text:
            return 0

        ratio = self.CHAR_TO_TOKEN_RATIO.get(content_type, self.default_ratio)

        # 对于代码，还需要考虑特殊字符
        if content_type == "code":
            # 计算特殊字符数量
            special_chars = sum(1 for c in text if not c.isalnum() and c not in ' \n\t')
            # 特殊字符通常单独作为 token
            base_tokens = len(text) * ratio
            special_tokens = special_chars * 0.2  # 部分特殊字符会合并
            return int(base_tokens + special_tokens)

        return int(len(text) * ratio)

    def estimate_messages(
        self,
        messages: List[Dict[str, str]],
        content_type: str = "mixed"
    ) -> int:
        """估算消息列表的 token 数量

        Args:
            messages: 消息列表 [{"role": "user", "content": "..."}]
            content_type: 内容类型

        Returns:
            估算的 token 数量
        """
        total = 0
        for msg in messages:
            # 消息结构开销 (role, content 等)
            total += 4
            content = msg.get("content", "")
            total += self.estimate(content, content_type)
        return total


@dataclass
class TokenBudget:
    """Token 预算"""
    max_input_tokens: int = 6000      # 最大输入 token
    max_output_tokens: int = 4096     # 最大输出 token
    max_code_tokens: int = 3000       # 最大代码 token
    reserved_tokens: int = 500        # 保留给系统提示的 token

    # 当前使用情况
    used_input: int = 0
    used_output: int = 0

    def remaining_input(self) -> int:
        """剩余输入 token"""
        return max(0, self.max_input_tokens - self.used_input - self.reserved_tokens)

    def remaining_code(self) -> int:
        """剩余代码 token"""
        return max(0, self.max_code_tokens - self.used_input)

    def can_add(self, tokens: int) -> bool:
        """检查是否可以添加更多 token"""
        return self.used_input + tokens <= self.max_input_tokens - self.reserved_tokens

    def add_input(self, tokens: int) -> None:
        """记录输入 token 使用"""
        self.used_input += tokens

    def add_output(self, tokens: int) -> None:
        """记录输出 token 使用"""
        self.used_output += tokens

    def reset(self) -> None:
        """重置使用统计"""
        self.used_input = 0
        self.used_output = 0


class ContextTrimmer:
    """上下文智能截断器

    当内容超出 token 预算时，智能截断保留最重要的部分
    """

    def __init__(
        self,
        token_estimator: Optional[TokenEstimator] = None,
        budget: Optional[TokenBudget] = None
    ):
        """初始化

        Args:
            token_estimator: Token 估算器
            budget: Token 预算
        """
        self.estimator = token_estimator or TokenEstimator()
        self.budget = budget or TokenBudget()

    def trim_code(
        self,
        code: str,
        max_tokens: Optional[int] = None,
        keep_start: bool = True,
        keep_end: bool = True,
        keep_middle: bool = False
    ) -> str:
        """截断代码，保留关键部分

        Args:
            code: 代码内容
            max_tokens: 最大 token 数
            keep_start: 保留开头
            keep_end: 保留结尾
            keep_middle: 保留中间部分

        Returns:
            截断后的代码
        """
        max_tokens = max_tokens or self.budget.max_code_tokens
        estimated = self.estimator.estimate(code, "code")

        if estimated <= max_tokens:
            return code

        # 计算需要保留的字符数
        char_budget = int(max_tokens / 0.3)  # 反向估算字符数
        lines = code.split('\n')

        if len(lines) <= 10:
            # 短代码直接截断
            return code[:char_budget] + "\n... [truncated]"

        # 智能截断：保留开头和结尾
        start_lines = int(len(lines) * 0.4)  # 保留前 40%
        end_lines = int(len(lines) * 0.3)    # 保留后 30%

        start_part = '\n'.join(lines[:start_lines])
        end_part = '\n'.join(lines[-end_lines:])

        # 估算两部分的 token
        start_tokens = self.estimator.estimate(start_part, "code")
        end_tokens = self.estimator.estimate(end_part, "code")

        if start_tokens + end_tokens > max_tokens:
            # 还是太长，进一步截断
            ratio = max_tokens / (start_tokens + end_tokens)
            start_lines = int(start_lines * ratio)
            end_lines = int(end_lines * ratio)
            start_part = '\n'.join(lines[:start_lines])
            end_part = '\n'.join(lines[-end_lines:])

        truncated_lines = len(lines) - start_lines - end_lines
        return f"{start_part}\n\n... [{truncated_lines} lines omitted] ...\n\n{end_part}"

    def trim_context(
        self,
        context_items: List[Tuple[str, int]],  # [(content, priority), ...]
        max_tokens: Optional[int] = None
    ) -> List[str]:
        """根据优先级截断上下文

        Args:
            context_items: 上下文项列表，每项包含 (内容, 优先级)
            max_tokens: 最大 token 数

        Returns:
            筛选后的内容列表
        """
        max_tokens = max_tokens or self.budget.remaining_input()

        # 按优先级排序 (高优先级在前)
        sorted_items = sorted(context_items, key=lambda x: -x[1])

        result = []
        total_tokens = 0

        for content, priority in sorted_items:
            tokens = self.estimator.estimate(content, "mixed")
            if total_tokens + tokens <= max_tokens:
                result.append(content)
                total_tokens += tokens
            elif priority >= 8:  # 高优先级内容截断后也要保留
                trimmed = self.trim_code(content, max_tokens - total_tokens)
                result.append(trimmed)
                break

        return result


class RateLimiter:
    """速率限制器

    控制 API 调用频率
    """

    def __init__(
        self,
        calls_per_minute: int = 60,
        calls_per_second: int = 5
    ):
        """初始化

        Args:
            calls_per_minute: 每分钟最大调用次数
            calls_per_second: 每秒最大调用次数
        """
        self.calls_per_minute = calls_per_minute
        self.calls_per_second = calls_per_second

        self._minute_window: deque = deque()
        self._second_window: deque = deque()
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """获取调用许可

        Returns:
            需要等待的秒数 (0 表示立即可用)
        """
        with self._lock:
            now = time.time()

            # 清理过期的时间戳
            while self._minute_window and now - self._minute_window[0] > 60:
                self._minute_window.popleft()
            while self._second_window and now - self._second_window[0] > 1:
                self._second_window.popleft()

            # 检查限制
            wait_time = 0

            if len(self._second_window) >= self.calls_per_second:
                wait_time = max(wait_time, 1 - (now - self._second_window[0]))

            if len(self._minute_window) >= self.calls_per_minute:
                wait_time = max(wait_time, 60 - (now - self._minute_window[0]))

            if wait_time > 0:
                return wait_time

            # 记录调用
            self._minute_window.append(now)
            self._second_window.append(now)
            return 0

    def wait_and_acquire(self) -> None:
        """等待并获取调用许可"""
        while True:
            wait_time = self.acquire()
            if wait_time == 0:
                return
            logger.debug(f"Rate limited, waiting {wait_time:.2f}s")
            time.sleep(wait_time)


class ConcurrencyController:
    """并发控制器

    管理并行任务执行
    """

    def __init__(
        self,
        max_workers: int = 4,
        rate_limiter: Optional[RateLimiter] = None
    ):
        """初始化

        Args:
            max_workers: 最大工作线程数
            rate_limiter: 速率限制器
        """
        self.max_workers = max_workers
        self.rate_limiter = rate_limiter
        self._executor: Optional[ThreadPoolExecutor] = None
        self._active_tasks: Dict[str, Future] = {}

    def _get_executor(self) -> ThreadPoolExecutor:
        """获取线程池"""
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        return self._executor

    def submit(
        self,
        func: Callable,
        *args,
        task_id: Optional[str] = None,
        **kwargs
    ) -> Future:
        """提交任务

        Args:
            func: 要执行的函数
            *args: 函数参数
            task_id: 任务 ID
            **kwargs: 函数关键字参数

        Returns:
            Future 对象
        """
        def wrapped():
            if self.rate_limiter:
                self.rate_limiter.wait_and_acquire()
            return func(*args, **kwargs)

        executor = self._get_executor()
        future = executor.submit(wrapped)

        if task_id:
            self._active_tasks[task_id] = future

        return future

    def map(
        self,
        func: Callable,
        items: List[Any],
        chunk_size: int = 10
    ) -> List[Any]:
        """并行执行函数

        Args:
            func: 要执行的函数
            items: 输入项列表
            chunk_size: 分块大小

        Returns:
            结果列表
        """
        executor = self._get_executor()
        results = []

        # 分块处理
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i + chunk_size]
            futures = []

            for item in chunk:
                if self.rate_limiter:
                    self.rate_limiter.wait_and_acquire()
                futures.append(executor.submit(func, item))

            # 收集结果
            for future in futures:
                try:
                    results.append(future.result())
                except Exception as e:
                    logger.warning(f"Task failed: {e}")
                    results.append(None)

        return results

    def get_active_count(self) -> int:
        """获取活跃任务数"""
        return len([f for f in self._active_tasks.values() if not f.done()])

    def shutdown(self, wait: bool = True) -> None:
        """关闭线程池"""
        if self._executor:
            self._executor.shutdown(wait=wait)
            self._executor = None
            self._active_tasks.clear()


class PerformanceMonitor:
    """性能监控器"""

    def __init__(self):
        """初始化"""
        self._metrics: Dict[str, List[float]] = {
            "llm_latency": [],
            "embedding_latency": [],
            "search_latency": [],
            "total_tokens": [],
        }
        self._start_times: Dict[str, float] = {}

    def start_timer(self, metric_name: str) -> None:
        """开始计时"""
        self._start_times[metric_name] = time.time()

    def end_timer(self, metric_name: str) -> float:
        """结束计时并记录"""
        start = self._start_times.pop(metric_name, None)
        if start is None:
            return 0

        elapsed = time.time() - start
        if metric_name not in self._metrics:
            self._metrics[metric_name] = []
        self._metrics[metric_name].append(elapsed)
        return elapsed

    def record_tokens(self, count: int) -> None:
        """记录 token 使用"""
        self._metrics["total_tokens"].append(count)

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {}
        for metric, values in self._metrics.items():
            if not values:
                continue
            stats[metric] = {
                "count": len(values),
                "total": sum(values),
                "avg": sum(values) / len(values),
                "min": min(values),
                "max": max(values),
            }
        return stats

    def reset(self) -> None:
        """重置统计"""
        for key in self._metrics:
            self._metrics[key] = []


# 装饰器
def with_rate_limit(limiter: RateLimiter):
    """速率限制装饰器"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            limiter.wait_and_acquire()
            return func(*args, **kwargs)
        return wrapper
    return decorator


def with_token_budget(budget: TokenBudget, estimator: Optional[TokenEstimator] = None):
    """Token 预算装饰器"""
    est = estimator or TokenEstimator()

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 估算输入 token
            input_tokens = 0
            for arg in args:
                if isinstance(arg, str):
                    input_tokens += est.estimate(arg)
                elif isinstance(arg, list):
                    for item in arg:
                        if isinstance(item, dict) and "content" in item:
                            input_tokens += est.estimate(item["content"])

            if not budget.can_add(input_tokens):
                raise ValueError(
                    f"Token budget exceeded. Need {input_tokens}, "
                    f"remaining {budget.remaining_input()}"
                )

            budget.add_input(input_tokens)
            result = func(*args, **kwargs)

            # 记录输出 token (如果可获取)
            if hasattr(result, "usage"):
                budget.add_output(result.usage.get("completion_tokens", 0))

            return result
        return wrapper
    return decorator


# 便捷创建函数
def create_token_budget(config) -> TokenBudget:
    """从配置创建 Token 预算"""
    return TokenBudget(
        max_input_tokens=config.llm.max_context_tokens,
        max_output_tokens=config.llm.max_tokens,
        max_code_tokens=config.llm.max_code_tokens_per_call,
    )


def create_rate_limiter(
    calls_per_minute: int = 60,
    calls_per_second: int = 5
) -> RateLimiter:
    """创建速率限制器"""
    return RateLimiter(
        calls_per_minute=calls_per_minute,
        calls_per_second=calls_per_second
    )


def create_concurrency_controller(config) -> ConcurrencyController:
    """从配置创建并发控制器"""
    return ConcurrencyController(
        max_workers=config.scan.max_concurrent
    )
