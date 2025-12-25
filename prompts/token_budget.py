"""Token 预算管理器

提供精确的 Token 计算、动态截断和预算分配功能。
"""

import logging
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum

try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False
    logging.warning("[TokenBudget] tiktoken 未安装，将使用启发式估算")

logger = logging.getLogger(__name__)


class TokenPriority(Enum):
    """内容优先级

    用于在 Token 预算不足时决定截断顺序。
    """
    CRITICAL = 1  # 绝不截断（如系统提示词、输出格式）
    HIGH = 2      # 优先保留（如 Sink 代码、入口点）
    MEDIUM = 3    # 可部分截断（如调用链节点）
    LOW = 4       # 可大量截断（如元数据、辅助信息）


@dataclass
class ContentBlock:
    """内容块

    表示 Prompt 中的一个逻辑片段。
    """
    text: str
    priority: TokenPriority
    name: str
    actual_tokens: int = 0
    truncated: bool = False
    original_length: int = field(init=False)

    def __post_init__(self):
        self.original_length = len(self.text)


class TokenCounter:
    """Token 计数器

    支持 tiktoken 精确计算和启发式估算。
    """

    def __init__(self, encoding_name: str = "cl100k_base"):
        """初始化 Token 计数器

        Args:
            encoding_name: tiktoken 编码器名称（仅在 tiktoken 可用时生效）
        """
        self.encoding_name = encoding_name
        self.encoder = None

        if TIKTOKEN_AVAILABLE:
            try:
                self.encoder = tiktoken.get_encoding(encoding_name)
                logger.info(f"[TokenCounter] 使用 tiktoken: {encoding_name}")
            except Exception as e:
                logger.warning(f"[TokenCounter] tiktoken 初始化失败: {e}，降级为启发式估算")

    def count(self, text: str) -> int:
        """计算文本的 Token 数量

        Args:
            text: 文本内容

        Returns:
            Token 数量
        """
        if self.encoder:
            try:
                return len(self.encoder.encode(text))
            except Exception as e:
                logger.warning(f"[TokenCounter] tiktoken 计算失败: {e}，降级为启发式估算")

        # 启发式估算
        return self._heuristic_count(text)

    def _heuristic_count(self, text: str) -> int:
        """启发式 Token 估算

        规则：
        - 中文字符：1 字符 = 1 token
        - 英文单词：1 单词 ≈ 1.3 tokens
        - 标点符号：计入单词
        """
        chinese_chars = len([c for c in text if '\u4e00' <= c <= '\u9fff'])
        english_chars = len([c for c in text if c.isalpha() and ord(c) < 128])

        # 粗略估算
        tokens = chinese_chars + int(english_chars / 4 * 1.3)
        return max(tokens, len(text.split()) // 2)

    def truncate(self, text: str, max_tokens: int) -> str:
        """截断文本到指定 Token 数量

        Args:
            text: 文本内容
            max_tokens: 最大 Token 数

        Returns:
            截断后的文本
        """
        if self.encoder:
            try:
                tokens = self.encoder.encode(text)
                if len(tokens) > max_tokens:
                    truncated_tokens = tokens[:max_tokens]
                    return self.encoder.decode(truncated_tokens)
                return text
            except Exception as e:
                logger.warning(f"[TokenCounter] tiktoken 截断失败: {e}，降级为字符截断")

        # 启发式截断：按字符比例
        current_tokens = self.count(text)
        if current_tokens <= max_tokens:
            return text

        ratio = max_tokens / current_tokens
        char_limit = int(len(text) * ratio)
        return text[:char_limit] + "..."


class TokenBudgetManager:
    """Token 预算管理器

    智能分配和管理 Prompt 的 Token 预算。
    """

    def __init__(
        self,
        max_total_tokens: int,
        encoding_name: str = "cl100k_base",
        truncation_suffix: str = "\n\n[注意: 上下文已截断]",
    ):
        """初始化预算管理器

        Args:
            max_total_tokens: 总 Token 预算
            encoding_name: tiktoken 编码器名称
            truncation_suffix: 截断后缀文本
        """
        self.max_total_tokens = max_total_tokens
        self.truncation_suffix = truncation_suffix
        self.counter = TokenCounter(encoding_name)

        logger.info(f"[TokenBudget] 初始化: max_tokens={max_total_tokens}")

    def build_prompt(
        self,
        content_blocks: List[ContentBlock],
    ) -> Tuple[str, Dict[str, Any]]:
        """构建 Prompt 并管理 Token 预算

        Args:
            content_blocks: 内容块列表

        Returns:
            (final_prompt, budget_info)
        """
        # 计算每个块的实际 Token 数
        for block in content_blocks:
            block.actual_tokens = self.counter.count(block.text)

        # 计算总 Token 数
        total_tokens = sum(b.actual_tokens for b in content_blocks)

        # 如果未超限，直接拼接
        if total_tokens <= self.max_total_tokens:
            final_prompt = "\n\n".join(b.text for b in content_blocks)
            return final_prompt, {
                "total_tokens": total_tokens,
                "max_tokens": self.max_total_tokens,
                "utilization": total_tokens / self.max_total_tokens,
                "truncated_count": 0,
                "truncated_blocks": [],
            }

        # 超限：按优先级截断
        logger.warning(
            f"[TokenBudget] Token 超限: {total_tokens} > {self.max_total_tokens}, "
            f"开始智能截断"
        )

        return self._truncate_blocks(content_blocks, total_tokens)

    def _truncate_blocks(
        self,
        content_blocks: List[ContentBlock],
        total_tokens: int,
    ) -> Tuple[str, Dict[str, Any]]:
        """智能截断内容块

        策略：
        1. CRITICAL 优先级：绝不截断
        2. LOW 优先级：优先截断
        3. MEDIUM 优先级：按比例截断
        4. HIGH 优先级：最小程度截断

        Args:
            content_blocks: 内容块列表
            total_tokens: 当前总 Token 数

        Returns:
            (final_prompt, budget_info)
        """
        # 按优先级分组
        critical = [b for b in content_blocks if b.priority == TokenPriority.CRITICAL]
        high = [b for b in content_blocks if b.priority == TokenPriority.HIGH]
        medium = [b for b in content_blocks if b.priority == TokenPriority.MEDIUM]
        low = [b for b in content_blocks if b.priority == TokenPriority.LOW]

        # 计算各组 Token
        critical_tokens = sum(b.actual_tokens for b in critical)
        high_tokens = sum(b.actual_tokens for b in high)
        medium_tokens = sum(b.actual_tokens for b in medium)
        low_tokens = sum(b.actual_tokens for b in low)

        # 可用预算
        budget = self.max_total_tokens
        overflow = total_tokens - budget

        # 保证 CRITICAL 完整
        budget -= critical_tokens

        # 如果仅 CRITICAL 就超限，只能报错
        if budget < 0:
            logger.error(
                f"[TokenBudget] CRITICAL 内容已超预算: {critical_tokens} > {self.max_total_tokens}"
            )
            raise ValueError("CRITICAL 内容超出 Token 预算，无法截断")

        # 截断 LOW
        if overflow > 0 and low_tokens > 0:
            cut = min(overflow, int(low_tokens * 0.9))  # 最多砍掉 90%
            self._apply_proportional_cut(low, cut)
            overflow -= cut
            budget -= (low_tokens - cut)

        # 截断 MEDIUM
        if overflow > 0 and medium_tokens > 0:
            cut = min(overflow, int(medium_tokens * 0.6))  # 最多砍掉 60%
            self._apply_proportional_cut(medium, cut)
            overflow -= cut
            budget -= (medium_tokens - cut)

        # 截断 HIGH（最后手段）
        if overflow > 0 and high_tokens > 0:
            cut = min(overflow, int(high_tokens * 0.3))  # 最多砍掉 30%
            self._apply_proportional_cut(high, cut)
            overflow -= cut
            budget -= (high_tokens - cut)

        # 重新拼接
        all_blocks = critical + high + medium + low
        final_prompt = "\n\n".join(b.text for b in all_blocks if b.actual_tokens > 0)
        final_prompt += self.truncation_suffix

        # 统计
        truncated_blocks = [b.name for b in all_blocks if b.truncated]
        final_tokens = self.counter.count(final_prompt)

        budget_info = {
            "total_tokens": final_tokens,
            "max_tokens": self.max_total_tokens,
            "utilization": final_tokens / self.max_total_tokens,
            "truncated_count": len(truncated_blocks),
            "truncated_blocks": truncated_blocks,
            "original_tokens": total_tokens,
            "tokens_saved": total_tokens - final_tokens,
        }

        logger.info(
            f"[TokenBudget] 截断完成: {total_tokens} -> {final_tokens} tokens, "
            f"截断 {len(truncated_blocks)} 个块"
        )

        return final_prompt, budget_info

    def _apply_proportional_cut(self, blocks: List[ContentBlock], total_cut: int):
        """按比例截断多个块

        Args:
            blocks: 内容块列表
            total_cut: 总共需要削减的 Token 数
        """
        if not blocks or total_cut <= 0:
            return

        total_tokens = sum(b.actual_tokens for b in blocks)
        if total_tokens == 0:
            return

        for block in blocks:
            # 按比例分配截断量
            cut_ratio = block.actual_tokens / total_tokens
            cut_amount = int(total_cut * cut_ratio)

            if cut_amount > 0:
                new_tokens = max(block.actual_tokens - cut_amount, 10)  # 至少保留 10 tokens
                block.text = self.counter.truncate(block.text, new_tokens)
                block.actual_tokens = self.counter.count(block.text)
                block.truncated = True


def count_tokens(text: str, encoding_name: str = "cl100k_base") -> int:
    """计算文本的 Token 数量（便捷函数）

    Args:
        text: 文本内容
        encoding_name: 编码器名称

    Returns:
        Token 数量
    """
    counter = TokenCounter(encoding_name)
    return counter.count(text)


def truncate_text_by_tokens(
    text: str,
    max_tokens: int,
    encoding_name: str = "cl100k_base"
) -> str:
    """根据最大 Token 数量截断文本（便捷函数）

    Args:
        text: 文本内容
        max_tokens: 最大 Token 数
        encoding_name: 编码器名称

    Returns:
        截断后的文本
    """
    counter = TokenCounter(encoding_name)
    return counter.truncate(text, max_tokens)
