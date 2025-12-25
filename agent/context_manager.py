"""
上下文管理器 - 管理智能体对话上下文

功能：
1. 对话历史管理与裁剪
2. 代码上下文收集与组织
3. Token 计数与限制
4. 上下文摘要生成
"""

import logging
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any, Callable
from enum import Enum

from llm_client import ChatMessage

logger = logging.getLogger(__name__)


class ContextType(Enum):
    """上下文类型"""
    CONVERSATION = "conversation"  # 对话历史
    CODE = "code"                  # 代码片段
    TOOL_RESULT = "tool_result"    # 工具执行结果
    FINDING = "finding"            # 安全发现
    SUMMARY = "summary"            # 摘要


@dataclass
class ContextItem:
    """上下文项"""
    id: str
    type: ContextType
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    token_count: int = 0
    priority: int = 0  # 优先级，越高越重要

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "content": self.content,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
            "token_count": self.token_count,
            "priority": self.priority,
        }


@dataclass
class ContextManagerConfig:
    """上下文管理器配置"""
    # Token 限制
    max_total_tokens: int = 100000      # 最大总 token 数
    max_conversation_tokens: int = 50000  # 对话历史最大 token
    max_code_tokens: int = 30000        # 代码上下文最大 token
    max_tool_result_tokens: int = 20000  # 工具结果最大 token

    # 消息数量限制
    max_conversation_messages: int = 50  # 最大对话消息数
    min_conversation_messages: int = 10  # 最少保留消息数

    # 裁剪策略
    trim_strategy: str = "fifo"  # fifo, priority, hybrid

    # Token 计数函数（可自定义）
    token_counter: Optional[Callable[[str], int]] = None


class ContextManager:
    """上下文管理器

    管理智能体的对话上下文，包括：
    - 对话历史
    - 代码片段
    - 工具执行结果
    - 安全发现

    支持自动裁剪以控制 token 使用量。

    Usage:
        manager = ContextManager(config=ContextManagerConfig())

        # 添加对话消息
        manager.add_message("user", "分析这个函数")
        manager.add_message("assistant", "好的，让我查看...")

        # 添加代码上下文
        manager.add_code_context("auth.py", code_content, priority=5)

        # 获取用于 LLM 的消息列表
        messages = manager.get_llm_messages(system_prompt="...")

        # 检查是否需要裁剪
        if manager.needs_trim():
            manager.trim()
    """

    def __init__(self, config: Optional[ContextManagerConfig] = None):
        """初始化上下文管理器

        Args:
            config: 配置
        """
        self.config = config or ContextManagerConfig()

        # 上下文存储
        self._conversation: List[ContextItem] = []
        self._code_contexts: Dict[str, ContextItem] = {}
        self._tool_results: List[ContextItem] = []
        self._findings: Dict[str, ContextItem] = {}
        self._summaries: List[ContextItem] = []

        # 统计
        self._total_tokens = 0
        self._conversation_tokens = 0
        self._code_tokens = 0
        self._tool_result_tokens = 0

        # 计数器
        self._item_counter = 0

        logger.debug("[ContextManager] 初始化完成")

    def _generate_id(self, prefix: str = "ctx") -> str:
        """生成唯一 ID"""
        self._item_counter += 1
        return f"{prefix}-{self._item_counter}"

    def _count_tokens(self, text: str) -> int:
        """计算 token 数量"""
        if self.config.token_counter:
            return self.config.token_counter(text)
        # 简单估算：英文约 4 字符/token，中文约 2 字符/token
        # 这里使用简单的字符数估算
        return len(text) // 3

    # ============ 对话管理 ============

    def add_message(
        self,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        priority: int = 0,
    ) -> ContextItem:
        """添加对话消息

        Args:
            role: 角色（user/assistant/system）
            content: 消息内容
            metadata: 元数据
            priority: 优先级

        Returns:
            ContextItem
        """
        token_count = self._count_tokens(content)

        item = ContextItem(
            id=self._generate_id("msg"),
            type=ContextType.CONVERSATION,
            content=content,
            metadata={
                "role": role,
                **(metadata or {}),
            },
            token_count=token_count,
            priority=priority,
        )

        self._conversation.append(item)
        self._conversation_tokens += token_count
        self._total_tokens += token_count

        # 检查是否需要裁剪
        if self._conversation_tokens > self.config.max_conversation_tokens:
            self._trim_conversation()

        return item

    def get_conversation(self) -> List[ContextItem]:
        """获取对话历史"""
        return self._conversation.copy()

    def get_conversation_messages(self) -> List[ChatMessage]:
        """获取对话消息（ChatMessage 格式）"""
        messages = []
        for item in self._conversation:
            role = item.metadata.get("role", "user")
            messages.append(ChatMessage(role=role, content=item.content))
        return messages

    def _trim_conversation(self):
        """裁剪对话历史"""
        if len(self._conversation) <= self.config.min_conversation_messages:
            return

        logger.debug(f"[ContextManager] 裁剪对话历史，当前 {len(self._conversation)} 条")

        if self.config.trim_strategy == "fifo":
            # 先进先出，保留最近的消息
            self._trim_conversation_fifo()
        elif self.config.trim_strategy == "priority":
            # 按优先级裁剪
            self._trim_conversation_priority()
        else:
            # 混合策略
            self._trim_conversation_hybrid()

    def _trim_conversation_fifo(self):
        """FIFO 裁剪策略"""
        # 保留最少消息数
        keep_count = max(
            self.config.min_conversation_messages,
            len(self._conversation) // 2,
        )

        # 计算要移除的消息
        to_remove = self._conversation[:-keep_count]
        self._conversation = self._conversation[-keep_count:]

        # 更新 token 计数
        removed_tokens = sum(item.token_count for item in to_remove)
        self._conversation_tokens -= removed_tokens
        self._total_tokens -= removed_tokens

        logger.debug(f"[ContextManager] FIFO 裁剪，移除 {len(to_remove)} 条消息")

    def _trim_conversation_priority(self):
        """按优先级裁剪"""
        # 按优先级排序，保留高优先级的
        sorted_items = sorted(self._conversation, key=lambda x: x.priority, reverse=True)

        # 保留到 token 限制以内
        kept = []
        kept_tokens = 0
        target_tokens = self.config.max_conversation_tokens * 0.8  # 留出 20% 余量

        for item in sorted_items:
            if kept_tokens + item.token_count <= target_tokens:
                kept.append(item)
                kept_tokens += item.token_count

        # 按时间顺序重排
        kept.sort(key=lambda x: x.timestamp)
        self._conversation = kept
        self._conversation_tokens = kept_tokens

        logger.debug(f"[ContextManager] 优先级裁剪，保留 {len(kept)} 条消息")

    def _trim_conversation_hybrid(self):
        """混合裁剪策略"""
        # 先按 FIFO 移除旧消息
        half_count = len(self._conversation) // 2
        self._conversation = self._conversation[-half_count:]

        # 如果还超限，再按优先级裁剪
        if self._conversation_tokens > self.config.max_conversation_tokens:
            self._trim_conversation_priority()

    # ============ 代码上下文管理 ============

    def add_code_context(
        self,
        file_path: str,
        code: str,
        symbol: Optional[str] = None,
        line_start: int = 0,
        line_end: int = 0,
        priority: int = 0,
    ) -> ContextItem:
        """添加代码上下文

        Args:
            file_path: 文件路径
            code: 代码内容
            symbol: 符号名称
            line_start: 起始行
            line_end: 结束行
            priority: 优先级

        Returns:
            ContextItem
        """
        token_count = self._count_tokens(code)

        # 使用文件路径+行号作为 key
        key = f"{file_path}:{line_start}-{line_end}"

        item = ContextItem(
            id=self._generate_id("code"),
            type=ContextType.CODE,
            content=code,
            metadata={
                "file_path": file_path,
                "symbol": symbol,
                "line_start": line_start,
                "line_end": line_end,
            },
            token_count=token_count,
            priority=priority,
        )

        # 如果已存在相同的代码块，更新它
        if key in self._code_contexts:
            old_item = self._code_contexts[key]
            self._code_tokens -= old_item.token_count
            self._total_tokens -= old_item.token_count

        self._code_contexts[key] = item
        self._code_tokens += token_count
        self._total_tokens += token_count

        # 检查是否需要裁剪
        if self._code_tokens > self.config.max_code_tokens:
            self._trim_code_contexts()

        return item

    def get_code_contexts(self) -> List[ContextItem]:
        """获取所有代码上下文"""
        return list(self._code_contexts.values())

    def remove_code_context(self, file_path: str, line_start: int = 0, line_end: int = 0) -> bool:
        """移除代码上下文"""
        key = f"{file_path}:{line_start}-{line_end}"
        if key in self._code_contexts:
            item = self._code_contexts.pop(key)
            self._code_tokens -= item.token_count
            self._total_tokens -= item.token_count
            return True
        return False

    def _trim_code_contexts(self):
        """裁剪代码上下文"""
        # 按优先级排序
        items = sorted(
            self._code_contexts.values(),
            key=lambda x: (x.priority, x.timestamp),
            reverse=True,
        )

        # 保留到限制以内
        kept = {}
        kept_tokens = 0
        target_tokens = self.config.max_code_tokens * 0.8

        for item in items:
            if kept_tokens + item.token_count <= target_tokens:
                key = f"{item.metadata['file_path']}:{item.metadata['line_start']}-{item.metadata['line_end']}"
                kept[key] = item
                kept_tokens += item.token_count

        removed_count = len(self._code_contexts) - len(kept)
        self._code_contexts = kept
        self._code_tokens = kept_tokens

        logger.debug(f"[ContextManager] 代码上下文裁剪，移除 {removed_count} 个")

    # ============ 工具结果管理 ============

    def add_tool_result(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        result: Any,
        priority: int = 0,
    ) -> ContextItem:
        """添加工具执行结果

        Args:
            tool_name: 工具名称
            arguments: 调用参数
            result: 执行结果
            priority: 优先级

        Returns:
            ContextItem
        """
        content = json.dumps({
            "tool": tool_name,
            "arguments": arguments,
            "result": result,
        }, ensure_ascii=False, indent=2)

        token_count = self._count_tokens(content)

        item = ContextItem(
            id=self._generate_id("tool"),
            type=ContextType.TOOL_RESULT,
            content=content,
            metadata={
                "tool_name": tool_name,
                "arguments": arguments,
            },
            token_count=token_count,
            priority=priority,
        )

        self._tool_results.append(item)
        self._tool_result_tokens += token_count
        self._total_tokens += token_count

        # 检查是否需要裁剪
        if self._tool_result_tokens > self.config.max_tool_result_tokens:
            self._trim_tool_results()

        return item

    def get_tool_results(self) -> List[ContextItem]:
        """获取工具执行结果"""
        return self._tool_results.copy()

    def _trim_tool_results(self):
        """裁剪工具结果"""
        # 保留最近的一半
        keep_count = len(self._tool_results) // 2
        to_remove = self._tool_results[:-keep_count]
        self._tool_results = self._tool_results[-keep_count:]

        removed_tokens = sum(item.token_count for item in to_remove)
        self._tool_result_tokens -= removed_tokens
        self._total_tokens -= removed_tokens

        logger.debug(f"[ContextManager] 工具结果裁剪，移除 {len(to_remove)} 个")

    # ============ 发现管理 ============

    def add_finding(
        self,
        finding_id: str,
        title: str,
        summary: str,
        severity: str,
        file_path: str,
        priority: int = 5,
    ) -> ContextItem:
        """添加安全发现

        Args:
            finding_id: 发现 ID
            title: 标题
            summary: 摘要
            severity: 严重性
            file_path: 文件路径
            priority: 优先级

        Returns:
            ContextItem
        """
        content = f"[{severity}] {title}\n位置: {file_path}\n{summary}"
        token_count = self._count_tokens(content)

        item = ContextItem(
            id=finding_id,
            type=ContextType.FINDING,
            content=content,
            metadata={
                "title": title,
                "severity": severity,
                "file_path": file_path,
            },
            token_count=token_count,
            priority=priority,
        )

        self._findings[finding_id] = item
        self._total_tokens += token_count

        return item

    def get_findings(self) -> List[ContextItem]:
        """获取所有发现"""
        return list(self._findings.values())

    def remove_finding(self, finding_id: str) -> bool:
        """移除发现"""
        if finding_id in self._findings:
            item = self._findings.pop(finding_id)
            self._total_tokens -= item.token_count
            return True
        return False

    # ============ 摘要管理 ============

    def add_summary(self, summary: str, priority: int = 10) -> ContextItem:
        """添加摘要

        Args:
            summary: 摘要内容
            priority: 优先级（摘要通常高优先级）

        Returns:
            ContextItem
        """
        token_count = self._count_tokens(summary)

        item = ContextItem(
            id=self._generate_id("sum"),
            type=ContextType.SUMMARY,
            content=summary,
            token_count=token_count,
            priority=priority,
        )

        self._summaries.append(item)
        self._total_tokens += token_count

        return item

    def get_summaries(self) -> List[ContextItem]:
        """获取摘要"""
        return self._summaries.copy()

    # ============ 综合接口 ============

    def get_llm_messages(
        self,
        system_prompt: str,
        include_code: bool = True,
        include_findings: bool = True,
        include_summaries: bool = True,
    ) -> List[ChatMessage]:
        """获取用于 LLM 的完整消息列表

        Args:
            system_prompt: 系统提示词
            include_code: 是否包含代码上下文
            include_findings: 是否包含发现
            include_summaries: 是否包含摘要

        Returns:
            ChatMessage 列表
        """
        messages = []

        # 构建增强的系统提示词
        enhanced_system = system_prompt

        # 添加摘要
        if include_summaries and self._summaries:
            summaries_text = "\n\n".join(s.content for s in self._summaries)
            enhanced_system += f"\n\n## 分析摘要\n{summaries_text}"

        # 添加发现
        if include_findings and self._findings:
            findings_text = "\n".join(f.content for f in self._findings.values())
            enhanced_system += f"\n\n## 已发现的问题\n{findings_text}"

        # 添加代码上下文
        if include_code and self._code_contexts:
            code_parts = []
            for item in self._code_contexts.values():
                meta = item.metadata
                code_parts.append(
                    f"### {meta.get('file_path', '')}:{meta.get('line_start', 0)}\n"
                    f"```\n{item.content}\n```"
                )
            enhanced_system += f"\n\n## 相关代码\n" + "\n".join(code_parts)

        messages.append(ChatMessage(role="system", content=enhanced_system))

        # 添加对话历史
        messages.extend(self.get_conversation_messages())

        return messages

    def get_total_tokens(self) -> int:
        """获取总 token 数"""
        return self._total_tokens

    def get_token_breakdown(self) -> Dict[str, int]:
        """获取 token 分布"""
        findings_tokens = sum(f.token_count for f in self._findings.values())
        summaries_tokens = sum(s.token_count for s in self._summaries)

        return {
            "total": self._total_tokens,
            "conversation": self._conversation_tokens,
            "code": self._code_tokens,
            "tool_results": self._tool_result_tokens,
            "findings": findings_tokens,
            "summaries": summaries_tokens,
        }

    def needs_trim(self) -> bool:
        """检查是否需要裁剪"""
        return self._total_tokens > self.config.max_total_tokens

    def trim(self):
        """执行全局裁剪"""
        logger.info(f"[ContextManager] 执行全局裁剪，当前 {self._total_tokens} tokens")

        # 按类型裁剪
        if self._conversation_tokens > self.config.max_conversation_tokens:
            self._trim_conversation()

        if self._code_tokens > self.config.max_code_tokens:
            self._trim_code_contexts()

        if self._tool_result_tokens > self.config.max_tool_result_tokens:
            self._trim_tool_results()

        # 重新计算总 token
        self._recalculate_total_tokens()

        logger.info(f"[ContextManager] 裁剪完成，当前 {self._total_tokens} tokens")

    def _recalculate_total_tokens(self):
        """重新计算总 token 数"""
        self._total_tokens = (
            self._conversation_tokens +
            self._code_tokens +
            self._tool_result_tokens +
            sum(f.token_count for f in self._findings.values()) +
            sum(s.token_count for s in self._summaries)
        )

    def clear(self):
        """清空所有上下文"""
        self._conversation.clear()
        self._code_contexts.clear()
        self._tool_results.clear()
        self._findings.clear()
        self._summaries.clear()

        self._total_tokens = 0
        self._conversation_tokens = 0
        self._code_tokens = 0
        self._tool_result_tokens = 0

        logger.info("[ContextManager] 已清空所有上下文")

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "conversation_count": len(self._conversation),
            "code_contexts_count": len(self._code_contexts),
            "tool_results_count": len(self._tool_results),
            "findings_count": len(self._findings),
            "summaries_count": len(self._summaries),
            "tokens": self.get_token_breakdown(),
        }


def create_context_manager(
    max_tokens: int = 100000,
    token_counter: Optional[Callable[[str], int]] = None,
) -> ContextManager:
    """创建上下文管理器（工厂函数）

    Args:
        max_tokens: 最大 token 数
        token_counter: 自定义 token 计数函数

    Returns:
        ContextManager 实例
    """
    config = ContextManagerConfig(
        max_total_tokens=max_tokens,
        token_counter=token_counter,
    )
    return ContextManager(config)
