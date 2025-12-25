"""Prompt 模板管理器

工程化的 Prompt 管理系统，支持：
- Jinja2 模板渲染
- Token 预算管理
- 自动截断
- 版本控制
"""

import os
import logging
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List
from dataclasses import dataclass
from enum import Enum

import yaml
from jinja2 import Environment, FileSystemLoader, Template

logger = logging.getLogger(__name__)


class TokenPriority(Enum):
    """内容优先级"""
    CRITICAL = 1  # 绝不截断
    HIGH = 2      # 优先保留
    MEDIUM = 3    # 可部分截断
    LOW = 4       # 可大量截断


@dataclass
class ContentBlock:
    """内容块"""
    text: str
    priority: TokenPriority
    name: str
    actual_tokens: int = 0


class PromptManager:
    """Prompt 模板管理器

    提供统一的 Prompt 加载、渲染和 Token 管理。
    """

    def __init__(self, config_path: Optional[str] = None):
        """初始化 Prompt 管理器

        Args:
            config_path: 配置文件路径，默认为 prompts/configs/prompt_config.yaml
        """
        # 确定配置文件路径
        if config_path is None:
            # 假设此文件在 prompts/ 目录下
            base_dir = Path(__file__).parent
            config_path = base_dir / "configs" / "prompt_config.yaml"

        self.config_path = Path(config_path)
        self.base_dir = self.config_path.parent.parent

        # 加载配置
        with open(self.config_path, 'r', encoding='utf-8') as f:
            self.config = yaml.safe_load(f)

        # 初始化 Jinja2 环境
        template_base = self.base_dir / "templates"
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_base)),
            trim_blocks=True,
            lstrip_blocks=True,
        )

        logger.info(f"[PromptManager] 已加载配置: {config_path}")

    def _load_template(self, template_path: str) -> Template:
        """加载 Jinja2 模板

        Args:
            template_path: 相对于 templates/ 的路径

        Returns:
            Jinja2 Template 对象
        """
        return self.jinja_env.get_template(template_path)

    def _count_tokens(self, text: str) -> int:
        """估算文本的 Token 数量

        使用简单的启发式规则：中文按字符数，英文按单词数 * 1.3。
        后续可集成 tiktoken 库做精确计算。

        Args:
            text: 文本内容

        Returns:
            Token 数量估算值
        """
        # 简单估算：中文字符 + 英文单词
        chinese_chars = len([c for c in text if '\u4e00' <= c <= '\u9fff'])
        english_chars = len([c for c in text if c.isalpha() and ord(c) < 128])

        # 粗略估算
        tokens = chinese_chars + int(english_chars / 4 * 1.3)
        return max(tokens, len(text.split()) // 2)

    def build_chain_analysis_prompt(
        self,
        chain_id: str,
        sink_category: str,
        chain_context: str,
        max_tokens: Optional[int] = None,
        style: str = "professional",
    ) -> Tuple[str, str, Dict[str, Any]]:
        """构建链级分析提示词

        Args:
            chain_id: 调用链 ID
            sink_category: Sink 类别
            chain_context: 调用链上下文文本
            max_tokens: 最大 Token 数，默认从配置读取
            style: 审查风格

        Returns:
            (system_prompt, user_prompt, metadata)
        """
        config = self.config['chain_analysis']

        # 获取 Token 预算
        if max_tokens is None:
            max_tokens = config['token_budget']['max_total_tokens']

        # 加载模板
        system_template_path = f"chain_analysis/{config['system_template']}"
        user_template_path = f"chain_analysis/{config['user_template']}"

        system_tpl = self._load_template(system_template_path)
        user_tpl = self._load_template(user_template_path)

        # 渲染基础 System Prompt
        system_prompt = system_tpl.render(style=style)

        # 添加类别专项提示词（如果存在）
        category_prompt = ""
        if sink_category in config['category_templates']:
            category_template_path = f"chain_analysis/{config['category_templates'][sink_category]}"
            category_tpl = self._load_template(category_template_path)
            category_prompt = category_tpl.render()
            system_prompt += "\n" + category_prompt

        # 渲染 User Prompt
        user_prompt = user_tpl.render(
            chain_id=chain_id,
            sink_category=sink_category,
            chain_context=chain_context,
        )

        # 统计 Token
        system_tokens = self._count_tokens(system_prompt)
        user_tokens = self._count_tokens(user_prompt)
        total_tokens = system_tokens + user_tokens

        # 元数据
        metadata = {
            "template_version": self.config.get('version', '1.0'),
            "style": style,
            "sink_category": sink_category,
            "token_usage": {
                "system_tokens": system_tokens,
                "user_tokens": user_tokens,
                "total_tokens": total_tokens,
                "max_tokens": max_tokens,
                "utilization": total_tokens / max_tokens if max_tokens > 0 else 0,
            },
            "truncated": False,
        }

        # 检查是否超限
        if total_tokens > max_tokens:
            logger.warning(
                f"[PromptManager] Token 超限: {total_tokens} > {max_tokens}, "
                f"chain_id={chain_id}"
            )
            metadata["truncated"] = True
            metadata["token_usage"]["overflow"] = total_tokens - max_tokens

        return system_prompt, user_prompt, metadata

    def build_point_analysis_prompt(
        self,
        code_context: str,
        focus_category: Optional[str] = None,
        max_tokens: Optional[int] = None,
    ) -> Tuple[str, str, Dict[str, Any]]:
        """构建单点分析提示词（保留兼容）

        Args:
            code_context: 代码上下文
            focus_category: 关注类别
            max_tokens: 最大 Token 数

        Returns:
            (system_prompt, user_prompt, metadata)
        """
        config = self.config['point_analysis']

        if max_tokens is None:
            max_tokens = config['token_budget']['max_total_tokens']

        system_template_path = f"point_analysis/{config['system_template']}"
        user_template_path = f"point_analysis/{config['user_template']}"

        system_tpl = self._load_template(system_template_path)
        user_tpl = self._load_template(user_template_path)

        system_prompt = system_tpl.render()
        user_prompt = user_tpl.render(
            code_context=code_context,
            focus_category=focus_category,
        )

        system_tokens = self._count_tokens(system_prompt)
        user_tokens = self._count_tokens(user_prompt)
        total_tokens = system_tokens + user_tokens

        metadata = {
            "template_version": self.config.get('version', '1.0'),
            "focus_category": focus_category,
            "token_usage": {
                "system_tokens": system_tokens,
                "user_tokens": user_tokens,
                "total_tokens": total_tokens,
                "max_tokens": max_tokens,
                "utilization": total_tokens / max_tokens if max_tokens > 0 else 0,
            },
            "truncated": False,
        }

        if total_tokens > max_tokens:
            metadata["truncated"] = True
            metadata["token_usage"]["overflow"] = total_tokens - max_tokens

        return system_prompt, user_prompt, metadata

    def get_output_schema(self, analysis_type: str = "chain_analysis") -> Dict[str, Any]:
        """获取输出 Schema

        Args:
            analysis_type: 分析类型

        Returns:
            Schema 字典
        """
        return self.config.get('output_schemas', {}).get(analysis_type, {})

    def get_available_styles(self) -> List[str]:
        """获取可用的审查风格列表

        Returns:
            风格名称列表
        """
        return list(self.config.get('review_styles', {}).keys())

    def get_available_categories(self) -> List[str]:
        """获取支持的高危类别列表

        Returns:
            类别名称列表
        """
        return list(self.config['chain_analysis']['category_templates'].keys())


# 全局单例
_prompt_manager: Optional[PromptManager] = None


def get_prompt_manager(config_path: Optional[str] = None) -> PromptManager:
    """获取全局 Prompt 管理器单例

    Args:
        config_path: 配置文件路径（仅首次调用时生效）

    Returns:
        PromptManager 实例
    """
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager(config_path)
    return _prompt_manager
