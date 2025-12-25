"""LLM 分析提示词模块 - 迁移到 prompts 模块

此模块保留向后兼容性，但内部已重构为使用 prompts.manager。
新代码应直接使用 prompts.get_prompt_manager()。

根据目标文档 P0-5 的要求：
- LLM 分析必须以"链"为单位输出结构化结果
- 输出包含 chain_id, sink_category, has_issue, issue_type, confidence 等字段
- 为高危类别（command/file/deserialize）提供专用提示词
"""

from typing import Tuple, Optional, Dict, Any

from prompts import get_prompt_manager

# 获取全局 Prompt 管理器
_manager = get_prompt_manager()


def build_analysis_prompt(context_text: str, focus_category: Optional[str] = None) -> Tuple[str, str]:
    """构建单点分析提示词（保留兼容）

    Args:
        context_text: 上下文文本
        focus_category: 重点关注的类别

    Returns:
        (system_prompt, user_prompt)
    """
    system, user, _ = _manager.build_point_analysis_prompt(
        code_context=context_text,
        focus_category=focus_category,
    )
    return system, user


def build_chain_analysis_prompt(
    chain_context_text: str,
    chain_id: str,
    sink_category: str,
) -> Tuple[str, str]:
    """构建链级分析提示词

    根据目标文档 P0-5 的要求，LLM 分析必须以"链"为单位。

    Args:
        chain_context_text: 调用链上下文文本（由 ChainContext.to_prompt_text() 生成）
        chain_id: 调用链标识
        sink_category: sink 类别

    Returns:
        (system_prompt, user_prompt)
    """
    system, user, _ = _manager.build_chain_analysis_prompt(
        chain_id=chain_id,
        sink_category=sink_category,
        chain_context=chain_context_text,
    )
    return system, user


def get_chain_output_schema() -> Dict[str, Any]:
    """获取链级分析的输出 Schema

    用于验证 LLM 输出的格式正确性。
    """
    return _manager.get_output_schema("chain_analysis")


# 向后兼容：导出旧的常量（废弃警告）
import warnings


def __getattr__(name):
    """动态属性访问 - 用于废弃警告"""
    if name in ('SYSTEM_PROMPT', 'USER_PROMPT_TEMPLATE', 'CHAIN_SYSTEM_PROMPT',
                'CHAIN_USER_PROMPT_TEMPLATE', 'FOCUS_PROMPTS', 'SINK_CATEGORY_PROMPTS'):
        warnings.warn(
            f"直接访问 {name} 已废弃，请使用 prompts.get_prompt_manager() 或封装函数",
            DeprecationWarning,
            stacklevel=2
        )
        # 返回空字符串避免代码崩溃
        return ""

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
