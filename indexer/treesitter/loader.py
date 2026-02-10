"""
Tree-sitter 语言加载器

负责动态加载各语言的 Tree-sitter 语法包。
"""

import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# 尝试导入 tree-sitter
try:
    from tree_sitter import Language
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Language = None


# 语言包映射表：语言名称 -> 包名
LANGUAGE_PACKAGES = {
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_typescript",
    "python": "tree_sitter_python",
    "php": "tree_sitter_php",
    "java": "tree_sitter_java",
    "go": "tree_sitter_go",
    "rust": "tree_sitter_rust",
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
    "c_sharp": "tree_sitter_c_sharp",
    "csharp": "tree_sitter_c_sharp",  # 别名
    "ruby": "tree_sitter_ruby",
    "kotlin": "tree_sitter_kotlin",
}

# TypeScript 子语言
TYPESCRIPT_SUBLANGUAGES = {
    "typescript": "typescript",
    "tsx": "tsx",
}


class LanguageLoader:
    """语言加载器

    负责加载和缓存各语言的 Tree-sitter Language 对象。
    支持动态检测已安装的语言包。
    """

    _cache: Dict[str, Any] = {}
    _availability: Dict[str, bool] = {}

    @classmethod
    def load(cls, language_name: str) -> Optional['Language']:
        """加载指定语言的 Language 对象

        Args:
            language_name: 语言名称（如 "javascript", "python"）

        Returns:
            Language 对象，如果加载失败返回 None
        """
        if not TREE_SITTER_AVAILABLE:
            logger.error("tree-sitter 未安装")
            return None

        # 检查缓存
        if language_name in cls._cache:
            return cls._cache[language_name]

        # 尝试加载
        language = cls._load_language(language_name)
        if language:
            cls._cache[language_name] = language
            cls._availability[language_name] = True
        else:
            cls._availability[language_name] = False

        return language

    @classmethod
    def _load_language(cls, language_name: str) -> Optional['Language']:
        """实际加载语言的内部方法"""
        package_name = LANGUAGE_PACKAGES.get(language_name)
        if not package_name:
            logger.warning(f"未知语言: {language_name}")
            return None

        try:
            # 动态导入语言包
            module = __import__(package_name)

            # 获取语言 capsule
            capsule = None

            # 处理 TypeScript 的特殊情况（有 typescript 和 tsx 两个子语言）
            if language_name == "typescript":
                if hasattr(module, 'language_typescript'):
                    capsule = module.language_typescript()
                elif hasattr(module, 'language'):
                    capsule = module.language()
            elif language_name == "tsx":
                if hasattr(module, 'language_tsx'):
                    capsule = module.language_tsx()
            elif hasattr(module, 'language'):
                capsule = module.language()

            if capsule is None:
                logger.error(f"语言包 {package_name} 没有 language() 函数")
                return None

            # tree-sitter 0.25.x 返回 PyCapsule，需要用 Language() 包装
            # 检查是否已经是 Language 对象
            if isinstance(capsule, Language):
                return capsule
            else:
                # 新版本 API：capsule 需要包装成 Language 对象
                return Language(capsule)

        except ImportError as e:
            logger.warning(f"语言包 {package_name} 未安装: {e}")
            return None
        except Exception as e:
            logger.error(f"加载语言 {language_name} 失败: {e}")
            return None

    @classmethod
    def is_available(cls, language_name: str) -> bool:
        """检查语言是否可用

        Args:
            language_name: 语言名称

        Returns:
            是否可用
        """
        if language_name in cls._availability:
            return cls._availability[language_name]

        # 尝试加载以确定可用性
        cls.load(language_name)
        return cls._availability.get(language_name, False)

    @classmethod
    def list_available(cls) -> list:
        """列出所有可用的语言

        Returns:
            可用语言名称列表
        """
        available = []
        for lang in LANGUAGE_PACKAGES.keys():
            if cls.is_available(lang):
                available.append(lang)
        return available

    @classmethod
    def clear_cache(cls) -> None:
        """清空缓存（主要用于测试）"""
        cls._cache.clear()
        cls._availability.clear()


def get_language(language_name: str) -> Optional['Language']:
    """便捷函数：获取指定语言的 Language 对象

    Args:
        language_name: 语言名称

    Returns:
        Language 对象
    """
    return LanguageLoader.load(language_name)


def check_language_support() -> Dict[str, bool]:
    """检查所有语言的支持情况

    Returns:
        语言名称 -> 是否支持 的字典
    """
    result = {}
    for lang in LANGUAGE_PACKAGES.keys():
        result[lang] = LanguageLoader.is_available(lang)
    return result
