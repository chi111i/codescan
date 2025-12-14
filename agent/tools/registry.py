"""
工具注册表 - 管理 OpenAI Function Calling 格式的工具定义

提供工具定义的注册、查询和管理功能。
"""

import logging
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)


class ToolRegistry:
    """工具注册表

    管理 OpenAI Function Calling 格式的工具定义。

    Usage:
        registry = ToolRegistry()
        registry.register("read_file", {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "读取文件内容",
                "parameters": {...}
            }
        })
    """

    def __init__(self):
        """初始化注册表"""
        self._tools: Dict[str, Dict[str, Any]] = {}

    def register(self, name: str, schema: Dict[str, Any]):
        """注册工具定义

        Args:
            name: 工具名称
            schema: OpenAI 格式的工具定义
        """
        self._tools[name] = schema
        logger.debug(f"注册工具定义: {name}")

    def register_many(self, tools: List[Dict[str, Any]]):
        """批量注册工具定义

        Args:
            tools: 工具定义列表
        """
        for tool in tools:
            func = tool.get("function", {})
            name = func.get("name")
            if name:
                self._tools[name] = tool

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        """获取工具定义

        Args:
            name: 工具名称

        Returns:
            工具定义或 None
        """
        return self._tools.get(name)

    def get_all(self) -> List[Dict[str, Any]]:
        """获取所有工具定义

        Returns:
            工具定义列表
        """
        return list(self._tools.values())

    def get_names(self) -> List[str]:
        """获取所有工具名称

        Returns:
            工具名称列表
        """
        return list(self._tools.keys())

    def has(self, name: str) -> bool:
        """检查工具是否存在

        Args:
            name: 工具名称

        Returns:
            是否存在
        """
        return name in self._tools

    def remove(self, name: str) -> bool:
        """移除工具

        Args:
            name: 工具名称

        Returns:
            是否成功移除
        """
        if name in self._tools:
            del self._tools[name]
            return True
        return False

    def clear(self):
        """清空所有工具"""
        self._tools.clear()

    def count(self) -> int:
        """获取工具数量"""
        return len(self._tools)

    def get_by_category(self, category: str) -> List[Dict[str, Any]]:
        """按类别获取工具

        Args:
            category: 类别名称（从工具 description 中推断）

        Returns:
            匹配的工具列表
        """
        result = []
        for tool in self._tools.values():
            desc = tool.get("function", {}).get("description", "").lower()
            if category.lower() in desc:
                result.append(tool)
        return result


# 预定义的代码导航工具（与 CodeReader 和 CodeAnalysisAgent 对应）
CODE_NAVIGATION_TOOLS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "通过语义搜索查找相关代码。适用于：查找与某个概念、功能或漏洞模式相关的代码片段；不确定代码位置时的模糊搜索；查找类似功能的实现。",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "搜索查询，描述要查找的代码功能或模式。例如：'用户登录验证'、'文件上传处理'、'SQL查询执行'"
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "返回结果数量，默认 5，最大 20",
                        "default": 5
                    },
                    "language": {
                        "type": "string",
                        "description": "限定编程语言（python/javascript/php/java等）"
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "文件路径模式，如 '**/auth/*.py' 或 'controllers/*'"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "读取指定文件的内容。可以读取整个文件或指定行范围。适用于：查看完整文件内容；查看特定行号范围的代码；获取文件上下文。",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "文件路径（相对于项目根目录）"
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "起始行号（从 1 开始）。不指定则从头开始读取"
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "结束行号。不指定则读取到文件末尾或最大行数限制"
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "额外读取的上下文行数（在指定范围前后各扩展）",
                        "default": 0
                    }
                },
                "required": ["file_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_symbol",
            "description": "读取指定函数、类或方法的完整定义。适用于：获取函数/类的完整代码；查看函数签名和文档；追踪调用关系。",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "符号名称（函数名、类名、方法名）。支持类方法格式如 'ClassName.method_name'"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定在特定文件中查找（可选）"
                    },
                    "include_callers": {
                        "type": "boolean",
                        "description": "是否包含调用此符号的代码位置",
                        "default": False
                    },
                    "include_callees": {
                        "type": "boolean",
                        "description": "是否包含此符号调用的其他函数列表",
                        "default": False
                    }
                },
                "required": ["symbol_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "列出项目中的文件和目录结构。适用于：了解项目布局；查找特定类型的文件；发现配置文件和入口点。",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "文件匹配模式，如 '**/*.py'（所有Python文件）、'src/auth/*'（auth目录）、'**/test_*.py'（测试文件）",
                        "default": "**/*"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "最大返回数量",
                        "default": 50
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_file_outline",
            "description": "获取文件的结构大纲，列出所有类、函数、方法的定义。适用于：快速了解文件结构；定位要深入查看的符号；获取代码组织概览。",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "文件路径（相对于项目根目录）"
                    }
                },
                "required": ["file_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_callers",
            "description": "查找谁调用了指定函数（向上追溯调用链）。适用于：找到函数的所有使用位置；追踪数据流入口；分析函数的影响范围。",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "要查找调用者的函数名"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定在特定文件中查找（可选）"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "最大返回数量",
                        "default": 10
                    }
                },
                "required": ["symbol_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_callees",
            "description": "查找指定函数调用了哪些其他函数（向下追溯调用链）。适用于：分析函数依赖；追踪数据流向危险函数；理解函数行为。",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "要分析的函数名"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定在特定文件中查找（可选）"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "调用链追溯深度（1=直接调用，2=间接调用）",
                        "default": 1
                    }
                },
                "required": ["symbol_name"]
            }
        }
    },
]


# 安全分析专用工具
SECURITY_ANALYSIS_TOOLS: List[Dict[str, Any]] = CODE_NAVIGATION_TOOLS + [
    {
        "type": "function",
        "function": {
            "name": "analyze_taint_path",
            "description": "分析从输入源（Source）到危险函数（Sink）的污点传播路径。",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_symbol": {
                        "type": "string",
                        "description": "污点源函数名"
                    },
                    "sink_symbol": {
                        "type": "string",
                        "description": "危险函数名"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "最大路径深度",
                        "default": 10
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_auth",
            "description": "检查指定函数是否有认证和授权检查。",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "要检查的函数名"
                    },
                    "check_type": {
                        "type": "string",
                        "description": "检查类型",
                        "enum": ["authentication", "authorization", "both"],
                        "default": "both"
                    }
                },
                "required": ["symbol_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "find_entry_points",
            "description": "查找项目的入口点（HTTP 路由、API 端点等）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "description": "框架类型",
                        "enum": ["flask", "django", "fastapi", "express", "spring", "auto"]
                    },
                    "include_internal": {
                        "type": "boolean",
                        "description": "是否包含内部 API",
                        "default": False
                    }
                }
            }
        }
    },
]


def create_default_registry() -> ToolRegistry:
    """创建默认工具注册表

    Returns:
        包含预定义工具的注册表
    """
    registry = ToolRegistry()
    registry.register_many(CODE_NAVIGATION_TOOLS)
    return registry


def create_security_registry() -> ToolRegistry:
    """创建安全分析工具注册表

    Returns:
        包含安全分析工具的注册表
    """
    registry = ToolRegistry()
    registry.register_many(SECURITY_ANALYSIS_TOOLS)
    return registry
