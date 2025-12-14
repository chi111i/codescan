"""
代码读取工具定义 - OpenAI Function Calling 格式

定义供 LLM 调用的工具，用于读取和搜索代码。
"""

from typing import Dict, Any, Optional, List


# 代码读取工具定义
CODE_READER_TOOLS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "通过语义搜索查找相关代码。用于查找与某个概念、功能或漏洞模式相关的代码片段。返回匹配的函数、类或方法定义。",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "搜索查询，描述要查找的代码功能或模式。例如：'用户认证逻辑'、'SQL 查询执行'、'文件上传处理'"
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "返回结果数量，默认 5，最大 20",
                        "default": 5
                    },
                    "language": {
                        "type": "string",
                        "description": "限定编程语言，如 python、javascript、php、java 等",
                        "enum": ["python", "javascript", "typescript", "php", "java", "go", "rust", "ruby", "c", "cpp"]
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "文件路径模式过滤，如 '**/auth/*.py'、'src/**/*.js'"
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
            "description": "读取指定文件的内容。可以读取整个文件或指定行范围。用于查看完整的代码上下文。",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "文件路径（相对于项目根目录），如 'src/auth/login.py'"
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "起始行号（从 1 开始），不指定则从文件开头读取"
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "结束行号，不指定则根据 start_line 读取一定行数"
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "在指定行范围前后额外读取的上下文行数，默认 0",
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
            "description": "读取指定符号（函数、类、方法）的完整定义代码。可以同时获取调用关系。",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "符号名称，如函数名 'authenticate'、类名 'UserController'、方法名 'validate_token'"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定在特定文件中查找，用于同名符号区分"
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
            "description": "列出项目中的文件，支持按模式过滤。用于了解项目结构。",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "文件匹配模式，如 '**/*.py'（所有 Python 文件）、'src/auth/*'（auth 目录下的文件）",
                        "default": "**/*"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "最大返回数量，默认 50",
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
            "description": "获取文件的结构大纲，包含所有类、函数、方法的列表及其位置。用于快速了解文件结构。",
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
    }
]


# 安全分析专用工具（扩展）
SECURITY_ANALYSIS_TOOLS: List[Dict[str, Any]] = CODE_READER_TOOLS + [
    {
        "type": "function",
        "function": {
            "name": "check_vulnerability_pattern",
            "description": "检查代码中是否存在特定的漏洞模式。",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern_type": {
                        "type": "string",
                        "description": "漏洞模式类型",
                        "enum": [
                            "sql_injection",
                            "command_injection",
                            "xss",
                            "path_traversal",
                            "insecure_deserialization",
                            "authentication_bypass",
                            "authorization_bypass",
                            "idor",
                            "ssrf",
                            "open_redirect"
                        ]
                    },
                    "file_path": {
                        "type": "string",
                        "description": "限定检查的文件"
                    },
                    "symbol_name": {
                        "type": "string",
                        "description": "限定检查的符号"
                    }
                },
                "required": ["pattern_type"]
            }
        }
    }
]


def get_tool_by_name(name: str, tools: List[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """根据名称获取工具定义

    Args:
        name: 工具名称
        tools: 工具列表，默认使用 CODE_READER_TOOLS

    Returns:
        工具定义字典，如果未找到则返回 None
    """
    tools = tools or CODE_READER_TOOLS
    for tool in tools:
        if tool.get("function", {}).get("name") == name:
            return tool
    return None


def get_tool_names(tools: List[Dict[str, Any]] = None) -> List[str]:
    """获取所有工具名称

    Args:
        tools: 工具列表，默认使用 CODE_READER_TOOLS

    Returns:
        工具名称列表
    """
    tools = tools or CODE_READER_TOOLS
    return [tool.get("function", {}).get("name") for tool in tools]
