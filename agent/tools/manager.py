"""
统一工具管理器 - 整合所有代码分析工具

提供：
1. 工具定义注册（OpenAI Function Calling 格式）
2. 工具执行器注册
3. 工具调用执行
4. 工具分类管理
"""

import asyncio
import functools
import logging
import sys
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable, Awaitable, Union
from concurrent.futures import ThreadPoolExecutor

from .registry import ToolRegistry
from .executor import ToolExecutor, ToolResult


# Python 3.8 compatibility: provide asyncio.to_thread if not available
if sys.version_info < (3, 9):
    _executor = ThreadPoolExecutor(max_workers=4)

    async def _to_thread(func, *args, **kwargs):
        """Python 3.8 compatible version of asyncio.to_thread"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            _executor,
            functools.partial(func, *args, **kwargs)
        )
    asyncio_to_thread = _to_thread
else:
    asyncio_to_thread = asyncio.to_thread

logger = logging.getLogger(__name__)


@dataclass
class ToolDefinition:
    """工具定义"""
    name: str
    description: str
    parameters: Dict[str, Any]
    category: str = "general"
    is_async: bool = False
    requires_context: bool = False  # 是否需要会话上下文

    def to_openai_schema(self) -> Dict[str, Any]:
        """转换为 OpenAI Function Calling 格式"""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            }
        }


@dataclass
class ToolCategory:
    """工具分类"""
    name: str
    description: str
    tools: List[str] = field(default_factory=list)


class AgentToolManager:
    """统一工具管理器

    整合所有代码分析工具的注册、发现和执行逻辑。
    支持同步和异步工具执行。

    Usage:
        manager = AgentToolManager()

        # 注册工具定义
        manager.register_tool(
            name="search_code",
            description="语义搜索代码",
            parameters={...},
            executor=search_code_func,
        )

        # 获取所有工具（供 LLM 使用）
        tools = manager.get_tools_for_llm()

        # 执行工具调用
        result = await manager.execute("search_code", {"query": "用户认证"})
    """

    def __init__(self):
        """初始化工具管理器"""
        self._definitions: Dict[str, ToolDefinition] = {}
        self._executors: Dict[str, Union[Callable, Awaitable]] = {}
        self._categories: Dict[str, ToolCategory] = {}
        self._context_provider: Optional[Callable[[], Dict[str, Any]]] = None

        # 预定义分类
        self._init_categories()

        logger.info("[ToolManager] 工具管理器已初始化")

    def _init_categories(self):
        """初始化预定义分类"""
        categories = [
            ToolCategory(
                name="code_navigation",
                description="代码导航工具：搜索、读取、浏览代码"
            ),
            ToolCategory(
                name="call_chain",
                description="调用链分析工具：分析函数调用关系"
            ),
            ToolCategory(
                name="code_graph",
                description="代码图分析工具：数据流、控制流分析"
            ),
            ToolCategory(
                name="variant_analysis",
                description="变体分析工具：相似代码检测、模式匹配"
            ),
            ToolCategory(
                name="security",
                description="安全分析工具：漏洞检测、规则匹配"
            ),
            ToolCategory(
                name="finding_management",
                description="发现管理工具：确认、拒绝、备注"
            ),
            ToolCategory(
                name="project",
                description="项目管理工具：索引、配置"
            ),
        ]
        for cat in categories:
            self._categories[cat.name] = cat

    def set_context_provider(self, provider: Callable[[], Dict[str, Any]]):
        """设置上下文提供器

        某些工具需要访问会话上下文（如当前会话 ID、已分析的代码等），
        通过上下文提供器获取这些信息。

        Args:
            provider: 返回上下文字典的可调用对象
        """
        self._context_provider = provider

    def register_tool(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        executor: Union[Callable, Awaitable],
        category: str = "general",
        is_async: bool = False,
        requires_context: bool = False,
    ):
        """注册工具

        Args:
            name: 工具名称
            description: 工具描述（会显示给 LLM）
            parameters: 参数 JSON Schema
            executor: 执行函数
            category: 工具分类
            is_async: 是否为异步函数
            requires_context: 是否需要会话上下文
        """
        definition = ToolDefinition(
            name=name,
            description=description,
            parameters=parameters,
            category=category,
            is_async=is_async,
            requires_context=requires_context,
        )

        self._definitions[name] = definition
        self._executors[name] = executor

        # 添加到分类
        if category in self._categories:
            if name not in self._categories[category].tools:
                self._categories[category].tools.append(name)

        logger.debug(f"[ToolManager] 注册工具: {name} (category={category})")

    def register_from_schema(
        self,
        schema: Dict[str, Any],
        executor: Union[Callable, Awaitable],
        category: str = "general",
        is_async: bool = False,
        requires_context: bool = False,
    ):
        """从 OpenAI Schema 注册工具

        Args:
            schema: OpenAI Function Calling 格式的工具定义
            executor: 执行函数
            category: 工具分类
            is_async: 是否为异步函数
            requires_context: 是否需要会话上下文
        """
        func = schema.get("function", {})
        name = func.get("name")
        if not name:
            raise ValueError("Schema 必须包含 function.name")

        self.register_tool(
            name=name,
            description=func.get("description", ""),
            parameters=func.get("parameters", {}),
            executor=executor,
            category=category,
            is_async=is_async,
            requires_context=requires_context,
        )

    def register_many(
        self,
        tools: List[Dict[str, Any]],
        executors: Dict[str, Union[Callable, Awaitable]],
        category: str = "general",
        is_async: bool = False,
    ):
        """批量注册工具

        Args:
            tools: OpenAI Schema 列表
            executors: 工具名称 -> 执行函数的映射
            category: 工具分类
            is_async: 是否为异步函数
        """
        for schema in tools:
            func = schema.get("function", {})
            name = func.get("name")
            if name and name in executors:
                self.register_from_schema(
                    schema=schema,
                    executor=executors[name],
                    category=category,
                    is_async=is_async,
                )

    def _filter_arguments(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        definition: Optional[ToolDefinition],
    ) -> Dict[str, Any]:
        """过滤工具参数，移除未定义的参数

        Args:
            tool_name: 工具名称
            arguments: 原始参数
            definition: 工具定义

        Returns:
            过滤后的参数字典
        """
        if not definition or not arguments:
            return arguments or {}

        # 获取定义的参数列表
        properties = definition.parameters.get("properties", {})
        defined_params = set(properties.keys())

        # 如果没有定义任何参数，返回空字典（忽略所有传入参数）
        if not defined_params:
            if arguments:
                undefined_keys = list(arguments.keys())
                logger.debug(
                    f"[ToolManager] 工具 {tool_name} 未定义任何参数，"
                    f"忽略传入的参数: {undefined_keys}"
                )
            return {}

        # 过滤参数
        filtered = {}
        undefined_keys = []

        for key, value in arguments.items():
            if key in defined_params:
                filtered[key] = value
            else:
                undefined_keys.append(key)

        # 记录未定义参数的警告
        if undefined_keys:
            logger.warning(
                f"[ToolManager] 工具 {tool_name} 收到未定义的参数: {undefined_keys}，已忽略"
            )

        return filtered

    def _validate_arguments(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        definition: Optional[ToolDefinition],
    ) -> Optional[str]:
        """校验工具参数的 required 和基本类型约束

        Args:
            tool_name: 工具名称
            arguments: 已过滤的参数
            definition: 工具定义

        Returns:
            校验失败时返回错误描述，通过时返回 None
        """
        if not definition:
            return None

        schema = definition.parameters
        if not schema:
            return None

        # 校验 required 字段
        required = schema.get("required", [])
        missing = [r for r in required if r not in arguments]
        if missing:
            return f"缺少必需参数: {missing}"

        # 基本类型校验
        properties = schema.get("properties", {})
        type_map = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "array": list,
            "object": dict,
        }

        type_errors = []
        for key, value in arguments.items():
            if key not in properties:
                continue
            expected_type_str = properties[key].get("type")
            if not expected_type_str:
                continue
            expected_type = type_map.get(expected_type_str)
            if expected_type and not isinstance(value, expected_type):
                type_errors.append(
                    f"{key}: 期望 {expected_type_str}, 实际 {type(value).__name__}"
                )

        if type_errors:
            return f"参数类型错误: {'; '.join(type_errors)}"

        return None

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """获取工具定义"""
        return self._definitions.get(name)

    def get_tools_for_llm(
        self,
        categories: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """获取供 LLM 使用的工具列表

        Args:
            categories: 限定分类列表，None 表示全部
            exclude: 排除的工具名称列表

        Returns:
            OpenAI Function Calling 格式的工具列表
        """
        exclude = exclude or []
        tools = []

        for name, definition in self._definitions.items():
            # 排除检查
            if name in exclude:
                continue

            # 分类检查
            if categories and definition.category not in categories:
                continue

            tools.append(definition.to_openai_schema())

        return tools

    def get_tools_by_category(self, category: str) -> List[Dict[str, Any]]:
        """按分类获取工具"""
        return self.get_tools_for_llm(categories=[category])

    def get_all_names(self) -> List[str]:
        """获取所有工具名称"""
        return list(self._definitions.keys())

    def get_categories(self) -> Dict[str, ToolCategory]:
        """获取所有分类"""
        return self._categories.copy()

    def has_tool(self, name: str) -> bool:
        """检查工具是否存在"""
        return name in self._definitions

    async def execute(
        self,
        name: str,
        arguments: Dict[str, Any],
    ) -> ToolResult:
        """执行工具

        自动处理同步和异步执行器。

        Args:
            name: 工具名称
            arguments: 工具参数

        Returns:
            ToolResult 执行结果
        """
        import time
        start_time = time.time()

        if name not in self._executors:
            return ToolResult(
                tool_name=name,
                success=False,
                error=f"未知工具: {name}",
            )

        definition = self._definitions.get(name)
        executor = self._executors[name]

        try:
            # 参数验证和过滤：移除未定义的参数
            filtered_arguments = self._filter_arguments(name, arguments, definition)

            # 参数约束校验：required 和类型检查
            validation_error = self._validate_arguments(name, filtered_arguments, definition)
            if validation_error:
                logger.warning(f"[ToolManager] 工具 {name} 参数校验失败: {validation_error}")
                return ToolResult(
                    tool_name=name,
                    success=False,
                    error=f"参数校验失败: {validation_error}",
                    duration_ms=int((time.time() - start_time) * 1000),
                )

            # 如果需要上下文，注入上下文
            if definition and definition.requires_context and self._context_provider:
                context = self._context_provider()
                filtered_arguments = {**filtered_arguments, "_context": context}

            # 执行工具
            if definition and definition.is_async:
                # 异步执行
                data = await executor(filtered_arguments)
            else:
                # 同步执行（在线程池中运行以避免阻塞）
                data = await asyncio_to_thread(executor, filtered_arguments)

            # 处理结果
            success = data.get("success", True) if isinstance(data, dict) else True
            result = ToolResult(
                tool_name=name,
                success=success,
                data=data if isinstance(data, dict) else {"result": data},
            )

        except Exception as e:
            logger.error(f"[ToolManager] 工具执行失败 {name}: {e}")
            result = ToolResult(
                tool_name=name,
                success=False,
                error=str(e),
            )

        result.duration_ms = int((time.time() - start_time) * 1000)

        logger.info(
            f"[ToolManager] {name} - "
            f"{'成功' if result.success else '失败'} - "
            f"{result.duration_ms}ms"
        )

        return result

    def execute_sync(
        self,
        name: str,
        arguments: Dict[str, Any],
    ) -> ToolResult:
        """同步执行工具（用于非异步上下文）"""
        return asyncio.run(self.execute(name, arguments))

    def get_tool_description(self, name: str) -> str:
        """获取工具描述"""
        definition = self._definitions.get(name)
        if definition:
            return definition.description
        return ""

    def get_tool_summary(self) -> str:
        """生成工具摘要（用于系统提示词）"""
        lines = ["可用工具列表：\n"]

        for cat_name, category in self._categories.items():
            if category.tools:
                lines.append(f"\n## {category.description}")
                for tool_name in category.tools:
                    definition = self._definitions.get(tool_name)
                    if definition:
                        lines.append(f"- **{tool_name}**: {definition.description[:80]}")

        return "\n".join(lines)

    def clear(self):
        """清空所有工具"""
        self._definitions.clear()
        self._executors.clear()
        for cat in self._categories.values():
            cat.tools.clear()

    def count(self) -> int:
        """获取工具数量"""
        return len(self._definitions)


def create_unified_tool_manager() -> AgentToolManager:
    """创建统一工具管理器（工厂函数）

    Returns:
        配置好基础工具的管理器
    """
    manager = AgentToolManager()

    # 注册基础代码导航工具
    from .registry import CODE_NAVIGATION_TOOLS

    # 这里只注册定义，执行器需要外部提供
    for schema in CODE_NAVIGATION_TOOLS:
        func = schema.get("function", {})
        name = func.get("name")
        if name:
            manager._definitions[name] = ToolDefinition(
                name=name,
                description=func.get("description", ""),
                parameters=func.get("parameters", {}),
                category="code_navigation",
            )
            if name not in manager._categories["code_navigation"].tools:
                manager._categories["code_navigation"].tools.append(name)

    logger.info(f"[ToolManager] 创建统一工具管理器，已注册 {manager.count()} 个工具定义")

    return manager
