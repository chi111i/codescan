"""
代码读取服务 - 为 LLM Function Calling 提供代码访问能力

提供以下能力：
- 语义搜索代码 (search_code)
- 按文件/行号读取 (read_file)
- 按符号名读取 (read_symbol)
- 列出项目文件 (list_files)
- 获取文件大纲 (get_file_outline)
"""

import fnmatch
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .indexer import CodeIndexer

logger = logging.getLogger(__name__)


# 语言检测映射
EXTENSION_LANGUAGE_MAP = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".php": "php",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".vue": "vue",
    ".svelte": "svelte",
}


class CodeReader:
    """代码读取服务

    为 LLM Function Calling 提供代码访问能力，支持：
    - 语义搜索代码
    - 精确行号读取
    - 符号定位读取
    - 文件列表和大纲
    """

    def __init__(
        self,
        project_path: str,
        indexer: "CodeIndexer",
        max_file_lines: int = 500,
        max_search_results: int = 20,
    ):
        """初始化代码读取器

        Args:
            project_path: 项目根路径
            indexer: 代码索引器实例
            max_file_lines: 单次读取最大行数限制
            max_search_results: 搜索最大结果数
        """
        self.project_path = Path(project_path).resolve()
        self.indexer = indexer
        self.max_file_lines = max_file_lines
        self.max_search_results = max_search_results

        # P0-3.4: 调用关系缓存（懒加载）
        self._caller_index: Optional[Dict[str, List[Dict[str, Any]]]] = None
        self._caller_index_version: int = 0

    def _validate_path(self, file_path: str) -> Optional[Path]:
        """验证并解析文件路径

        确保路径在项目范围内

        Args:
            file_path: 相对或绝对路径

        Returns:
            解析后的绝对路径，如果无效则返回 None
        """
        try:
            # 支持相对路径和绝对路径
            if Path(file_path).is_absolute():
                full_path = Path(file_path).resolve()
            else:
                full_path = (self.project_path / file_path).resolve()

            # 安全检查：确保路径在项目范围内
            if not str(full_path).startswith(str(self.project_path)):
                logger.warning(f"Path outside project: {file_path}")
                return None

            return full_path
        except Exception as e:
            logger.warning(f"Invalid path {file_path}: {e}")
            return None

    def _detect_language(self, file_path: str) -> str:
        """检测文件语言"""
        suffix = Path(file_path).suffix.lower()
        return EXTENSION_LANGUAGE_MAP.get(suffix, "unknown")

    def search_code(
        self,
        query: str,
        top_k: int = 5,
        language: Optional[str] = None,
        file_pattern: Optional[str] = None,
    ) -> Dict[str, Any]:
        """语义搜索代码

        通过向量相似度搜索与查询相关的代码片段

        Args:
            query: 搜索查询，描述要查找的代码功能或模式
            top_k: 返回结果数量
            language: 限定编程语言
            file_pattern: 文件路径模式，如 '**/auth/*.py'

        Returns:
            包含搜索结果的字典
        """
        try:
            # 限制结果数量
            top_k = min(top_k, self.max_search_results)

            # P0-2.2: 检查索引状态
            index_status = self._get_index_status()
            if not index_status["is_ready"]:
                return {
                    "success": False,
                    "error": index_status["message"],
                    "results": [],
                    "total": 0,
                    "hint": index_status.get("hint"),
                    "index_status": index_status,
                }

            results = self.indexer.search(
                query=query,
                top_k=top_k,
                language=language,
                file_pattern=file_pattern,
            )

            # P0-2.2: 处理空结果情况
            if not results:
                return {
                    "success": True,
                    "query": query,
                    "results": [],
                    "total": 0,
                    "message": "未找到匹配的代码。语义搜索依赖向量相似度，可能无法匹配精确关键词。",
                    "hint": f"如果需要精确匹配关键词或正则表达式，请使用 grep_code(pattern='{query}') 工具。",
                    "index_status": index_status,
                }

            return {
                "success": True,
                "query": query,
                "results": [
                    {
                        "file_path": unit.file_path,
                        "symbol": unit.symbol,
                        "type": unit.unit_type.value,
                        "start_line": unit.span.start_line,
                        "end_line": unit.span.end_line,
                        "code": unit.code,
                        "signature": unit.signature,
                        "language": unit.language,
                        "parent_class": unit.parent_class,
                    }
                    for unit in results
                ],
                "total": len(results),
            }
        except Exception as e:
            logger.error(f"Search failed: {e}")
            error_msg = str(e).lower()

            # P0-2.2: 区分不同类型的错误
            if "embed" in error_msg or "embedding" in error_msg:
                hint = "嵌入生成失败，可能是 LLM API 配置问题。请检查 API 密钥和网络连接。"
            elif "connect" in error_msg or "timeout" in error_msg:
                hint = "连接超时，请检查向量数据库服务是否正常运行。"
            else:
                hint = f"如果需要精确搜索，可以使用 grep_code(pattern='{query}') 工具作为替代。"

            return {
                "success": False,
                "error": f"搜索失败: {str(e)}",
                "results": [],
                "total": 0,
                "hint": hint,
            }

    def _get_index_status(self) -> Dict[str, Any]:
        """获取索引状态

        Returns:
            索引状态字典，包含 is_ready、total_units、message 等
        """
        try:
            stats = self.indexer.get_stats()
            total_units = stats.get("total_units", 0)

            if total_units == 0:
                return {
                    "is_ready": False,
                    "total_units": 0,
                    "message": "索引为空，没有可搜索的代码单元。请先执行索引操作。",
                    "hint": "使用 'python -m codescan index <项目路径>' 命令索引项目，或通过 API 调用 /api/index 端点。",
                }

            return {
                "is_ready": True,
                "total_units": total_units,
                "collection_name": stats.get("collection_name"),
                "chunked_parents": stats.get("chunked_parents", 0),
                "total_chunks": stats.get("total_chunks", 0),
                "message": f"索引就绪，共 {total_units} 个代码单元。",
            }
        except Exception as e:
            logger.warning(f"Failed to get index status: {e}")
            return {
                "is_ready": False,
                "total_units": 0,
                "message": f"无法获取索引状态: {str(e)}",
                "hint": "索引器可能未正确初始化，请检查配置。",
            }

    def read_file(
        self,
        file_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
        context_lines: int = 0,
    ) -> Dict[str, Any]:
        """读取文件内容

        支持读取整个文件或指定行范围。类似于 Claude Code 的精确行号读取功能。

        Args:
            file_path: 文件路径（相对于项目根目录）
            start_line: 起始行号（从 1 开始）
            end_line: 结束行号
            context_lines: 额外读取的上下文行数

        Returns:
            包含文件内容的字典
        """
        full_path = self._validate_path(file_path)
        if not full_path:
            return {
                "success": False,
                "error": "无效路径或路径超出项目范围",
            }

        if not full_path.exists():
            return {
                "success": False,
                "error": f"文件不存在: {file_path}",
            }

        if not full_path.is_file():
            return {
                "success": False,
                "error": f"不是文件: {file_path}",
            }

        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")
            total_lines = len(lines)

            # 处理行号范围
            if start_line is not None:
                start_idx = max(0, start_line - 1 - context_lines)
            else:
                start_idx = 0

            if end_line is not None:
                end_idx = min(total_lines, end_line + context_lines)
            else:
                end_idx = min(total_lines, start_idx + self.max_file_lines)

            # 检查是否超过最大行数限制
            if end_idx - start_idx > self.max_file_lines:
                end_idx = start_idx + self.max_file_lines
                truncated = True
            else:
                truncated = (end_idx < total_lines and end_line is None)

            selected_lines = lines[start_idx:end_idx]

            # 添加行号
            numbered_lines = [
                f"{i + start_idx + 1:4d} | {line}"
                for i, line in enumerate(selected_lines)
            ]

            # 获取相对路径
            try:
                rel_path = str(full_path.relative_to(self.project_path))
            except ValueError:
                rel_path = file_path

            result = {
                "success": True,
                "file_path": rel_path,
                "content": "\n".join(numbered_lines),
                "start_line": start_idx + 1,
                "end_line": end_idx,
                "total_lines": total_lines,
                "language": self._detect_language(file_path),
                "truncated": truncated,
            }

            # 增强：为大文件提供智能提示
            if truncated or total_lines > self.max_file_lines:
                remaining_lines = total_lines - end_idx
                result["hint"] = (
                    f"文件共 {total_lines} 行，当前显示第 {start_idx + 1}-{end_idx} 行。"
                )
                if remaining_lines > 0:
                    # 计算建议的下一个读取范围
                    next_start = end_idx + 1
                    next_end = min(total_lines, next_start + self.max_file_lines - 1)
                    result["next_range"] = {
                        "start_line": next_start,
                        "end_line": next_end,
                        "remaining_lines": remaining_lines,
                    }
                    result["hint"] += (
                        f" 还有 {remaining_lines} 行未显示。"
                        f"使用 read_file(file_path, start_line={next_start}, end_line={next_end}) 继续读取。"
                    )

            return result
        except Exception as e:
            logger.error(f"Read file failed: {e}")
            return {
                "success": False,
                "error": f"读取文件失败: {str(e)}",
            }

    def read_symbol(
        self,
        symbol_name: str,
        file_path: Optional[str] = None,
        include_callers: bool = False,
        include_callees: bool = False,
    ) -> Dict[str, Any]:
        """读取符号定义

        查找并读取指定函数、类或方法的代码

        Args:
            symbol_name: 符号名称（函数名、类名、方法名）
            file_path: 限定在特定文件中查找
            include_callers: 是否包含调用此符号的代码
            include_callees: 是否包含此符号调用的其他函数

        Returns:
            包含符号定义的字典
        """
        try:
            # P0-2.3: 检查索引状态
            index_status = self._get_index_status()
            if not index_status["is_ready"]:
                return {
                    "success": False,
                    "error": index_status["message"],
                    "hint": index_status.get("hint"),
                    "alternative": f"使用 grep_code(pattern='{symbol_name}') 进行精确搜索",
                }

            # 从向量库搜索符号
            results = self.indexer.search(
                query=symbol_name,
                top_k=15,
            )

            # 精确匹配符号名
            matched = []
            for unit in results:
                # 完全匹配或作为方法名匹配
                if (unit.symbol == symbol_name or
                    unit.symbol.endswith(f".{symbol_name}") or
                    unit.symbol.split(".")[-1] == symbol_name):
                    matched.append(unit)

            # 按文件过滤
            if file_path:
                matched = [u for u in matched if file_path in u.file_path]

            if not matched:
                return {
                    "success": False,
                    "error": f"未找到符号: {symbol_name}",
                    "hint": "尝试使用 search_code 进行模糊搜索，或 grep_code 进行精确匹配",
                }

            # 大函数阈值（行数）
            max_symbol_lines = 200

            definitions = []
            for unit in matched[:3]:  # 最多返回 3 个定义
                code = unit.code
                start_line = unit.span.start_line
                end_line = unit.span.end_line
                total_lines = end_line - start_line + 1
                truncated = False
                truncation_hint = None

                # 大函数截断处理
                if total_lines > max_symbol_lines:
                    lines = code.splitlines()
                    code = "\n".join(lines[:max_symbol_lines])
                    truncated = True
                    display_end = start_line + max_symbol_lines - 1
                    truncation_hint = (
                        f"函数过大（共 {total_lines} 行），已截断为前 {max_symbol_lines} 行。"
                        f"使用 read_file(file_path='{unit.file_path}', start_line={display_end + 1}, "
                        f"end_line={end_line}) 查看剩余部分。"
                    )

                definition = {
                    "file_path": unit.file_path,
                    "type": unit.unit_type.value,
                    "start_line": start_line,
                    "end_line": end_line,
                    "code": code,
                    "signature": unit.signature,
                    "parent_class": unit.parent_class,
                    "docstring": unit.docstring,
                    "decorators": unit.decorators,
                    "total_lines": total_lines,
                }

                if truncated:
                    definition["truncated"] = True
                    definition["truncation_hint"] = truncation_hint

                definitions.append(definition)

            result = {
                "success": True,
                "symbol": symbol_name,
                "definitions": definitions,
                "total_found": len(matched),
            }

            # 获取调用者
            if include_callers and matched:
                callers = self._find_callers(matched[0])
                result["callers"] = callers[:5]

            # 获取被调用者
            if include_callees and matched:
                result["callees"] = matched[0].calls[:10] if matched[0].calls else []

            return result

        except Exception as e:
            logger.error(f"Read symbol failed: {e}")
            return {
                "success": False,
                "error": f"读取符号失败: {str(e)}",
            }

    def list_files(
        self,
        pattern: str = "**/*",
        max_results: int = 50,
    ) -> Dict[str, Any]:
        """列出项目文件

        Args:
            pattern: 文件匹配模式，如 '**/*.py' 或 'src/auth/*'
            max_results: 最大返回数量

        Returns:
            包含文件列表的字典
        """
        try:
            files = []
            directories = set()

            # 默认排除模式
            exclude_patterns = [
                "**/node_modules/**",
                "**/__pycache__/**",
                "**/.git/**",
                "**/venv/**",
                "**/.venv/**",
                "**/dist/**",
                "**/build/**",
                "**/*.pyc",
                "**/*.pyo",
            ]

            for path in self.project_path.rglob("*"):
                if path.is_file():
                    try:
                        rel_path = str(path.relative_to(self.project_path)).replace("\\", "/")

                        # 检查排除模式
                        excluded = False
                        for exc_pattern in exclude_patterns:
                            if fnmatch.fnmatch(rel_path, exc_pattern):
                                excluded = True
                                break

                        if excluded:
                            continue

                        # 检查包含模式
                        if fnmatch.fnmatch(rel_path, pattern):
                            files.append({
                                "path": rel_path,
                                "language": self._detect_language(rel_path),
                                "size": path.stat().st_size,
                            })

                            # 记录目录
                            parent = str(path.parent.relative_to(self.project_path)).replace("\\", "/")
                            if parent != ".":
                                directories.add(parent)

                            if len(files) >= max_results:
                                break
                    except ValueError:
                        continue

            return {
                "success": True,
                "pattern": pattern,
                "files": files,
                "directories": sorted(list(directories))[:20],
                "total": len(files),
                "truncated": len(files) >= max_results,
            }

        except Exception as e:
            logger.error(f"List files failed: {e}")
            return {
                "success": False,
                "error": f"列出文件失败: {str(e)}",
                "files": [],
            }

    def get_file_outline(self, file_path: str) -> Dict[str, Any]:
        """获取文件结构大纲

        返回文件中所有符号（类、函数、方法）的列表

        Args:
            file_path: 文件路径

        Returns:
            包含文件大纲的字典
        """
        try:
            # 从索引获取该文件的所有代码单元
            units = self.indexer.get_units_by_file(file_path)

            if not units:
                # 尝试模糊匹配
                all_units = self.indexer.get_all_units(limit=5000)
                units = [u for u in all_units if file_path in u.file_path]

            outline = []
            for unit in units:
                outline.append({
                    "symbol": unit.symbol,
                    "type": unit.unit_type.value,
                    "start_line": unit.span.start_line,
                    "end_line": unit.span.end_line,
                    "signature": unit.signature,
                    "parent": unit.parent_class,
                    "decorators": unit.decorators[:3] if unit.decorators else [],
                })

            # 按行号排序
            outline.sort(key=lambda x: x["start_line"])

            return {
                "success": True,
                "file_path": file_path,
                "outline": outline,
                "total_symbols": len(outline),
            }

        except Exception as e:
            logger.error(f"Get file outline failed: {e}")
            return {
                "success": False,
                "error": f"获取文件大纲失败: {str(e)}",
                "outline": [],
            }

    def _build_caller_index(self) -> Dict[str, List[Dict[str, Any]]]:
        """P0-3.4: 构建调用者索引缓存

        遍历所有代码单元一次，建立 被调用函数名 -> 调用者列表 的反向索引。
        后续 get_callers 调用直接查索引，避免重复遍历。

        Returns:
            符号名到调用者列表的映射
        """
        caller_index: Dict[str, List[Dict[str, Any]]] = {}

        try:
            all_units = self.indexer.get_all_units(limit=10000)
            logger.info(f"Building caller index for {len(all_units)} code units...")

            for unit in all_units:
                # 分析该单元调用了哪些函数
                calls = getattr(unit, 'calls', []) or []

                # 从代码中额外提取函数调用（更可靠）
                if unit.code:
                    import re
                    # 匹配函数调用模式: word(
                    call_pattern = re.compile(r'\b(\w+)\s*\(')
                    code_calls = call_pattern.findall(unit.code)
                    calls = list(set(calls) | set(code_calls))

                caller_info = {
                    "file_path": unit.file_path,
                    "caller_symbol": unit.symbol,
                    "caller_type": unit.unit_type.value,
                    "start_line": unit.span.start_line,
                    "end_line": unit.span.end_line,
                    "code_preview": unit.code[:200] + "..." if len(unit.code) > 200 else unit.code,
                }

                for call in calls:
                    if call == unit.symbol:
                        continue  # 跳过自引用
                    if call not in caller_index:
                        caller_index[call] = []
                    # 避免重复添加
                    if not any(c["caller_symbol"] == unit.symbol and c["file_path"] == unit.file_path
                               for c in caller_index[call]):
                        caller_index[call].append(caller_info)

            logger.info(f"Caller index built: {len(caller_index)} unique symbols")
            return caller_index

        except Exception as e:
            logger.warning(f"Failed to build caller index: {e}")
            return {}

    def _get_caller_index(self) -> Dict[str, List[Dict[str, Any]]]:
        """P0-3.4: 获取或构建调用者索引

        懒加载调用者索引，只在首次访问时构建。

        Returns:
            符号名到调用者列表的映射
        """
        # 检查索引版本是否过期
        current_version = getattr(self.indexer, '_index_version', 0)

        if self._caller_index is None or self._caller_index_version != current_version:
            self._caller_index = self._build_caller_index()
            self._caller_index_version = current_version

        return self._caller_index

    def _find_callers(self, unit) -> List[Dict[str, Any]]:
        """查找调用者

        Args:
            unit: 代码单元

        Returns:
            调用者列表
        """
        callers = []
        try:
            # 搜索调用此符号的代码
            results = self.indexer.search(
                query=f"调用 {unit.symbol}",
                top_k=15,
            )

            for r in results:
                if r.id == unit.id:
                    continue
                # 检查是否真的调用了该符号
                if unit.symbol in r.calls or unit.symbol in r.code:
                    callers.append({
                        "file_path": r.file_path,
                        "symbol": r.symbol,
                        "line": r.span.start_line,
                        "type": r.unit_type.value,
                    })

        except Exception as e:
            logger.warning(f"Find callers failed: {e}")

        return callers

    def get_callers(
        self,
        symbol_name: str,
        file_path: Optional[str] = None,
        max_results: int = 10,
    ) -> Dict[str, Any]:
        """查找谁调用了指定函数（向上追溯调用链）

        P0-3.4: 使用调用者索引缓存优化性能，避免每次遍历所有代码单元。

        Args:
            symbol_name: 要查找调用者的函数名
            file_path: 限定在特定文件中查找（可选）
            max_results: 最大返回数量

        Returns:
            包含调用者列表的字典
        """
        try:
            # 先找到目标符号，验证其存在
            symbol_result = self.read_symbol(symbol_name, file_path)
            if not symbol_result.get("success"):
                return {
                    "success": False,
                    "error": f"未找到符号: {symbol_name}",
                    "callers": [],
                }

            # P0-3.4: 使用调用者索引缓存
            caller_index = self._get_caller_index()

            # 获取符号的短名称（用于匹配）
            symbol_parts = symbol_name.split(".")
            short_name = symbol_parts[-1]

            # 从索引中查找调用者
            callers = []

            # 尝试完整名称匹配
            if symbol_name in caller_index:
                callers.extend(caller_index[symbol_name])

            # 尝试短名称匹配（避免重复）
            if short_name != symbol_name and short_name in caller_index:
                for caller in caller_index[short_name]:
                    if not any(c["caller_symbol"] == caller["caller_symbol"] and
                               c["file_path"] == caller["file_path"] for c in callers):
                        callers.append(caller)

            # 过滤自身
            callers = [c for c in callers if c["caller_symbol"] != symbol_name]

            # 限制结果数量
            callers = callers[:max_results]

            return {
                "success": True,
                "symbol": symbol_name,
                "callers": callers,
                "total": len(callers),
                "hint": "使用 read_file 查看调用位置的完整上下文" if callers else "未找到调用者，可能是入口函数或未被使用",
                "cache_status": "indexed" if caller_index else "empty",
            }

        except Exception as e:
            logger.error(f"Get callers failed: {e}")
            return {
                "success": False,
                "error": f"查找调用者失败: {str(e)}",
                "callers": [],
            }

    def get_callees(
        self,
        symbol_name: str,
        file_path: Optional[str] = None,
        max_depth: int = 1,
    ) -> Dict[str, Any]:
        """查找指定函数调用了哪些其他函数（向下追溯调用链）

        Args:
            symbol_name: 要分析的函数名
            file_path: 限定在特定文件中查找（可选）
            max_depth: 调用链追溯深度

        Returns:
            包含被调用函数列表的字典
        """
        try:
            # 先找到目标符号
            symbol_result = self.read_symbol(symbol_name, file_path)
            if not symbol_result.get("success"):
                return {
                    "success": False,
                    "error": f"未找到符号: {symbol_name}",
                    "callees": [],
                }

            definitions = symbol_result.get("definitions", [])
            if not definitions:
                return {
                    "success": False,
                    "error": f"未找到符号定义: {symbol_name}",
                    "callees": [],
                }

            # 获取直接调用的函数
            target_def = definitions[0]
            direct_calls = symbol_result.get("callees", [])

            # 分析代码中的函数调用
            callees = []
            seen_calls = set()

            for call in direct_calls:
                if call in seen_calls:
                    continue
                seen_calls.add(call)

                # 尝试找到被调用函数的定义
                callee_result = self.read_symbol(call)
                if callee_result.get("success") and callee_result.get("definitions"):
                    callee_def = callee_result["definitions"][0]
                    callees.append({
                        "symbol": call,
                        "type": callee_def.get("type", "unknown"),
                        "file_path": callee_def.get("file_path"),
                        "line": callee_def.get("start_line"),
                        "signature": callee_def.get("signature"),
                        "found": True,
                    })
                else:
                    # 外部库函数或未索引的函数
                    callees.append({
                        "symbol": call,
                        "type": "unknown",
                        "file_path": None,
                        "line": None,
                        "signature": None,
                        "found": False,
                        "note": "可能是外部库函数或未索引的函数",
                    })

            # 如果需要更深层次的调用链
            if max_depth > 1 and callees:
                nested_callees = []
                for callee in callees:
                    if callee.get("found") and callee.get("file_path"):
                        nested_result = self.get_callees(
                            callee["symbol"],
                            callee.get("file_path"),
                            max_depth=max_depth - 1,
                        )
                        if nested_result.get("success"):
                            callee["nested_calls"] = nested_result.get("callees", [])[:5]

            return {
                "success": True,
                "symbol": symbol_name,
                "file_path": target_def.get("file_path"),
                "callees": callees,
                "total": len(callees),
                "depth": max_depth,
                "hint": "标记 found=False 的函数可能是外部库或内置函数",
            }

        except Exception as e:
            logger.exception(f"Get callees failed: {e}")
            return {
                "success": False,
                "error": f"查找被调用函数失败: {str(e)}",
                "callees": [],
            }

    def grep_code(
        self,
        pattern: str,
        file_glob: str | None = None,
        max_results: int = 50,
        context_lines: int = 2,
        use_regex: bool = False,
        case_sensitive: bool = True,
    ) -> dict:
        """精确代码搜索（基于正则/关键词，非语义搜索）

        与 search_code（语义搜索）不同，此方法提供精确的字符串/正则匹配，
        类似于 grep/ripgrep 的功能，但集成了索引辅助加速。

        Args:
            pattern: 搜索模式（字符串或正则表达式）
            file_glob: 可选的文件过滤模式，如 "*.py", "src/**/*.js"
            max_results: 最大返回结果数
            context_lines: 匹配行前后的上下文行数
            use_regex: 是否将 pattern 作为正则表达式处理
            case_sensitive: 是否区分大小写

        Returns:
            {
                "success": bool,
                "matches": [
                    {
                        "file_path": str,
                        "line_number": int,
                        "line_content": str,
                        "context_before": [str],
                        "context_after": [str],
                        "match_start": int,  # 匹配在行内的起始位置
                        "match_end": int,    # 匹配在行内的结束位置
                    }
                ],
                "total_matches": int,
                "truncated": bool,
                "hint": str,
            }
        """
        import fnmatch
        import re
        from pathlib import Path

        matches = []
        total_matches = 0
        truncated = False

        try:
            # 编译搜索模式
            if use_regex:
                try:
                    flags = 0 if case_sensitive else re.IGNORECASE
                    regex = re.compile(pattern, flags)
                except re.error as e:
                    return {
                        "success": False,
                        "error": f"无效的正则表达式: {str(e)}",
                        "matches": [],
                    }
            else:
                # 纯字符串搜索，转义特殊字符
                escaped = re.escape(pattern)
                flags = 0 if case_sensitive else re.IGNORECASE
                regex = re.compile(escaped, flags)

            # 方案 B：索引辅助搜索 - 先从已索引的文件列表中筛选
            # 获取所有已索引的文件
            indexed_files = set()

            if self.indexer and hasattr(self.indexer, 'get_all_units'):
                units = self.indexer.get_all_units()
                for unit in units:
                    if hasattr(unit, 'file_path') and unit.file_path:
                        indexed_files.add(unit.file_path)

            # 如果没有索引，回退到目录扫描
            if not indexed_files:
                # 从项目根目录扫描文件
                project_root = Path.cwd()
                if hasattr(self.indexer, 'project_root'):
                    project_root = Path(self.indexer.project_root)

                # 常见代码文件扩展名
                code_extensions = {
                    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go',
                    '.c', '.cpp', '.h', '.hpp', '.cs', '.php', '.rb',
                    '.rs', '.swift', '.kt', '.scala', '.vue', '.svelte',
                }

                for file_path in project_root.rglob('*'):
                    if file_path.is_file() and file_path.suffix.lower() in code_extensions:
                        # 跳过常见的忽略目录
                        parts = file_path.parts
                        if any(p in {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'} for p in parts):
                            continue
                        indexed_files.add(str(file_path))

            # 应用文件过滤
            target_files = list(indexed_files)
            if file_glob:
                target_files = [
                    f for f in target_files
                    if fnmatch.fnmatch(Path(f).name, file_glob) or
                       fnmatch.fnmatch(str(f), file_glob)
                ]

            # 按文件名排序，便于结果稳定
            target_files.sort()

            # 遍历文件搜索
            for file_path in target_files:
                if len(matches) >= max_results:
                    truncated = True
                    break

                try:
                    path = Path(file_path)
                    if not path.exists() or not path.is_file():
                        continue

                    # 读取文件内容
                    try:
                        content = path.read_text(encoding='utf-8', errors='ignore')
                    except Exception:
                        continue

                    lines = content.splitlines()

                    # 逐行搜索
                    for line_idx, line in enumerate(lines):
                        match = regex.search(line)
                        if match:
                            total_matches += 1

                            if len(matches) < max_results:
                                # 获取上下文
                                start_ctx = max(0, line_idx - context_lines)
                                end_ctx = min(len(lines), line_idx + context_lines + 1)

                                matches.append({
                                    "file_path": str(file_path),
                                    "line_number": line_idx + 1,  # 1-based
                                    "line_content": line,
                                    "context_before": lines[start_ctx:line_idx],
                                    "context_after": lines[line_idx + 1:end_ctx],
                                    "match_start": match.start(),
                                    "match_end": match.end(),
                                    "matched_text": match.group(),
                                })
                            else:
                                truncated = True

                except Exception as e:
                    logger.debug(f"Error searching file {file_path}: {e}")
                    continue

            # 构建提示信息
            hint = f"找到 {total_matches} 处匹配"
            if truncated:
                hint += f"，仅显示前 {max_results} 条结果。使用 file_glob 参数缩小搜索范围。"
            if not use_regex:
                hint += " 提示：设置 use_regex=True 可使用正则表达式进行更复杂的模式匹配。"

            return {
                "success": True,
                "pattern": pattern,
                "use_regex": use_regex,
                "case_sensitive": case_sensitive,
                "file_glob": file_glob,
                "matches": matches,
                "total_matches": total_matches,
                "truncated": truncated,
                "files_searched": len(target_files),
                "hint": hint,
            }

        except Exception as e:
            logger.exception(f"Grep code failed: {e}")
            return {
                "success": False,
                "error": f"代码搜索失败: {str(e)}",
                "matches": [],
            }
