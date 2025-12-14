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

            results = self.indexer.search(
                query=query,
                top_k=top_k,
                language=language,
                file_pattern=file_pattern,
            )

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
            return {
                "success": False,
                "error": f"搜索失败: {str(e)}",
                "results": [],
                "total": 0,
            }

    def read_file(
        self,
        file_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
        context_lines: int = 0,
    ) -> Dict[str, Any]:
        """读取文件内容

        支持读取整个文件或指定行范围

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

            return {
                "success": True,
                "file_path": rel_path,
                "content": "\n".join(numbered_lines),
                "start_line": start_idx + 1,
                "end_line": end_idx,
                "total_lines": total_lines,
                "language": self._detect_language(file_path),
                "truncated": truncated,
            }
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
                    "hint": "尝试使用 search_code 进行模糊搜索",
                }

            result = {
                "success": True,
                "symbol": symbol_name,
                "definitions": [
                    {
                        "file_path": unit.file_path,
                        "type": unit.unit_type.value,
                        "start_line": unit.span.start_line,
                        "end_line": unit.span.end_line,
                        "code": unit.code,
                        "signature": unit.signature,
                        "parent_class": unit.parent_class,
                        "docstring": unit.docstring,
                        "decorators": unit.decorators,
                    }
                    for unit in matched[:3]  # 最多返回 3 个定义
                ],
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

        Args:
            symbol_name: 要查找调用者的函数名
            file_path: 限定在特定文件中查找（可选）
            max_results: 最大返回数量

        Returns:
            包含调用者列表的字典
        """
        try:
            # 先找到目标符号
            symbol_result = self.read_symbol(symbol_name, file_path)
            if not symbol_result.get("success"):
                return {
                    "success": False,
                    "error": f"未找到符号: {symbol_name}",
                    "callers": [],
                }

            # 搜索所有可能调用此符号的代码
            all_units = self.indexer.get_all_units(limit=5000)
            callers = []

            for unit in all_units:
                # 跳过自身
                if unit.symbol == symbol_name:
                    continue

                # 检查代码中是否包含对目标符号的调用
                symbol_parts = symbol_name.split(".")
                short_name = symbol_parts[-1]  # 获取最后一部分（方法名）

                # 检查 calls 列表或代码内容
                is_caller = False
                if unit.calls:
                    for call in unit.calls:
                        if short_name in call or symbol_name in call:
                            is_caller = True
                            break

                # 也检查代码文本（更可靠）
                if not is_caller and (short_name + "(" in unit.code or symbol_name + "(" in unit.code):
                    is_caller = True

                if is_caller:
                    # 找到调用位置的具体行号
                    call_lines = []
                    lines = unit.code.split("\n")
                    for i, line in enumerate(lines):
                        if short_name + "(" in line or symbol_name + "(" in line:
                            call_lines.append(unit.span.start_line + i)

                    callers.append({
                        "file_path": unit.file_path,
                        "caller_symbol": unit.symbol,
                        "caller_type": unit.unit_type.value,
                        "start_line": unit.span.start_line,
                        "end_line": unit.span.end_line,
                        "call_lines": call_lines[:3],  # 只显示前3个调用位置
                        "code_preview": unit.code[:200] + "..." if len(unit.code) > 200 else unit.code,
                    })

                    if len(callers) >= max_results:
                        break

            return {
                "success": True,
                "symbol": symbol_name,
                "callers": callers,
                "total": len(callers),
                "hint": "使用 read_file 查看调用位置的完整上下文" if callers else "未找到调用者，可能是入口函数或未被使用",
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
            logger.error(f"Get callees failed: {e}")
            return {
                "success": False,
                "error": f"查找被调用函数失败: {str(e)}",
                "callees": [],
            }
