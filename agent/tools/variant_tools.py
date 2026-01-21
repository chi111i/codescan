"""
变体分析工具 - 封装为 LLM Function Calling 格式

提供：
1. find_similar_code - 查找相似代码
2. detect_code_clones - 检测代码克隆
3. create_vuln_pattern - 从漏洞创建模式
4. search_variants - 搜索漏洞变体
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


# ============ 工具定义（OpenAI Function Calling 格式）============

VARIANT_TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "find_similar_code",
            "description": """查找与给定代码片段相似的代码。

功能：
- 使用语义相似度（向量嵌入）查找相似代码
- 支持按相似度阈值过滤
- 可以指定搜索范围

使用场景：
- 发现漏洞后查找类似的代码模式
- 检查是否有其他地方存在相同的问题
- 代码审计时扩大检查范围""",
            "parameters": {
                "type": "object",
                "properties": {
                    "code_snippet": {
                        "type": "string",
                        "description": "要查找相似代码的代码片段"
                    },
                    "query_text": {
                        "type": "string",
                        "description": "或者使用自然语言描述要查找的代码模式"
                    },
                    "similarity_threshold": {
                        "type": "number",
                        "description": "相似度阈值（0-1），默认 0.75",
                        "default": 0.75,
                        "minimum": 0.5,
                        "maximum": 1.0
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "最大返回数量",
                        "default": 10
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "文件路径模式过滤，如 '**/auth/*.py'"
                    },
                    "language": {
                        "type": "string",
                        "description": "限定编程语言"
                    },
                    "exclude_same_file": {
                        "type": "boolean",
                        "description": "是否排除同一文件中的结果",
                        "default": True
                    }
                },
                "oneOf": [
                    {"required": ["code_snippet"]},
                    {"required": ["query_text"]}
                ]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "detect_code_clones",
            "description": """检测项目中的代码克隆（重复代码）。

功能：
- 识别完全相同或高度相似的代码片段
- 按克隆类型分类（Type 1-3）
- 提供去重建议

使用场景：
- 发现需要统一修复的代码
- 识别可能遗漏的漏洞点
- 代码质量分析""",
            "parameters": {
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "string",
                        "description": "检测范围",
                        "enum": ["all", "functions", "classes", "handlers"],
                        "default": "functions"
                    },
                    "min_similarity": {
                        "type": "number",
                        "description": "最小相似度（0-1），默认 0.85",
                        "default": 0.85
                    },
                    "min_lines": {
                        "type": "integer",
                        "description": "最小代码行数（过滤太短的代码）",
                        "default": 5
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "文件路径模式过滤"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "最大返回数量",
                        "default": 20
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "create_vuln_pattern",
            "description": """从已确认的漏洞创建可重用的漏洞模式。

创建模式后，可以使用 search_variants 工具在整个代码库中搜索类似的漏洞。

使用场景：
- 确认一个漏洞后，想要查找其他类似漏洞
- 建立漏洞模式库用于自动检测
- 记录和分享漏洞知识""",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "已确认的漏洞发现 ID"
                    },
                    "pattern_name": {
                        "type": "string",
                        "description": "模式名称（如 'SQL注入-直接拼接'）"
                    },
                    "pattern_type": {
                        "type": "string",
                        "description": "模式类型",
                        "enum": [
                            "injection",
                            "auth_bypass",
                            "access_control",
                            "taint_flow",
                            "business_logic",
                            "dangerous_call",
                            "data_exposure",
                            "custom"
                        ]
                    },
                    "description": {
                        "type": "string",
                        "description": "模式的详细描述"
                    },
                    "sink_functions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "相关的危险函数列表"
                    }
                },
                "required": ["pattern_name", "pattern_type"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_variants",
            "description": """根据漏洞模式搜索代码库中的变体。

使用已创建的漏洞模式，在整个代码库中搜索可能存在相同问题的代码。

使用场景：
- 系统性地查找某类漏洞的所有实例
- 验证漏洞修复的完整性
- 扩大安全审计的覆盖范围""",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern_id": {
                        "type": "string",
                        "description": "漏洞模式 ID（由 create_vuln_pattern 创建）"
                    },
                    "pattern_type": {
                        "type": "string",
                        "description": "或者按模式类型搜索",
                        "enum": [
                            "injection",
                            "auth_bypass",
                            "access_control",
                            "taint_flow",
                            "business_logic",
                            "dangerous_call",
                            "data_exposure"
                        ]
                    },
                    "similarity_threshold": {
                        "type": "number",
                        "description": "相似度阈值（0-1），默认 0.75",
                        "default": 0.75
                    },
                    "use_llm_verification": {
                        "type": "boolean",
                        "description": "是否使用 LLM 验证匹配结果",
                        "default": False
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "最大返回数量",
                        "default": 20
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_vuln_patterns",
            "description": """列出已创建的漏洞模式。

查看当前可用的漏洞模式，用于后续的变体搜索。""",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern_type": {
                        "type": "string",
                        "description": "按类型过滤",
                        "enum": [
                            "all",
                            "injection",
                            "auth_bypass",
                            "access_control",
                            "taint_flow",
                            "business_logic",
                            "dangerous_call",
                            "data_exposure",
                            "custom"
                        ],
                        "default": "all"
                    },
                    "include_stats": {
                        "type": "boolean",
                        "description": "是否包含统计信息（变体数量等）",
                        "default": True
                    }
                }
            }
        }
    }
]


# ============ 工具执行器类 ============

class VariantToolExecutor:
    """变体分析工具执行器

    封装 VariantAnalyzer，提供工具执行接口。
    """

    def __init__(
        self,
        variant_analyzer = None,
        vector_store = None,
        embedding_client = None,
        code_units: List = None,
    ):
        """初始化执行器

        Args:
            variant_analyzer: VariantAnalyzer 实例
            vector_store: 向量存储实例
            embedding_client: 嵌入模型客户端
            code_units: 代码单元列表
        """
        self.analyzer = variant_analyzer
        self.vector_store = vector_store
        self.embedding_client = embedding_client
        self.code_units = code_units or []

        # 建立索引
        self._unit_by_id: Dict[str, Any] = {}
        for unit in self.code_units:
            self._unit_by_id[unit.id] = unit

    def find_similar_code(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行 find_similar_code 工具"""
        code_snippet = args.get("code_snippet")
        query_text = args.get("query_text")
        similarity_threshold = args.get("similarity_threshold", 0.75)
        max_results = args.get("max_results", 10)
        file_pattern = args.get("file_pattern")
        language = args.get("language")
        exclude_same_file = args.get("exclude_same_file", True)

        if not code_snippet and not query_text:
            return {"success": False, "error": "需要提供 code_snippet 或 query_text"}

        # P0-3.3: 增强依赖缺失提示
        if not self.vector_store:
            return {
                "success": False,
                "error": "向量存储未配置",
                "hint": "请确保在创建 VariantToolExecutor 时传入 vector_store 参数。"
                       "可以使用 CodeIndexer.get_vector_store() 获取向量存储实例。",
            }
        if not self.embedding_client:
            return {
                "success": False,
                "error": "嵌入模型客户端未配置",
                "hint": "请确保在创建 VariantToolExecutor 时传入 embedding_client 参数。"
                       "可以使用 LLMClient 实例作为嵌入客户端。",
            }

        try:
            # 生成查询向量
            query = code_snippet or query_text
            embed_response = self.embedding_client.embed([query])
            if not embed_response or not embed_response.embeddings or not embed_response.embeddings[0]:
                return {"success": False, "error": "无法生成嵌入向量"}

            query_vector = embed_response.embeddings[0]

            # 搜索相似代码 - 使用正确的参数名 query_embedding
            results = self.vector_store.search(
                query_embedding=query_vector,
                top_k=max_results * 2,  # 预留过滤空间
            )

            # 过滤和格式化结果
            similar_codes = []
            source_file = None

            # 如果是代码片段，尝试找到源文件
            if code_snippet and exclude_same_file:
                for unit in self.code_units:
                    if code_snippet in unit.code:
                        source_file = unit.file_path
                        break

            for result in results:
                if result.score < similarity_threshold:
                    continue

                metadata = result.metadata or {}
                file_path = metadata.get("file_path", "")

                # 排除同一文件
                if exclude_same_file and source_file and file_path == source_file:
                    continue

                # 文件模式过滤
                if file_pattern:
                    import fnmatch
                    if not fnmatch.fnmatch(file_path, file_pattern):
                        continue

                # 语言过滤
                if language and metadata.get("language") != language:
                    continue

                similar_codes.append({
                    "file_path": file_path,
                    "symbol": metadata.get("symbol", ""),
                    "line_start": metadata.get("line_start", 0),
                    "line_end": metadata.get("line_end", 0),
                    "similarity": round(result.score, 3),
                    "code_preview": metadata.get("code", "")[:300],
                })

                if len(similar_codes) >= max_results:
                    break

            return {
                "success": True,
                "similar_codes": similar_codes,
                "total_found": len(similar_codes),
                "threshold_used": similarity_threshold,
            }

        except Exception as e:
            logger.error(f"find_similar_code 失败: {e}")
            return {"success": False, "error": str(e)}

    def detect_code_clones(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行 detect_code_clones 工具"""
        scope = args.get("scope", "functions")
        min_similarity = args.get("min_similarity", 0.85)
        min_lines = args.get("min_lines", 5)
        file_pattern = args.get("file_pattern")
        max_results = args.get("max_results", 20)

        if not self.code_units:
            return {
                "success": False,
                "error": "代码单元未加载",
                "hint": "请确保在创建 VariantToolExecutor 时传入 code_units 参数。"
                       "可以使用 CodeIndexer.get_all_units() 获取代码单元列表。",
            }

        # P0-3.3: 增强嵌入客户端依赖检查
        if not self.embedding_client:
            return {
                "success": False,
                "error": "嵌入模型客户端未配置",
                "hint": "请确保在创建 VariantToolExecutor 时传入 embedding_client 参数。"
                       "可以使用 LLMClient 实例作为嵌入客户端。",
            }

        try:
            # 过滤代码单元
            filtered_units = []
            for unit in self.code_units:
                # 行数过滤
                lines = unit.code.count('\n') + 1
                if lines < min_lines:
                    continue

                # 范围过滤
                if scope == "functions" and unit.unit_type.value not in ("function", "method"):
                    continue
                elif scope == "classes" and unit.unit_type.value != "class":
                    continue
                elif scope == "handlers" and unit.unit_type.value != "handler":
                    continue

                # 文件过滤
                if file_pattern:
                    import fnmatch
                    if not fnmatch.fnmatch(unit.file_path, file_pattern):
                        continue

                filtered_units.append(unit)

            if len(filtered_units) < 2:
                return {
                    "success": True,
                    "clones": [],
                    "message": "没有足够的代码单元进行克隆检测"
                }

            # 生成所有嵌入
            codes = [unit.code for unit in filtered_units]
            embed_response = self.embedding_client.embed(codes)

            if not embed_response or not embed_response.embeddings or len(embed_response.embeddings) != len(filtered_units):
                return {"success": False, "error": "嵌入生成失败"}

            embeddings = embed_response.embeddings

            # 计算相似度矩阵并找出克隆
            clones = []
            for i in range(len(filtered_units)):
                for j in range(i + 1, len(filtered_units)):
                    similarity = self._cosine_similarity(embeddings[i], embeddings[j])

                    if similarity >= min_similarity:
                        unit_a = filtered_units[i]
                        unit_b = filtered_units[j]

                        clones.append({
                            "similarity": round(similarity, 3),
                            "code_a": {
                                "file_path": unit_a.file_path,
                                "symbol": unit_a.symbol,
                                "line_start": unit_a.span.start_line,
                                "lines": unit_a.code.count('\n') + 1,
                            },
                            "code_b": {
                                "file_path": unit_b.file_path,
                                "symbol": unit_b.symbol,
                                "line_start": unit_b.span.start_line,
                                "lines": unit_b.code.count('\n') + 1,
                            },
                        })

                        if len(clones) >= max_results:
                            break

                if len(clones) >= max_results:
                    break

            # 按相似度排序
            clones.sort(key=lambda x: x["similarity"], reverse=True)

            return {
                "success": True,
                "clones": clones,
                "total_found": len(clones),
                "units_analyzed": len(filtered_units),
            }

        except Exception as e:
            logger.error(f"detect_code_clones 失败: {e}")
            return {"success": False, "error": str(e)}

    def _cosine_similarity(self, vec_a: List[float], vec_b: List[float]) -> float:
        """计算余弦相似度"""
        if not vec_a or not vec_b or len(vec_a) != len(vec_b):
            return 0.0

        dot_product = sum(a * b for a, b in zip(vec_a, vec_b))
        norm_a = sum(a * a for a in vec_a) ** 0.5
        norm_b = sum(b * b for b in vec_b) ** 0.5

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return dot_product / (norm_a * norm_b)

    def create_vuln_pattern(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行 create_vuln_pattern 工具"""
        pattern_name = args.get("pattern_name")
        pattern_type = args.get("pattern_type")
        finding_id = args.get("finding_id")
        description = args.get("description", "")
        sink_functions = args.get("sink_functions", [])

        if not pattern_name or not pattern_type:
            return {"success": False, "error": "pattern_name 和 pattern_type 是必需参数"}

        # P0-3.3: 增强变体分析器依赖检查
        if not self.analyzer:
            return {
                "success": False,
                "error": "变体分析器未配置",
                "hint": "请确保在创建 VariantToolExecutor 时传入 variant_analyzer 参数。"
                       "需要先创建 VariantAnalyzer 实例并注入到执行器中。",
            }

        try:
            # 构建 finding 数据
            finding = {
                "id": finding_id,
                "issue_type": pattern_type,
                "summary": description,
                "sinks": sink_functions,
                "category": pattern_type,
            }

            # 获取代码上下文
            code_context = ""
            if finding_id:
                # 尝试从代码单元获取
                for unit in self.code_units:
                    if unit.id == finding_id:
                        code_context = unit.code
                        break

            if not code_context:
                code_context = f"Pattern: {pattern_name}\nType: {pattern_type}\nDescription: {description}"

            # 创建模式
            pattern = self.analyzer.confirm_vulnerability(
                finding=finding,
                code_context=code_context,
            )

            return {
                "success": True,
                "pattern_id": pattern.id,
                "pattern_name": pattern.name,
                "pattern_type": pattern.pattern_type.value,
                "message": f"已创建漏洞模式 {pattern.id}，可以使用 search_variants 搜索变体"
            }

        except Exception as e:
            logger.error(f"create_vuln_pattern 失败: {e}")
            return {"success": False, "error": str(e)}

    def search_variants(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行 search_variants 工具"""
        pattern_id = args.get("pattern_id")
        pattern_type = args.get("pattern_type")
        similarity_threshold = args.get("similarity_threshold", 0.75)
        use_llm_verification = args.get("use_llm_verification", False)
        max_results = args.get("max_results", 20)

        # P0-3.3: 增强变体分析器依赖检查
        if not self.analyzer:
            return {
                "success": False,
                "error": "变体分析器未配置",
                "hint": "请确保在创建 VariantToolExecutor 时传入 variant_analyzer 参数。"
                       "需要先创建 VariantAnalyzer 实例并注入到执行器中。",
            }

        try:
            if pattern_id:
                # 按模式 ID 搜索
                variants = self.analyzer.search_variants(
                    pattern_id=pattern_id,
                    top_k=max_results,
                    similarity_threshold=similarity_threshold,
                    use_llm_verification=use_llm_verification,
                )
            elif pattern_type:
                # 按类型搜索所有相关模式的变体
                variants = []
                for pid, pattern in self.analyzer.patterns.items():
                    if pattern.pattern_type.value == pattern_type:
                        pattern_variants = self.analyzer.search_variants(
                            pattern_id=pid,
                            top_k=max_results // 2,
                            similarity_threshold=similarity_threshold,
                            use_llm_verification=use_llm_verification,
                        )
                        variants.extend(pattern_variants)
            else:
                return {"success": False, "error": "需要提供 pattern_id 或 pattern_type"}

            # 格式化结果
            results = []
            for v in variants[:max_results]:
                results.append({
                    "id": v.id,
                    "file_path": v.file_path,
                    "function_name": v.function_name,
                    "line_start": v.line_start,
                    "similarity_score": round(v.similarity_score, 3),
                    "status": v.status,
                    "code_preview": v.code_snippet[:200] if v.code_snippet else "",
                })

            return {
                "success": True,
                "variants": results,
                "total_found": len(results),
            }

        except Exception as e:
            logger.error(f"search_variants 失败: {e}")
            return {"success": False, "error": str(e)}

    def list_vuln_patterns(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """执行 list_vuln_patterns 工具"""
        pattern_type = args.get("pattern_type", "all")
        include_stats = args.get("include_stats", True)

        # P0-3.3: 增强变体分析器依赖检查
        if not self.analyzer:
            return {
                "success": False,
                "error": "变体分析器未配置",
                "hint": "请确保在创建 VariantToolExecutor 时传入 variant_analyzer 参数。"
                       "需要先创建 VariantAnalyzer 实例并注入到执行器中。",
            }

        patterns = []
        for pid, pattern in self.analyzer.patterns.items():
            # 类型过滤
            if pattern_type != "all" and pattern.pattern_type.value != pattern_type:
                continue

            pattern_info = {
                "id": pid,
                "name": pattern.name,
                "pattern_type": pattern.pattern_type.value,
                "description": pattern.description[:100] if pattern.description else "",
                "severity": pattern.severity,
                "created_at": pattern.created_at,
            }

            if include_stats:
                pattern_info["variants_found"] = pattern.variants_found
                pattern_info["false_positives"] = pattern.false_positives

            patterns.append(pattern_info)

        return {
            "success": True,
            "patterns": patterns,
            "total": len(patterns),
        }

    def get_executors(self) -> Dict[str, callable]:
        """返回所有执行器映射"""
        return {
            "find_similar_code": self.find_similar_code,
            "detect_code_clones": self.detect_code_clones,
            "create_vuln_pattern": self.create_vuln_pattern,
            "search_variants": self.search_variants,
            "list_vuln_patterns": self.list_vuln_patterns,
        }


def get_variant_tool_definitions() -> List[Dict[str, Any]]:
    """获取变体分析工具定义列表"""
    return VARIANT_TOOL_DEFINITIONS.copy()


def create_variant_executor(
    variant_analyzer = None,
    vector_store = None,
    embedding_client = None,
    code_units: List = None,
) -> VariantToolExecutor:
    """创建变体分析工具执行器"""
    return VariantToolExecutor(
        variant_analyzer=variant_analyzer,
        vector_store=vector_store,
        embedding_client=embedding_client,
        code_units=code_units,
    )
