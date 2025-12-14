"""
安全分析引擎 - 核心分析逻辑
"""

import json
import logging
import re
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import AuditConfig
from llm_client import BaseLLMClient, ChatMessage
from indexer import CodeIndexer, CodeUnit
from rules import RuleManager, RuleType

from .models import Finding, Candidate, AnalysisContext, Severity, Evidence
from .prompts import build_analysis_prompt

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """安全分析引擎

    负责：
    1. 发现候选分析点
    2. 构建分析上下文
    3. 调用 LLM 进行深度分析
    4. 解析和验证结果
    """

    def __init__(
        self,
        config: AuditConfig,
        llm_client: BaseLLMClient,
        indexer: CodeIndexer,
        rule_manager: RuleManager,
    ):
        self.config = config
        self.llm_client = llm_client
        self.indexer = indexer
        self.rule_manager = rule_manager

        # 新增：调用链和污点分析器
        self.call_chain_analyzer = None
        self.taint_analyzer = None
        self._call_graph = None
        self._taint_flows = None

        # 新增：Agent 模式标志
        self.use_agent_mode = True  # 默认使用 Agent 模式

    def discover_candidates(
        self,
        language: Optional[str] = None,
        file_pattern: Optional[str] = None,
        max_candidates: int = 100,
    ) -> List[Candidate]:
        """发现候选分析点

        通过静态规则匹配找到可能有问题的代码位置
        """
        candidates = []

        # 获取危险函数规则
        sinks = self.rule_manager.get_sinks(language)

        # 从向量库搜索包含危险函数调用的代码
        for sink_rule in sinks:
            for pattern in sink_rule.patterns[:3]:  # 每个规则最多搜索3个模式
                # 构建搜索查询
                if pattern.startswith(("regex:", "prefix:", "suffix:", "contains:")):
                    search_term = pattern.split(":", 1)[1]
                else:
                    search_term = pattern

                # 搜索相关代码
                results = self.indexer.search(
                    query=f"调用 {search_term} 函数",
                    top_k=20,
                    language=language,
                    file_pattern=file_pattern,
                )

                for unit in results:
                    # 检查代码中是否真的包含该调用
                    if self._contains_pattern(unit.code, sink_rule.patterns):
                        # 计算优先级
                        priority = self._calculate_priority(unit, sink_rule)

                        candidates.append(Candidate(
                            code_unit_id=unit.id,
                            file_path=unit.file_path,
                            symbol=unit.symbol,
                            line_start=unit.span.start_line,
                            line_end=unit.span.end_line,
                            code=unit.code,
                            triggered_rules=[sink_rule.id],
                            priority=priority,
                        ))

        # 去重和排序
        seen_ids = set()
        unique_candidates = []
        for c in candidates:
            if c.code_unit_id not in seen_ids:
                seen_ids.add(c.code_unit_id)
                unique_candidates.append(c)

        # 按优先级排序
        unique_candidates.sort(key=lambda x: x.priority, reverse=True)

        logger.info(f"Discovered {len(unique_candidates)} candidates")
        return unique_candidates[:max_candidates]

    def _contains_pattern(self, code: str, patterns: List[str]) -> bool:
        """检查代码是否包含指定模式"""
        for pattern in patterns:
            if pattern.startswith("regex:"):
                if re.search(pattern[6:], code):
                    return True
            elif pattern.startswith("prefix:"):
                if pattern[7:] in code:
                    return True
            elif pattern.startswith("suffix:"):
                if pattern[7:] in code:
                    return True
            elif pattern.startswith("contains:"):
                if pattern[9:] in code:
                    return True
            else:
                if pattern in code:
                    return True
        return False

    def _calculate_priority(self, unit: CodeUnit, rule) -> float:
        """计算分析优先级"""
        score = 0.0

        # 基于风险等级
        risk_scores = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
        score += risk_scores.get(rule.risk_level.value, 0.5)

        # 基于代码类型
        type_scores = {
            "handler": 0.3,  # Web 处理器优先级高
            "method": 0.2,
            "function": 0.15,
            "class": 0.1,
        }
        score += type_scores.get(unit.unit_type.value, 0.1)

        # 基于是否有可疑装饰器
        suspicious_decorators = {"route", "api", "post", "put", "delete", "admin"}
        for dec in unit.decorators:
            if any(s in dec.lower() for s in suspicious_decorators):
                score += 0.1
                break

        return min(score, 1.0)

    def build_context(
        self,
        candidate: Candidate,
        max_related: int = 5,
    ) -> AnalysisContext:
        """构建分析上下文"""
        # 获取主代码单元
        unit = self.indexer.get_unit(candidate.code_unit_id)
        if not unit:
            # 如果找不到，使用候选点的信息
            target_code = candidate.code
            language = "unknown"
        else:
            target_code = unit.code
            language = unit.language

        # 获取相关代码
        related_code = []

        # 1. 查找调用的函数
        if unit and unit.calls:
            for call_name in unit.calls[:3]:
                related_units = self.indexer.search(
                    query=call_name,
                    top_k=1,
                    language=language,
                )
                for related in related_units:
                    if related.id != candidate.code_unit_id:
                        related_code.append({
                            "file": related.file_path,
                            "symbol": related.symbol,
                            "code": related.code[:800],
                        })

        # 2. 查找类的其他方法（如果是方法）
        if unit and unit.parent_class:
            class_methods = self.indexer.search(
                query=unit.parent_class,
                top_k=3,
                language=language,
            )
            for method in class_methods:
                if method.id != candidate.code_unit_id:
                    related_code.append({
                        "file": method.file_path,
                        "symbol": method.symbol,
                        "code": method.code[:600],
                    })

        # 限制相关代码数量
        related_code = related_code[:max_related]

        # 获取规则摘要
        rules_summary = self.rule_manager.get_rules_summary(
            language=language,
            categories=self.config.rules.enabled_categories,
            max_rules=30,
        )

        # 推断业务上下文
        business_context = self._infer_business_context(unit or candidate)

        return AnalysisContext(
            target_code=target_code,
            target_file=candidate.file_path,
            target_symbol=candidate.symbol,
            target_line_start=candidate.line_start,
            related_code=related_code,
            rules_summary=rules_summary,
            business_context=business_context,
            triggered_rules=candidate.triggered_rules,
        )

    def _infer_business_context(self, source) -> str:
        """推断业务上下文"""
        context_hints = []

        # 从符号名推断
        symbol = source.symbol if hasattr(source, 'symbol') else source
        symbol_lower = symbol.lower()

        if any(kw in symbol_lower for kw in ["login", "auth", "signin", "signup"]):
            context_hints.append("该函数可能处理用户认证相关逻辑")
        if any(kw in symbol_lower for kw in ["payment", "pay", "order", "checkout"]):
            context_hints.append("该函数可能处理支付/订单相关逻辑")
        if any(kw in symbol_lower for kw in ["delete", "remove", "destroy"]):
            context_hints.append("该函数可能执行删除操作，需要特别关注权限验证")
        if any(kw in symbol_lower for kw in ["admin", "manage", "config"]):
            context_hints.append("该函数可能是管理功能，应验证管理员权限")
        if any(kw in symbol_lower for kw in ["user", "profile", "account"]):
            context_hints.append("该函数可能操作用户数据，需关注越权风险")
        if any(kw in symbol_lower for kw in ["upload", "file", "import"]):
            context_hints.append("该函数可能处理文件上传，需关注文件类型和路径验证")

        # 从装饰器推断
        if hasattr(source, 'decorators'):
            for dec in source.decorators:
                if "admin" in dec.lower():
                    context_hints.append("该函数标记为需要管理员权限")
                if "login_required" in dec.lower() or "authenticated" in dec.lower():
                    context_hints.append("该函数需要用户登录")

        return "\n".join(context_hints) if context_hints else ""

    def analyze_candidate(
        self,
        candidate: Candidate,
        focus_category: Optional[str] = None,
    ) -> Optional[Finding]:
        """分析单个候选点"""
        logger.debug(f"Analyzing: {candidate.file_path}:{candidate.symbol}")

        # 构建上下文
        context = self.build_context(candidate)

        # 构建提示词
        system_prompt, user_prompt = build_analysis_prompt(
            context.to_prompt(),
            focus_category=focus_category,
        )

        # 调用 LLM
        try:
            response = self.llm_client.chat_completion(
                messages=[
                    ChatMessage(role="system", content=system_prompt),
                    ChatMessage(role="user", content=user_prompt),
                ],
                response_format={"type": "json_object"},
                temperature=0.0,
            )

            # 解析响应
            result = self._parse_llm_response(response.content)

            if result and result.get("has_issue"):
                return self._create_finding(candidate, context, result)

        except Exception as e:
            logger.error(f"Analysis failed for {candidate.symbol}: {e}")

        return None

    def _parse_llm_response(self, content: str) -> Optional[Dict[str, Any]]:
        """解析 LLM 响应"""
        try:
            # 尝试直接解析 JSON
            return json.loads(content)
        except json.JSONDecodeError:
            # 尝试提取 JSON 块
            json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', content)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass

            # 尝试找到 { } 块
            brace_match = re.search(r'\{[\s\S]*\}', content)
            if brace_match:
                try:
                    return json.loads(brace_match.group(0))
                except json.JSONDecodeError:
                    pass

            logger.warning(f"Failed to parse LLM response: {content[:200]}")
            return None

    def _create_finding(
        self,
        candidate: Candidate,
        context: AnalysisContext,
        result: Dict[str, Any],
    ) -> Finding:
        """从分析结果创建 Finding"""
        # 解析严重性
        severity_map = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }
        severity = severity_map.get(result.get("severity", "medium"), Severity.MEDIUM)

        # 解析证据
        evidence_list = []
        for e in result.get("evidence", []):
            if isinstance(e, dict):
                evidence_list.append(Evidence(
                    file_path=e.get("location", candidate.file_path),
                    line_start=candidate.line_start,
                    line_end=candidate.line_end,
                    code_snippet=e.get("snippet", ""),
                    description=e.get("reason", ""),
                ))

        return Finding(
            id=Finding.generate_id(),
            title=result.get("issue_type", "未知问题"),
            category=result.get("issue_type", "other"),
            severity=severity,
            confidence=float(result.get("confidence", 0.5)),
            file_path=candidate.file_path,
            symbol=candidate.symbol,
            line_start=candidate.line_start,
            line_end=candidate.line_end,
            summary=result.get("summary", ""),
            details=result.get("details", ""),
            attack_scenario=result.get("attack_scenario", ""),
            evidence=evidence_list,
            fix_suggestion=result.get("fix_suggestion", ""),
            notes=result.get("notes", ""),
            rule_ids=candidate.triggered_rules,
        )

    def analyze(
        self,
        language: Optional[str] = None,
        file_pattern: Optional[str] = None,
        max_candidates: int = 50,
        max_workers: int = 2,
        use_agent: Optional[bool] = None,
    ) -> List[Finding]:
        """执行完整分析流程

        Args:
            language: 限定语言
            file_pattern: 文件模式
            max_candidates: 最大候选点数量
            max_workers: 并行分析数量
            use_agent: 是否使用 Agent 模式（None 则使用默认配置）

        Returns:
            Finding 列表
        """
        use_agent_mode = use_agent if use_agent is not None else self.use_agent_mode

        if use_agent_mode:
            logger.info("Using Agent-based analysis mode")
            return self.analyze_with_agent(
                language=language,
                file_pattern=file_pattern,
                max_candidates=max_candidates,
            )
        else:
            logger.info("Using legacy analysis mode")
            return self.analyze_legacy(
                language=language,
                file_pattern=file_pattern,
                max_candidates=max_candidates,
                max_workers=max_workers,
            )

    def analyze_with_agent(
        self,
        language: Optional[str] = None,
        file_pattern: Optional[str] = None,
        max_candidates: int = 50,
    ) -> List[Finding]:
        """使用 Agent 模式进行分析（新方法）

        流程：
        1. 构建调用图和污点分析
        2. 发现候选点
        3. 为每个候选点使用 Agent 进行深度分析
        """
        logger.info("Starting Agent-based security analysis...")

        # 1. 准备分析环境
        self._prepare_analysis_environment()

        # 2. 发现候选点
        candidates = self.discover_candidates(
            language=language,
            file_pattern=file_pattern,
            max_candidates=max_candidates,
        )

        if not candidates:
            logger.info("No candidates found")
            return []

        logger.info(f"Analyzing {len(candidates)} candidates with Agent...")

        # 3. 使用 Agent 分析每个候选点
        findings = []
        for i, candidate in enumerate(candidates):
            logger.info(f"[{i+1}/{len(candidates)}] Analyzing {candidate.symbol}")

            finding = self._analyze_candidate_with_agent(candidate)
            if finding:
                findings.append(finding)
                logger.info(f"  -> Found issue: {finding.title}")

        # 4. 排序和过滤
        findings = self._filter_and_sort_findings(findings)

        logger.info(f"Agent analysis complete. Found {len(findings)} issues.")
        return findings

    def analyze_legacy(
        self,
        language: Optional[str] = None,
        file_pattern: Optional[str] = None,
        max_candidates: int = 50,
        max_workers: int = 2,
    ) -> List[Finding]:
        """原始分析流程（保留作为 fallback）"""
        logger.info("Starting security analysis...")

        # 1. 发现候选点
        candidates = self.discover_candidates(
            language=language,
            file_pattern=file_pattern,
            max_candidates=max_candidates,
        )

        if not candidates:
            logger.info("No candidates found")
            return []

        logger.info(f"Analyzing {len(candidates)} candidates...")

        # 2. 分析候选点
        findings = []

        # 使用线程池并行分析（注意 API 速率限制）
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.analyze_candidate, c): c
                for c in candidates
            }

            for i, future in enumerate(as_completed(futures)):
                candidate = futures[future]
                try:
                    finding = future.result()
                    if finding:
                        findings.append(finding)
                        logger.info(
                            f"[{i+1}/{len(candidates)}] Found issue: "
                            f"{finding.title} in {finding.file_path}"
                        )
                except Exception as e:
                    logger.error(f"Analysis error for {candidate.symbol}: {e}")

        # 3. 排序和过滤
        findings = self._filter_and_sort_findings(findings)

        logger.info(f"Analysis complete. Found {len(findings)} issues.")
        return findings

    def _prepare_analysis_environment(self):
        """准备分析环境（构建调用图和污点分析）"""
        from .call_chain import CallChainAnalyzer
        from .taint_analysis import TaintAnalyzer

        # 获取所有代码单元
        code_units = self.indexer.get_all_units()

        # 构建调用图
        if self.call_chain_analyzer is None:
            logger.info("Initializing call chain analyzer...")
            self.call_chain_analyzer = CallChainAnalyzer(self.rule_manager)

        if self._call_graph is None:
            logger.info("Building call graph...")
            self._call_graph = self.call_chain_analyzer.build_call_graph(code_units)
            logger.info(
                f"Call graph built: {len(self._call_graph.nodes)} nodes, "
                f"{len(self._call_graph.edges)} edges"
            )

        # 执行污点分析
        if self.taint_analyzer is None:
            logger.info("Initializing taint analyzer...")
            self.taint_analyzer = TaintAnalyzer(self.rule_manager, self._call_graph)

        if self._taint_flows is None:
            logger.info("Running interprocedural taint analysis...")
            self._taint_flows = self.taint_analyzer.analyze_interprocedural(
                code_units,
                max_depth=10,
                use_topological=True,
            )
            logger.info(f"Taint analysis complete: {len(self._taint_flows)} flows")

    def _analyze_candidate_with_agent(self, candidate: Candidate) -> Optional[Finding]:
        """使用 Agent 分析候选点"""
        try:
            from agent import EnhancedSecurityAgent
            from indexer import CodeReader

            # 创建 CodeReader
            code_reader = CodeReader(
                project_path=self.config.scan.target_path,
                indexer=self.indexer,
            )

            # 创建增强 Agent
            agent = EnhancedSecurityAgent(
                llm_client=self.llm_client,
                code_reader=code_reader,
                indexer=self.indexer,
                call_chain_analyzer=self.call_chain_analyzer,
                taint_analyzer=self.taint_analyzer,
                max_tool_calls=15,
            )

            # 准备 Agent 的分析环境
            agent._call_graph = self._call_graph
            agent._taint_flows = self._taint_flows

            # 构建分析任务
            task = self._build_agent_task(candidate)

            # 执行分析
            result = agent.analyze(
                task=task,
                context=self._build_candidate_context(candidate),
            )

            # 解析结果
            if result.error:
                logger.error(f"Agent error: {result.error}")
                return None

            finding = self._parse_agent_result(result, candidate)
            return finding

        except Exception as e:
            logger.error(f"Agent analysis failed for {candidate.symbol}: {e}")
            # Fallback to legacy method
            return self.analyze_candidate(candidate)

    def _build_agent_task(self, candidate: Candidate) -> str:
        """构建 Agent 分析任务"""
        rules_text = ", ".join(candidate.triggered_rules)

        task = f"""请分析以下代码是否存在安全漏洞：

**目标函数**: {candidate.symbol}
**文件位置**: {candidate.file_path}:{candidate.line_start}-{candidate.line_end}
**触发规则**: {rules_text}

请按以下步骤进行分析：
1. 使用 read_symbol 读取目标函数的完整代码
2. 使用 analyze_call_chain 了解调用关系，识别入口点和调用链
3. 如果涉及用户输入，使用 trace_taint_path 追踪污点传播
4. 根据需要使用 get_code_context 获取完整上下文
5. 检查以下安全问题：
   - 认证和授权是否正确
   - 用户输入是否经过验证
   - 业务流程是否可被绕过
   - 是否存在越权访问风险

最后以 JSON 格式返回分析结果，包含：
- has_issue: boolean
- issue_type: string
- severity: "low" | "medium" | "high" | "critical"
- confidence: 0-1
- summary: string
- details: string
- attack_scenario: string
- fix_suggestion: string
- notes: string"""

        return task

    def _build_candidate_context(self, candidate: Candidate) -> str:
        """构建候选点上下文"""
        context_parts = []

        # 代码预览
        code_preview = candidate.code[:500] if len(candidate.code) > 500 else candidate.code
        context_parts.append(f"代码预览：\n```\n{code_preview}\n```")

        return "\n\n".join(context_parts)

    def _parse_agent_result(self, agent_result: "AgentResult", candidate: Candidate) -> Optional[Finding]:
        """从 Agent 结果解析 Finding"""
        try:
            # 尝试从 content 中解析 JSON
            result_data = self._parse_llm_response(agent_result.content)

            if not result_data or not result_data.get("has_issue"):
                logger.debug(f"No issue found in {candidate.symbol}")
                return None

            # 创建 Finding
            finding = self._create_finding(candidate, None, result_data)

            # 添加 Agent 元数据
            finding.metadata["agent_tool_calls"] = agent_result.total_tool_calls
            finding.metadata["agent_total_tokens"] = agent_result.total_tokens

            return finding

        except Exception as e:
            logger.error(f"Failed to parse agent result: {e}")
            return None

    def _filter_and_sort_findings(self, findings: List[Finding]) -> List[Finding]:
        """过滤和排序发现"""
        # 按严重性排序
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }
        findings.sort(key=lambda f: (severity_order.get(f.severity, 4), -f.confidence))

        # 按置信度过滤
        min_confidence = self.config.report.min_confidence
        findings = [f for f in findings if f.confidence >= min_confidence]

        return findings
