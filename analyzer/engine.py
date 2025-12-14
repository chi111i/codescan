"""
安全分析引擎 - 核心分析逻辑
"""

import json
import logging
import re
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import AuditConfig
from llm_client import BaseLLMClient, ChatMessage, OutputValidator, CHAIN_ANALYSIS_SCHEMA
from indexer import CodeIndexer, CodeUnit
from rules import RuleManager, RuleType

from .models import Finding, Candidate, AnalysisContext, Severity, Evidence
from .prompts import build_analysis_prompt, build_chain_analysis_prompt
from .sink_scanner import SinkCallScanner, SinkCallSite, SinkCategory
from .chain_context import ChainContextCollector, ChainContext

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

        # 新增：SinkCallScanner 确定性扫描器
        self.sink_scanner = SinkCallScanner(rule_manager)

        # 新增：调用链和污点分析器
        self.call_chain_analyzer = None
        self.taint_analyzer = None
        self._call_graph = None
        self._taint_flows = None

        # 新增：Agent 模式标志
        self.use_agent_mode = True  # 默认使用 Agent 模式

        # 新增：输出验证器（用于链级分析）
        self.output_validator = OutputValidator(
            project_root=config.scan.target_path,
            min_confidence=config.rules.min_confidence if hasattr(config.rules, 'min_confidence') else 0.0,
        )

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

        # 获取所有规则（包括 sink 和 pattern 类型）
        sinks = self.rule_manager.get_sinks(language)
        patterns = self.rule_manager.get_rules_by_type(RuleType.PATTERN)
        if language:
            patterns = [r for r in patterns if language in r.languages]

        all_rules = sinks + patterns
        logger.info(f"Searching for {len(all_rules)} rules (sinks: {len(sinks)}, patterns: {len(patterns)})...")

        # 从向量库搜索包含危险函数调用的代码
        for rule in all_rules:
            for pattern in rule.patterns[:3]:  # 每个规则最多搜索3个模式
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
                    if self._contains_pattern(unit.code, rule.patterns):
                        # 计算优先级
                        priority = self._calculate_priority(unit, rule)

                        candidates.append(Candidate(
                            code_unit_id=unit.id,
                            file_path=unit.file_path,
                            symbol=unit.symbol,
                            line_start=unit.span.start_line,
                            line_end=unit.span.end_line,
                            code=unit.code,
                            triggered_rules=[rule.id],
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

    def discover_candidates_from_units(
        self,
        code_units: List[CodeUnit],
        language: Optional[str] = None,
        max_candidates: int = 100,
    ) -> List[Candidate]:
        """从给定的代码单元列表中发现候选分析点（不使用向量搜索）

        适用于 skip_index 模式，直接遍历代码单元进行模式匹配
        """
        candidates = []

        # 获取所有规则（包括 sink 和 pattern 类型）
        sinks = self.rule_manager.get_sinks(language)
        patterns = self.rule_manager.get_rules_by_type(RuleType.PATTERN)
        if language:
            patterns = [r for r in patterns if language in r.languages]

        all_rules = sinks + patterns
        print(f"[DISCOVER] 扫描 {len(code_units)} 个代码单元，使用 {len(all_rules)} 条规则 (sinks: {len(sinks)}, patterns: {len(patterns)})")
        logger.info(f"Scanning {len(code_units)} code units for {len(all_rules)} rules (sinks: {len(sinks)}, patterns: {len(patterns)})...")

        # 调试：显示 PHP 相关规则
        php_rules = [r for r in all_rules if 'php' in r.languages]
        print(f"[DISCOVER] PHP 规则数: {len(php_rules)}")
        if php_rules:
            print(f"[DISCOVER] PHP 规则示例: {[r.id for r in php_rules[:5]]}")
            print(f"[DISCOVER] 第一条 PHP 规则的模式: {php_rules[0].patterns[:5] if php_rules else 'none'}")

        # 遍历所有代码单元
        for unit in code_units:
            print(f"[DISCOVER] 检查代码单元: {unit.symbol}, 语言: {unit.language}")
            print(f"[DISCOVER] 代码预览: {unit.code[:300]}...")

            # 如果指定了语言，跳过不匹配的
            if language and unit.language != language:
                print(f"[DISCOVER] 跳过（语言不匹配）: {unit.language} != {language}")
                continue

            # 检查每个规则
            matched_rule = None
            print(f"[DISCOVER] 开始对 {len(all_rules)} 条规则进行模式匹配...")

            # 首先手动检查代码中是否包含常见的危险函数关键词
            code_lower = unit.code.lower()
            dangerous_keywords = ['mysql_query', 'mysqli_query', 'exec(', 'eval(', 'system(', 'shell_exec', '$_get', '$_post', '$_request']
            found_keywords = [kw for kw in dangerous_keywords if kw in code_lower]
            if found_keywords:
                print(f"[DISCOVER] 代码中发现危险关键词: {found_keywords}")
            else:
                print(f"[DISCOVER] 代码中未发现常见危险关键词")

            for rule in all_rules:
                if self._contains_pattern(unit.code, rule.patterns, debug=True):
                    matched_rule = rule
                    print(f"[DISCOVER] 匹配规则: {rule.id}, 模式: {rule.patterns[:3]}")
                    # 计算优先级
                    priority = self._calculate_priority(unit, rule)

                    candidates.append(Candidate(
                        code_unit_id=unit.id,
                        file_path=unit.file_path,
                        symbol=unit.symbol,
                        line_start=unit.span.start_line,
                        line_end=unit.span.end_line,
                        code=unit.code,
                        triggered_rules=[rule.id],
                        priority=priority,
                    ))
                    break  # 每个代码单元只记录一次

            if not matched_rule:
                print(f"[DISCOVER] 未匹配任何规则")

        # 按优先级排序
        candidates.sort(key=lambda x: x.priority, reverse=True)

        print(f"[DISCOVER] 发现 {len(candidates)} 个候选点")
        logger.info(f"Discovered {len(candidates)} candidates from direct scan")
        return candidates[:max_candidates]

    def discover_sink_sites(
        self,
        code_units: List[CodeUnit],
        language: Optional[str] = None,
    ) -> List[SinkCallSite]:
        """使用 SinkCallScanner 确定性扫描危险函数触发点

        这是目标文档 P0-1 的核心实现：不使用向量检索，
        而是使用 AST/正则进行确定性扫描。

        Args:
            code_units: 代码单元列表
            language: 限定语言

        Returns:
            SinkCallSite 列表
        """
        logger.info(f"[SinkScanner] 开始确定性扫描 {len(code_units)} 个代码单元")

        # 使用 SinkCallScanner 进行扫描
        sink_sites = self.sink_scanner.scan(
            code_units=code_units,
            language=language,
        )

        # 输出统计信息
        stats = self.sink_scanner.get_statistics(sink_sites)
        logger.info(f"[SinkScanner] 扫描完成: {stats}")

        return sink_sites

    def sink_sites_to_candidates(
        self,
        sink_sites: List[SinkCallSite],
    ) -> List[Candidate]:
        """将 SinkCallSite 转换为 Candidate

        Args:
            sink_sites: SinkCallSite 列表

        Returns:
            Candidate 列表
        """
        candidates = []

        for site in sink_sites:
            # 计算优先级（基于风险等级和置信度）
            risk_scores = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
            priority = risk_scores.get(site.risk_level.value, 0.5) * site.confidence

            candidate = Candidate(
                code_unit_id=site.unit_id,
                file_path=site.file_path,
                symbol=site.symbol,
                line_start=site.line_start,
                line_end=site.line_end,
                code=site.call_snippet,
                triggered_rules=site.matched_rule_ids,
                priority=priority,
            )
            candidates.append(candidate)

        # 按优先级排序
        candidates.sort(key=lambda x: x.priority, reverse=True)

        return candidates

    def analyze_with_sink_scanner(
        self,
        code_units: List[CodeUnit],
        language: Optional[str] = None,
        max_candidates: int = 50,
        max_workers: int = 2,
    ) -> List[Finding]:
        """使用 SinkCallScanner 确定性扫描 + LLM 分析的完整流程

        这是目标文档推荐的分析流程：
        1. 确定性扫描所有危险函数触发点
        2. 转换为候选点
        3. 为每个候选点调用 LLM 进行深度分析

        Args:
            code_units: 代码单元列表
            language: 限定语言
            max_candidates: 最大候选点数量
            max_workers: 并行分析数量

        Returns:
            Finding 列表
        """
        logger.info(f"[SinkScan] 开始确定性扫描分析流程...")

        # 1. 使用 SinkCallScanner 扫描危险函数触发点
        sink_sites = self.discover_sink_sites(code_units, language)

        if not sink_sites:
            logger.info("[SinkScan] 未发现任何危险函数触发点")
            return []

        logger.info(f"[SinkScan] 发现 {len(sink_sites)} 个危险函数触发点")

        # 2. 转换为候选点
        candidates = self.sink_sites_to_candidates(sink_sites)
        candidates = candidates[:max_candidates]

        logger.info(f"[SinkScan] 转换为 {len(candidates)} 个候选点，开始 LLM 分析...")

        # 3. 使用 LLM 分析每个候选点
        findings = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._analyze_candidate_simple, c, code_units): c
                for c in candidates
            }

            for i, future in enumerate(as_completed(futures)):
                candidate = futures[future]
                try:
                    finding = future.result()
                    if finding:
                        findings.append(finding)
                        logger.info(
                            f"[{i+1}/{len(candidates)}] 发现问题: "
                            f"{finding.title} in {finding.file_path}"
                        )
                except Exception as e:
                    logger.error(f"分析错误 {candidate.symbol}: {e}")

        # 4. 排序和过滤
        findings = self._filter_and_sort_findings(findings)

        logger.info(f"[SinkScan] 分析完成，发现 {len(findings)} 个安全问题")
        return findings

    def analyze_chains(
        self,
        code_units: List[CodeUnit],
        language: Optional[str] = None,
        max_candidates: int = 50,
        max_workers: int = 2,
        max_chain_depth: int = 5,
    ) -> List[Finding]:
        """统一的链级分析入口（P0 目标推荐流程）

        完整流程：
        1. P0-1: SinkCallScanner 确定性扫描危险函数触发点
        2. P0-2: 构建调用图
        3. P0-3: 枚举调用链（带爆炸控制）
        4. P0-4: ChainContextCollector 收集调用链上下文
        5. P0-5: LLM 链级分析（输出结构化结果）+ 输出验证

        Args:
            code_units: 代码单元列表
            language: 限定语言
            max_candidates: 最大候选点数量
            max_workers: 并行分析数量
            max_chain_depth: 最大调用链深度

        Returns:
            Finding 列表
        """
        from .call_chain import CallChainAnalyzer

        logger.info(f"[P0] 开始链级分析流程，代码单元数: {len(code_units)}")

        # ============================================================
        # P0-1: 使用 SinkCallScanner 确定性扫描危险函数触发点
        # ============================================================
        logger.info("[P0-1] SinkCallScanner 确定性扫描...")
        sink_sites = self.discover_sink_sites(code_units, language)

        if not sink_sites:
            logger.info("[P0-1] 未发现任何危险函数触发点")
            return []

        logger.info(f"[P0-1] 发现 {len(sink_sites)} 个危险函数触发点")

        # 限制候选点数量
        sink_sites = sink_sites[:max_candidates]

        # ============================================================
        # P0-2: 构建调用图
        # ============================================================
        logger.info("[P0-2] 构建调用图...")
        if self.call_chain_analyzer is None:
            self.call_chain_analyzer = CallChainAnalyzer(self.rule_manager)

        if self._call_graph is None:
            self._call_graph = self.call_chain_analyzer.build_call_graph(code_units)
            logger.info(
                f"[P0-2] 调用图: {len(self._call_graph.nodes)} 节点, "
                f"{len(self._call_graph.edges)} 边"
            )

        # ============================================================
        # P0-3 & P0-4: 枚举调用链并收集上下文
        # ============================================================
        logger.info("[P0-3/P0-4] 收集调用链上下文...")
        context_collector = ChainContextCollector(
            call_chain_analyzer=self.call_chain_analyzer,
            code_units=code_units,
        )

        chain_contexts = context_collector.collect_contexts_batch(
            sink_sites=sink_sites,
            max_depth=max_chain_depth,
        )

        if not chain_contexts:
            logger.warning("[P0-4] 未能收集到任何调用链上下文，回退到简单分析")
            # 回退：直接使用 sink_sites 进行简单分析
            return self._analyze_sink_sites_fallback(sink_sites, code_units, max_workers)

        logger.info(f"[P0-4] 收集了 {len(chain_contexts)} 个调用链上下文")

        # ============================================================
        # P0-5: LLM 链级分析
        # ============================================================
        logger.info("[P0-5] 开始 LLM 链级分析...")
        findings = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._analyze_chain_context, ctx, code_units): ctx
                for ctx in chain_contexts
            }

            for i, future in enumerate(as_completed(futures)):
                ctx = futures[future]
                try:
                    finding = future.result()
                    if finding:
                        findings.append(finding)
                        logger.info(
                            f"[{i+1}/{len(chain_contexts)}] 发现问题: "
                            f"{finding.title} (置信度: {finding.confidence:.2f})"
                        )
                except Exception as e:
                    logger.error(f"分析错误 {ctx.sink_site.symbol}: {e}")

        # 排序和过滤
        findings = self._filter_and_sort_findings(findings)

        logger.info(f"[P0] 链级分析完成，发现 {len(findings)} 个安全问题")
        return findings

    def _analyze_sink_sites_fallback(
        self,
        sink_sites: List[SinkCallSite],
        code_units: List[CodeUnit],
        max_workers: int = 2,
    ) -> List[Finding]:
        """回退分析：当无法收集调用链上下文时，直接分析 sink sites

        Args:
            sink_sites: SinkCallSite 列表
            code_units: 代码单元列表
            max_workers: 并行数量

        Returns:
            Finding 列表
        """
        logger.info(f"[Fallback] 直接分析 {len(sink_sites)} 个 sink sites...")

        # 转换为 Candidate
        candidates = self.sink_sites_to_candidates(sink_sites)

        findings = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._analyze_candidate_simple, c, code_units): c
                for c in candidates
            }

            for future in as_completed(futures):
                try:
                    finding = future.result()
                    if finding:
                        findings.append(finding)
                except Exception as e:
                    logger.error(f"Fallback 分析错误: {e}")

        return self._filter_and_sort_findings(findings)

    def analyze_with_chain_context(
        self,
        code_units: List[CodeUnit],
        language: Optional[str] = None,
        max_candidates: int = 50,
        max_workers: int = 2,
        max_chain_depth: int = 5,
    ) -> List[Finding]:
        """使用调用链上下文的完整分析流程（目标文档推荐）

        流程：
        1. SinkCallScanner 确定性扫描
        2. 构建调用图
        3. 为每个 sink 收集调用链上下文
        4. 使用调用链上下文调用 LLM 分析

        Args:
            code_units: 代码单元列表
            language: 限定语言
            max_candidates: 最大候选点数量
            max_workers: 并行分析数量
            max_chain_depth: 最大调用链深度

        Returns:
            Finding 列表
        """
        from .call_chain import CallChainAnalyzer

        logger.info(f"[ChainAnalysis] 开始调用链驱动的分析流程...")

        # 1. 使用 SinkCallScanner 扫描危险函数触发点
        sink_sites = self.discover_sink_sites(code_units, language)

        if not sink_sites:
            logger.info("[ChainAnalysis] 未发现任何危险函数触发点")
            return []

        logger.info(f"[ChainAnalysis] 发现 {len(sink_sites)} 个危险函数触发点")

        # 2. 构建调用图
        if self.call_chain_analyzer is None:
            self.call_chain_analyzer = CallChainAnalyzer(self.rule_manager)

        if self._call_graph is None:
            logger.info("[ChainAnalysis] 构建调用图...")
            self._call_graph = self.call_chain_analyzer.build_call_graph(code_units)
            logger.info(
                f"[ChainAnalysis] 调用图: {len(self._call_graph.nodes)} 节点, "
                f"{len(self._call_graph.edges)} 边"
            )

        # 3. 收集调用链上下文
        logger.info("[ChainAnalysis] 收集调用链上下文...")
        context_collector = ChainContextCollector(
            call_chain_analyzer=self.call_chain_analyzer,
            code_units=code_units,
        )

        chain_contexts = context_collector.collect_contexts_batch(
            sink_sites=sink_sites[:max_candidates],
            max_depth=max_chain_depth,
        )

        logger.info(f"[ChainAnalysis] 收集了 {len(chain_contexts)} 个调用链上下文")

        # 4. 使用调用链上下文进行 LLM 分析
        findings = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._analyze_chain_context, ctx, code_units): ctx
                for ctx in chain_contexts
            }

            for i, future in enumerate(as_completed(futures)):
                ctx = futures[future]
                try:
                    finding = future.result()
                    if finding:
                        findings.append(finding)
                        logger.info(
                            f"[{i+1}/{len(chain_contexts)}] 发现问题: "
                            f"{finding.title} in {finding.file_path}"
                        )
                except Exception as e:
                    logger.error(f"分析错误 {ctx.sink_site.symbol}: {e}")

        # 5. 排序和过滤
        findings = self._filter_and_sort_findings(findings)

        logger.info(f"[ChainAnalysis] 分析完成，发现 {len(findings)} 个安全问题")
        return findings

    def _analyze_chain_context(
        self,
        chain_context: ChainContext,
        code_units: List[CodeUnit],
    ) -> Optional[Finding]:
        """使用调用链上下文分析单个 sink（链级分析）

        根据目标文档 P0-5 的要求：
        - 使用链级分析提示词
        - 输出包含 chain_id, sink_category, data_flow 等字段
        - 集成输出验证器

        Args:
            chain_context: 调用链上下文
            code_units: 代码单元列表

        Returns:
            Finding 或 None
        """
        try:
            sink_site = chain_context.sink_site

            # 生成调用链 ID
            chain_id = f"chain-{sink_site.id}"

            # 获取 sink 类别
            sink_category = sink_site.sink_category.value

            # 构建调用链上下文文本
            context_text = chain_context.to_prompt_text()

            # 添加规则信息
            rule_info_parts = []
            for rule_id in sink_site.matched_rule_ids:
                rule = self.rule_manager.get_rule(rule_id)
                if rule:
                    rule_info_parts.append(f"- {rule.name}: {rule.description}")
                    if rule.cwe_ids:
                        rule_info_parts.append(f"  CWE: {', '.join(rule.cwe_ids)}")

            if rule_info_parts:
                context_text += f"\n\n【触发的安全规则】\n" + "\n".join(rule_info_parts)

            # 使用链级分析提示词（根据目标文档 P0-5）
            system_prompt, user_prompt = build_chain_analysis_prompt(
                chain_context_text=context_text,
                chain_id=chain_id,
                sink_category=sink_category,
            )

            # 调用 LLM
            logger.info(f"[ChainLLM] 分析调用链: {chain_id}, Sink类别: {sink_category}")
            response = self.llm_client.chat_completion(
                messages=[
                    ChatMessage(role="system", content=system_prompt),
                    ChatMessage(role="user", content=user_prompt),
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=2500,
            )

            # 使用输出验证器验证响应
            validation_report = self.output_validator.validate(
                content=response.content,
                schema=CHAIN_ANALYSIS_SCHEMA,
                check_hallucinations=True,
            )

            if not validation_report.is_valid:
                logger.warning(
                    f"[ChainLLM] 输出验证失败 {chain_id}: {validation_report.errors}"
                )
                # 尝试使用原始解析
                result = self._parse_llm_response(response.content)
            else:
                result = validation_report.corrected_data
                if validation_report.warnings:
                    logger.info(f"[ChainLLM] 验证警告 {chain_id}: {validation_report.warnings}")

            if not result:
                logger.warning(f"[ChainLLM] 无法解析响应 {chain_id}")
                return None

            # 检查是否存在问题
            has_issue = result.get("has_issue", False)
            if has_issue is False or has_issue == "false":
                logger.debug(f"[ChainLLM] 调用链 {chain_id} 未发现问题")
                return None

            # 处理 "uncertain" 情况
            is_uncertain = has_issue == "uncertain"

            # 从 LLM 结果提取 evidence
            evidence_list = []
            llm_evidence = result.get("evidence", [])
            if isinstance(llm_evidence, list):
                for e in llm_evidence:
                    if isinstance(e, dict):
                        evidence_list.append(Evidence(
                            file_path=e.get("file_path", sink_site.file_path),
                            line_start=e.get("line_start", sink_site.line_start),
                            line_end=e.get("line_end", sink_site.line_end),
                            code_snippet=e.get("snippet", ""),
                            description=e.get("reason", ""),
                        ))

            # 如果没有提取到 evidence，使用 sink 信息
            if not evidence_list:
                evidence_list.append(Evidence(
                    file_path=sink_site.file_path,
                    line_start=sink_site.line_start,
                    line_end=sink_site.line_end,
                    code_snippet=sink_site.call_snippet,
                    description=result.get("summary", "危险函数调用点"),
                ))

            # 构建 Finding
            logger.info(
                f"[ChainLLM] 发现问题: {result.get('issue_type', 'unknown')} "
                f"(置信度: {result.get('confidence', 0)})"
            )

            return Finding(
                id=f"finding-{chain_id}",
                title=result.get("issue_type", "Security Issue"),
                file_path=sink_site.file_path,
                line_start=sink_site.line_start,
                line_end=sink_site.line_end,
                symbol=sink_site.symbol,
                severity=Severity.from_string(result.get("risk_level", "medium")),
                confidence=result.get("confidence", chain_context.confidence),
                category=result.get("sink_category", sink_category),
                summary=result.get("summary", ""),
                details=result.get("details", "") or result.get("data_flow", ""),
                evidence=evidence_list,
                attack_scenario=result.get("exploitability_conditions", ""),
                fix_suggestion=result.get("fix_suggestion", ""),
                notes=result.get("notes", ""),
                rule_ids=sink_site.matched_rule_ids,
                metadata={
                    # 调用链信息
                    "chain_id": chain_id,
                    "chain_length": chain_context.chain_length,
                    "has_user_input": chain_context.has_user_input,
                    "sanitizers_on_path": chain_context.sanitizers_on_path,
                    # Sink 信息
                    "sink_category": sink_category,
                    # LLM 分析信息
                    "is_uncertain": is_uncertain,
                    "data_flow": result.get("data_flow", ""),
                    "security_controls": result.get("security_controls", []),
                },
            )

        except Exception as e:
            logger.error(f"调用链分析错误 {chain_context.sink_site.symbol}: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None

    def _contains_pattern(self, code: str, patterns: List[str], debug: bool = False) -> bool:
        """检查代码是否包含指定模式"""
        for pattern in patterns:
            matched = False
            if pattern.startswith("regex:"):
                if re.search(pattern[6:], code):
                    matched = True
            elif pattern.startswith("prefix:"):
                if pattern[7:] in code:
                    matched = True
            elif pattern.startswith("suffix:"):
                if pattern[7:] in code:
                    matched = True
            elif pattern.startswith("contains:"):
                if pattern[9:] in code:
                    matched = True
            else:
                if pattern in code:
                    matched = True

            if matched:
                if debug:
                    print(f"[PATTERN] 匹配成功: '{pattern}'")
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
        code_units: Optional[List[CodeUnit]] = None,
        use_chain_analysis: bool = True,
        max_chain_depth: int = 5,
    ) -> List[Finding]:
        """执行完整分析流程

        Args:
            language: 限定语言
            file_pattern: 文件模式
            max_candidates: 最大候选点数量
            max_workers: 并行分析数量
            use_agent: 是否使用 Agent 模式（None 则使用默认配置）
            code_units: 直接提供的代码单元列表（用于 skip_index 模式）
            use_chain_analysis: 是否使用链级分析（默认 True，推荐）
            max_chain_depth: 最大调用链深度

        Returns:
            Finding 列表
        """
        # 如果提供了 code_units，优先使用链级分析
        if code_units is not None:
            logger.info(f"Using direct analysis mode with {len(code_units)} code units")

            # 默认使用链级分析（P0 目标推荐）
            if use_chain_analysis:
                logger.info("[P0] Using chain-level analysis (recommended)")
                return self.analyze_chains(
                    code_units=code_units,
                    language=language,
                    max_candidates=max_candidates,
                    max_workers=max_workers,
                    max_chain_depth=max_chain_depth,
                )
            else:
                # 回退到 SinkScanner 模式
                return self.analyze_units_direct(
                    code_units=code_units,
                    language=language,
                    max_candidates=max_candidates,
                    max_workers=max_workers,
                )

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

    def analyze_units_direct(
        self,
        code_units: List[CodeUnit],
        language: Optional[str] = None,
        max_candidates: int = 50,
        max_workers: int = 2,
        use_sink_scanner: bool = True,
    ) -> List[Finding]:
        """直接分析代码单元列表（不使用向量索引）

        适用于 skip_index 模式

        Args:
            code_units: 代码单元列表
            language: 限定语言
            max_candidates: 最大候选点数量
            max_workers: 并行分析数量
            use_sink_scanner: 是否使用 SinkCallScanner（推荐，确定性扫描）

        Returns:
            Finding 列表
        """
        print(f"[ANALYZE_DIRECT] 进入 analyze_units_direct，代码单元数: {len(code_units)}, 语言: {language}")
        logger.info(f"Starting direct analysis of {len(code_units)} code units...")

        # 调试：打印代码单元信息
        for i, unit in enumerate(code_units[:5]):  # 只打印前5个
            print(f"[ANALYZE_DIRECT] 代码单元 {i+1}: symbol={unit.symbol}, language={unit.language}, file={unit.file_path}")

        # 优先使用 SinkCallScanner（确定性扫描）
        if use_sink_scanner:
            logger.info("[ANALYZE_DIRECT] 使用 SinkCallScanner 进行确定性扫描")
            return self.analyze_with_sink_scanner(
                code_units=code_units,
                language=language,
                max_candidates=max_candidates,
                max_workers=max_workers,
            )

        # 回退到旧的模式匹配方法
        logger.info("[ANALYZE_DIRECT] 使用旧的模式匹配方法")

        # 1. 直接从代码单元发现候选点
        candidates = self.discover_candidates_from_units(
            code_units=code_units,
            language=language,
            max_candidates=max_candidates,
        )

        if not candidates:
            print(f"[ANALYZE_DIRECT] 未发现任何候选点！")
            logger.info("No candidates found in direct scan")
            return []

        print(f"[ANALYZE_DIRECT] 发现 {len(candidates)} 个候选点，开始 LLM 分析...")
        logger.info(f"Analyzing {len(candidates)} candidates...")

        # 2. 分析候选点
        findings = []

        # 使用线程池并行分析
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._analyze_candidate_simple, c, code_units): c
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

        logger.info(f"Direct analysis complete. Found {len(findings)} issues.")
        return findings

    def _analyze_candidate_simple(
        self,
        candidate: Candidate,
        code_units: List[CodeUnit],
    ) -> Optional[Finding]:
        """简化的候选点分析（用于直接分析模式）

        使用 LLM 分析但不依赖向量索引获取上下文
        """
        logger.info(f"[LLM] 开始分析候选点: {candidate.file_path}:{candidate.symbol}")
        try:
            # 构建基本上下文
            context_parts = []

            # 1. 目标代码
            context_parts.append(f"【目标代码】\n文件: {candidate.file_path}\n函数: {candidate.symbol}\n行号: {candidate.line_start}-{candidate.line_end}\n```\n{candidate.code}\n```")

            # 查找相关的代码单元（调用者/被调用者）
            related_units = []
            for unit in code_units:
                if unit.id == candidate.code_unit_id:
                    continue
                # 检查是否有调用关系
                if candidate.symbol in unit.calls or unit.symbol in (candidate.code.split() if candidate.code else []):
                    related_units.append(unit)
                    if len(related_units) >= 3:
                        break

            # 2. 添加相关代码到上下文
            if related_units:
                context_parts.append("【相关代码】")
                for ru in related_units:
                    context_parts.append(f"文件: {ru.file_path}:{ru.span.start_line}\n```\n{ru.code[:600]}\n```")

            # 3. 获取规则信息
            rule_info_parts = []
            for rule_id in candidate.triggered_rules:
                rule = self.rule_manager.get_rule(rule_id)
                if rule:
                    rule_info_parts.append(f"- {rule.name}: {rule.description}")

            if rule_info_parts:
                context_parts.append(f"【触发的安全规则】\n" + "\n".join(rule_info_parts))

            # 4. 构建完整上下文文本
            context_text = "\n\n".join(context_parts)

            # 构建提示词
            system_prompt, user_prompt = build_analysis_prompt(
                context_text=context_text,
                focus_category=None,
            )

            # 调用 LLM
            logger.info(f"[LLM] 调用 chat_completion, 模型: {self.llm_client.model if hasattr(self.llm_client, 'model') else 'unknown'}")
            response = self.llm_client.chat_completion(
                messages=[
                    ChatMessage(role="system", content=system_prompt),
                    ChatMessage(role="user", content=user_prompt),
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=2000,
            )
            logger.info(f"[LLM] 收到响应，长度: {len(response.content) if response.content else 0}")

            # 解析结果
            result = self._parse_llm_response(response.content)
            if not result:
                logger.warning(f"[LLM] 无法解析响应: {response.content[:200] if response.content else 'empty'}")
                return None

            # 检查是否有问题
            if not result.get("has_issue", False):
                logger.info(f"[LLM] 分析结果: 无安全问题")
                return None

            logger.info(f"[LLM] 发现问题: {result.get('issue_type', 'unknown')}, 严重性: {result.get('severity', 'unknown')}")

            # 构建 Finding
            return Finding(
                id=f"finding-{candidate.code_unit_id}",
                title=result.get("issue_type", "Security Issue"),
                file_path=candidate.file_path,
                line_start=candidate.line_start,
                line_end=candidate.line_end,
                symbol=candidate.symbol,
                severity=Severity.from_string(result.get("severity", "medium")),
                confidence=result.get("confidence", 0.5),
                category=result.get("issue_type", "unknown"),
                summary=result.get("summary", ""),
                details=result.get("details", ""),
                evidence=[Evidence(
                    file_path=candidate.file_path,
                    line_start=candidate.line_start,
                    line_end=candidate.line_end,
                    code_snippet=candidate.code[:500] if candidate.code else "",
                    description=result.get("summary", ""),
                )],
                attack_scenario=result.get("attack_scenario", ""),
                fix_suggestion=result.get("fix_suggestion", ""),
                notes=result.get("notes", ""),
                rule_ids=candidate.triggered_rules,
            )

        except Exception as e:
            logger.error(f"Error analyzing candidate {candidate.symbol}: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None

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
