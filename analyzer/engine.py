"""
安全分析引擎 - 核心分析逻辑
"""

import json
import logging
import re
import time
import hashlib
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError

from config import AuditConfig
from llm_client import BaseLLMClient, ChatMessage, OutputValidator, CHAIN_ANALYSIS_SCHEMA
from indexer import CodeIndexer, CodeUnit
from rules import RuleManager, RuleType

from .models import Finding, Candidate, AnalysisContext, Severity, Evidence
from .prompts import build_analysis_prompt, build_chain_analysis_prompt
from .sink_scanner import SinkCallScanner, SinkCallSite, SinkCategory
from .chain_context import ChainContextCollector, ChainContext, ChainNode
from .call_chain import CallChainAnalyzer
from .enhancer import DeepAnalysisEnhancer, EnhancementConfig, EnhancedSite
from .fc_adapter import (
    FunctionCallingAdapter,
    FCAdapterConfig,
    FCSecurityTools,
    FCAnalysisResult,
)

# P0-6: 导入 Token 预算管理器
from prompts.token_budget import TokenBudgetManager, ContentBlock, TokenPriority

logger = logging.getLogger(__name__)

# 单个 LLM 分析任务的超时时间（秒）
LLM_TASK_TIMEOUT = 120  # 2 分钟


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
        interaction_repo=None,
        scan_id: Optional[str] = None,
    ):
        self.config = config
        self.llm_client = llm_client
        self.indexer = indexer
        self.rule_manager = rule_manager

        # 日志仓库（用于记录工具调用和分析过程）
        self.interaction_repo = interaction_repo
        self.scan_id = scan_id

        # 新增：SinkCallScanner 确定性扫描器
        self.sink_scanner = SinkCallScanner(rule_manager)

        # 新增：调用链和污点分析器
        self.call_chain_analyzer = None
        self.taint_analyzer = None
        self._call_graph = None
        self._taint_flows = None

        # 新增：Agent 模式标志
        self.use_agent_mode = True  # 默认使用 Agent 模式
        self.use_function_calling = False  # Function Calling 模式开关

        # 新增：输出验证器（用于链级分析）
        self.output_validator = OutputValidator(
            project_root=config.scan.target_path,
            min_confidence=config.rules.min_confidence if hasattr(config.rules, 'min_confidence') else 0.0,
        )

        # P0-6: Token 预算管理器
        # 默认使用 8000 token 预算（为 LLM 输出预留空间）
        max_context_tokens = getattr(config.llm, 'max_context_tokens', 8000)
        self.token_budget_manager = TokenBudgetManager(
            max_total_tokens=max_context_tokens,
            encoding_name="cl100k_base",
        )

        # P0-7: 深度分析增强器（用于 sink_sites 排序）
        self.deep_enhancer = DeepAnalysisEnhancer(
            rule_manager=rule_manager,
            config=EnhancementConfig(
                enable_call_chain=True,
                enable_taint_analysis=True,
                max_call_depth=10,
                min_confidence_threshold=0.3,
            ),
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
        logger.debug(
            "[DISCOVER] 扫描 %s 个代码单元，使用 %s 条规则 (sinks: %s, patterns: %s)",
            len(code_units),
            len(all_rules),
            len(sinks),
            len(patterns),
        )
        logger.info(f"Scanning {len(code_units)} code units for {len(all_rules)} rules (sinks: {len(sinks)}, patterns: {len(patterns)})...")

        # 调试：显示 PHP 相关规则
        php_rules = [r for r in all_rules if 'php' in r.languages]
        if php_rules and logger.isEnabledFor(logging.DEBUG):
            logger.debug("[DISCOVER] PHP 规则数: %s", len(php_rules))
            logger.debug("[DISCOVER] PHP 规则示例: %s", [r.id for r in php_rules[:5]])
            logger.debug("[DISCOVER] 第一条 PHP 规则的模式: %s", php_rules[0].patterns[:5])

        # 遍历所有代码单元
        for unit in code_units:
            logger.debug("[DISCOVER] 检查代码单元: %s, 语言: %s", unit.symbol, unit.language)

            # 如果指定了语言，跳过不匹配的
            if language and unit.language != language:
                logger.debug("[DISCOVER] 跳过（语言不匹配）: %s != %s", unit.language, language)
                continue

            # 检查每个规则
            matched_rule = None
            logger.debug("[DISCOVER] 开始对 %s 条规则进行模式匹配...", len(all_rules))

            # 首先手动检查代码中是否包含常见的危险函数关键词
            code_lower = unit.code.lower()
            dangerous_keywords = ['mysql_query', 'mysqli_query', 'exec(', 'eval(', 'system(', 'shell_exec', '$_get', '$_post', '$_request']
            found_keywords = [kw for kw in dangerous_keywords if kw in code_lower]
            if found_keywords:
                logger.debug("[DISCOVER] 代码中发现危险关键词: %s", found_keywords)

            for rule in all_rules:
                if self._contains_pattern(unit.code, rule.patterns, debug=self.config.debug):
                    matched_rule = rule
                    logger.debug("[DISCOVER] 匹配规则: %s, 模式: %s", rule.id, rule.patterns[:3])
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
                logger.debug("[DISCOVER] 未匹配任何规则: %s", unit.symbol)

        # 按优先级排序
        candidates.sort(key=lambda x: x.priority, reverse=True)

        logger.debug("[DISCOVER] 发现 %s 个候选点", len(candidates))
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
                    finding = future.result(timeout=LLM_TASK_TIMEOUT)
                    if finding:
                        findings.append(finding)
                        logger.info(
                            f"[{i+1}/{len(candidates)}] 发现问题: "
                            f"{finding.title} in {finding.file_path}"
                        )
                except FuturesTimeoutError:
                    logger.warning(f"分析超时 {candidate.symbol}，跳过该任务")
                except Exception as e:
                    logger.exception(f"分析错误 {candidate.symbol}: {e}")

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
        max_llm_calls: int = 30,
        vuln_types: Optional[List[str]] = None,
        progress_callback: Optional[callable] = None,
        use_llm: bool = True,
    ) -> List[Finding]:
        """统一的链级分析入口（P0 目标推荐流程）

        完整流程：
        1. P0-1: SinkCallScanner 确定性扫描危险函数触发点
        2. P0-2: 构建调用图
        3. P0-3: 枚举调用链（带爆炸控制）
        4. P0-4: ChainContextCollector 收集调用链上下文
        5. P0-5: LLM 链级分析（输出结构化结果）+ 输出验证（use_llm=True 时）

        Args:
            code_units: 代码单元列表
            language: 限定语言
            max_candidates: 最大候选点数量
            max_workers: 并行分析数量
            max_chain_depth: 最大调用链深度
            max_llm_calls: 最大 LLM 调用次数（防止失控）
            vuln_types: 要检测的漏洞类型列表（如 ['command_injection', 'logic_flaw']）
            progress_callback: 可选的进度回调函数 (progress: float, step: str) -> None
            use_llm: 是否使用 LLM 深度分析（False 时只返回确定性扫描结果）

        Returns:
            Finding 列表
        """
        from .call_chain import CallChainAnalyzer

        # Reset per-run state so empty scans don't reuse stale graphs or taint results
        self._call_graph = None
        self._taint_flows = None
        if self.call_chain_analyzer:
            self.call_chain_analyzer.taint_paths = []

        # 辅助函数：安全调用进度回调
        def report_progress(progress: float, step: str):
            if progress_callback:
                try:
                    progress_callback(progress, step)
                except Exception as e:
                    logger.warning(f"Progress callback failed: {e}")

        logger.info(f"[P0] 开始链级分析流程，代码单元数: {len(code_units)}, 最大 LLM 调用: {max_llm_calls}")
        if vuln_types:
            logger.info(f"[P0] 漏洞类型过滤: {vuln_types}")

        report_progress(0.41, "开始危险函数扫描...")

        # ============================================================
        # P0-1: 使用 SinkCallScanner 确定性扫描危险函数触发点
        # ============================================================
        logger.info("[P0-1] SinkCallScanner 确定性扫描...")
        sink_sites = self.discover_sink_sites(code_units, language)

        if not sink_sites:
            logger.info("[P0-1] 未发现任何危险函数触发点")
            return []

        logger.info(f"[P0-1] 发现 {len(sink_sites)} 个危险函数触发点")
        report_progress(0.43, f"发现 {len(sink_sites)} 个危险函数触发点")

        # 按漏洞类型过滤 sink_sites
        if vuln_types:
            # 漏洞类型到 SinkCategory 的映射
            vuln_to_sink_category = {
                'rce': [SinkCategory.CODE_EXEC, SinkCategory.COMMAND_EXEC],
                'command_injection': [SinkCategory.COMMAND_EXEC],
                'sql_injection': [SinkCategory.SQL_INJECTION],
                'file_read': [SinkCategory.FILE_READ],
                'file_write': [SinkCategory.FILE_WRITE],
                'file_upload': [SinkCategory.FILE_WRITE],
                'ssrf': [SinkCategory.SSRF],
                'ssti': [SinkCategory.CODE_EXEC],
                'deserialization': [SinkCategory.DESERIALIZATION],
                'xss': [SinkCategory.XSS],
                'path_traversal': [SinkCategory.PATH_TRAVERSAL],
                'xxe': [SinkCategory.FILE_READ],  # XXE 可以读取文件
                # 逻辑类漏洞不基于 sink category
                # 'logic_flaw', 'auth_bypass', 'authz_bypass', 'idor', 'race_condition', 'mass_assignment'
            }

            # 逻辑类漏洞类型列表
            logic_vuln_types = {'logic_flaw', 'auth_bypass', 'authz_bypass', 'idor', 'race_condition', 'mass_assignment'}

            # 收集要检测的 sink categories
            target_categories = set()
            check_logic = False
            for vt in vuln_types:
                vt_lower = vt.lower()
                if vt_lower in logic_vuln_types:
                    check_logic = True
                elif vt_lower in vuln_to_sink_category:
                    target_categories.update(vuln_to_sink_category[vt_lower])

            # 过滤 sink_sites
            if target_categories:
                original_count = len(sink_sites)
                sink_sites = [
                    site for site in sink_sites
                    if site.sink_category in target_categories
                ]
                logger.info(
                    f"[P0-1] 漏洞类型过滤后: {len(sink_sites)}/{original_count} 个触发点 "
                    f"(过滤类别: {[c.value for c in target_categories]})"
                )
            else:
                # 如果没有匹配的 sink category（比如只选了 logic_flaw），清空 sink_sites
                if not check_logic:
                    sink_sites = []
                    logger.info("[P0-1] 没有匹配的 sink category，跳过 sink 扫描")

        if not sink_sites:
            logger.info("[P0-1] 过滤后未发现任何危险函数触发点")
            return []

        # ============================================================
        # P0-2: 构建调用图
        # ============================================================
        report_progress(0.44, "构建调用图...")
        logger.info("[P0-2] 构建调用图...")
        if self.call_chain_analyzer is None:
            self.call_chain_analyzer = CallChainAnalyzer(self.rule_manager)

        # 每次分析都重建调用图，避免复用过期结果
        self._call_graph = self.call_chain_analyzer.build_call_graph(code_units)
        logger.info(
            f"[P0-2] 调用图: {len(self._call_graph.nodes)} 节点, "
            f"{len(self._call_graph.edges)} 边"
        )
        report_progress(0.46, f"调用图: {len(self._call_graph.nodes)} 节点")

        # ============================================================
        # P0-7: sink_sites 排序（enhancer 评分）并截断
        # ============================================================
        report_progress(0.465, "对危险函数触发点排序...")
        logger.info(f"[P0-7] 使用 DeepAnalysisEnhancer 对 {len(sink_sites)} 个触发点评分排序...")

        enhancement_result = self.deep_enhancer.enhance_sites(
            sink_sites=sink_sites,
            code_units=code_units,
            call_graph=self._call_graph,  # 复用已构建的调用图
        )

        # 按 enhanced_score 排序后取 top max_candidates（修复：先排序再截断）
        sorted_enhanced = enhancement_result.get_top_sites(limit=max_candidates)
        sink_sites = [enhanced.site for enhanced in sorted_enhanced]

        logger.info(
            f"[P0-7] 排序截断完成: {len(sink_sites)}/{len(enhancement_result.enhanced_sites)} 个, "
            f"高置信度 {enhancement_result.high_confidence_count} 个, "
            f"top-3 分数: {[f'{s.enhanced_score:.2f}' for s in sorted_enhanced[:3]]}"
        )

        # ============================================================
        # P0-3 & P0-4: 枚举调用链并收集上下文
        # ============================================================
        report_progress(0.47, "收集调用链上下文...")
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
        report_progress(0.49, f"收集了 {len(chain_contexts)} 个调用链上下文")

        # ============================================================
        # use_llm=False: 跳过 LLM 分析，返回确定性扫描结果
        # ============================================================
        if not use_llm:
            logger.info(f"[P0] use_llm=False，跳过 LLM 分析，生成确定性 Finding")
            report_progress(0.90, "生成确定性扫描结果（无 LLM）...")
            findings = self._generate_deterministic_findings(sink_sites, chain_contexts)
            findings = self._filter_and_sort_findings(findings)
            logger.info(f"[P0] 确定性扫描完成，发现 {len(findings)} 个潜在安全问题")
            return findings

        # ============================================================
        # P0-5: LLM 链级分析（限制调用次数）
        # ============================================================
        # 限制 LLM 调用次数，防止无限分析
        if len(chain_contexts) > max_llm_calls:
            logger.warning(
                f"[P0-5] 调用链上下文数 ({len(chain_contexts)}) 超过 LLM 调用限制 ({max_llm_calls})，"
                f"只分析前 {max_llm_calls} 个"
            )
            chain_contexts = chain_contexts[:max_llm_calls]

        logger.info(f"[P0-5] 开始 LLM 链级分析，共 {len(chain_contexts)} 个上下文...")
        report_progress(0.50, f"开始 LLM 分析 {len(chain_contexts)} 个上下文...")
        findings = []
        total_contexts = len(chain_contexts)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._analyze_chain_context, ctx, code_units): ctx
                for ctx in chain_contexts
            }

            for i, future in enumerate(as_completed(futures)):
                ctx = futures[future]
                # 更新进度：50% -> 58%，按分析进度线性增长
                progress = 0.50 + (i + 1) / total_contexts * 0.08
                report_progress(progress, f"LLM 分析 {i+1}/{total_contexts}")
                try:
                    finding = future.result(timeout=LLM_TASK_TIMEOUT)
                    if finding:
                        findings.append(finding)
                        logger.info(
                            f"[{i+1}/{total_contexts}] 发现问题: "
                            f"{finding.title} (置信度: {finding.confidence:.2f})"
                        )
                except FuturesTimeoutError:
                    logger.warning(f"分析超时 {ctx.sink_site.symbol}，跳过该任务")
                except Exception as e:
                    logger.exception(f"分析错误 {ctx.sink_site.symbol}: {e}")

        # 排序和过滤
        findings = self._filter_and_sort_findings(findings)

        logger.info(f"[P0] 链级分析完成，发现 {len(findings)} 个安全问题")
        return findings

    def _generate_deterministic_findings(
        self,
        sink_sites: List[SinkCallSite],
        chain_contexts: list,
    ) -> List[Finding]:
        """生成确定性 Finding（不调用 LLM）

        基于 sink 匹配和调用链信息生成 Finding，用于 use_llm=False 模式。

        Args:
            sink_sites: 危险函数触发点列表
            chain_contexts: 调用链上下文列表

        Returns:
            Finding 列表
        """
        findings = []

        # 建立 sink_site -> chain_contexts 的映射
        site_chains: Dict[str, list] = {}
        for ctx in chain_contexts:
            key = f"{ctx.sink_site.file_path}:{ctx.sink_site.line_start}:{ctx.sink_site.symbol}"
            if key not in site_chains:
                site_chains[key] = []
            site_chains[key].append(ctx)

        for site in sink_sites:
            key = f"{site.file_path}:{site.line_start}:{site.symbol}"
            chains = site_chains.get(key, [])

            # 生成确定性 Finding ID
            content_for_hash = f"{self.scan_id}:{site.file_path}:{site.line_start}:{site.symbol}"
            finding_hash = hashlib.sha256(content_for_hash.encode()).hexdigest()[:12]
            finding_id = f"f-{finding_hash}"

            # 构建调用链路径描述
            chain_desc = ""
            if chains:
                chain_paths = []
                for ctx in chains[:3]:  # 最多展示 3 条链
                    if ctx.chain_nodes:
                        path_str = " -> ".join([n.symbol for n in ctx.chain_nodes])
                        chain_paths.append(path_str)
                if chain_paths:
                    chain_desc = f"\n调用链路径:\n" + "\n".join(f"  - {p}" for p in chain_paths)

            # 基于 sink category 推断严重性
            high_severity_categories = {
                SinkCategory.CODE_EXEC, SinkCategory.COMMAND_EXEC,
                SinkCategory.DESERIALIZATION, SinkCategory.SQL_INJECTION,
            }
            severity = Severity.HIGH if site.sink_category in high_severity_categories else Severity.MEDIUM

            finding = Finding(
                id=finding_id,
                title=f"[确定性扫描] {site.sink_category.value}: {site.symbol}",
                file_path=site.file_path,
                line_start=site.line_start,
                line_end=site.line_end,
                symbol=site.symbol,
                severity=severity,
                confidence=0.5,  # 未经 LLM 验证，置信度设为中等
                category=site.sink_category.value,
                summary=f"检测到危险函数调用 {site.call_snippet[:80] if site.call_snippet else site.symbol}，"
                        f"匹配规则: {', '.join(site.matched_rule_ids) if site.matched_rule_ids else 'N/A'}。"
                        f"（未经 LLM 深度分析，建议人工审查）{chain_desc}",
                details="此结果由确定性扫描生成（use_llm=False），仅基于 sink 模式匹配和调用链分析，未经 LLM 深度验证。",
                evidence=[Evidence(
                    file_path=site.file_path,
                    line_start=site.line_start,
                    line_end=site.line_end,
                    code_snippet=site.call_snippet,
                    description=f"触发点: {site.symbol}"
                )],
                rule_ids=site.matched_rule_ids,
                metadata={
                    "analysis_mode": "deterministic_no_llm",
                    "sink_category": site.sink_category.value,
                    "chain_count": len(chains),
                }
            )
            findings.append(finding)

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
                candidate = futures[future]
                try:
                    finding = future.result(timeout=LLM_TASK_TIMEOUT)
                    if finding:
                        findings.append(finding)
                except FuturesTimeoutError:
                    logger.warning(f"Fallback 分析超时 {candidate.symbol}，跳过该任务")
                except Exception as e:
                    logger.exception(f"Fallback 分析错误: {e}")

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

        # 2. 构建调用图（每次分析都重建，避免复用过期结果）
        if self.call_chain_analyzer is None:
            self.call_chain_analyzer = CallChainAnalyzer(self.rule_manager)

        # 重置状态，避免复用过期的调用图
        self._call_graph = None
        self._taint_flows = None
        if self.call_chain_analyzer:
            self.call_chain_analyzer.taint_paths = []

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
                    finding = future.result(timeout=LLM_TASK_TIMEOUT)
                    if finding:
                        findings.append(finding)
                        logger.info(
                            f"[{i+1}/{len(chain_contexts)}] 发现问题: "
                            f"{finding.title} in {finding.file_path}"
                        )
                except FuturesTimeoutError:
                    logger.warning(f"分析超时 {ctx.sink_site.symbol}，跳过该任务")
                except Exception as e:
                    logger.exception(f"分析错误 {ctx.sink_site.symbol}: {e}")

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

            # 生成调用链 ID（用于日志和关联）
            chain_id = f"chain-{sink_site.id}"

            # 生成确定性 Finding ID（同一漏洞跨扫描可去重）
            content_for_hash = f"{self.scan_id}:{sink_site.file_path}:{sink_site.line_start}:{sink_site.symbol}"
            finding_hash = hashlib.sha256(content_for_hash.encode()).hexdigest()[:12]
            finding_id = f"f-{finding_hash}"

            # 获取 sink 类别
            sink_category = sink_site.sink_category.value

            # 添加规则信息
            rule_info_parts = []
            for rule_id in sink_site.matched_rule_ids:
                rule = self.rule_manager.get_rule(rule_id)
                if rule:
                    rule_info_parts.append(f"- {rule.name}: {rule.description}")
                    if rule.cwe_ids:
                        rule_info_parts.append(f"  CWE: {', '.join(rule.cwe_ids)}")
            rule_info = "\n".join(rule_info_parts)

            # P0-6: 使用 Token 预算管理器构建上下文
            context_text, budget_info = self._build_prompt_with_budget(
                chain_context=chain_context,
                rule_info=rule_info,
            )

            # 记录 Token 预算信息
            if budget_info.get("truncated_count", 0) > 0:
                logger.info(
                    f"[P0-6] 调用链 {chain_id}: Token 截断 {budget_info['truncated_count']} 个块, "
                    f"节省 {budget_info.get('tokens_saved', 0)} tokens"
                )

            # 使用链级分析提示词（根据目标文档 P0-5）
            system_prompt, user_prompt = build_chain_analysis_prompt(
                chain_context_text=context_text,
                chain_id=chain_id,
                sink_category=sink_category,
            )

            # 记录开始分析（thinking）
            if self.interaction_repo and self.scan_id:
                self.interaction_repo.log_thinking(
                    self.scan_id,
                    f"正在分析调用链 {chain_id}，Sink 类别: {sink_category}"
                )

            # 调用 LLM
            logger.info(f"[ChainLLM] 分析调用链: {chain_id}, Sink类别: {sink_category}")
            start_time = time.time()
            response = self.llm_client.chat_completion(
                messages=[
                    ChatMessage(role="system", content=system_prompt),
                    ChatMessage(role="user", content=user_prompt),
                ],
                response_format={"type": "json_object"},
                temperature=self.config.llm.temperature,
                max_tokens=2500,
            )
            duration_ms = int((time.time() - start_time) * 1000)

            # 记录 LLM 分析结果
            tokens_used = response.usage.get("total_tokens", 0) if response.usage else 0
            if self.interaction_repo and self.scan_id:
                self.interaction_repo.log_analysis(
                    self.scan_id,
                    llm_response=response.content[:500] if response.content else "",
                    tokens_used=tokens_used,
                    duration_ms=duration_ms,
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

            finding = Finding(
                id=finding_id,  # 使用全局唯一的 finding_id
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

            # 记录发现的问题
            if self.interaction_repo and self.scan_id:
                self.interaction_repo.log_finding(
                    self.scan_id,
                    finding_data={
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "file_path": finding.file_path,
                        "line_start": finding.line_start,
                        "confidence": finding.confidence,
                        "category": finding.category,
                    }
                )

            return finding

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.exception(f"调用链分析错误 {chain_context.sink_site.symbol}: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None

    def _build_prompt_with_budget(
        self,
        chain_context: ChainContext,
        rule_info: str,
    ) -> tuple:
        """P0-6: 使用 Token 预算管理器构建 Prompt

        将 chain_context 的各部分按优先级分配 Token 预算。

        Args:
            chain_context: 调用链上下文
            rule_info: 规则信息文本

        Returns:
            (final_prompt, budget_info)
        """
        content_blocks = []

        # 1. Sink 信息（CRITICAL - 绝不截断）
        sink_site = chain_context.sink_site
        sink_text = f"""【危险函数调用】
文件: {sink_site.file_path}:{sink_site.line_start}
函数: {sink_site.symbol}
类别: {sink_site.sink_category.value}
风险等级: {sink_site.risk_level.value}
匹配规则: {', '.join(sink_site.matched_rule_ids)}
```
{sink_site.call_snippet}
```"""
        content_blocks.append(ContentBlock(
            text=sink_text,
            priority=TokenPriority.CRITICAL,
            name="sink_info",
        ))

        # 2. 入口点代码（HIGH - 优先保留）
        if chain_context.entry_point:
            entry_text = f"""【入口点】
函数: {chain_context.entry_point.qualified_name}
位置: {chain_context.entry_point.file_path}:{chain_context.entry_point.line_start}
```
{chain_context.entry_point.code[:1500]}
```"""
            content_blocks.append(ContentBlock(
                text=entry_text,
                priority=TokenPriority.HIGH,
                name="entry_point",
            ))

        # 3. 调用链概述（HIGH）
        chain_summary_lines = ["【调用链路】"]
        for i, node in enumerate(chain_context.chain_nodes):
            prefix = "└─>" if i == len(chain_context.chain_nodes) - 1 else "├─>"
            marks = []
            if node.is_sink:
                marks.append("[SINK]")
            if node.node_type == "entry_point":
                marks.append("[ENTRY]")
            if node.node_type == "sanitizer":
                marks.append("[SANITIZER]")
            mark_str = " ".join(marks)
            chain_summary_lines.append(f"{prefix} {node.qualified_name} {mark_str}")
            chain_summary_lines.append(f"    位置: {node.file_path}:{node.line_start}")

        content_blocks.append(ContentBlock(
            text="\n".join(chain_summary_lines),
            priority=TokenPriority.HIGH,
            name="chain_summary",
        ))

        # 4. 中间函数代码（MEDIUM - 可部分截断）
        intermediate_nodes = [
            node for node in chain_context.chain_nodes
            if not node.is_sink and node.node_type != "entry_point" and node.code
        ]
        if intermediate_nodes:
            intermediate_lines = ["【中间函数代码】"]
            for node in intermediate_nodes:
                intermediate_lines.append(f"--- {node.qualified_name} ---")
                intermediate_lines.append(f"```")
                intermediate_lines.append(node.code[:800])
                intermediate_lines.append("```")
                intermediate_lines.append("")

            content_blocks.append(ContentBlock(
                text="\n".join(intermediate_lines),
                priority=TokenPriority.MEDIUM,
                name="intermediate_code",
            ))

        # 5. 规则信息（LOW - 可大量截断）
        if rule_info:
            content_blocks.append(ContentBlock(
                text=f"【触发的安全规则】\n{rule_info}",
                priority=TokenPriority.LOW,
                name="rule_info",
            ))

        # 6. 元数据（LOW）
        meta_lines = [
            f"【分析元数据】",
            f"调用链长度: {chain_context.chain_length}",
            f"存在用户输入: {'是' if chain_context.has_user_input else '否'}",
        ]
        if chain_context.sanitizers_on_path:
            meta_lines.append(f"路径过滤器: {', '.join(chain_context.sanitizers_on_path)}")

        content_blocks.append(ContentBlock(
            text="\n".join(meta_lines),
            priority=TokenPriority.LOW,
            name="metadata",
        ))

        # 使用预算管理器构建最终 Prompt
        final_prompt, budget_info = self.token_budget_manager.build_prompt(content_blocks)

        logger.debug(
            f"[P0-6] Token 预算: {budget_info.get('total_tokens', 0)}/{budget_info.get('max_tokens', 0)} "
            f"(利用率: {budget_info.get('utilization', 0):.1%})"
        )

        return final_prompt, budget_info

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
                    logger.debug("[PATTERN] 匹配成功: %r", pattern)
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

        # 记录开始分析
        if self.interaction_repo and self.scan_id:
            self.interaction_repo.log_thinking(
                self.scan_id,
                f"正在分析: {candidate.file_path}:{candidate.symbol}"
            )

        # 调用 LLM
        try:
            start_time = time.time()
            response = self.llm_client.chat_completion(
                messages=[
                    ChatMessage(role="system", content=system_prompt),
                    ChatMessage(role="user", content=user_prompt),
                ],
                response_format={"type": "json_object"},
                temperature=self.config.llm.temperature,
            )
            duration_ms = int((time.time() - start_time) * 1000)

            # 记录 LLM 分析结果
            tokens_used = response.usage.get("total_tokens", 0) if response.usage else 0
            if self.interaction_repo and self.scan_id:
                self.interaction_repo.log_analysis(
                    self.scan_id,
                    llm_response=response.content[:500] if response.content else "",
                    tokens_used=tokens_used,
                    duration_ms=duration_ms,
                )

            # 解析响应
            result = self._parse_llm_response(response.content)

            if result and result.get("has_issue"):
                finding = self._create_finding(candidate, context, result)
                # 记录发现的问题
                if finding and self.interaction_repo and self.scan_id:
                    self.interaction_repo.log_finding(
                        self.scan_id,
                        finding_data={
                            "title": finding.title,
                            "severity": finding.severity.value,
                            "file_path": finding.file_path,
                            "line_start": finding.line_start,
                            "confidence": finding.confidence,
                            "category": finding.category,
                        }
                    )
                return finding

        except (KeyboardInterrupt, SystemExit):
            raise
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
        vuln_types: Optional[List[str]] = None,
        max_llm_calls: int = 30,
        progress_callback: Optional[callable] = None,
        use_llm: bool = True,
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
            vuln_types: 要检测的漏洞类型列表（如 ['command_injection', 'logic_flaw']）
            max_llm_calls: 最大 LLM 调用次数
            progress_callback: 可选的进度回调函数 (progress: float, step: str) -> None
            use_llm: 是否使用 LLM 深度分析（False 时只返回确定性扫描结果）

        Returns:
            Finding 列表
        """
        # P0-3: chain_analysis 开关优先级最高
        # 无论是否提供 code_units，都应该尊重 use_chain_analysis 参数
        logger.info(f"[Analyze] Mode: {'chain' if use_chain_analysis else 'simple'}, use_llm={use_llm}")

        # 如果没有提供 code_units，从索引器获取
        if code_units is None:
            logger.info("No code_units provided, fetching from indexer...")
            code_units = self.indexer.get_all_units()
            if language:
                code_units = [u for u in code_units if u.language == language]
            logger.info(f"Fetched {len(code_units)} code units from indexer")

        if vuln_types:
            logger.info(f"漏洞类型过滤: {vuln_types}")

        # 根据 use_chain_analysis 选择分析模式
        if use_chain_analysis:
            logger.info("[P0] Using chain-level analysis (recommended)")
            return self.analyze_chains(
                code_units=code_units,
                language=language,
                max_candidates=max_candidates,
                max_workers=max_workers,
                max_chain_depth=max_chain_depth,
                max_llm_calls=max_llm_calls,
                vuln_types=vuln_types,
                progress_callback=progress_callback,
                use_llm=use_llm,
            )
        else:
            # 不使用链级分析时，根据 use_agent 决定使用哪种模式
            use_agent_mode = use_agent if use_agent is not None else self.use_agent_mode

            if use_agent_mode:
                logger.info("Using Agent-based analysis mode (no chain)")
                return self.analyze_with_agent(
                    language=language,
                    file_pattern=file_pattern,
                    max_candidates=max_candidates,
                )
            else:
                logger.info("Using legacy analysis mode (no chain)")
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
        logger.debug(
            "[ANALYZE_DIRECT] 进入 analyze_units_direct，代码单元数: %s, 语言: %s",
            len(code_units),
            language,
        )
        logger.info(f"Starting direct analysis of {len(code_units)} code units...")

        # 调试：打印代码单元信息
        if logger.isEnabledFor(logging.DEBUG):
            for i, unit in enumerate(code_units[:5]):  # 只打印前5个
                logger.debug(
                    "[ANALYZE_DIRECT] 代码单元 %s: symbol=%s, language=%s, file=%s",
                    i + 1,
                    unit.symbol,
                    unit.language,
                    unit.file_path,
                )

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
            logger.debug("[ANALYZE_DIRECT] 未发现任何候选点")
            logger.info("No candidates found in direct scan")
            return []

        logger.debug("[ANALYZE_DIRECT] 发现 %s 个候选点，开始 LLM 分析", len(candidates))
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
                    finding = future.result(timeout=LLM_TASK_TIMEOUT)
                    if finding:
                        findings.append(finding)
                        logger.info(
                            f"[{i+1}/{len(candidates)}] Found issue: "
                            f"{finding.title} in {finding.file_path}"
                        )
                except FuturesTimeoutError:
                    logger.warning(f"Analysis timeout for {candidate.symbol}, skipping")
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

        # 记录开始分析（thinking）
        if self.interaction_repo and self.scan_id:
            self.interaction_repo.log_thinking(
                self.scan_id,
                f"正在分析候选点: {candidate.file_path}:{candidate.symbol}"
            )
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
            start_time = time.time()
            response = self.llm_client.chat_completion(
                messages=[
                    ChatMessage(role="system", content=system_prompt),
                    ChatMessage(role="user", content=user_prompt),
                ],
                response_format={"type": "json_object"},
                temperature=self.config.llm.temperature,
                max_tokens=2000,
            )
            duration_ms = int((time.time() - start_time) * 1000)
            logger.info(f"[LLM] 收到响应，长度: {len(response.content) if response.content else 0}, 耗时: {duration_ms}ms")

            # 记录 LLM 分析结果
            tokens_used = response.usage.get("total_tokens", 0) if response.usage else 0
            if self.interaction_repo and self.scan_id:
                self.interaction_repo.log_analysis(
                    self.scan_id,
                    llm_response=response.content[:500] if response.content else "",
                    tokens_used=tokens_used,
                    duration_ms=duration_ms,
                )

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

            # 生成唯一的 Finding ID
            finding_context = f"{candidate.file_path}:{candidate.line_start}:{candidate.symbol}"
            unique_finding_id = Finding.generate_id(self.scan_id, finding_context)

            # 构建 Finding
            finding = Finding(
                id=unique_finding_id,
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

            # 记录发现的问题
            if self.interaction_repo and self.scan_id:
                self.interaction_repo.log_finding(
                    self.scan_id,
                    finding_data={
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "file_path": finding.file_path,
                        "line_start": finding.line_start,
                        "confidence": finding.confidence,
                        "category": finding.category,
                    }
                )

            return finding

        except (KeyboardInterrupt, SystemExit):
            raise
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
                    finding = future.result(timeout=LLM_TASK_TIMEOUT)
                    if finding:
                        findings.append(finding)
                        logger.info(
                            f"[{i+1}/{len(candidates)}] Found issue: "
                            f"{finding.title} in {finding.file_path}"
                        )
                except FuturesTimeoutError:
                    logger.warning(f"Analysis timeout for {candidate.symbol}, skipping")
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

        # 每次都重建调用图，避免复用过期结果
        logger.info("Building call graph...")
        self._call_graph = self.call_chain_analyzer.build_call_graph(code_units)
        logger.info(
            f"Call graph built: {len(self._call_graph.nodes)} nodes, "
            f"{len(self._call_graph.edges)} edges"
        )

        # 每次都重新创建 TaintAnalyzer，确保使用最新的 call_graph
        # （call_graph 已在上面重建，taint_analyzer 需要持有新引用）
        logger.info("Initializing taint analyzer with updated call graph...")
        self.taint_analyzer = TaintAnalyzer(self.rule_manager, self._call_graph)

        # 每次都重新运行污点分析
        logger.info("Running interprocedural taint analysis...")
        self._taint_flows = self.taint_analyzer.analyze_interprocedural(
            code_units,
            max_depth=10,
            use_topological=True,
        )
        logger.info(f"Taint analysis complete: {len(self._taint_flows)} flows")

    def _analyze_candidate_with_agent(self, candidate: Candidate) -> Optional[Finding]:
        """使用 Agent 分析候选点（带日志记录）"""
        try:
            from agent import LoggedEnhancedSecurityAgent
            from indexer import CodeReader

            # 创建 CodeReader
            code_reader = CodeReader(
                project_path=self.config.scan.target_path,
                indexer=self.indexer,
            )

            # 创建带日志的增强 Agent
            agent = LoggedEnhancedSecurityAgent(
                llm_client=self.llm_client,
                code_reader=code_reader,
                indexer=self.indexer,
                call_chain_analyzer=self.call_chain_analyzer,
                taint_analyzer=self.taint_analyzer,
                interaction_repo=self.interaction_repo,
                scan_id=self.scan_id,
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

        except (KeyboardInterrupt, SystemExit):
            raise
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

        except (KeyboardInterrupt, SystemExit):
            raise
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

    def analyze_selected_sinks(
        self,
        selected_sites: List["SinkCallSite"],
        code_units: List[CodeUnit],
        use_chain_analysis: bool = True,
        max_chain_depth: int = 5,
        max_chains_per_sink: int = 10,
        progress_callback: Optional[callable] = None,
        on_tool_call: Optional[callable] = None,
        on_llm_thinking: Optional[callable] = None,
    ) -> List[Finding]:
        """分析用户选中的触发点

        这是"两步确认"模式的核心方法：
        1. 用户已通过前端选择了感兴趣的触发点
        2. 此方法仅对选中的触发点进行 LLM 深度分析

        Args:
            selected_sites: 用户选中的 SinkCallSite 列表
            code_units: 代码单元列表（用于构建调用图）
            use_chain_analysis: 是否使用调用链分析
            max_chain_depth: 最大调用链深度
            max_chains_per_sink: 每个触发点最大调用链数量
            progress_callback: 进度回调函数
            on_tool_call: FC 模式的工具调用回调（可选）
            on_llm_thinking: FC 模式的 LLM 思考状态回调（可选）

        Returns:
            Finding 列表
        """
        from .sink_scanner import SinkCallSite

        if not selected_sites:
            logger.warning("没有选中的触发点")
            return []

        logger.info(f"[SelectedAnalysis] 开始分析 {len(selected_sites)} 个选中的触发点")

        # 记录开始
        if self.interaction_repo:
            self.interaction_repo.log_thinking(
                self.scan_id,
                f"开始对 {len(selected_sites)} 个用户选中的触发点进行深度分析"
            )

        all_findings = []
        total_sites = len(selected_sites)

        if use_chain_analysis:
            # 构建调用图
            logger.info("[SelectedAnalysis] 构建调用图...")
            if progress_callback:
                progress_callback(0.05, "正在构建调用图...")

            chain_analyzer = CallChainAnalyzer(self.rule_manager)
            call_graph = chain_analyzer.build_call_graph(code_units)

            # 将 chain_analyzer 赋值给实例属性，以便 Function Calling 模式使用
            self.call_chain_analyzer = chain_analyzer
            self._call_graph = call_graph

            logger.info(f"[SelectedAnalysis] 调用图: {len(call_graph.nodes)} 节点, {len(call_graph.edges)} 边")

            # 创建符号到 CodeUnit 的映射
            symbol_to_unit = {}
            for unit in code_units:
                symbol_to_unit[unit.symbol] = unit
                if unit.parent_class:
                    full_name = f"{unit.parent_class}.{unit.symbol}"
                    symbol_to_unit[full_name] = unit

            # 创建上下文收集器
            context_collector = ChainContextCollector(
                call_chain_analyzer=chain_analyzer,
                code_units=code_units,
            )

            # 逐个分析选中的触发点
            for idx, sink_site in enumerate(selected_sites):
                site_progress = idx / total_sites
                if progress_callback:
                    progress_callback(
                        0.1 + site_progress * 0.85,
                        f"正在分析触发点 ({idx + 1}/{total_sites}): {sink_site.symbol}"
                    )

                logger.info(f"[SelectedAnalysis] 分析触发点 {idx + 1}/{total_sites}: {sink_site.symbol}")

                # 查找到达此触发点的调用链
                try:
                    chains = chain_analyzer.find_paths_to_sink(
                        sink_site.symbol,
                        max_depth=max_chain_depth,
                        max_paths=max_chains_per_sink
                    )
                except Exception as e:
                    logger.warning(f"查找调用链失败: {e}")
                    chains = []

                if not chains:
                    # 没有调用链，直接分析触发点本身
                    logger.debug(f"触发点 {sink_site.symbol} 没有调用链，直接分析")
                    chains = [[sink_site.symbol]]

                # 对每条调用链进行分析
                for chain_idx, chain in enumerate(chains[:max_chains_per_sink]):
                    chain_id = f"chain-{sink_site.id}-{chain_idx}"

                    # 收集调用链上下文
                    try:
                        # 正确调用 collect_context 方法
                        chain_context = context_collector.collect_context(
                            sink_site,
                            max_depth=len(chain)
                        )
                    except Exception as e:
                        logger.warning(f"收集调用链上下文失败: {e}")
                        # 回退：仅使用触发点所在函数的代码
                        unit = symbol_to_unit.get(sink_site.symbol)
                        if unit:
                            # 创建 ChainNode 需要 qualified_name
                            qualified_name = unit.symbol
                            if unit.parent_class:
                                qualified_name = f"{unit.parent_class}.{unit.symbol}"

                            fallback_node = ChainNode(
                                symbol=unit.symbol,
                                qualified_name=qualified_name,
                                file_path=unit.file_path,
                                line_start=unit.span.start_line,
                                line_end=unit.span.end_line,
                                node_type="sink",
                                code=unit.code,
                                is_sink=True
                            )
                            chain_context = ChainContext(
                                sink_site=sink_site,
                                chain_nodes=[fallback_node],
                                chain_length=1,
                                risk_level=sink_site.risk_level.value if sink_site.risk_level else "medium"
                            )
                        else:
                            continue

                    # 构建分析 Prompt
                    prompt = self._build_chain_prompt_for_site(
                        sink_site,
                        chain_context,
                        chain_id
                    )

                    # 调用 LLM
                    if self.interaction_repo:
                        self.interaction_repo.log_thinking(
                            self.scan_id,
                            f"正在分析调用链 {chain_id}: {' -> '.join(chain[:5])}{'...' if len(chain) > 5 else ''}"
                        )

                    try:
                        # 根据是否启用 Function Calling 模式选择分析方法
                        if self.use_function_calling:
                            # 为当前 sink 创建回调适配器
                            # on_tool_call 期望签名: (sink_symbol, tool_call_dict, status)
                            # fc_adapter 调用签名: (FCToolCall)
                            adapted_on_tool_call = None
                            if on_tool_call:
                                current_sink_symbol = sink_site.symbol
                                def make_tool_call_adapter(sink_sym):
                                    def adapter(fc_call):
                                        # 将 FCToolCall 对象转换为 API 期望的格式
                                        tool_call_dict = fc_call.to_dict() if hasattr(fc_call, 'to_dict') else {
                                            "id": getattr(fc_call, 'id', ''),
                                            "tool_name": getattr(fc_call, 'tool_name', ''),
                                            "arguments": getattr(fc_call, 'arguments', {}),
                                            "status": getattr(fc_call, 'status', 'running').value if hasattr(getattr(fc_call, 'status', None), 'value') else str(getattr(fc_call, 'status', 'running')),
                                            "result": getattr(fc_call, 'result', None),
                                            "error": getattr(fc_call, 'error', None),
                                            "duration_ms": getattr(fc_call, 'duration_ms', 0),
                                        }
                                        status = tool_call_dict.get("status", "running")
                                        on_tool_call(sink_sym, tool_call_dict, status)
                                    return adapter
                                adapted_on_tool_call = make_tool_call_adapter(current_sink_symbol)

                            finding = self.analyze_with_function_calling(
                                sink_site,
                                chain_context,
                                code_units,
                                on_tool_call=adapted_on_tool_call,
                                on_llm_thinking=on_llm_thinking,
                            )
                        else:
                            finding = self._analyze_chain_with_llm(
                                sink_site,
                                chain_context,
                                chain_id,
                                prompt
                            )

                        if finding:
                            all_findings.append(finding)
                            logger.info(f"[SelectedAnalysis] 发现问题: {finding.title} ({finding.severity.value})")

                            if self.interaction_repo:
                                # log_finding 只接受 scan_id 和 finding_data 两个参数
                                self.interaction_repo.log_finding(
                                    self.scan_id,
                                    finding.to_dict()
                                )

                    except Exception as e:
                        logger.error(f"LLM 分析失败: {e}")
                        continue

        else:
            # 不使用调用链分析，直接分析每个触发点
            for idx, sink_site in enumerate(selected_sites):
                site_progress = idx / total_sites
                if progress_callback:
                    progress_callback(
                        0.1 + site_progress * 0.85,
                        f"正在分析触发点 ({idx + 1}/{total_sites}): {sink_site.symbol}"
                    )

                # 简单分析模式
                finding = self._analyze_sink_site_simple(sink_site, code_units)
                if finding:
                    all_findings.append(finding)

        # 过滤和排序
        all_findings = self._filter_and_sort_findings(all_findings)

        if progress_callback:
            progress_callback(1.0, f"分析完成，发现 {len(all_findings)} 个问题")

        logger.info(f"[SelectedAnalysis] 完成，共发现 {len(all_findings)} 个问题")
        return all_findings

    def _build_chain_prompt_for_site(
        self,
        sink_site: "SinkCallSite",
        chain_context: ChainContext,
        chain_id: str
    ) -> str:
        """为触发点构建调用链分析 Prompt"""
        from .prompts import build_chain_analysis_prompt

        # Sink 类别特定的提示（硬编码，避免使用废弃的 SINK_CATEGORY_PROMPTS）
        category_prompts = {
            "command_execution": "重点关注：命令注入漏洞。检查用户输入是否经过充分的过滤和转义后才传入系统命令执行函数。",
            "file_read": "重点关注：任意文件读取漏洞。检查文件路径是否可控，是否有目录遍历风险。",
            "file_write": "重点关注：任意文件写入漏洞。检查文件路径和内容是否可控，是否可能写入恶意文件。",
            "file_include": "重点关注：文件包含漏洞。检查包含路径是否可控，是否可能包含恶意文件。",
            "sql_query": "重点关注：SQL注入漏洞。检查SQL语句拼接是否安全，是否使用参数化查询。",
            "deserialization": "重点关注：反序列化漏洞。检查反序列化的数据来源是否可信，是否可能构造恶意对象。",
            "ssrf": "重点关注：SSRF漏洞。检查URL是否可控，是否可能访问内部服务。",
            "code_execution": "重点关注：代码执行漏洞。检查eval/exec等函数的参数是否可控。",
            "ldap_query": "重点关注：LDAP注入漏洞。检查LDAP查询参数是否经过转义。",
            "xpath_query": "重点关注：XPath注入漏洞。检查XPath查询参数是否经过转义。",
            "xml_parse": "重点关注：XXE漏洞。检查XML解析器是否禁用了外部实体。",
        }
        category_hint = category_prompts.get(
            sink_site.sink_category.value,
            "请分析此代码是否存在安全漏洞。"
        )

        # 构建调用链代码上下文
        code_context_parts = []
        # 使用 chain_nodes 属性（ChainContext 的正确属性名）
        nodes = getattr(chain_context, 'chain_nodes', []) or getattr(chain_context, 'nodes', [])
        for node in nodes:
            code_context_parts.append(
                f"### {node.symbol} ({node.file_path}:{node.line_start}-{node.line_end})\n"
                f"```\n{node.code}\n```"
            )
        code_context = "\n\n".join(code_context_parts)

        # 构建调用链路径（从 chain_nodes 提取符号名称）
        chain_path = [node.symbol for node in nodes] if nodes else [sink_site.symbol]
        chain_path_str = ' -> '.join(chain_path)

        # 构建 Prompt
        prompt = f"""## 安全审计任务

**触发点**: {sink_site.symbol}
**文件**: {sink_site.file_path}:{sink_site.line_start}
**危险函数类别**: {sink_site.sink_category.value}
**风险等级**: {sink_site.risk_level.value}
**匹配规则**: {', '.join(sink_site.matched_rule_ids)}
**匹配模式**: {', '.join(sink_site.matched_patterns)}

**触发代码片段**:
```
{sink_site.call_snippet}
```

{category_hint}

## 调用链路径
{chain_path_str}

## 调用链代码上下文
{code_context}

## 分析要求
1. 分析用户输入是否能到达此危险函数
2. 检查是否有充分的输入验证和过滤
3. 评估是否存在可利用的安全漏洞
4. 如果存在问题，描述攻击场景和修复建议

请以 JSON 格式输出分析结果。"""

        return prompt

    def _analyze_chain_with_llm(
        self,
        sink_site: "SinkCallSite",
        chain_context: ChainContext,
        chain_id: str,
        prompt: str
    ) -> Optional[Finding]:
        """使用 LLM 分析调用链"""
        from .prompts import get_chain_output_schema

        # 使用内置的系统提示词
        chain_system_prompt = """你是一个专业的代码安全审计专家，擅长发现代码中的安全漏洞。

你需要分析给定的调用链代码，判断是否存在安全漏洞。重点关注：
1. 用户可控输入是否能到达危险函数（如命令执行、SQL查询、文件操作等）
2. 输入是否经过充分的验证和过滤
3. 是否存在可被利用的攻击路径

请基于代码事实进行分析，输出结构化的 JSON 结果。"""

        try:
            # 记录 LLM 调用（使用 log_thinking 替代不存在的 log_llm_call）
            if self.interaction_repo:
                self.interaction_repo.log_thinking(
                    self.scan_id,
                    f"正在分析调用链: {chain_id}"
                )

            # 调用 LLM
            response = self.llm_client.chat_completion(
                messages=[
                    ChatMessage(role="system", content=chain_system_prompt),
                    ChatMessage(role="user", content=prompt),
                ],
                temperature=self.config.llm.temperature,
                max_tokens=self.config.llm.max_tokens,
                response_format={"type": "json_object"}
            )

            # 记录响应（使用 log_analysis 替代不存在的 log_llm_response）
            if self.interaction_repo:
                self.interaction_repo.log_analysis(
                    self.scan_id,
                    response.content[:2000] if response.content else "",
                    tokens_used=response.usage.get("total_tokens", 0) if response.usage else 0
                )

            # 解析响应
            result = self._parse_llm_response(response.content)

            if not result or not result.get("has_issue"):
                return None

            # 生成确定性 Finding ID（同一漏洞跨扫描可去重）
            content_for_hash = f"{self.scan_id}:{sink_site.file_path}:{sink_site.line_start}:{sink_site.symbol}"
            finding_hash = hashlib.sha256(content_for_hash.encode()).hexdigest()[:12]
            finding_id = f"f-{finding_hash}"

            # 创建 Finding
            finding = Finding(
                id=finding_id,
                title=result.get("issue_type", sink_site.sink_category.value),
                file_path=sink_site.file_path,
                line_start=sink_site.line_start,
                line_end=sink_site.line_end,
                symbol=sink_site.symbol,
                severity=Severity.from_string(result.get("severity", "medium")),
                confidence=result.get("confidence", 0.7),
                category=sink_site.sink_category.value,
                summary=result.get("summary", ""),
                details=result.get("details", ""),
                evidence=[Evidence(
                    file_path=sink_site.file_path,
                    line_start=sink_site.line_start,
                    line_end=sink_site.line_end,
                    code_snippet=sink_site.call_snippet,
                    description=f"触发点: {sink_site.symbol}"
                )],
                attack_scenario=result.get("attack_scenario", ""),
                fix_suggestion=result.get("fix_suggestion", ""),
                rule_ids=sink_site.matched_rule_ids,
                cwe_ids=result.get("cwe_ids", []),
                notes=result.get("notes", ""),
                metadata={
                    "chain_id": chain_id,
                    # chain_context 没有 chain_path 属性，改用 chain_nodes 构建路径
                    "chain_path": " -> ".join([n.symbol for n in chain_context.chain_nodes]) if chain_context.chain_nodes else "",
                    "sink_category": sink_site.sink_category.value,
                    "analysis_mode": "selected_analysis"
                }
            )

            return finding

        except Exception as e:
            logger.error(f"LLM 调用失败: {e}")
            return None

    def _analyze_sink_site_simple(
        self,
        sink_site: "SinkCallSite",
        code_units: List[CodeUnit]
    ) -> Optional[Finding]:
        """简单模式分析触发点（不使用调用链）"""
        # 查找对应的 CodeUnit
        target_unit = None
        for unit in code_units:
            if unit.symbol == sink_site.symbol and unit.file_path == sink_site.file_path:
                target_unit = unit
                break

        if not target_unit:
            return None

        # 构建简单的分析 prompt
        prompt = f"""请分析以下代码是否存在安全漏洞：

**函数**: {sink_site.symbol}
**文件**: {sink_site.file_path}:{sink_site.line_start}
**危险函数类别**: {sink_site.sink_category.value}
**匹配的危险模式**: {', '.join(sink_site.matched_patterns)}

**代码**:
```
{target_unit.code}
```

请以 JSON 格式输出分析结果。"""

        try:
            # 使用内置的系统提示词
            chain_system_prompt = """你是一个专业的代码安全审计专家，擅长发现代码中的安全漏洞。

你需要分析给定的代码，判断是否存在安全漏洞。重点关注：
1. 用户可控输入是否能到达危险函数
2. 输入是否经过充分的验证和过滤
3. 是否存在可被利用的攻击路径

请基于代码事实进行分析，输出结构化的 JSON 结果。"""

            response = self.llm_client.chat_completion(
                messages=[
                    ChatMessage(role="system", content=chain_system_prompt),
                    ChatMessage(role="user", content=prompt),
                ],
                temperature=self.config.llm.temperature,
                max_tokens=self.config.llm.max_tokens,
                response_format={"type": "json_object"}
            )

            result = self._parse_llm_response(response.content)

            if not result or not result.get("has_issue"):
                return None

            # 生成唯一的 Finding ID
            # 生成确定性 Finding ID（同一漏洞跨扫描可去重）
            content_for_hash = f"{self.scan_id}:{sink_site.file_path}:{sink_site.line_start}:{sink_site.symbol}"
            finding_hash = hashlib.sha256(content_for_hash.encode()).hexdigest()[:12]
            finding_id = f"f-{finding_hash}"

            finding = Finding(
                id=finding_id,
                title=result.get("issue_type", sink_site.sink_category.value),
                file_path=sink_site.file_path,
                line_start=sink_site.line_start,
                line_end=sink_site.line_end,
                symbol=sink_site.symbol,
                severity=Severity.from_string(result.get("severity", "medium")),
                confidence=result.get("confidence", 0.7),
                category=sink_site.sink_category.value,
                summary=result.get("summary", ""),
                details=result.get("details", ""),
                evidence=[Evidence(
                    file_path=sink_site.file_path,
                    line_start=sink_site.line_start,
                    line_end=sink_site.line_end,
                    code_snippet=sink_site.call_snippet,
                    description=f"触发点: {sink_site.symbol}"
                )],
                attack_scenario=result.get("attack_scenario", ""),
                fix_suggestion=result.get("fix_suggestion", ""),
                rule_ids=sink_site.matched_rule_ids,
                cwe_ids=result.get("cwe_ids", []),
                notes=result.get("notes", ""),
                metadata={
                    "sink_category": sink_site.sink_category.value,
                    "analysis_mode": "simple"
                }
            )

            return finding

        except Exception as e:
            logger.error(f"简单分析失败: {e}")
            return None

    # ========================================================================
    # Function Calling 模式分析方法
    # ========================================================================

    def analyze_with_function_calling(
        self,
        sink_site: SinkCallSite,
        chain_context: ChainContext,
        code_units: List[CodeUnit],
        on_tool_call: Optional[callable] = None,
        on_llm_thinking: Optional[callable] = None,
    ) -> Optional[Finding]:
        """使用 Function Calling 模式分析触发点

        与普通 LLM 分析的区别：
        - LLM 可以主动调用工具查看更多代码
        - 分析过程更加自主和深入
        - 支持工具调用回调，用于实时展示

        Args:
            sink_site: 危险函数触发点
            chain_context: 调用链上下文
            code_units: 代码单元列表
            on_tool_call: 工具调用回调 (FCToolCall) -> None
            on_llm_thinking: LLM 思考状态回调 (str) -> None

        Returns:
            Finding 或 None
        """
        try:
            # 获取系统提示词基础部分
            # 注意：PromptManager 没有 get_prompt 方法，使用 build_chain_analysis_prompt 会返回完整的 prompt
            # 这里我们使用简化的基础 prompt，因为 FC 模式下工具说明会动态添加
            chain_system_prompt_base = """你是一个专业的代码安全审计专家，擅长发现代码中的安全漏洞。

你需要分析给定的调用链代码，判断是否存在安全漏洞。重点关注：
1. 用户可控输入是否能到达危险函数（如命令执行、SQL查询、文件操作等）
2. 输入是否经过充分的验证和过滤
3. 是否存在可被利用的攻击路径

请基于代码事实进行分析，避免猜测。如果需要更多上下文，使用提供的工具获取。"""

            # 创建安全分析工具集
            tools = FCSecurityTools(
                indexer=self.indexer,
                code_units=code_units,
                call_chain_analyzer=self.call_chain_analyzer,
                rule_manager=self.rule_manager,
            )

            # 配置回调
            fc_config = FCAdapterConfig(
                max_tool_calls_per_turn=5,
                max_turns=8,
                # temperature 使用 LLM 客户端配置的默认值（None）
                max_tokens=3000,
                on_tool_call_start=on_tool_call,
                on_tool_call_end=on_tool_call,
                on_llm_thinking=on_llm_thinking,
            )

            # 创建适配器
            adapter = FunctionCallingAdapter(
                llm_client=self.llm_client,
                tools=tools,
                config=fc_config,
            )

            # 构建分析提示
            sink_category = sink_site.sink_category.value
            chain_id = f"chain-{sink_site.id}"

            system_prompt = f"""{chain_system_prompt_base}

## 可用工具

你可以使用以下工具来获取更多代码上下文：
- read_function_code: 读取指定函数的完整代码
- find_callers: 查找调用指定函数的位置
- find_callees: 查找函数调用的其他函数
- search_code: 搜索代码库中的相关代码
- get_call_chain: 获取调用链路径
- check_sanitization: 检查是否有输入验证

分析完成后，使用 report_finding 工具报告你的发现。

## 分析要求

1. 仔细分析提供的调用链代码
2. 如果需要更多上下文，使用工具查看相关代码
3. 重点关注用户输入是否能到达危险函数
4. 评估是否存在可利用的安全漏洞
5. 使用 report_finding 输出结构化结果"""

            # 构建用户提示（调用链上下文）
            context_text = chain_context.to_prompt_text()

            user_prompt = f"""## 分析任务

**触发点**: {sink_site.symbol}
**文件**: {sink_site.file_path}:{sink_site.line_start}
**危险函数类别**: {sink_category}
**匹配规则**: {', '.join(sink_site.matched_rule_ids)}

**触发代码**:
```
{sink_site.call_snippet}
```

## 调用链上下文

{context_text}

请分析此代码是否存在安全漏洞。如需更多上下文，请使用提供的工具。
分析完成后，调用 report_finding 报告你的发现。"""

            # 记录开始分析
            if self.interaction_repo and self.scan_id:
                self.interaction_repo.log_thinking(
                    self.scan_id,
                    f"[FC Mode] 开始分析 {sink_site.symbol}，使用 Function Calling 模式"
                )

            # 执行分析
            logger.info(f"[FCAnalysis] 开始 Function Calling 分析: {sink_site.symbol}")
            result = adapter.analyze(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )

            logger.info(
                f"[FCAnalysis] 完成: LLM调用={result.total_llm_calls}, "
                f"工具调用={len(result.tool_calls)}, 耗时={result.duration_ms}ms"
            )

            # 记录工具调用
            if self.interaction_repo and self.scan_id:
                for tc in result.tool_calls:
                    self.interaction_repo.log_tool_call(
                        self.scan_id,
                        tool_name=tc.tool_name,
                        tool_input=tc.arguments,
                        tool_output=tc.result,
                    )

            # 检查是否发现问题
            if not result.has_issue or not result.parsed_result:
                logger.debug(f"[FCAnalysis] {sink_site.symbol} 未发现问题")
                return None

            # 从结果构建 Finding
            parsed = result.parsed_result

            # 生成确定性 Finding ID（同一漏洞跨扫描可去重）
            content_for_hash = f"{self.scan_id}:{sink_site.file_path}:{sink_site.line_start}:{sink_site.symbol}"
            finding_hash = hashlib.sha256(content_for_hash.encode()).hexdigest()[:12]
            finding_id = f"fc-{finding_hash}"

            finding = Finding(
                id=finding_id,
                title=parsed.get("issue_type", sink_category),
                file_path=sink_site.file_path,
                line_start=sink_site.line_start,
                line_end=sink_site.line_end,
                symbol=sink_site.symbol,
                severity=Severity.from_string(parsed.get("severity", "medium")),
                confidence=parsed.get("confidence", 0.7),
                category=sink_category,
                summary=parsed.get("summary", ""),
                details=parsed.get("details", ""),
                evidence=[Evidence(
                    file_path=sink_site.file_path,
                    line_start=sink_site.line_start,
                    line_end=sink_site.line_end,
                    code_snippet=sink_site.call_snippet,
                    description=f"触发点: {sink_site.symbol}",
                )],
                attack_scenario=parsed.get("attack_scenario", ""),
                fix_suggestion=parsed.get("fix_suggestion", ""),
                rule_ids=sink_site.matched_rule_ids,
                notes=parsed.get("notes", ""),
                metadata={
                    "chain_id": chain_id,
                    "chain_length": chain_context.chain_length,
                    "sink_category": sink_category,
                    "analysis_mode": "function_calling",
                    "llm_calls": result.total_llm_calls,
                    "tool_calls_count": len(result.tool_calls),
                    "total_tokens": result.total_tokens,
                },
            )

            logger.info(f"[FCAnalysis] 发现问题: {finding.title} ({finding.severity.value})")

            # 记录发现
            if self.interaction_repo and self.scan_id:
                self.interaction_repo.log_finding(
                    self.scan_id,
                    finding_data={
                        "id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "confidence": finding.confidence,
                        "analysis_mode": "function_calling",
                    }
                )

            return finding

        except Exception as e:
            logger.exception(f"[FCAnalysis] Function Calling 分析失败: {e}")
            return None

    def analyze_chains_with_fc(
        self,
        code_units: List[CodeUnit],
        language: Optional[str] = None,
        max_candidates: int = 50,
        max_chain_depth: int = 5,
        max_llm_calls: int = 30,
        vuln_types: Optional[List[str]] = None,
        progress_callback: Optional[callable] = None,
        on_tool_call: Optional[callable] = None,
    ) -> List[Finding]:
        """使用 Function Calling 模式进行链级分析

        这是 analyze_chains 的 Function Calling 版本，
        LLM 可以主动调用工具获取更多上下文。

        Args:
            code_units: 代码单元列表
            language: 限定语言
            max_candidates: 最大候选点数量
            max_chain_depth: 最大调用链深度
            max_llm_calls: 最大 LLM 调用次数
            vuln_types: 漏洞类型过滤
            progress_callback: 进度回调
            on_tool_call: 工具调用回调

        Returns:
            Finding 列表
        """
        from .call_chain import CallChainAnalyzer

        logger.info(f"[FC-P0] 开始 Function Calling 链级分析")

        # 辅助函数
        def report_progress(progress: float, step: str):
            if progress_callback:
                try:
                    progress_callback(progress, step)
                except Exception as e:
                    logger.warning(f"Progress callback failed: {e}")

        report_progress(0.1, "扫描危险函数触发点...")

        # 1. 扫描触发点
        sink_sites = self.discover_sink_sites(code_units, language)
        if not sink_sites:
            logger.info("[FC-P0] 未发现危险函数触发点")
            return []

        logger.info(f"[FC-P0] 发现 {len(sink_sites)} 个触发点")
        sink_sites = sink_sites[:max_candidates]

        # 2. 构建调用图
        report_progress(0.2, "构建调用图...")
        if self.call_chain_analyzer is None:
            self.call_chain_analyzer = CallChainAnalyzer(self.rule_manager)

        self._call_graph = self.call_chain_analyzer.build_call_graph(code_units)
        logger.info(f"[FC-P0] 调用图: {len(self._call_graph.nodes)} 节点")

        # 3. 收集调用链上下文
        report_progress(0.3, "收集调用链上下文...")
        context_collector = ChainContextCollector(
            call_chain_analyzer=self.call_chain_analyzer,
            code_units=code_units,
        )

        chain_contexts = context_collector.collect_contexts_batch(
            sink_sites=sink_sites,
            max_depth=max_chain_depth,
        )

        if not chain_contexts:
            logger.warning("[FC-P0] 未收集到调用链上下文")
            return []

        logger.info(f"[FC-P0] 收集了 {len(chain_contexts)} 个调用链上下文")

        # 限制分析数量
        if len(chain_contexts) > max_llm_calls:
            chain_contexts = chain_contexts[:max_llm_calls]

        # 4. Function Calling 分析
        report_progress(0.4, f"开始 FC 分析 {len(chain_contexts)} 个上下文...")
        findings = []
        total = len(chain_contexts)

        for idx, ctx in enumerate(chain_contexts):
            progress = 0.4 + (idx + 1) / total * 0.55
            report_progress(progress, f"FC 分析 {idx+1}/{total}: {ctx.sink_site.symbol}")

            finding = self.analyze_with_function_calling(
                sink_site=ctx.sink_site,
                chain_context=ctx,
                code_units=code_units,
                on_tool_call=on_tool_call,
            )

            if finding:
                findings.append(finding)
                logger.info(f"[{idx+1}/{total}] 发现: {finding.title}")

        # 5. 过滤和排序
        findings = self._filter_and_sort_findings(findings)

        report_progress(1.0, f"分析完成，发现 {len(findings)} 个问题")
        logger.info(f"[FC-P0] 完成，共 {len(findings)} 个发现")

        return findings

