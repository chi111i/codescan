"""
命令行接口 - 主入口
"""

import sys
import json
import logging
from pathlib import Path
from typing import Optional, List
from datetime import datetime

try:
    import typer
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    typer = None

# 设置项目路径
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import load_config, save_default_config, AuditConfig
from llm_client import create_llm_client
from indexer import CodeIndexer, create_vector_store, StorageManager
from rules import create_rule_manager
from analyzer import (
    SecurityAnalyzer,
    CallChainAnalyzer,
    HighRiskVulnDetector,
    VulnType,
)
from reporting import ReportGenerator

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def create_app():
    """创建 CLI 应用"""
    if not HAS_RICH:
        print("警告: 未安装 typer/rich，使用简化 CLI")
        return None

    app = typer.Typer(
        name="audit",
        help="LLM 驱动的代码安全审计工具",
        add_completion=False,
    )
    console = Console()

    @app.command()
    def init(
        output: str = typer.Option(
            "audit.config.yaml",
            "--output", "-o",
            help="配置文件输出路径"
        ),
    ):
        """初始化配置文件"""
        save_default_config(output)
        console.print(f"[green]配置文件已生成: {output}[/green]")
        console.print("请编辑配置文件，设置 LLM API Key 等参数后使用")

    @app.command()
    def index(
        path: str = typer.Argument(
            ".",
            help="要索引的项目路径"
        ),
        config_file: Optional[str] = typer.Option(
            None,
            "--config", "-c",
            help="配置文件路径"
        ),
        clear: bool = typer.Option(
            False,
            "--clear",
            help="清空现有索引后重建"
        ),
    ):
        """索引项目代码"""
        try:
            # 加载配置
            config = load_config(config_path=config_file, target_path=path)
            _setup_logging(config)

            console.print(f"[cyan]正在索引: {path}[/cyan]")

            # 创建组件
            llm_client = create_llm_client(config.llm)
            vector_store = create_vector_store(config.vector_store)
            indexer = CodeIndexer(config, llm_client, vector_store)

            if clear:
                console.print("[yellow]清空现有索引...[/yellow]")
                indexer.clear_index()

            # 执行索引
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console,
            ) as progress:
                task = progress.add_task("索引中...", total=100)

                def update_progress(current, total):
                    progress.update(task, completed=int(current / total * 100))

                count = indexer.index_directory(path, progress_callback=update_progress)

            console.print(f"[green]索引完成! 共 {count} 个代码单元[/green]")

            # 显示统计
            stats = indexer.get_stats()
            console.print(f"  集合: {stats['collection_name']}")
            console.print(f"  总数: {stats['total_units']}")

        except Exception as e:
            console.print(f"[red]错误: {e}[/red]")
            raise typer.Exit(1)

    @app.command()
    def scan(
        path: str = typer.Argument(
            ".",
            help="要扫描的项目路径"
        ),
        config_file: Optional[str] = typer.Option(
            None,
            "--config", "-c",
            help="配置文件路径"
        ),
        language: Optional[str] = typer.Option(
            None,
            "--language", "-l",
            help="限定语言 (python, javascript)"
        ),
        output: Optional[str] = typer.Option(
            None,
            "--output", "-o",
            help="报告输出路径"
        ),
        format: str = typer.Option(
            "console",
            "--format", "-f",
            help="输出格式 (console, json, sarif)"
        ),
        max_issues: int = typer.Option(
            50,
            "--max-issues", "-n",
            help="最大分析候选数量"
        ),
        reindex: bool = typer.Option(
            False,
            "--reindex",
            help="扫描前重新索引"
        ),
        chain_analysis: bool = typer.Option(
            True,
            "--chain/--no-chain",
            help="是否使用链级分析（P0推荐流程，默认开启）"
        ),
        max_chain_depth: int = typer.Option(
            5,
            "--chain-depth",
            help="最大调用链深度"
        ),
    ):
        """执行安全扫描"""
        try:
            # 加载配置
            config = load_config(config_path=config_file, target_path=path)
            _setup_logging(config)

            console.print(Panel.fit(
                "[bold cyan]LLM 代码安全审计工具[/bold cyan]\n"
                f"目标: {path}",
                border_style="cyan"
            ))

            # 创建组件
            console.print("[dim]初始化组件...[/dim]")
            llm_client = create_llm_client(config.llm)
            vector_store = create_vector_store(config.vector_store)
            indexer = CodeIndexer(config, llm_client, vector_store)
            rule_manager = create_rule_manager(config.rules)
            analyzer = SecurityAnalyzer(config, llm_client, indexer, rule_manager)
            reporter = ReportGenerator(config.report)

            console.print(f"  已加载 {rule_manager.count()} 条安全规则")

            # 检查是否需要索引
            stats = indexer.get_stats()
            if stats["total_units"] == 0 or reindex:
                console.print("[yellow]索引代码...[/yellow]")
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                ) as progress:
                    task = progress.add_task("索引中...", total=None)
                    count = indexer.index_directory(path)
                console.print(f"  索引了 {count} 个代码单元")
            else:
                console.print(f"  使用现有索引 ({stats['total_units']} 个单元)")

            # 执行分析
            analysis_mode = "链级分析" if chain_analysis else "简单分析"
            console.print(f"\n[cyan]正在分析（{analysis_mode}模式）...[/cyan]")
            with console.status("[bold green]LLM 分析中..."):
                findings = analyzer.analyze(
                    language=language,
                    max_candidates=max_issues,
                    max_workers=2,
                    use_chain_analysis=chain_analysis,
                    max_chain_depth=max_chain_depth,
                )

            # 生成报告
            console.print(f"\n[green]发现 {len(findings)} 个潜在问题[/green]\n")

            output_path = output or config.report.output_path
            reporter.generate_report(
                findings=findings,
                output_format=format,
                output_path=output_path,
                metadata={"target_path": path, "language": language},
            )

            # 如果输出到文件，显示路径
            if format != "console" and output_path:
                console.print(f"\n[dim]报告已保存到: {output_path}[/dim]")

            # 根据发现的严重性设置退出码
            has_critical = any(f.severity.value in ("critical", "high") for f in findings)
            if has_critical:
                raise typer.Exit(1)

        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[red]错误: {e}[/red]")
            if config.debug:
                import traceback
                console.print(traceback.format_exc())
            raise typer.Exit(1)

    @app.command()
    def callgraph(
        path: str = typer.Argument(
            ".",
            help="要分析的项目路径"
        ),
        config_file: Optional[str] = typer.Option(
            None,
            "--config", "-c",
            help="配置文件路径"
        ),
        output: Optional[str] = typer.Option(
            None,
            "--output", "-o",
            help="调用图输出路径"
        ),
        max_depth: int = typer.Option(
            10,
            "--max-depth", "-d",
            help="最大调用链深度"
        ),
        show_stats: bool = typer.Option(
            True,
            "--stats/--no-stats",
            help="是否显示统计信息"
        ),
        find_taint: bool = typer.Option(
            True,
            "--taint/--no-taint",
            help="是否查找污点路径"
        ),
    ):
        """构建并分析函数调用图"""
        try:
            # 加载配置
            config = load_config(config_path=config_file, target_path=path)
            _setup_logging(config)

            console.print(Panel.fit(
                "[bold cyan]调用链分析[/bold cyan]\n"
                f"目标: {path}",
                border_style="cyan"
            ))

            # 创建组件
            console.print("[dim]初始化组件...[/dim]")
            llm_client = create_llm_client(config.llm)
            vector_store = create_vector_store(config.vector_store)
            indexer = CodeIndexer(config, llm_client, vector_store)
            rule_manager = create_rule_manager(config.rules)

            # 检查索引
            stats = indexer.get_stats()
            if stats["total_units"] == 0:
                console.print("[yellow]索引代码...[/yellow]")
                with console.status("[bold green]索引中..."):
                    indexer.index_directory(path)

            # 获取所有代码单元
            console.print("[cyan]获取代码单元...[/cyan]")
            code_units = indexer.get_all_units()
            console.print(f"  共 {len(code_units)} 个代码单元")

            # 创建调用链分析器
            chain_analyzer = CallChainAnalyzer(rule_manager)

            # 构建调用图
            console.print("[cyan]构建调用图...[/cyan]")
            with console.status("[bold green]分析中..."):
                call_graph = chain_analyzer.build_call_graph(code_units)

            # 显示统计
            if show_stats:
                console.print("\n[bold]调用图统计:[/bold]")
                stats_table = Table(show_header=False, box=None)
                stats_table.add_column("指标", style="cyan")
                stats_table.add_column("值", style="green")

                stats_table.add_row("总节点数", str(len(call_graph.nodes)))
                stats_table.add_row("总边数", str(len(call_graph.edges)))
                stats_table.add_row("入口点", str(len(call_graph.get_entry_points())))
                stats_table.add_row("输入源 (Source)", str(len(call_graph.get_sources())))
                stats_table.add_row("危险函数 (Sink)", str(len(call_graph.get_sinks())))
                stats_table.add_row("过滤函数 (Sanitizer)", str(len(call_graph.get_sanitizers())))

                console.print(stats_table)

            # 查找污点路径
            if find_taint:
                console.print("\n[cyan]查找污点传播路径...[/cyan]")
                with console.status("[bold green]分析中..."):
                    taint_paths = chain_analyzer.find_taint_paths(
                        max_depth=max_depth,
                        max_paths=100,
                    )

                if taint_paths:
                    console.print(f"\n[yellow]发现 {len(taint_paths)} 条污点路径[/yellow]")

                    # 按风险排序显示前 10 条
                    unsafe_paths = [p for p in taint_paths if not p.is_sanitized]
                    console.print(f"  其中 [red]{len(unsafe_paths)} 条未经过滤[/red]")

                    if unsafe_paths:
                        console.print("\n[bold red]高风险污点路径:[/bold red]")
                        for i, path in enumerate(unsafe_paths[:10], 1):
                            source_node = call_graph.get_node(path.source_node)
                            sink_node = call_graph.get_node(path.sink_node)

                            source_name = source_node.qualified_name if source_node else path.source_node
                            sink_name = sink_node.qualified_name if sink_node else path.sink_node

                            console.print(f"\n  {i}. [cyan]{source_name}[/cyan] → [red]{sink_name}[/red]")
                            console.print(f"     风险: {path.risk_level}, 置信度: {path.confidence:.0%}")
                            console.print(f"     路径长度: {len(path.path)}")
                            console.print(f"     {path.description}")
                else:
                    console.print("[green]未发现污点路径[/green]")

            # 查找危险调用链
            console.print("\n[cyan]分析危险调用链...[/cyan]")
            with console.status("[bold green]分析中..."):
                dangerous_chains = chain_analyzer.find_dangerous_chains()

            if dangerous_chains:
                console.print(f"\n[yellow]发现 {len(dangerous_chains)} 条危险调用链[/yellow]")

                # 按风险分组统计
                risk_counts = {}
                for chain in dangerous_chains:
                    risk = chain.get("effective_risk", "unknown")
                    risk_counts[risk] = risk_counts.get(risk, 0) + 1

                console.print("风险分布:")
                for risk, count in sorted(risk_counts.items()):
                    color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(risk, "white")
                    console.print(f"  [{color}]{risk}[/{color}]: {count}")

            # 导出结果
            output_path = output or f".audit_data/call_graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            console.print(f"\n[dim]导出结果到: {output_path}[/dim]")

            chain_analyzer.export_to_json(
                output_path,
                include_call_graph=True,
                include_taint_paths=find_taint,
                include_dangerous_chains=True,
            )

            console.print("[green]调用链分析完成![/green]")

        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[red]错误: {e}[/red]")
            import traceback
            console.print(traceback.format_exc())
            raise typer.Exit(1)

    @app.command()
    def vulnscan(
        path: str = typer.Argument(
            ".",
            help="要扫描的项目路径"
        ),
        config_file: Optional[str] = typer.Option(
            None,
            "--config", "-c",
            help="配置文件路径"
        ),
        output: Optional[str] = typer.Option(
            None,
            "--output", "-o",
            help="报告输出路径"
        ),
        vuln_types: Optional[str] = typer.Option(
            None,
            "--types", "-t",
            help="漏洞类型，逗号分隔 (rce,command_injection,file_read,file_write,auth_bypass,idor,ssrf,ssti,deserialization,logic_flaw,race_condition)"
        ),
        use_llm: bool = typer.Option(
            True,
            "--llm/--no-llm",
            help="是否使用 LLM 深度分析"
        ),
        logic_scan: bool = typer.Option(
            True,
            "--logic/--no-logic",
            help="是否扫描业务逻辑漏洞"
        ),
        min_confidence: float = typer.Option(
            0.5,
            "--min-confidence",
            help="最小置信度过滤"
        ),
    ):
        """扫描高危漏洞 (RCE、文件操作、逻辑漏洞等)"""
        try:
            # 加载配置
            config = load_config(config_path=config_file, target_path=path)
            _setup_logging(config)

            console.print(Panel.fit(
                "[bold red]高危漏洞扫描[/bold red]\n"
                f"目标: {path}",
                border_style="red"
            ))

            # 解析漏洞类型
            selected_types = None
            if vuln_types:
                type_map = {
                    "rce": VulnType.RCE,
                    "command_injection": VulnType.COMMAND_INJECTION,
                    "file_read": VulnType.FILE_READ,
                    "file_write": VulnType.FILE_WRITE,
                    "file_upload": VulnType.FILE_UPLOAD,
                    "path_traversal": VulnType.PATH_TRAVERSAL,
                    "sql_injection": VulnType.SQL_INJECTION,
                    "nosql_injection": VulnType.NOSQL_INJECTION,
                    "ssrf": VulnType.SSRF,
                    "xxe": VulnType.XXE,
                    "deserialization": VulnType.DESERIALIZATION,
                    "ssti": VulnType.SSTI,
                    "auth_bypass": VulnType.AUTH_BYPASS,
                    "authz_bypass": VulnType.AUTHZ_BYPASS,
                    "idor": VulnType.IDOR,
                    "logic_flaw": VulnType.LOGIC_FLAW,
                    "race_condition": VulnType.RACE_CONDITION,
                    "mass_assignment": VulnType.MASS_ASSIGNMENT,
                }
                selected_types = []
                for t in vuln_types.split(","):
                    t = t.strip().lower()
                    if t in type_map:
                        selected_types.append(type_map[t])
                    else:
                        console.print(f"[yellow]未知漏洞类型: {t}[/yellow]")

                if selected_types:
                    console.print(f"扫描类型: {', '.join(t.value for t in selected_types)}")

            # 创建组件
            console.print("[dim]初始化组件...[/dim]")
            llm_client = create_llm_client(config.llm)
            vector_store = create_vector_store(config.vector_store)
            indexer = CodeIndexer(config, llm_client, vector_store)
            rule_manager = create_rule_manager(config.rules)

            # 检查索引
            stats = indexer.get_stats()
            if stats["total_units"] == 0:
                console.print("[yellow]索引代码...[/yellow]")
                with console.status("[bold green]索引中..."):
                    indexer.index_directory(path)

            # 获取代码单元
            console.print("[cyan]获取代码单元...[/cyan]")
            code_units = indexer.get_all_units()
            console.print(f"  共 {len(code_units)} 个代码单元")

            # 创建漏洞检测器
            vuln_detector = HighRiskVulnDetector(llm_client, rule_manager)

            # 执行漏洞检测
            console.print("\n[cyan]扫描高危漏洞...[/cyan]")
            all_findings = []

            with console.status("[bold red]模式匹配扫描中..."):
                findings = vuln_detector.detect_vulnerabilities(
                    code_units,
                    vuln_types=selected_types,
                    use_llm=use_llm,
                )
                all_findings.extend(findings)

            console.print(f"  模式匹配发现 {len(findings)} 个潜在漏洞")

            # 业务逻辑漏洞扫描
            if logic_scan:
                console.print("\n[cyan]扫描业务逻辑漏洞...[/cyan]")
                with console.status("[bold red]LLM 深度分析中..."):
                    logic_findings = vuln_detector.detect_logic_vulnerabilities(code_units)
                    all_findings.extend(logic_findings)

                console.print(f"  逻辑分析发现 {len(logic_findings)} 个潜在漏洞")

            # 过滤低置信度结果
            filtered_findings = [f for f in all_findings if f.confidence >= min_confidence]

            if len(filtered_findings) < len(all_findings):
                console.print(f"\n[dim]过滤掉 {len(all_findings) - len(filtered_findings)} 个低置信度结果[/dim]")

            # 显示结果
            if filtered_findings:
                console.print(f"\n[bold red]发现 {len(filtered_findings)} 个高危漏洞:[/bold red]\n")

                # 按严重性分组
                findings_by_severity = {}
                for f in filtered_findings:
                    sev = f.severity.value
                    if sev not in findings_by_severity:
                        findings_by_severity[sev] = []
                    findings_by_severity[sev].append(f)

                # 显示表格
                table = Table(title="漏洞扫描结果")
                table.add_column("ID", style="cyan", width=12)
                table.add_column("类型", width=15)
                table.add_column("严重性", width=10)
                table.add_column("置信度", width=8)
                table.add_column("位置", width=40)
                table.add_column("需审查", width=6)

                severity_order = ["critical", "high", "medium", "low"]
                for sev in severity_order:
                    if sev not in findings_by_severity:
                        continue

                    for f in findings_by_severity[sev]:
                        sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(sev, "white")
                        review_mark = "[yellow]是[/yellow]" if f.needs_manual_review else "[green]否[/green]"

                        table.add_row(
                            f.id,
                            f.vuln_type.value,
                            f"[{sev_color}]{sev}[/{sev_color}]",
                            f"{f.confidence:.0%}",
                            f"{f.file_path}:{f.line_start}",
                            review_mark,
                        )

                console.print(table)

                # 显示详细信息（前 5 个高危）
                critical_high = [f for f in filtered_findings if f.severity.value in ("critical", "high")]
                if critical_high:
                    console.print("\n[bold red]高危漏洞详情:[/bold red]")
                    for f in critical_high[:5]:
                        console.print(Panel(
                            f"[bold]{f.name}[/bold]\n\n"
                            f"[cyan]类型:[/cyan] {f.vuln_type.value}\n"
                            f"[cyan]位置:[/cyan] {f.file_path}:{f.line_start}-{f.line_end}\n"
                            f"[cyan]函数:[/cyan] {f.function_name}\n\n"
                            f"[yellow]描述:[/yellow]\n{f.description}\n\n"
                            f"[red]攻击场景:[/red]\n{f.attack_scenario[:300]}...\n\n"
                            f"[green]修复建议:[/green]\n{f.fix_suggestion}\n\n"
                            + (f"[dim]LLM 分析:[/dim]\n{f.llm_analysis[:200]}...\n" if f.llm_analysis else "")
                            + (f"\n[yellow]需人工确认:[/yellow] {f.review_notes}" if f.review_notes else ""),
                            title=f"[red]{f.id}[/red]",
                            border_style="red" if f.severity.value == "critical" else "yellow",
                        ))
            else:
                console.print("[green]未发现高危漏洞[/green]")

            # 导出结果
            output_path = output or f".audit_data/vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            console.print(f"\n[dim]导出结果到: {output_path}[/dim]")
            vuln_detector.export_findings(output_path)

            console.print("[green]漏洞扫描完成![/green]")

            # 如果有高危漏洞，返回非零退出码
            has_critical = any(f.severity.value in ("critical", "high") for f in filtered_findings)
            if has_critical:
                raise typer.Exit(1)

        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[red]错误: {e}[/red]")
            import traceback
            console.print(traceback.format_exc())
            raise typer.Exit(1)

    @app.command()
    def search(
        query: str = typer.Argument(
            ...,
            help="搜索查询"
        ),
        config_file: Optional[str] = typer.Option(
            None,
            "--config", "-c",
            help="配置文件路径"
        ),
        top_k: int = typer.Option(
            10,
            "--top", "-n",
            help="返回结果数量"
        ),
        language: Optional[str] = typer.Option(
            None,
            "--language", "-l",
            help="限定语言"
        ),
    ):
        """搜索相关代码"""
        try:
            config = load_config(config_path=config_file)
            _setup_logging(config)

            llm_client = create_llm_client(config.llm)
            vector_store = create_vector_store(config.vector_store)
            indexer = CodeIndexer(config, llm_client, vector_store)

            console.print(f"[cyan]搜索: {query}[/cyan]\n")

            results = indexer.search(query, top_k=top_k, language=language)

            if not results:
                console.print("[yellow]未找到相关代码[/yellow]")
                return

            for i, unit in enumerate(results, 1):
                console.print(f"[bold]{i}. {unit.file_path}:{unit.span.start_line}[/bold]")
                console.print(f"   {unit.symbol} ({unit.unit_type.value})")
                # 显示代码预览
                preview = unit.code[:200].replace("\n", " ")
                console.print(f"   [dim]{preview}...[/dim]")
                console.print()

        except Exception as e:
            console.print(f"[red]错误: {e}[/red]")
            raise typer.Exit(1)

    @app.command()
    def rules(
        action: str = typer.Argument(
            "list",
            help="操作: list, show, stats"
        ),
        rule_id: Optional[str] = typer.Option(
            None,
            "--id",
            help="规则 ID (用于 show)"
        ),
        language: Optional[str] = typer.Option(
            None,
            "--language", "-l",
            help="按语言过滤"
        ),
        category: Optional[str] = typer.Option(
            None,
            "--category", "-c",
            help="按类别过滤"
        ),
    ):
        """管理安全规则"""
        try:
            config = load_config()
            rule_manager = create_rule_manager(config.rules)

            if action == "list":
                rules_list = rule_manager.all_rules()

                if language:
                    rules_list = [r for r in rules_list if language in r.languages]
                if category:
                    rules_list = [r for r in rules_list if r.category.value == category]

                table = Table(title="安全规则列表")
                table.add_column("ID", style="cyan")
                table.add_column("名称")
                table.add_column("类型", style="green")
                table.add_column("类别")
                table.add_column("风险", style="yellow")
                table.add_column("语言")

                for r in rules_list:
                    risk_color = {
                        "critical": "red",
                        "high": "red",
                        "medium": "yellow",
                        "low": "blue",
                    }.get(r.risk_level.value, "white")

                    table.add_row(
                        r.id,
                        r.name[:30],
                        r.rule_type.value,
                        r.category.value,
                        f"[{risk_color}]{r.risk_level.value}[/{risk_color}]",
                        ", ".join(r.languages),
                    )

                console.print(table)
                console.print(f"\n共 {len(rules_list)} 条规则")

            elif action == "show":
                if not rule_id:
                    console.print("[red]请指定规则 ID (--id)[/red]")
                    raise typer.Exit(1)

                rule = rule_manager.get_rule(rule_id)
                if not rule:
                    console.print(f"[red]未找到规则: {rule_id}[/red]")
                    raise typer.Exit(1)

                console.print(Panel.fit(
                    f"[bold]{rule.name}[/bold]\n"
                    f"ID: {rule.id}\n"
                    f"类型: {rule.rule_type.value}\n"
                    f"类别: {rule.category.value}\n"
                    f"风险: {rule.risk_level.value}\n"
                    f"语言: {', '.join(rule.languages)}\n"
                    f"模式: {', '.join(rule.patterns)}\n\n"
                    f"描述: {rule.description}\n\n"
                    f"修复建议: {rule.fix_suggestion}",
                    title="规则详情"
                ))

            elif action == "stats":
                all_rules = rule_manager.all_rules()

                console.print("[bold]规则统计[/bold]\n")

                # 按类型统计
                type_counts = {}
                for r in all_rules:
                    type_counts[r.rule_type.value] = type_counts.get(r.rule_type.value, 0) + 1
                console.print("按类型:")
                for t, c in type_counts.items():
                    console.print(f"  {t}: {c}")

                # 按类别统计
                cat_counts = {}
                for r in all_rules:
                    cat_counts[r.category.value] = cat_counts.get(r.category.value, 0) + 1
                console.print("\n按类别:")
                for c, n in cat_counts.items():
                    console.print(f"  {c}: {n}")

                # 按语言统计
                lang_counts = {}
                for r in all_rules:
                    for lang in r.languages:
                        lang_counts[lang] = lang_counts.get(lang, 0) + 1
                console.print("\n按语言:")
                for l, n in lang_counts.items():
                    console.print(f"  {l}: {n}")

        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[red]错误: {e}[/red]")
            raise typer.Exit(1)

    @app.command()
    def explain(
        finding_id: str = typer.Argument(
            ...,
            help="发现 ID"
        ),
        report_file: str = typer.Option(
            ...,
            "--report", "-r",
            help="JSON 报告文件路径"
        ),
    ):
        """详细解释一个发现"""
        try:
            from analyzer import Finding

            # 读取报告
            with open(report_file, "r", encoding="utf-8") as f:
                report = json.load(f)

            # 查找指定的发现
            finding_data = None
            for f_data in report.get("findings", []):
                if f_data["id"] == finding_id:
                    finding_data = f_data
                    break

            if not finding_data:
                console.print(f"[red]未找到发现: {finding_id}[/red]")
                raise typer.Exit(1)

            finding = Finding.from_dict(finding_data)

            # 显示详细信息
            console.print(Panel.fit(
                f"[bold red]{finding.title}[/bold red]\n\n"
                f"[bold]位置:[/bold] {finding.file_path}:{finding.line_start}-{finding.line_end}\n"
                f"[bold]函数:[/bold] {finding.symbol}\n"
                f"[bold]严重性:[/bold] {finding.severity.value}\n"
                f"[bold]置信度:[/bold] {finding.confidence:.0%}\n\n"
                f"[bold cyan]摘要:[/bold cyan]\n{finding.summary}\n\n"
                f"[bold cyan]详细分析:[/bold cyan]\n{finding.details}\n\n"
                f"[bold yellow]攻击思路:[/bold yellow]\n{finding.attack_scenario}\n\n"
                f"[bold green]修复建议:[/bold green]\n{finding.fix_suggestion}",
                title=f"发现详情: {finding_id}",
                border_style="red"
            ))

            if finding.notes:
                console.print(f"\n[dim]备注: {finding.notes}[/dim]")

        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[red]错误: {e}[/red]")
            raise typer.Exit(1)

    @app.command()
    def storage(
        action: str = typer.Argument(
            "stats",
            help="操作: stats, clear, export"
        ),
        config_file: Optional[str] = typer.Option(
            None,
            "--config", "-c",
            help="配置文件路径"
        ),
        output: Optional[str] = typer.Option(
            None,
            "--output", "-o",
            help="导出路径"
        ),
    ):
        """管理存储（向量库 + JSON）"""
        try:
            config = load_config(config_path=config_file)
            _setup_logging(config)

            llm_client = create_llm_client(config.llm)
            vector_store = create_vector_store(config.vector_store)
            storage_manager = StorageManager(config, llm_client, vector_store)

            if action == "stats":
                stats = storage_manager.get_statistics()

                console.print("[bold]存储统计[/bold]\n")
                console.print(f"存储目录: {stats['storage_dir']}")
                console.print(f"\n向量存储:")
                console.print(f"  提供者: {stats['vector_store']['provider']}")
                console.print(f"  总单元: {stats['vector_store']['total_units']}")

                if "project_index" in stats:
                    pi = stats["project_index"]
                    console.print(f"\n项目索引:")
                    console.print(f"  项目路径: {pi['project_path']}")
                    console.print(f"  索引时间: {pi['indexed_at']}")
                    console.print(f"  文件数: {pi['total_files']}")
                    console.print(f"  代码单元: {pi['total_units']}")
                    console.print(f"  语言: {', '.join(pi['languages'])}")

                js = stats.get("json_storage", {})
                console.print(f"\nJSON 存储:")
                console.print(f"  调用图: {js.get('call_graphs', 0)} 个")
                console.print(f"  分析结果: {js.get('analysis_results', 0)} 个")

            elif action == "clear":
                if typer.confirm("确定要清空所有存储吗？此操作不可恢复！"):
                    storage_manager.clear_all()
                    console.print("[green]存储已清空[/green]")
                else:
                    console.print("[yellow]操作已取消[/yellow]")

            elif action == "export":
                console.print("[yellow]导出功能待实现[/yellow]")

        except Exception as e:
            console.print(f"[red]错误: {e}[/red]")
            raise typer.Exit(1)

    def _setup_logging(config: AuditConfig):
        """配置日志"""
        level = getattr(logging, config.log_level.upper(), logging.INFO)
        logging.getLogger().setLevel(level)
        if config.debug:
            logging.getLogger().setLevel(logging.DEBUG)

    return app


def simple_cli():
    """简化版 CLI（无 typer 依赖）"""
    import argparse

    parser = argparse.ArgumentParser(description="LLM 代码安全审计工具")
    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # init 命令
    init_parser = subparsers.add_parser("init", help="初始化配置文件")
    init_parser.add_argument("-o", "--output", default="audit.config.yaml")

    # index 命令
    index_parser = subparsers.add_parser("index", help="索引项目代码")
    index_parser.add_argument("path", nargs="?", default=".")
    index_parser.add_argument("-c", "--config")
    index_parser.add_argument("--clear", action="store_true")

    # scan 命令
    scan_parser = subparsers.add_parser("scan", help="执行安全扫描")
    scan_parser.add_argument("path", nargs="?", default=".")
    scan_parser.add_argument("-c", "--config")
    scan_parser.add_argument("-l", "--language")
    scan_parser.add_argument("-o", "--output")
    scan_parser.add_argument("-f", "--format", default="console")
    scan_parser.add_argument("-n", "--max-issues", type=int, default=50)
    scan_parser.add_argument("--reindex", action="store_true")

    # vulnscan 命令
    vuln_parser = subparsers.add_parser("vulnscan", help="高危漏洞扫描")
    vuln_parser.add_argument("path", nargs="?", default=".")
    vuln_parser.add_argument("-c", "--config")
    vuln_parser.add_argument("-o", "--output")
    vuln_parser.add_argument("-t", "--types")
    vuln_parser.add_argument("--no-llm", action="store_true")
    vuln_parser.add_argument("--no-logic", action="store_true")

    # callgraph 命令
    cg_parser = subparsers.add_parser("callgraph", help="调用链分析")
    cg_parser.add_argument("path", nargs="?", default=".")
    cg_parser.add_argument("-c", "--config")
    cg_parser.add_argument("-o", "--output")
    cg_parser.add_argument("-d", "--max-depth", type=int, default=10)

    args = parser.parse_args()

    if args.command == "init":
        save_default_config(args.output)
        print(f"配置文件已生成: {args.output}")

    elif args.command == "index":
        config = load_config(config_path=args.config, target_path=args.path)
        llm_client = create_llm_client(config.llm)
        vector_store = create_vector_store(config.vector_store)
        indexer = CodeIndexer(config, llm_client, vector_store)

        if args.clear:
            indexer.clear_index()

        print(f"正在索引: {args.path}")
        count = indexer.index_directory(args.path)
        print(f"索引完成! 共 {count} 个代码单元")

    elif args.command == "scan":
        config = load_config(config_path=args.config, target_path=args.path)
        llm_client = create_llm_client(config.llm)
        vector_store = create_vector_store(config.vector_store)
        indexer = CodeIndexer(config, llm_client, vector_store)
        rule_manager = create_rule_manager(config.rules)
        analyzer = SecurityAnalyzer(config, llm_client, indexer, rule_manager)
        reporter = ReportGenerator(config.report)

        # 检查索引
        stats = indexer.get_stats()
        if stats["total_units"] == 0 or args.reindex:
            print("索引代码...")
            indexer.index_directory(args.path)

        # 分析
        print("分析中...")
        findings = analyzer.analyze(
            language=args.language,
            max_candidates=args.max_issues,
        )

        # 报告
        print(f"发现 {len(findings)} 个潜在问题")
        reporter.generate_report(
            findings=findings,
            output_format=args.format,
            output_path=args.output or config.report.output_path,
            metadata={"target_path": args.path},
        )

    elif args.command == "vulnscan":
        config = load_config(config_path=args.config, target_path=args.path)
        llm_client = create_llm_client(config.llm)
        vector_store = create_vector_store(config.vector_store)
        indexer = CodeIndexer(config, llm_client, vector_store)
        rule_manager = create_rule_manager(config.rules)

        # 检查索引
        stats = indexer.get_stats()
        if stats["total_units"] == 0:
            print("索引代码...")
            indexer.index_directory(args.path)

        code_units = indexer.get_all_units()
        vuln_detector = HighRiskVulnDetector(llm_client, rule_manager)

        print("扫描高危漏洞...")
        findings = vuln_detector.detect_vulnerabilities(
            code_units,
            use_llm=not args.no_llm,
        )

        if not args.no_logic:
            print("扫描逻辑漏洞...")
            logic_findings = vuln_detector.detect_logic_vulnerabilities(code_units)
            findings.extend(logic_findings)

        print(f"发现 {len(findings)} 个潜在漏洞")

        output_path = args.output or f".audit_data/vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        vuln_detector.export_findings(output_path)
        print(f"结果已导出到: {output_path}")

    elif args.command == "callgraph":
        config = load_config(config_path=args.config, target_path=args.path)
        llm_client = create_llm_client(config.llm)
        vector_store = create_vector_store(config.vector_store)
        indexer = CodeIndexer(config, llm_client, vector_store)
        rule_manager = create_rule_manager(config.rules)

        # 检查索引
        stats = indexer.get_stats()
        if stats["total_units"] == 0:
            print("索引代码...")
            indexer.index_directory(args.path)

        code_units = indexer.get_all_units()
        chain_analyzer = CallChainAnalyzer(rule_manager)

        print("构建调用图...")
        call_graph = chain_analyzer.build_call_graph(code_units)
        print(f"节点: {len(call_graph.nodes)}, 边: {len(call_graph.edges)}")

        print("查找污点路径...")
        taint_paths = chain_analyzer.find_taint_paths(max_depth=args.max_depth)
        print(f"发现 {len(taint_paths)} 条污点路径")

        output_path = args.output or f".audit_data/call_graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        chain_analyzer.export_to_json(output_path)
        print(f"结果已导出到: {output_path}")

    else:
        parser.print_help()


def main():
    """主入口"""
    app = create_app()
    if app:
        app()
    else:
        simple_cli()


if __name__ == "__main__":
    main()
