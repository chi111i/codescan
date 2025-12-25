"""
配置模块 - 加载和管理所有配置项

支持：
- 默认配置
- 项目级配置文件 (audit.config.yaml)
- 环境变量覆盖
- 扫描模式控制
- 安全与隐私保护
"""

import os
from pathlib import Path
from dataclasses import dataclass, field, fields
from typing import Optional, List, Dict, Any
from enum import Enum
import yaml


class ScanMode(Enum):
    """扫描模式"""
    FAST_RULE = "fast-rule"      # 只跑规则 + 简单静态分析（不调用 LLM）
    LLM_DEEP = "llm-deep"        # 对高风险入口做深度 LLM 审计
    FULL = "full"                # 先规则筛选 → 再对命中的点做 LLM 深度分析
    HOTSPOT = "hotspot"          # 只分析最近改动的代码（Git diff）


class RiskLevel(Enum):
    """风险等级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class LLMConfig:
    """LLM 服务配置"""
    provider: str = "openai-compatible"
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4"
    embedding_model: str = "text-embedding-3-small"
    max_tokens: int = 4096
    temperature: float = 0.0
    timeout: int = 60
    max_retries: int = 3

    # 嵌入模型独立配置（如果不设置则使用 LLM 的配置）
    embedding_base_url: str = ""          # 嵌入模型 API 地址，为空则使用 base_url
    embedding_api_key: str = ""           # 嵌入模型 API Key，为空则使用 api_key
    embedding_dim: int = 1536             # 嵌入向量维度

    # Token 预算控制
    max_code_tokens_per_call: int = 3000  # 每次 LLM 调用的最大代码 token 数
    max_context_tokens: int = 6000        # 最大上下文 token 数

    # 多轮分析配置
    enable_multi_round: bool = True       # 是否启用多轮分析
    max_rounds: int = 2                   # 最大分析轮数

    # 离线/降级配置
    # 当嵌入接口不可用（网络/鉴权/服务异常）时，是否使用本地哈希向量作为退化方案。
    # 该方案可保证工具在离线环境仍能运行，但检索质量会低于真实嵌入模型。
    enable_local_embeddings_fallback: bool = True


@dataclass
class VectorStoreConfig:
    """向量数据库配置"""
    # 默认使用内存向量存储，开箱即用、无外部依赖。
    # 如需使用 Qdrant，请将 provider 设置为 "qdrant" 并安装可选依赖 qdrant-client。
    provider: str = "memory"
    host: str = "localhost"
    port: int = 6333
    collection_name: str = "code_audit"
    # Qdrant 特定配置
    api_key: Optional[str] = None
    https: bool = False

    # 缓存配置
    enable_cache: bool = True                    # 启用嵌入缓存
    cache_dir: str = ".audit_cache"              # 缓存目录
    cache_ttl_days: int = 30                     # 缓存过期天数


@dataclass
class ScanConfig:
    """扫描配置"""
    target_path: str = "."
    languages: List[str] = field(default_factory=lambda: ["python", "javascript", "php"])
    include_patterns: List[str] = field(default_factory=lambda: [
        "**/*.py", "**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx", "**/*.php"
    ])
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "**/node_modules/**",
        "**/__pycache__/**",
        "**/venv/**",
        "**/.git/**",
        "**/dist/**",
        "**/build/**",
        "**/vendor/**",
    ])
    max_file_size_kb: int = 500
    max_concurrent: int = 4
    chunk_size: int = 2000  # 每个代码块的最大 token 数

    # 扫描模式
    mode: str = "full"  # fast-rule, llm-deep, full, hotspot

    # Hotspot 模式配置
    git_diff_base: str = "HEAD~10"               # Git diff 基准
    recent_commits: int = 10                      # 最近 N 个提交

    # Hybrid 检索配置
    enable_hybrid_search: bool = True            # 启用混合检索
    keyword_boost: float = 0.3                   # 关键词匹配权重
    metadata_filter_first: bool = True           # 先元数据过滤再向量检索

    # 高级重排序配置
    enable_reranking: bool = True                # 启用高级重排序
    rerank_security_priority: bool = True        # 安全优先模式
    rerank_security_boost: float = 1.5           # 安全相关代码提升因子
    rerank_prefer_entry_points: bool = True      # 优先入口点 (handler/controller)


@dataclass
class RulesetConfig:
    """规则集配置"""
    id: str = "default"
    version: str = "1.0.0"
    name: str = "默认规则集"
    enabled: bool = True


@dataclass
class RulesConfig:
    """安全规则配置"""
    rules_dir: str = "rules/data"
    custom_rules_dir: Optional[str] = None
    enabled_categories: List[str] = field(default_factory=lambda: [
        "auth", "access-control", "business-logic",
        "injection", "deserialization", "file", "crypto"
    ])
    risk_threshold: str = "low"  # low, medium, high, critical
    min_confidence: float = 0.5  # 最小置信度过滤

    # 规则集版本化
    ruleset_id: str = "web-backend-v1"
    ruleset_version: str = "1.0.0"

    # 规则启停控制
    disabled_rules: List[str] = field(default_factory=list)  # 禁用的规则 ID
    enabled_rules: Optional[List[str]] = None                 # 仅启用的规则 ID（为空表示全部）

    # 第三方规则映射
    semgrep_rules_dir: Optional[str] = None      # Semgrep 规则目录
    codeql_rules_dir: Optional[str] = None       # CodeQL 规则目录


@dataclass
class SecurityConfig:
    """安全与隐私配置"""
    # API Key 安全
    mask_api_key_in_logs: bool = True            # 日志中遮蔽 API Key
    api_key_mask_length: int = 4                  # 只显示前 N 位

    # 代码隐私
    enable_desensitization: bool = False          # 启用脱敏模式
    desensitize_patterns: List[str] = field(default_factory=lambda: [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        r'\b\d{3}-\d{2}-\d{4}\b',                                 # SSN
        r'\b\d{15,19}\b',                                         # 信用卡号
        r'(?:password|passwd|pwd|secret|token|api_key)\s*[=:]\s*["\']?[\w\-\.]+',  # 密钥
    ])

    # 远程日志控制
    disable_remote_code_logging: bool = True     # 禁止远程日志记录代码片段
    max_code_in_logs: int = 200                  # 日志中最大代码字符数

    # LLM 安全
    prevent_auto_execution: bool = True          # 禁止 LLM 自动执行危险操作
    require_human_confirm: bool = True           # 关键操作需人工确认

    # 依赖安全
    verify_dependencies: bool = True             # 验证依赖包是否存在
    dependency_whitelist: List[str] = field(default_factory=list)  # 依赖白名单


@dataclass
class ReportConfig:
    """报告输出配置"""
    output_format: str = "json"  # json, sarif, console
    output_path: str = "./audit_report"
    include_evidence: bool = True
    include_fix_suggestions: bool = True
    min_confidence: float = 0.5

    # 报告增强
    include_code_snippets: bool = True           # 包含代码片段
    max_snippet_lines: int = 20                  # 最大代码片段行数
    group_by_file: bool = True                   # 按文件分组
    include_statistics: bool = True              # 包含统计信息


@dataclass
class EvaluationConfig:
    """评估配置"""
    enable_evaluation: bool = False              # 启用评估模式
    dataset_path: Optional[str] = None           # 评估数据集路径
    metrics: List[str] = field(default_factory=lambda: [
        "precision", "recall", "f1", "accuracy"
    ])
    save_results: bool = True                    # 保存评估结果
    results_path: str = "./evaluation_results"


@dataclass
class AuditConfig:
    """主配置类 - 聚合所有子配置"""
    llm: LLMConfig = field(default_factory=LLMConfig)
    vector_store: VectorStoreConfig = field(default_factory=VectorStoreConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    evaluation: EvaluationConfig = field(default_factory=EvaluationConfig)

    # 全局设置
    debug: bool = False
    log_level: str = "INFO"

    def get_scan_mode(self) -> ScanMode:
        """获取扫描模式枚举"""
        mode_map = {
            "fast-rule": ScanMode.FAST_RULE,
            "llm-deep": ScanMode.LLM_DEEP,
            "full": ScanMode.FULL,
            "hotspot": ScanMode.HOTSPOT,
        }
        return mode_map.get(self.scan.mode, ScanMode.FULL)

    def mask_api_key(self, key: str) -> str:
        """遮蔽 API Key"""
        if not key or not self.security.mask_api_key_in_logs:
            return key
        mask_len = self.security.api_key_mask_length
        if len(key) <= mask_len:
            return "****"
        return key[:mask_len] + "*" * (len(key) - mask_len)

    # ---------------------------------------------------------------------
    # 便捷的序列化/反序列化接口（面向脚本/测试）
    # ---------------------------------------------------------------------

    @classmethod
    def from_yaml(
        cls,
        config_path: str = "audit.config.yaml",
        target_path: Optional[str] = None,
        use_user_config: bool = True,
    ) -> "AuditConfig":
        """从 YAML 配置文件加载 AuditConfig。

        该方法是对 `load_config` 的轻量封装，主要用于测试脚本与快速调用。

        Args:
            config_path: 配置文件路径
            target_path: 扫描目标路径（覆盖配置文件）
            use_user_config: 是否合并用户配置（见 load_config）

        Returns:
            AuditConfig
        """
        # 延迟导入，避免循环依赖
        return load_config(config_path=config_path, target_path=target_path, use_user_config=use_user_config)

    def to_dict(self) -> Dict[str, Any]:
        """转换为可序列化 dict（用于调试/持久化）。"""
        from dataclasses import asdict

        return asdict(self)


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """深度合并两个字典，override 优先"""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _apply_env_overrides(config_dict: Dict[str, Any]) -> Dict[str, Any]:
    """应用环境变量覆盖

    环境变量格式: AUDIT_<SECTION>_<KEY>
    例如: AUDIT_LLM_API_KEY, AUDIT_SCAN_TARGET_PATH
    """
    env_mappings = {
        "AUDIT_LLM_BASE_URL": ("llm", "base_url"),
        "AUDIT_LLM_API_KEY": ("llm", "api_key"),
        "AUDIT_LLM_MODEL": ("llm", "model"),
        "AUDIT_LLM_EMBEDDING_MODEL": ("llm", "embedding_model"),
        "AUDIT_LLM_EMBEDDING_BASE_URL": ("llm", "embedding_base_url"),
        "AUDIT_LLM_EMBEDDING_API_KEY": ("llm", "embedding_api_key"),
        "AUDIT_LLM_EMBEDDING_DIM": ("llm", "embedding_dim"),
        "AUDIT_VECTOR_HOST": ("vector_store", "host"),
        "AUDIT_VECTOR_PORT": ("vector_store", "port"),
        "AUDIT_VECTOR_API_KEY": ("vector_store", "api_key"),
        "AUDIT_SCAN_TARGET": ("scan", "target_path"),
        "AUDIT_DEBUG": ("debug",),
        "AUDIT_LOG_LEVEL": ("log_level",),
    }

    for env_var, path in env_mappings.items():
        value = os.environ.get(env_var)
        if value is not None:
            # 类型转换
            if env_var == "AUDIT_VECTOR_PORT":
                value = int(value)
            elif env_var == "AUDIT_LLM_EMBEDDING_DIM":
                value = int(value)
            elif env_var == "AUDIT_DEBUG":
                value = value.lower() in ("true", "1", "yes")

            # 设置值
            if len(path) == 1:
                config_dict[path[0]] = value
            else:
                if path[0] not in config_dict:
                    config_dict[path[0]] = {}
                config_dict[path[0]][path[1]] = value

    return config_dict


def _filter_dataclass_fields(cls, data: Dict[str, Any]) -> Dict[str, Any]:
    """过滤字典，只保留 dataclass 中定义的字段"""
    if not data:
        return {}
    valid_fields = {f.name for f in fields(cls)}
    return {k: v for k, v in data.items() if k in valid_fields}


def _dict_to_config(config_dict: Dict[str, Any]) -> AuditConfig:
    """将字典转换为配置对象

    自动过滤掉不存在的字段，避免 TypeError
    """
    llm_dict = _filter_dataclass_fields(LLMConfig, config_dict.get("llm", {}))
    vector_dict = _filter_dataclass_fields(VectorStoreConfig, config_dict.get("vector_store", {}))
    scan_dict = _filter_dataclass_fields(ScanConfig, config_dict.get("scan", {}))
    rules_dict = _filter_dataclass_fields(RulesConfig, config_dict.get("rules", {}))
    report_dict = _filter_dataclass_fields(ReportConfig, config_dict.get("report", {}))
    security_dict = _filter_dataclass_fields(SecurityConfig, config_dict.get("security", {}))
    evaluation_dict = _filter_dataclass_fields(EvaluationConfig, config_dict.get("evaluation", {}))

    return AuditConfig(
        llm=LLMConfig(**llm_dict) if llm_dict else LLMConfig(),
        vector_store=VectorStoreConfig(**vector_dict) if vector_dict else VectorStoreConfig(),
        scan=ScanConfig(**scan_dict) if scan_dict else ScanConfig(),
        rules=RulesConfig(**rules_dict) if rules_dict else RulesConfig(),
        report=ReportConfig(**report_dict) if report_dict else ReportConfig(),
        security=SecurityConfig(**security_dict) if security_dict else SecurityConfig(),
        evaluation=EvaluationConfig(**evaluation_dict) if evaluation_dict else EvaluationConfig(),
        debug=config_dict.get("debug", False),
        log_level=config_dict.get("log_level", "INFO"),
    )


# =============================================================================
# 用户配置持久化
# =============================================================================

# -----------------------------------------------------------------------------
# 用户配置持久化
# -----------------------------------------------------------------------------
#
# 说明：.user_config.yaml 属于“用户私有配置”（如 API Key、私有 base_url），
# 不应存放在项目仓库根目录中（避免误提交/泄露）。
#
# 默认保存位置：
# - Linux/macOS:   ~/.config/codescan/user_config.yaml (遵循 XDG_CONFIG_HOME)
# - Windows:       %USERPROFILE%\.config\codescan\user_config.yaml (由 Path.home() 推导)
#
# 兼容：若检测到旧版路径 <repo>/.user_config.yaml，将在读取时兼容并提示迁移。

_XDG_CONFIG_HOME = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
_DEFAULT_USER_CONFIG_DIR = _XDG_CONFIG_HOME / "codescan"

# 可通过环境变量强制指定用户配置路径
USER_CONFIG_FILE = Path(
    os.environ.get("CODESCAN_USER_CONFIG", str(_DEFAULT_USER_CONFIG_DIR / "user_config.yaml"))
)

# 旧版（不推荐）路径：项目根目录下的 .user_config.yaml
LEGACY_USER_CONFIG_FILE = Path(__file__).parent.parent / ".user_config.yaml"


def save_user_config(config_updates: Dict[str, Any]) -> bool:
    """保存用户配置到本地文件

    Args:
        config_updates: 要更新的配置字典

    Returns:
        是否保存成功
    """
    try:
        # 确保目录存在
        USER_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

        # 读取现有配置
        existing_config = {}
        if USER_CONFIG_FILE.exists():
            with open(USER_CONFIG_FILE, "r", encoding="utf-8") as f:
                existing_config = yaml.safe_load(f) or {}

        # 深度合并配置
        merged_config = _deep_merge(existing_config, config_updates)

        # 写入文件
        with open(USER_CONFIG_FILE, "w", encoding="utf-8") as f:
            yaml.dump(merged_config, f, default_flow_style=False, allow_unicode=True)

        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"保存用户配置失败: {e}")
        return False


def load_user_config() -> Dict[str, Any]:
    """加载用户本地配置

    Returns:
        用户配置字典
    """
    # 1) 新位置
    if USER_CONFIG_FILE.exists():
        try:
            with open(USER_CONFIG_FILE, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"加载用户配置失败: {e}")
            return {}

    # 2) 兼容旧位置（项目根目录）
    if LEGACY_USER_CONFIG_FILE.exists():
        try:
            import logging
            logging.getLogger(__name__).warning(
                f"检测到旧版用户配置文件: {LEGACY_USER_CONFIG_FILE}。建议迁移到: {USER_CONFIG_FILE}"
            )
            with open(LEGACY_USER_CONFIG_FILE, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"加载旧版用户配置失败: {e}")
            return {}

    return {}


def clear_user_config() -> bool:
    """清除用户本地配置

    Returns:
        是否清除成功
    """
    try:
        if USER_CONFIG_FILE.exists():
            USER_CONFIG_FILE.unlink()
        # 不主动删除旧文件，避免用户误删；仅在存在时提示用户自行处理
        if LEGACY_USER_CONFIG_FILE.exists():
            import logging
            logging.getLogger(__name__).warning(
                f"旧版用户配置文件仍存在: {LEGACY_USER_CONFIG_FILE}（未删除）。可手动迁移/删除。"
            )
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"清除用户配置失败: {e}")
        return False


def load_config(
    config_path: Optional[str] = None,
    target_path: Optional[str] = None,
    use_user_config: bool = True,
) -> AuditConfig:
    """加载配置

    优先级（从低到高）：
    1. 默认配置
    2. 项目级配置文件
    3. 用户本地配置文件 (.user_config.yaml)
    4. 环境变量
    5. 函数参数

    Args:
        config_path: 配置文件路径，默认查找 audit.config.yaml
        target_path: 扫描目标路径，覆盖配置文件中的设置
        use_user_config: 是否合并用户配置文件（默认 True）

    Returns:
        AuditConfig 配置对象
    """
    # 1. 默认配置
    config_dict: Dict[str, Any] = {}

    # 2. 查找并加载配置文件
    if config_path is None:
        # 查找默认配置文件
        search_paths = [
            Path.cwd() / "audit.config.yaml",
            Path.cwd() / "audit.config.yml",
            Path.cwd() / ".audit.yaml",
        ]
        for path in search_paths:
            if path.exists():
                config_path = str(path)
                break

    if config_path and Path(config_path).exists():
        with open(config_path, "r", encoding="utf-8") as f:
            file_config = yaml.safe_load(f) or {}
            config_dict = _deep_merge(config_dict, file_config)

    # 3. 加载用户本地配置文件（高优先级）
    if use_user_config:
        user_config = load_user_config()
        if user_config:
            config_dict = _deep_merge(config_dict, user_config)

    # 4. 应用环境变量覆盖
    config_dict = _apply_env_overrides(config_dict)

    # 5. 应用函数参数
    if target_path:
        if "scan" not in config_dict:
            config_dict["scan"] = {}
        config_dict["scan"]["target_path"] = target_path

    # 转换为配置对象
    config = _dict_to_config(config_dict)

    # 验证必填项
    _validate_config(config)

    return config


def _validate_config(config: AuditConfig, suppress_warnings: bool = False) -> None:
    """验证配置的必填项和合法性

    Args:
        config: 配置对象
        suppress_warnings: 是否抑制警告（用于运行时动态更新配置时）
    """
    errors = []

    # LLM 配置验证
    if not config.llm.api_key:
        # 检查环境变量作为后备
        if not os.environ.get("OPENAI_API_KEY"):
            errors.append("LLM API Key 未配置 (设置 AUDIT_LLM_API_KEY 或 OPENAI_API_KEY)")

    if not config.llm.base_url:
        errors.append("LLM Base URL 未配置")

    # 向量库配置验证
    if config.vector_store.provider == "qdrant":
        if not config.vector_store.host:
            errors.append("Qdrant host 未配置")

    # 扫描配置验证
    if config.scan.target_path and config.scan.target_path != ".":
        target = Path(config.scan.target_path)
        if not target.exists():
            errors.append(f"扫描目标路径不存在: {config.scan.target_path}")

    if errors:
        # 只打印警告，不阻止启动
        if not suppress_warnings:
            import warnings
            for error in errors:
                warnings.warn(f"配置警告: {error}")


def save_default_config(output_path: str = "audit.config.yaml") -> None:
    """生成默认配置文件模板"""
    template = """# LLM 驱动的代码审计工具 - 配置文件
# 支持: 默认配置 → 配置文件 → 环境变量 → 命令行参数 (优先级从低到高)

# =============================================================================
# LLM 服务配置
# =============================================================================
llm:
  provider: openai-compatible
  base_url: "https://api.openai.com/v1"  # 或你的 One-API/vLLM 地址
  api_key: ""  # 建议使用环境变量 AUDIT_LLM_API_KEY
  model: "gpt-4"
  embedding_model: "text-embedding-3-small"
  max_tokens: 4096
  temperature: 0.0
  timeout: 60
  max_retries: 3

  # Token 预算控制
  max_code_tokens_per_call: 3000  # 每次 LLM 调用的最大代码 token 数
  max_context_tokens: 6000        # 最大上下文 token 数

  # 多轮分析配置
  enable_multi_round: true        # 启用多轮分析 (先粗判 → 再追问细节)
  max_rounds: 2                   # 最大分析轮数

# =============================================================================
# 向量数据库配置
# =============================================================================
vector_store:
  # 默认使用内存向量存储（无需外部服务）。
  # 如需使用 Qdrant，请将 provider 改为 qdrant，并安装可选依赖: pip install qdrant-client
  provider: memory
  # host/port/api_key 仅在 provider=qdrant 时使用
  host: localhost
  port: 6333
  collection_name: code_audit
  embedding_dim: 1536
  # api_key: ""  # Qdrant Cloud 需要
  # https: false

  # 嵌入缓存配置 (基于文件 hash，避免重复计算)
  enable_cache: true
  cache_dir: ".audit_cache"
  cache_ttl_days: 30

# =============================================================================
# 扫描配置
# =============================================================================
scan:
  target_path: "."
  languages:
    - python
    - javascript
    - php
  include_patterns:
    - "**/*.py"
    - "**/*.js"
    - "**/*.ts"
    - "**/*.jsx"
    - "**/*.tsx"
    - "**/*.php"
  exclude_patterns:
    - "**/node_modules/**"
    - "**/__pycache__/**"
    - "**/venv/**"
    - "**/.git/**"
    - "**/dist/**"
    - "**/build/**"
    - "**/vendor/**"
  max_file_size_kb: 500
  max_concurrent: 4
  chunk_size: 2000

  # 扫描模式 (重要!)
  # - fast-rule: 只跑规则 + 简单静态分析 (不调用 LLM，速度快，适合 CI/CD)
  # - llm-deep: 对高风险入口做深度 LLM 审计 (消耗较多 token)
  # - full: 先规则筛选 → 再对命中的点做 LLM 深度分析 (推荐)
  # - hotspot: 只分析最近改动的代码 (Git diff，增量审计)
  mode: full

  # Hotspot 模式配置
  git_diff_base: "HEAD~10"        # Git diff 基准
  recent_commits: 10              # 分析最近 N 个提交

  # Hybrid 混合检索配置
  enable_hybrid_search: true      # 启用混合检索 (元数据 + 向量 + 关键词)
  keyword_boost: 0.3              # 关键词匹配权重
  metadata_filter_first: true     # 先元数据过滤再向量检索

# =============================================================================
# 安全规则配置
# =============================================================================
rules:
  rules_dir: "rules/data"
  custom_rules_dir: null          # 自定义规则目录
  enabled_categories:
    - auth
    - access-control
    - business-logic
    - injection
    - deserialization
    - file
    - crypto
  risk_threshold: low             # 最低风险等级: low, medium, high, critical
  min_confidence: 0.5             # 最小置信度过滤

  # 规则集版本化
  ruleset_id: "web-backend-v1"
  ruleset_version: "1.0.0"

  # 规则启停控制
  disabled_rules: []              # 禁用的规则 ID 列表
  # enabled_rules: null           # 仅启用的规则 ID (为空表示全部启用)

  # 第三方规则集成 (可选)
  # semgrep_rules_dir: null       # Semgrep 规则目录
  # codeql_rules_dir: null        # CodeQL 规则目录

# =============================================================================
# 安全与隐私配置
# =============================================================================
security:
  # API Key 安全
  mask_api_key_in_logs: true      # 日志中遮蔽 API Key
  api_key_mask_length: 4          # 只显示前 N 位

  # 代码隐私
  enable_desensitization: false   # 启用脱敏模式 (敏感信息不发送给 LLM)
  # desensitize_patterns:         # 脱敏正则模式 (email, SSN, 信用卡号, 密钥等)

  # 远程日志控制
  disable_remote_code_logging: true  # 禁止远程日志记录代码片段
  max_code_in_logs: 200           # 日志中最大代码字符数

  # LLM 安全
  prevent_auto_execution: true    # 禁止 LLM 自动执行危险操作
  require_human_confirm: true     # 关键操作需人工确认

  # 依赖安全
  verify_dependencies: true       # 验证依赖包是否存在 (防止包名幻觉攻击)
  dependency_whitelist: []        # 依赖白名单

# =============================================================================
# 报告输出配置
# =============================================================================
report:
  output_format: json             # json, sarif, console
  output_path: "./audit_report"
  include_evidence: true
  include_fix_suggestions: true
  min_confidence: 0.5

  # 报告增强
  include_code_snippets: true     # 包含代码片段
  max_snippet_lines: 20           # 最大代码片段行数
  group_by_file: true             # 按文件分组
  include_statistics: true        # 包含统计信息

# =============================================================================
# 评估配置 (用于衡量工具准确率)
# =============================================================================
evaluation:
  enable_evaluation: false        # 启用评估模式
  dataset_path: null              # 评估数据集路径
  metrics:                        # 评估指标
    - precision
    - recall
    - f1
    - accuracy
  save_results: true
  results_path: "./evaluation_results"

# =============================================================================
# 全局设置
# =============================================================================
debug: false
log_level: INFO
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(template)
    print(f"默认配置文件已生成: {output_path}")
