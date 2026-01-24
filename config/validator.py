"""配置验证器

在应用启动时验证所有配置的有效性，及早发现配置错误。
"""

import os
import logging
from pathlib import Path
from typing import List, Optional, Tuple

from pydantic import BaseModel, Field, field_validator, model_validator, ValidationError

from .settings import (
    AuditConfig,
    LLMConfig,
    VectorStoreConfig,
    ScanConfig,
    RulesConfig,
    ScanMode,
    RiskLevel,
)

logger = logging.getLogger(__name__)


class LLMConfigValidator(BaseModel):
    """LLM 配置验证器"""

    provider: str = Field(..., description="LLM 提供商")
    base_url: str = Field(..., description="API 基础 URL")
    api_key: str = Field(..., min_length=1, description="API 密钥")
    model: str = Field(..., min_length=1, description="模型名称")
    embedding_model: str = Field(..., min_length=1, description="嵌入模型名称")
    max_tokens: int = Field(gt=0, le=100000, description="最大 Token 数")
    temperature: float = Field(ge=0.0, le=2.0, description="温度参数")
    timeout: int = Field(gt=0, le=600, description="超时时间（秒）")
    max_retries: int = Field(ge=0, le=10, description="最大重试次数")

    embedding_base_url: str = Field(default="", description="嵌入模型 API 地址")
    embedding_api_key: str = Field(default="", description="嵌入模型 API Key")
    embedding_dim: int = Field(gt=0, le=10000, description="嵌入向量维度")

    max_code_tokens_per_call: int = Field(gt=0, le=50000, description="每次调用最大代码 Token")
    max_context_tokens: int = Field(gt=0, le=100000, description="最大上下文 Token")

    enable_multi_round: bool = Field(default=True, description="启用多轮分析")
    max_rounds: int = Field(ge=1, le=5, description="最大分析轮数")

    @field_validator("base_url", "embedding_base_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """验证 URL 格式"""
        if v and not v.startswith(("http://", "https://")):
            raise ValueError(f"URL 必须以 http:// 或 https:// 开头: {v}")
        return v

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        """验证 LLM 提供商"""
        allowed_providers = ["openai", "openai-compatible", "anthropic", "deepseek", "ollama"]
        if v not in allowed_providers:
            raise ValueError(f"不支持的 LLM 提供商: {v}，允许的值: {allowed_providers}")
        return v

    @model_validator(mode="after")
    def validate_token_budget(self) -> "LLMConfigValidator":
        """验证 Token 预算合理性"""
        if self.max_code_tokens_per_call > self.max_context_tokens:
            raise ValueError(
                f"max_code_tokens_per_call ({self.max_code_tokens_per_call}) "
                f"不能大于 max_context_tokens ({self.max_context_tokens})"
            )
        return self


class VectorStoreConfigValidator(BaseModel):
    """向量存储配置验证器"""

    provider: str = Field(..., description="向量存储提供商")
    host: str = Field(..., min_length=1, description="主机地址")
    port: int = Field(gt=0, le=65535, description="端口号")
    collection_name: str = Field(..., min_length=1, description="集合名称")
    api_key: Optional[str] = Field(default=None, description="API 密钥")
    https: bool = Field(default=False, description="是否使用 HTTPS")

    enable_cache: bool = Field(default=True, description="启用缓存")
    cache_dir: str = Field(..., min_length=1, description="缓存目录")
    cache_ttl_days: int = Field(ge=1, le=365, description="缓存过期天数")

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        """验证向量存储提供商"""
        allowed_providers = ["qdrant", "memory", "chroma", "pinecone"]
        if v not in allowed_providers:
            raise ValueError(f"不支持的向量存储提供商: {v}，允许的值: {allowed_providers}")
        return v

    @field_validator("cache_dir")
    @classmethod
    def validate_cache_dir(cls, v: str) -> str:
        """验证缓存目录"""
        # 如果是相对路径，转换为绝对路径
        cache_path = Path(v)
        if not cache_path.is_absolute():
            cache_path = Path.cwd() / cache_path

        # 尝试创建目录（如果不存在）
        try:
            cache_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise ValueError(f"无法创建缓存目录 {cache_path}: {e}")

        return str(cache_path)


class ScanConfigValidator(BaseModel):
    """扫描配置验证器"""

    target_path: str = Field(..., min_length=1, description="目标路径")
    languages: List[str] = Field(..., min_length=1, description="语言列表")
    include_patterns: List[str] = Field(default_factory=list, description="包含模式")
    exclude_patterns: List[str] = Field(default_factory=list, description="排除模式")
    max_file_size_kb: int = Field(gt=0, le=10240, description="最大文件大小（KB）")
    max_concurrent: int = Field(ge=1, le=32, description="最大并发数")
    chunk_size: int = Field(gt=0, le=10000, description="代码块大小")

    mode: str = Field(..., description="扫描模式")

    git_diff_base: str = Field(default="HEAD~10", description="Git diff 基准")
    recent_commits: int = Field(ge=1, le=100, description="最近提交数")

    enable_hybrid_search: bool = Field(default=True, description="启用混合检索")
    keyword_boost: float = Field(ge=0.0, le=1.0, description="关键词匹配权重")
    metadata_filter_first: bool = Field(default=True, description="先元数据过滤")

    enable_reranking: bool = Field(default=True, description="启用重排序")
    rerank_security_priority: bool = Field(default=True, description="安全优先模式")
    rerank_security_boost: float = Field(ge=1.0, le=5.0, description="安全提升因子")
    rerank_prefer_entry_points: bool = Field(default=True, description="优先入口点")

    @field_validator("target_path")
    @classmethod
    def validate_target_path(cls, v: str) -> str:
        """验证目标路径存在"""
        path = Path(v)
        if not path.exists():
            raise ValueError(f"目标路径不存在: {v}")
        return str(path.resolve())

    @field_validator("languages")
    @classmethod
    def validate_languages(cls, v: List[str]) -> List[str]:
        """验证语言列表"""
        # 支持的编程语言（15种）
        allowed_languages = [
            "python", "javascript", "typescript", "php", "java", "go", "ruby",
            "c", "cpp", "csharp", "rust", "kotlin", "scala", "swift", "dart"
        ]
        for lang in v:
            if lang not in allowed_languages:
                logger.warning(f"语言 {lang} 可能不被完全支持，允许的值: {allowed_languages}")
        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        """验证扫描模式"""
        try:
            ScanMode(v)
        except ValueError:
            allowed_modes = [mode.value for mode in ScanMode]
            raise ValueError(f"无效的扫描模式: {v}，允许的值: {allowed_modes}")
        return v


class RulesConfigValidator(BaseModel):
    """规则配置验证器"""

    rules_dir: str = Field(..., min_length=1, description="规则目录")
    custom_rules_dir: Optional[str] = Field(default=None, description="自定义规则目录")
    enabled_categories: List[str] = Field(..., min_length=1, description="启用的类别")
    risk_threshold: str = Field(..., description="风险阈值")
    min_confidence: float = Field(ge=0.0, le=1.0, description="最小置信度")

    ruleset_id: str = Field(..., min_length=1, description="规则集 ID")
    ruleset_version: str = Field(..., min_length=1, description="规则集版本")

    disabled_rules: List[str] = Field(default_factory=list, description="禁用的规则")
    enabled_rules: Optional[List[str]] = Field(default=None, description="仅启用的规则")

    semgrep_rules_dir: Optional[str] = Field(default=None, description="Semgrep 规则目录")

    @field_validator("rules_dir")
    @classmethod
    def validate_rules_dir(cls, v: str) -> str:
        """验证规则目录"""
        path = Path(v)
        if not path.exists():
            logger.warning(f"规则目录不存在: {v}，将使用内置规则")
        return v

    @field_validator("risk_threshold")
    @classmethod
    def validate_risk_threshold(cls, v: str) -> str:
        """验证风险阈值"""
        try:
            RiskLevel(v)
        except ValueError:
            allowed_levels = [level.value for level in RiskLevel]
            raise ValueError(f"无效的风险等级: {v}，允许的值: {allowed_levels}")
        return v


class ConfigValidator:
    """配置验证器

    在应用启动时验证所有配置的有效性。
    """

    def __init__(self, config: AuditConfig):
        """初始化验证器

        Args:
            config: 审计配置对象
        """
        self.config = config
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate_all(self, strict: bool = True) -> Tuple[bool, List[str], List[str]]:
        """验证所有配置

        Args:
            strict: 严格模式（有警告也返回 False）

        Returns:
            (is_valid, errors, warnings)
        """
        self.errors = []
        self.warnings = []

        # 验证各个子配置
        self._validate_llm_config()
        self._validate_vector_store_config()
        self._validate_scan_config()
        self._validate_rules_config()

        # 交叉验证
        self._validate_cross_dependencies()

        # 环境变量检查
        self._validate_environment()

        is_valid = len(self.errors) == 0
        if strict:
            is_valid = is_valid and len(self.warnings) == 0

        return is_valid, self.errors, self.warnings

    def _validate_llm_config(self):
        """验证 LLM 配置"""
        try:
            validator = LLMConfigValidator(**self.config.llm.__dict__)
            logger.debug("[ConfigValidator] LLM 配置验证通过")
        except ValidationError as e:
            for error in e.errors():
                field = ".".join(str(loc) for loc in error["loc"])
                self.errors.append(f"LLM 配置错误 [{field}]: {error['msg']}")

    def _validate_vector_store_config(self):
        """验证向量存储配置"""
        try:
            validator = VectorStoreConfigValidator(**self.config.vector_store.__dict__)
            logger.debug("[ConfigValidator] 向量存储配置验证通过")
        except ValidationError as e:
            for error in e.errors():
                field = ".".join(str(loc) for loc in error["loc"])
                self.errors.append(f"向量存储配置错误 [{field}]: {error['msg']}")

    def _validate_scan_config(self):
        """验证扫描配置"""
        try:
            validator = ScanConfigValidator(**self.config.scan.__dict__)
            logger.debug("[ConfigValidator] 扫描配置验证通过")
        except ValidationError as e:
            for error in e.errors():
                field = ".".join(str(loc) for loc in error["loc"])
                self.errors.append(f"扫描配置错误 [{field}]: {error['msg']}")

    def _validate_rules_config(self):
        """验证规则配置"""
        try:
            validator = RulesConfigValidator(**self.config.rules.__dict__)
            logger.debug("[ConfigValidator] 规则配置验证通过")
        except ValidationError as e:
            for error in e.errors():
                field = ".".join(str(loc) for loc in error["loc"])
                self.errors.append(f"规则配置错误 [{field}]: {error['msg']}")

    def _validate_cross_dependencies(self):
        """验证配置间的交叉依赖"""
        # 检查 Token 预算合理性
        if hasattr(self.config, 'llm') and hasattr(self.config, 'scan'):
            max_code = self.config.llm.max_code_tokens_per_call
            chunk_size = self.config.scan.chunk_size

            if max_code < chunk_size:
                self.warnings.append(
                    f"max_code_tokens_per_call ({max_code}) 小于 chunk_size ({chunk_size})，"
                    f"可能导致代码块被截断"
                )

        # 检查嵌入维度一致性（仅警告）
        if hasattr(self.config, 'llm') and hasattr(self.config, 'vector_store'):
            llm_dim = getattr(self.config.llm, "embedding_dim", None)
            vs_dim = getattr(self.config.vector_store, "embedding_dim", None)
            if llm_dim and vs_dim and llm_dim != vs_dim:
                self.warnings.append(
                    f"embedding_dim 不一致：llm.embedding_dim={llm_dim}, vector_store.embedding_dim={vs_dim}。"
                    "这可能导致向量库维度不匹配（尤其是 Qdrant）。"
                )

        # 检查模式与配置一致性
        if hasattr(self.config, 'scan'):
            mode = self.config.scan.mode
            if mode == "hotspot" and not hasattr(self.config.scan, 'git_diff_base'):
                self.warnings.append("扫描模式为 hotspot，但未配置 git_diff_base")

    def _validate_environment(self):
        """验证环境变量和依赖"""
        # 检查必需的环境变量
        if not self.config.llm.api_key:
            env_key = (
                os.getenv("AUDIT_LLM_API_KEY")
                or os.getenv("OPENAI_API_KEY")
                or os.getenv("LLM_API_KEY")
            )
            if not env_key:
                self.errors.append("LLM API Key 未配置（配置文件或环境变量）")
            else:
                logger.debug("[ConfigValidator] 使用环境变量中的 API Key")

        # 检查可选依赖
        try:
            import tiktoken
        except ImportError:
            self.warnings.append("tiktoken 未安装，将使用启发式 Token 估算")

        # 检查向量存储依赖（仅警告：允许在运行时回退到内存向量存储）
        # 说明：本项目默认可在无外部依赖下运行（memory provider）。
        # 若用户显式配置为 qdrant，但未安装 qdrant-client，我们给出警告，
        # 并在运行时由 create_vector_store 自动回退到 memory。
        if self.config.vector_store.provider == "qdrant":
            try:
                import qdrant_client  # noqa: F401
                # 暂不检查连接，避免启动时延迟
                logger.debug("[ConfigValidator] qdrant_client 已安装")
            except ImportError:
                self.warnings.append(
                    "向量存储配置为 qdrant，但 qdrant-client 未安装，将在运行时回退到 memory"
                )


def validate_config(config: AuditConfig, strict: bool = False) -> bool:
    """验证配置（便捷函数）

    Args:
        config: 审计配置对象
        strict: 严格模式（有警告也视为失败）

    Returns:
        是否通过验证

    Raises:
        ValueError: 验证失败时（仅在非严格模式）
    """
    validator = ConfigValidator(config)
    is_valid, errors, warnings = validator.validate_all(strict=strict)

    if not is_valid:
        logger.error("[ConfigValidator] 配置验证失败:")
        for error in errors:
            logger.error(f"  ❌ {error}")
        for warning in warnings:
            logger.warning(f"  ⚠️ {warning}")

        if errors:
            raise ValueError(f"配置验证失败: {len(errors)} 个错误，{len(warnings)} 个警告")

    if warnings:
        logger.warning(f"[ConfigValidator] 配置验证通过，但有 {len(warnings)} 个警告:")
        for warning in warnings:
            logger.warning(f"  ⚠️ {warning}")

    logger.info("[ConfigValidator] ✓ 配置验证通过")
    return is_valid
