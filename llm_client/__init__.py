"""LLM 客户端模块"""

from .client import (
    BaseLLMClient,
    OpenAICompatibleClient,
    MockLLMClient,
    ChatMessage,
    ChatResponse,
    EmbeddingResponse,
    LLMClientError,
    RateLimitError,
    APIError,
    create_llm_client,
)

from .output_validator import (
    OutputValidator,
    OutputCorrector,
    HallucinationGuard,
    ValidationResult,
    ValidationReport,
    LLMOutputSchema,
    AUDIT_RESULT_SCHEMA,
    create_validator,
)

__all__ = [
    # 客户端
    "BaseLLMClient",
    "OpenAICompatibleClient",
    "MockLLMClient",
    "ChatMessage",
    "ChatResponse",
    "EmbeddingResponse",
    "LLMClientError",
    "RateLimitError",
    "APIError",
    "create_llm_client",
    # 输出验证
    "OutputValidator",
    "OutputCorrector",
    "HallucinationGuard",
    "ValidationResult",
    "ValidationReport",
    "LLMOutputSchema",
    "AUDIT_RESULT_SCHEMA",
    "create_validator",
]
