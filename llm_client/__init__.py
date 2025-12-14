"""LLM 客户端模块"""

from .client import (
    BaseLLMClient,
    OpenAICompatibleClient,
    MockLLMClient,
    ChatMessage,
    ChatResponse,
    EmbeddingResponse,
    StreamChunk,
    ToolCall,
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
    CHAIN_ANALYSIS_SCHEMA,
    create_validator,
)

# 为了向后兼容，创建别名
LLMClient = OpenAICompatibleClient

__all__ = [
    # 客户端
    "BaseLLMClient",
    "OpenAICompatibleClient",
    "LLMClient",  # 别名
    "MockLLMClient",
    "ChatMessage",
    "ChatResponse",
    "EmbeddingResponse",
    "StreamChunk",
    "ToolCall",
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
    "CHAIN_ANALYSIS_SCHEMA",
    "create_validator",
]
