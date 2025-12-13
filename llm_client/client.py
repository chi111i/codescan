"""
LLM 客户端封装 - 统一的 OpenAI 兼容接口

支持：
- OpenAI 官方 API
- vLLM / OpenLLM 等 OpenAI-Compatible 服务
- One-API 等第三方代理
"""

import os
import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Union
import httpx

from config import LLMConfig

logger = logging.getLogger(__name__)


@dataclass
class ChatMessage:
    """聊天消息"""
    role: str  # system, user, assistant
    content: str


@dataclass
class ChatResponse:
    """聊天响应"""
    content: str
    model: str
    usage: Dict[str, int]
    finish_reason: str
    raw_response: Optional[Dict[str, Any]] = None


@dataclass
class EmbeddingResponse:
    """嵌入响应"""
    embeddings: List[List[float]]
    model: str
    usage: Dict[str, int]


class LLMClientError(Exception):
    """LLM 客户端异常基类"""
    pass


class RateLimitError(LLMClientError):
    """速率限制异常"""
    pass


class APIError(LLMClientError):
    """API 调用异常"""
    pass


class BaseLLMClient(ABC):
    """LLM 客户端抽象基类"""

    @abstractmethod
    def chat_completion(
        self,
        messages: List[ChatMessage],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> ChatResponse:
        """发送聊天请求"""
        pass

    @abstractmethod
    def embed(
        self,
        texts: List[str],
        model: Optional[str] = None
    ) -> EmbeddingResponse:
        """生成文本嵌入向量"""
        pass


class OpenAICompatibleClient(BaseLLMClient):
    """OpenAI 兼容客户端实现"""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.api_key = config.api_key or os.environ.get("OPENAI_API_KEY", "")
        self.default_model = config.model
        self.embedding_model = config.embedding_model
        self.timeout = config.timeout
        self.max_retries = config.max_retries

        # HTTP 客户端
        self._client = httpx.Client(
            timeout=httpx.Timeout(self.timeout, connect=10.0),
            headers=self._get_headers(),
        )

    def _get_headers(self) -> Dict[str, str]:
        """获取请求头"""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _log_request(self, endpoint: str, model: str, tokens: Optional[int] = None):
        """安全的请求日志（不输出敏感内容）"""
        logger.debug(
            f"LLM Request: endpoint={endpoint}, model={model}, "
            f"tokens={tokens or 'N/A'}"
        )

    def _handle_error(self, response: httpx.Response, attempt: int) -> None:
        """处理错误响应"""
        status = response.status_code

        if status == 429:
            # 速率限制，获取重试时间
            retry_after = int(response.headers.get("Retry-After", "60"))
            logger.warning(f"Rate limited. Retry after {retry_after}s (attempt {attempt})")
            raise RateLimitError(f"Rate limited. Retry after {retry_after}s")

        if status >= 500:
            logger.error(f"Server error {status} (attempt {attempt})")
            raise APIError(f"Server error: {status}")

        if status >= 400:
            try:
                error_detail = response.json().get("error", {}).get("message", "Unknown error")
            except Exception:
                error_detail = response.text[:200]
            logger.error(f"API error {status}: {error_detail}")
            raise APIError(f"API error {status}: {error_detail}")

    def _request_with_retry(
        self,
        method: str,
        endpoint: str,
        json_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """带重试的请求"""
        url = f"{self.base_url}{endpoint}"
        last_exception = None

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self._client.request(method, url, json=json_data)

                if response.status_code == 200:
                    return response.json()

                self._handle_error(response, attempt)

            except RateLimitError:
                if attempt < self.max_retries:
                    wait_time = min(60, 2 ** attempt)  # 指数退避，最多60秒
                    logger.info(f"Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                    continue
                raise

            except httpx.TimeoutException as e:
                last_exception = e
                logger.warning(f"Request timeout (attempt {attempt}/{self.max_retries})")
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)
                    continue

            except httpx.RequestError as e:
                last_exception = e
                logger.warning(f"Request error: {e} (attempt {attempt}/{self.max_retries})")
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)
                    continue

        raise APIError(f"Max retries exceeded. Last error: {last_exception}")

    def chat_completion(
        self,
        messages: List[ChatMessage],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> ChatResponse:
        """发送聊天请求

        Args:
            messages: 消息列表
            model: 模型名称，默认使用配置中的模型
            temperature: 温度参数
            max_tokens: 最大生成 token 数
            response_format: 响应格式，如 {"type": "json_object"}
            **kwargs: 额外参数（如 top_p, frequency_penalty 等）

        Returns:
            ChatResponse 对象
        """
        use_model = model or self.default_model
        use_temp = temperature if temperature is not None else self.config.temperature
        use_max_tokens = max_tokens or self.config.max_tokens

        payload = {
            "model": use_model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": use_temp,
            "max_tokens": use_max_tokens,
        }

        if response_format:
            payload["response_format"] = response_format

        # 合并额外参数
        payload.update(kwargs)

        self._log_request("/v1/chat/completions", use_model)

        result = self._request_with_retry("POST", "/v1/chat/completions", payload)

        # 解析响应
        choice = result["choices"][0]
        usage = result.get("usage", {})

        logger.debug(
            f"LLM Response: model={result.get('model')}, "
            f"tokens={usage.get('total_tokens', 'N/A')}"
        )

        return ChatResponse(
            content=choice["message"]["content"],
            model=result.get("model", use_model),
            usage={
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
            finish_reason=choice.get("finish_reason", "unknown"),
            raw_response=result,
        )

    def embed(
        self,
        texts: List[str],
        model: Optional[str] = None
    ) -> EmbeddingResponse:
        """生成文本嵌入向量

        Args:
            texts: 文本列表
            model: 嵌入模型名称

        Returns:
            EmbeddingResponse 对象
        """
        use_model = model or self.embedding_model

        payload = {
            "model": use_model,
            "input": texts,
        }

        self._log_request("/v1/embeddings", use_model, len(texts))

        result = self._request_with_retry("POST", "/v1/embeddings", payload)

        # 解析嵌入向量
        embeddings = [item["embedding"] for item in result["data"]]
        usage = result.get("usage", {})

        return EmbeddingResponse(
            embeddings=embeddings,
            model=result.get("model", use_model),
            usage={
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
        )

    def close(self):
        """关闭客户端"""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class MockLLMClient(BaseLLMClient):
    """模拟 LLM 客户端 - 用于测试和离线模式"""

    def __init__(self):
        self.call_history: List[Dict[str, Any]] = []

    def chat_completion(
        self,
        messages: List[ChatMessage],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> ChatResponse:
        """模拟聊天响应"""
        self.call_history.append({
            "type": "chat",
            "messages": messages,
            "model": model,
        })

        # 返回模拟响应
        mock_content = '{"has_issue": false, "notes": "Mock response for testing"}'
        if response_format and response_format.get("type") == "json_object":
            content = mock_content
        else:
            content = "This is a mock response for testing purposes."

        return ChatResponse(
            content=content,
            model=model or "mock-model",
            usage={"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            finish_reason="stop",
        )

    def embed(
        self,
        texts: List[str],
        model: Optional[str] = None
    ) -> EmbeddingResponse:
        """模拟嵌入响应"""
        self.call_history.append({
            "type": "embed",
            "texts": texts,
            "model": model,
        })

        # 返回模拟嵌入（零向量）
        dim = 1536
        embeddings = [[0.0] * dim for _ in texts]

        return EmbeddingResponse(
            embeddings=embeddings,
            model=model or "mock-embedding",
            usage={"prompt_tokens": len(texts) * 10, "total_tokens": len(texts) * 10},
        )


def create_llm_client(config: LLMConfig, offline: bool = False) -> BaseLLMClient:
    """创建 LLM 客户端工厂函数

    Args:
        config: LLM 配置
        offline: 是否使用离线模式（返回 Mock 客户端）

    Returns:
        LLM 客户端实例
    """
    if offline or os.environ.get("AUDIT_OFFLINE_MODE"):
        logger.info("Using MockLLMClient (offline mode)")
        return MockLLMClient()

    return OpenAICompatibleClient(config)
