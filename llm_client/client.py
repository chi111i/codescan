"""
LLM 客户端封装 - 统一的 OpenAI 兼容接口

支持：
- OpenAI 官方 API
- vLLM / OpenLLM 等 OpenAI-Compatible 服务
- One-API 等第三方代理
"""

import os
import time
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union, Iterator, Callable
import httpx

from config import LLMConfig

logger = logging.getLogger(__name__)


@dataclass
class ToolCall:
    """工具调用"""
    id: str
    name: str
    arguments: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """转换为 API 格式"""
        return {
            "id": self.id,
            "type": "function",
            "function": {
                "name": self.name,
                "arguments": json.dumps(self.arguments, ensure_ascii=False) if isinstance(self.arguments, dict) else self.arguments,
            }
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolCall":
        """从 API 响应创建"""
        func = data.get("function", {})
        arguments = func.get("arguments", "{}")
        # 解析 arguments JSON 字符串
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {}
        return cls(
            id=data.get("id", ""),
            name=func.get("name", ""),
            arguments=arguments,
        )


@dataclass
class ChatMessage:
    """聊天消息"""
    role: str  # system, user, assistant, tool
    content: Optional[str] = None
    tool_calls: Optional[List[ToolCall]] = None  # assistant 消息中的工具调用
    tool_call_id: Optional[str] = None  # tool 消息的调用 ID
    name: Optional[str] = None  # tool 消息的函数名

    def to_dict(self) -> Dict[str, Any]:
        """转换为 API 格式"""
        msg = {"role": self.role}

        if self.content is not None:
            msg["content"] = self.content

        if self.tool_calls:
            msg["tool_calls"] = [tc.to_dict() for tc in self.tool_calls]

        if self.tool_call_id:
            msg["tool_call_id"] = self.tool_call_id

        if self.name:
            msg["name"] = self.name

        return msg


@dataclass
class ChatResponse:
    """聊天响应"""
    content: Optional[str]
    model: str
    usage: Dict[str, int]
    finish_reason: str
    tool_calls: Optional[List[ToolCall]] = None  # 工具调用列表
    raw_response: Optional[Dict[str, Any]] = None


@dataclass
class EmbeddingResponse:
    """嵌入响应"""
    embeddings: List[List[float]]
    model: str
    usage: Dict[str, int]


@dataclass
class StreamChunk:
    """流式响应块"""
    content: str  # 增量内容
    is_done: bool = False  # 是否完成
    finish_reason: Optional[str] = None
    tool_calls: Optional[List[ToolCall]] = None
    usage: Optional[Dict[str, int]] = None


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
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[Union[str, Dict[str, Any]]] = None,
        **kwargs
    ) -> ChatResponse:
        """发送聊天请求

        Args:
            messages: 消息列表
            model: 模型名称
            temperature: 温度参数
            max_tokens: 最大生成 token 数
            response_format: 响应格式
            tools: 工具定义列表
            tool_choice: 工具选择策略 ("auto", "none", "required" 或指定工具)
        """
        pass

    @abstractmethod
    def embed(
        self,
        texts: List[str],
        model: Optional[str] = None,
        dimensions: Optional[int] = None,
        encoding_format: Optional[str] = None
    ) -> EmbeddingResponse:
        """生成文本嵌入向量

        Args:
            texts: 文本列表
            model: 嵌入模型名称
            dimensions: 向量维度（OpenAI text-embedding-3 系列支持）
            encoding_format: 编码格式，"float" 或 "base64"
        """
        pass

    def chat_completion_stream(
        self,
        messages: List[ChatMessage],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        on_chunk: Optional[Callable[[StreamChunk], None]] = None,
        **kwargs
    ) -> ChatResponse:
        """流式聊天请求（可选实现）

        Args:
            messages: 消息列表
            model: 模型名称
            temperature: 温度参数
            max_tokens: 最大生成 token 数
            on_chunk: 每个流块的回调函数，用于实时显示

        Returns:
            完整的 ChatResponse（流结束后返回）
        """
        # 默认实现：回退到非流式调用
        return self.chat_completion(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        )


class OpenAICompatibleClient(BaseLLMClient):
    """OpenAI 兼容客户端实现"""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.base_url = self._normalize_base_url(config.base_url)
        self.api_key = config.api_key or os.environ.get("OPENAI_API_KEY", "")
        self.default_model = config.model
        self.embedding_model = config.embedding_model
        self.timeout = config.timeout
        self.max_retries = config.max_retries

        # 嵌入模型独立配置（如果设置了则使用，否则使用 LLM 配置）
        self.embedding_base_url = self._normalize_base_url(config.embedding_base_url or config.base_url)
        self.embedding_api_key = config.embedding_api_key or self.api_key
        self.embedding_dim = config.embedding_dim

        # 初始化 HTTP 客户端
        self._init_http_clients()

    @staticmethod
    def _normalize_base_url(url: str) -> str:
        """规范化 base_url，确保以 /v1 结尾

        这样 endpoint 只需要用 /chat/completions 而不是 /v1/chat/completions，
        避免 URL 重复拼接问题（如 /v1/v1/chat/completions）

        规则：
        - 如果 url 已经以 /v1 结尾，保持不变
        - 如果 url 不以 /v1 结尾，自动添加 /v1
        """
        url = url.rstrip("/")
        if not url.endswith("/v1"):
            url = url + "/v1"
        return url

    def _init_http_clients(self):
        """初始化 HTTP 客户端"""
        # HTTP 客户端
        self._client = httpx.Client(
            timeout=httpx.Timeout(self.timeout, connect=10.0),
            headers=self._get_headers(),
        )

        # 嵌入模型的 HTTP 客户端（如果配置不同则单独创建）
        if self.embedding_base_url != self.base_url or self.embedding_api_key != self.api_key:
            self._embedding_client = httpx.Client(
                timeout=httpx.Timeout(self.timeout, connect=10.0),
                headers=self._get_embedding_headers(),
            )
        else:
            self._embedding_client = self._client

    def _get_headers(self) -> Dict[str, str]:
        """获取请求头"""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _get_embedding_headers(self) -> Dict[str, str]:
        """获取嵌入模型请求头"""
        return {
            "Authorization": f"Bearer {self.embedding_api_key}",
            "Content-Type": "application/json",
        }

    def _log_request(self, endpoint: str, model: str, tokens: Optional[int] = None, payload: Optional[Dict[str, Any]] = None):
        """安全的请求日志（不输出敏感内容）"""
        log_info = f"LLM Request: endpoint={endpoint}, model={model}, tokens={tokens or 'N/A'}"

        if payload:
            # 添加更多调试信息，但不输出敏感内容
            if "messages" in payload:
                msg_count = len(payload.get("messages", []))
                log_info += f", messages_count={msg_count}"
            if "tools" in payload:
                tool_count = len(payload.get("tools", []))
                log_info += f", tools_count={tool_count}"
            if "temperature" in payload:
                log_info += f", temperature={payload['temperature']}"
            if "max_tokens" in payload:
                log_info += f", max_tokens={payload['max_tokens']}"

        logger.info(log_info)

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
        json_data: Dict[str, Any],
        client: Optional[httpx.Client] = None,
        base_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """带重试的请求

        Args:
            method: HTTP 方法
            endpoint: API 端点
            json_data: 请求数据
            client: HTTP 客户端，默认使用 self._client
            base_url: API 基础 URL，默认使用 self.base_url
        """
        use_client = client or self._client
        use_base_url = base_url or self.base_url
        url = f"{use_base_url}{endpoint}"
        last_exception = None

        # 检查 API Key 是否配置
        api_key_to_check = self.embedding_api_key if client == self._embedding_client else self.api_key
        if not api_key_to_check:
            logger.error(f"API Key 未配置: endpoint={endpoint}, base_url={use_base_url}")
            raise APIError("API Key 未配置，请在设置中配置 API Key 后重试")

        # 记录请求详情
        logger.info(f"准备发送请求: {method} {url}")
        logger.info(f"  - 使用 API Key: {api_key_to_check[:8]}...{api_key_to_check[-4:] if len(api_key_to_check) > 12 else '****'}")
        logger.info(f"  - 模型: {json_data.get('model', 'N/A')}")

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(f"发送请求: {method} {url} (尝试 {attempt}/{self.max_retries})")
                response = use_client.request(method, url, json=json_data)

                logger.info(f"收到响应: status={response.status_code}")

                if response.status_code == 200:
                    result = response.json()
                    # 记录成功响应的简要信息
                    if "usage" in result:
                        usage = result["usage"]
                        logger.info(f"请求成功: prompt_tokens={usage.get('prompt_tokens', 0)}, completion_tokens={usage.get('completion_tokens', 0)}")
                    return result

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
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[Union[str, Dict[str, Any]]] = None,
        **kwargs
    ) -> ChatResponse:
        """发送聊天请求

        Args:
            messages: 消息列表
            model: 模型名称，默认使用配置中的模型
            temperature: 温度参数
            max_tokens: 最大生成 token 数
            response_format: 响应格式，如 {"type": "json_object"}
            tools: 工具定义列表 (Function Calling)
            tool_choice: 工具选择策略 ("auto", "none", "required" 或指定工具)
            **kwargs: 额外参数（如 top_p, frequency_penalty 等）

        Returns:
            ChatResponse 对象
        """
        use_model = model or self.default_model
        use_temp = temperature if temperature is not None else self.config.temperature
        use_max_tokens = max_tokens or self.config.max_tokens

        # 构建消息列表，使用 ChatMessage.to_dict() 支持 tool_calls
        formatted_messages = []
        for m in messages:
            if hasattr(m, 'to_dict'):
                formatted_messages.append(m.to_dict())
            else:
                formatted_messages.append({"role": m.role, "content": m.content})

        payload = {
            "model": use_model,
            "messages": formatted_messages,
            "temperature": use_temp,
            "max_tokens": use_max_tokens,
        }

        if response_format:
            payload["response_format"] = response_format

        # 添加工具定义
        if tools:
            payload["tools"] = tools

        # 添加工具选择策略
        if tool_choice is not None:
            payload["tool_choice"] = tool_choice

        # 合并额外参数
        payload.update(kwargs)

        self._log_request("/chat/completions", use_model, payload=payload)

        result = self._request_with_retry("POST", "/chat/completions", payload)

        # 解析响应
        choice = result["choices"][0]
        message = choice["message"]
        usage = result.get("usage", {})

        # 解析 tool_calls
        tool_calls = None
        if "tool_calls" in message and message["tool_calls"]:
            tool_calls = [
                ToolCall.from_dict(tc) for tc in message["tool_calls"]
            ]

        logger.info(
            f"LLM Response: model={result.get('model')}, "
            f"tokens={usage.get('total_tokens', 'N/A')}, "
            f"finish_reason={choice.get('finish_reason', 'unknown')}, "
            f"tool_calls={len(tool_calls) if tool_calls else 0}"
        )

        return ChatResponse(
            content=message.get("content"),
            model=result.get("model", use_model),
            usage={
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
            finish_reason=choice.get("finish_reason", "unknown"),
            tool_calls=tool_calls,
            raw_response=result,
        )

    def embed(
        self,
        texts: List[str],
        model: Optional[str] = None,
        dimensions: Optional[int] = None,
        encoding_format: Optional[str] = None
    ) -> EmbeddingResponse:
        """生成文本嵌入向量

        Args:
            texts: 文本列表
            model: 嵌入模型名称
            dimensions: 向量维度（OpenAI text-embedding-3 系列支持自定义维度）
            encoding_format: 编码格式，可选 "float" 或 "base64"，默认 "float"

        Returns:
            EmbeddingResponse 对象
        """
        use_model = model or self.embedding_model
        use_dimensions = dimensions or self.embedding_dim

        payload = {
            "model": use_model,
            "input": texts,
        }

        # 如果指定了维度，添加到请求中（OpenAI text-embedding-3 系列支持）
        if use_dimensions:
            payload["dimensions"] = use_dimensions

        # 编码格式（OpenAI 支持 "float" 或 "base64"）
        if encoding_format:
            payload["encoding_format"] = encoding_format

        self._log_request("/embeddings", use_model, len(texts), payload=payload)

        try:
            # 使用嵌入模型专用的客户端和 base_url
            result = self._request_with_retry(
                "POST",
                "/embeddings",
                payload,
                client=self._embedding_client,
                base_url=self.embedding_base_url,
            )

            # 解析嵌入向量
            embeddings = [item["embedding"] for item in result["data"]]
            usage = result.get("usage", {})

            logger.info(
                f"Embedding Response: model={result.get('model', use_model)}, "
                f"texts_count={len(texts)}, embedding_dim={len(embeddings[0]) if embeddings else 0}, "
                f"total_tokens={usage.get('total_tokens', 'N/A')}"
            )

            return EmbeddingResponse(
                embeddings=embeddings,
                model=result.get("model", use_model),
                usage={
                    "prompt_tokens": usage.get("prompt_tokens", 0),
                    "total_tokens": usage.get("total_tokens", 0),
                },
            )

        except Exception as e:
            # 可选：本地降级嵌入（无外部依赖），用于离线/内网无法访问 embedding 服务时。
            # 注意：这是退化方案，检索质量会低于真实向量模型。
            enable_fallback = getattr(self.config, "enable_local_embeddings_fallback", True)
            if enable_fallback:
                try:
                    from .local_embedding import embed_texts

                    embeddings = embed_texts(texts, dim=use_dimensions)
                    logger.warning(
                        "Embedding 请求失败，已使用本地哈希嵌入作为回退方案。"
                        f" 原因: {type(e).__name__}: {e}"
                    )
                    return EmbeddingResponse(
                        embeddings=embeddings,
                        model=f"local-hash-{use_dimensions}",
                        usage={"prompt_tokens": 0, "total_tokens": 0},
                    )
                except Exception as fallback_err:
                    logger.error(
                        "本地嵌入回退失败，将重新抛出原始异常。"
                        f" fallback_error={type(fallback_err).__name__}: {fallback_err}"
                    )

            raise

    def chat_completion_stream(
        self,
        messages: List[ChatMessage],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        on_chunk: Optional[Callable[[StreamChunk], None]] = None,
        **kwargs
    ) -> ChatResponse:
        """流式聊天请求

        实时返回 LLM 生成的内容，支持回调函数处理每个块。

        Args:
            messages: 消息列表
            model: 模型名称
            temperature: 温度参数
            max_tokens: 最大生成 token 数
            on_chunk: 每个流块的回调函数

        Returns:
            完整的 ChatResponse
        """
        use_model = model or self.default_model
        use_temp = temperature if temperature is not None else self.config.temperature
        use_max_tokens = max_tokens or self.config.max_tokens

        # 构建消息列表
        formatted_messages = []
        for m in messages:
            if hasattr(m, 'to_dict'):
                formatted_messages.append(m.to_dict())
            else:
                formatted_messages.append({"role": m.role, "content": m.content})

        payload = {
            "model": use_model,
            "messages": formatted_messages,
            "temperature": use_temp,
            "max_tokens": use_max_tokens,
            "stream": True,  # 启用流式
        }
        payload.update(kwargs)

        url = f"{self.base_url}/chat/completions"
        self._log_request("/chat/completions (stream)", use_model, payload=payload)

        full_content = ""
        finish_reason = None
        usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

        try:
            with self._client.stream("POST", url, json=payload) as response:
                if response.status_code != 200:
                    self._handle_error(response, 1)

                for line in response.iter_lines():
                    if not line:
                        continue

                    # SSE 格式: "data: {...}"
                    if line.startswith("data: "):
                        data_str = line[6:]  # 去掉 "data: " 前缀

                        if data_str.strip() == "[DONE]":
                            # 流结束
                            if on_chunk:
                                on_chunk(StreamChunk(
                                    content="",
                                    is_done=True,
                                    finish_reason=finish_reason,
                                    usage=usage
                                ))
                            break

                        try:
                            data = json.loads(data_str)
                            choice = data.get("choices", [{}])[0]
                            delta = choice.get("delta", {})

                            # 提取增量内容
                            chunk_content = delta.get("content", "")
                            if chunk_content:
                                full_content += chunk_content

                                if on_chunk:
                                    on_chunk(StreamChunk(
                                        content=chunk_content,
                                        is_done=False
                                    ))

                            # 检查完成原因
                            if choice.get("finish_reason"):
                                finish_reason = choice["finish_reason"]

                            # 更新 usage（如果提供）
                            if "usage" in data:
                                usage = data["usage"]

                        except json.JSONDecodeError:
                            logger.warning(f"无法解析流数据: {data_str[:100]}")
                            continue

        except httpx.TimeoutException:
            logger.error("流式请求超时")
            raise APIError("Stream request timeout")
        except httpx.RequestError as e:
            logger.error(f"流式请求错误: {e}")
            raise APIError(f"Stream request error: {e}")

        logger.info(f"Stream complete: content_length={len(full_content)}, finish_reason={finish_reason}")

        return ChatResponse(
            content=full_content,
            model=use_model,
            usage=usage,
            finish_reason=finish_reason or "stop",
            tool_calls=None,  # 流式模式通常不支持 tool_calls
        )

    def close(self):
        """关闭客户端"""
        self._client.close()
        # 如果嵌入模型客户端是独立创建的，也需要关闭
        if self._embedding_client is not self._client:
            self._embedding_client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class MockLLMClient(BaseLLMClient):
    """模拟 LLM 客户端 - 用于测试和离线模式"""

    def __init__(self):
        self.call_history: List[Dict[str, Any]] = []
        self.mock_tool_calls: Optional[List[ToolCall]] = None  # 可设置模拟的工具调用

    def set_mock_tool_calls(self, tool_calls: List[ToolCall]):
        """设置模拟返回的工具调用"""
        self.mock_tool_calls = tool_calls

    def chat_completion(
        self,
        messages: List[ChatMessage],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict[str, str]] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[Union[str, Dict[str, Any]]] = None,
        **kwargs
    ) -> ChatResponse:
        """模拟聊天响应"""
        self.call_history.append({
            "type": "chat",
            "messages": messages,
            "model": model,
            "tools": tools,
            "tool_choice": tool_choice,
        })

        # 如果设置了模拟工具调用，返回它
        if self.mock_tool_calls:
            tool_calls = self.mock_tool_calls
            self.mock_tool_calls = None  # 重置
            return ChatResponse(
                content=None,
                model=model or "mock-model",
                usage={"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
                finish_reason="tool_calls",
                tool_calls=tool_calls,
            )

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
            tool_calls=None,
        )

    def embed(
        self,
        texts: List[str],
        model: Optional[str] = None,
        dimensions: Optional[int] = None,
        encoding_format: Optional[str] = None
    ) -> EmbeddingResponse:
        """模拟嵌入响应"""
        self.call_history.append({
            "type": "embed",
            "texts": texts,
            "model": model,
            "dimensions": dimensions,
            "encoding_format": encoding_format,
        })

        # 返回本地哈希嵌入（确定性、无依赖）。
        # 这比零向量更适合做离线检索/演示。
        dim = dimensions or 1536
        from .local_embedding import embed_texts

        embeddings = embed_texts(texts, dim=dim)

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
