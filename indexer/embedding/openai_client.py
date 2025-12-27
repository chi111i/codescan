# OpenAI-compatible embedding client
# Based on ACI (augmented-codebase-indexer) best practices

import httpx
import logging
from dataclasses import dataclass
from typing import List, Optional, Callable, Dict, Any

from .interface import (
    EmbeddingClientInterface,
    EmbeddingResult,
    EmbeddingUsage,
    EmbeddingError,
    RetryableError,
    NonRetryableError,
    BatchSizeError,
)
from .retry import (
    RetryConfig,
    RetryExecutor,
    classify_http_error,
    EMBEDDING_RETRY_CONFIG,
)

logger = logging.getLogger(__name__)


@dataclass
class OpenAIClientConfig:
    """Configuration for OpenAI-compatible embedding client

    Attributes:
        base_url: API base URL (e.g., "https://api.openai.com/v1" or custom endpoint)
        api_key: API key for authentication
        model: Embedding model name (e.g., "text-embedding-ada-002")
        timeout: Request timeout in seconds
        max_keepalive_connections: Maximum keepalive connections in pool
        max_connections: Maximum total connections in pool
        http2: Whether to use HTTP/2 (disable for unstable networks)
        dimension: Expected embedding dimension (used for validation)
    """
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "text-embedding-ada-002"
    timeout: float = 30.0
    max_keepalive_connections: int = 10
    max_connections: int = 20
    http2: bool = False  # Disabled by default for stability
    dimension: int = 1536


class OpenAIEmbeddingClient(EmbeddingClientInterface):
    """OpenAI-compatible embedding client with connection pooling

    Features:
    - Async HTTP client with connection pooling
    - Configurable retry logic
    - Proper error classification
    - HTTP/2 toggle for network compatibility
    """

    def __init__(
        self,
        config: Optional[OpenAIClientConfig] = None,
        retry_config: Optional[RetryConfig] = None
    ):
        """Initialize OpenAI embedding client

        Args:
            config: Client configuration
            retry_config: Retry configuration
        """
        self.config = config or OpenAIClientConfig()
        self.retry_config = retry_config or EMBEDDING_RETRY_CONFIG
        self.retry_executor = RetryExecutor(self.retry_config)

        # Normalize base URL - remove trailing slash, ensure no duplicate /v1
        base_url = self.config.base_url.rstrip("/")
        if not base_url.endswith("/v1"):
            base_url = f"{base_url}/v1"
        self._base_url = base_url

        self._client: Optional[httpx.AsyncClient] = None
        self._dimension = self.config.dimension
        self._model = self.config.model

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with connection pooling"""
        if self._client is None or self._client.is_closed:
            # Configure transport with connection pooling
            limits = httpx.Limits(
                max_keepalive_connections=self.config.max_keepalive_connections,
                max_connections=self.config.max_connections,
                keepalive_expiry=30.0,  # Keep connections alive for 30s
            )

            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=httpx.Timeout(
                    connect=10.0,
                    read=self.config.timeout,
                    write=10.0,
                    pool=5.0,
                ),
                limits=limits,
                http2=self.config.http2,
            )

        return self._client

    async def embed_batch(
        self,
        texts: List[str],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> EmbeddingResult:
        """Generate embeddings for a batch of texts

        Args:
            texts: List of texts to embed
            progress_callback: Optional callback(processed, total)

        Returns:
            EmbeddingResult with embeddings

        Raises:
            RetryableError: For transient errors
            NonRetryableError: For permanent errors
            BatchSizeError: When batch is too large
        """
        if not texts:
            return EmbeddingResult(
                embeddings=[],
                model=self._model,
                usage=EmbeddingUsage()
            )

        async def do_request():
            return await self._make_request(texts)

        def on_retry(error: Exception, attempt: int, delay: float):
            logger.warning(
                f"Embedding retry {attempt + 1}/{self.retry_config.max_retries}: "
                f"{type(error).__name__}"
            )

        result = await self.retry_executor.execute(do_request, on_retry)

        if progress_callback:
            progress_callback(len(texts), len(texts))

        return result

    async def _make_request(self, texts: List[str]) -> EmbeddingResult:
        """Make embedding API request

        Args:
            texts: Texts to embed

        Returns:
            EmbeddingResult

        Raises:
            Appropriate exception based on error type
        """
        client = await self._get_client()

        payload = {
            "model": self._model,
            "input": texts,
        }

        try:
            response = await client.post("/embeddings", json=payload)

            if response.status_code == 200:
                data = response.json()
                return self._parse_response(data)
            else:
                error_msg = self._extract_error_message(response)
                raise classify_http_error(response.status_code, error_msg)

        except httpx.TimeoutException as e:
            raise RetryableError(f"Request timeout: {e}", status_code=408)

        except httpx.ConnectError as e:
            raise RetryableError(f"Connection error: {e}")

        except httpx.HTTPStatusError as e:
            error_msg = self._extract_error_message(e.response)
            raise classify_http_error(e.response.status_code, error_msg)

        except (EmbeddingError,):
            # Re-raise our own errors
            raise

        except Exception as e:
            # Check for SSL errors
            error_str = str(e).lower()
            if "ssl" in error_str or "eof" in error_str:
                raise RetryableError(f"SSL/Connection error: {e}")
            raise RetryableError(f"Unexpected error: {e}")

    def _parse_response(self, data: Dict[str, Any]) -> EmbeddingResult:
        """Parse API response into EmbeddingResult"""
        embeddings = []
        for item in sorted(data.get("data", []), key=lambda x: x.get("index", 0)):
            embeddings.append(item["embedding"])

        usage_data = data.get("usage", {})
        usage = EmbeddingUsage(
            prompt_tokens=usage_data.get("prompt_tokens", 0),
            total_tokens=usage_data.get("total_tokens", 0),
        )

        model = data.get("model", self._model)

        # Update dimension if we got embeddings
        if embeddings and len(embeddings[0]) > 0:
            self._dimension = len(embeddings[0])

        return EmbeddingResult(
            embeddings=embeddings,
            model=model,
            usage=usage,
        )

    def _extract_error_message(self, response: httpx.Response) -> str:
        """Extract error message from response"""
        try:
            data = response.json()
            if "error" in data:
                error = data["error"]
                if isinstance(error, dict):
                    return error.get("message", str(error))
                return str(error)
            return response.text[:200]
        except Exception:
            return response.text[:200] if response.text else f"HTTP {response.status_code}"

    async def embed_single(self, text: str) -> List[float]:
        """Generate embedding for a single text

        Args:
            text: Text to embed

        Returns:
            Embedding vector
        """
        result = await self.embed_batch([text])
        if result.embeddings:
            return result.embeddings[0]
        raise EmbeddingError("No embedding returned for text")

    @property
    def dimension(self) -> int:
        """Get embedding dimension"""
        return self._dimension

    @property
    def model_name(self) -> str:
        """Get model name"""
        return self._model

    async def close(self) -> None:
        """Close the client and release resources"""
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def create_embedding_client(
    base_url: str,
    api_key: str,
    model: str = "text-embedding-ada-002",
    dimension: int = 1536,
    timeout: float = 30.0,
    http2: bool = False,
    retry_config: Optional[RetryConfig] = None,
) -> EmbeddingClientInterface:
    """Factory function to create an embedding client

    Args:
        base_url: API base URL
        api_key: API key
        model: Model name
        dimension: Expected embedding dimension
        timeout: Request timeout in seconds
        http2: Whether to use HTTP/2
        retry_config: Optional retry configuration

    Returns:
        Configured embedding client
    """
    config = OpenAIClientConfig(
        base_url=base_url,
        api_key=api_key,
        model=model,
        timeout=timeout,
        http2=http2,
        dimension=dimension,
    )

    return OpenAIEmbeddingClient(config, retry_config)


def create_client_from_settings(settings: Any) -> EmbeddingClientInterface:
    """Create embedding client from application settings

    Args:
        settings: Application settings object with llm_* attributes

    Returns:
        Configured embedding client
    """
    # Extract settings
    base_url = getattr(settings, "llm_base_url", "https://api.openai.com")
    api_key = getattr(settings, "llm_api_key", "")
    model = getattr(settings, "embedding_model", "text-embedding-ada-002")
    dimension = getattr(settings, "embedding_dimension", 1536)
    timeout = getattr(settings, "embedding_timeout", 30.0)

    # Use shorter timeout for embeddings
    if timeout > 60:
        timeout = 30.0

    return create_embedding_client(
        base_url=base_url,
        api_key=api_key,
        model=model,
        dimension=dimension,
        timeout=timeout,
        http2=False,  # Disabled for stability with Chinese API providers
    )
