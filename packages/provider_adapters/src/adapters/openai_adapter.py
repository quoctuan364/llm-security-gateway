import json
import time
from typing import Any, AsyncIterator, Dict, Optional

import httpx

from packages.provider_adapters.src.adapters.base import BaseLLMAdapter
from packages.shared.src.models.schemas import (
    ChatCompletionChoice,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    Usage,
)


class OpenAICompatibleAdapter(BaseLLMAdapter):
    """
    Adapter for any OpenAI-compatible completions endpoint
    (OpenAI, vLLM, Ollama, LocalAI, Together, DeepSeek, etc.).
    """

    def __init__(
        self,
        base_url: str = "https://api.openai.com/v1",
        api_key: Optional[str] = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or ""
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def _headers(self, correlation_id: str = "") -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Aegis-LLM-Security-Gateway/1.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if correlation_id:
            headers["X-Correlation-ID"] = correlation_id
        return headers

    async def complete(
        self, request: ChatCompletionRequest, correlation_id: str = ""
    ) -> ChatCompletionResponse:
        url = f"{self.base_url}/chat/completions"
        payload = request.model_dump(exclude_none=True)
        payload["stream"] = False

        transport = httpx.AsyncHTTPTransport(retries=self.max_retries)
        async with httpx.AsyncClient(
            transport=transport, timeout=self.timeout_seconds
        ) as client:
            resp = await client.post(
                url, json=payload, headers=self._headers(correlation_id)
            )
            resp.raise_for_status()
            data = resp.json()

            choices = []
            for c in data.get("choices", []):
                msg_data = c.get("message", {})
                choices.append(
                    ChatCompletionChoice(
                        index=c.get("index", 0),
                        message=ChatMessage(
                            role=msg_data.get("role", "assistant"),
                            content=msg_data.get("content", ""),
                            tool_calls=msg_data.get("tool_calls"),
                        ),
                        finish_reason=c.get("finish_reason", "stop"),
                    )
                )

            usage_data = data.get("usage", {})
            return ChatCompletionResponse(
                id=data.get("id", f"chatcmpl-{int(time.time())}"),
                created=data.get("created", int(time.time())),
                model=data.get("model", request.model),
                choices=choices,
                usage=Usage(
                    prompt_tokens=usage_data.get("prompt_tokens", 0),
                    completion_tokens=usage_data.get("completion_tokens", 0),
                    total_tokens=usage_data.get("total_tokens", 0),
                ),
                system_fingerprint=data.get("system_fingerprint"),
            )

    async def stream_complete(
        self, request: ChatCompletionRequest, correlation_id: str = ""
    ) -> AsyncIterator[Dict[str, Any]]:
        url = f"{self.base_url}/chat/completions"
        payload = request.model_dump(exclude_none=True)
        payload["stream"] = True

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            async with client.stream(
                "POST", url, json=payload, headers=self._headers(correlation_id)
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    clean_line = line.strip()
                    if not clean_line or clean_line == "data: [DONE]":
                        continue
                    if clean_line.startswith("data: "):
                        clean_line = clean_line[6:]
                    try:
                        chunk = json.loads(clean_line)
                        yield chunk
                    except json.JSONDecodeError:
                        continue

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(f"{self.base_url}/models", headers=self._headers())
                return res.status_code in (200, 401)
        except Exception:
            return False
