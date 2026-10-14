import asyncio
import time
import uuid
from typing import Any, AsyncIterator, Dict

from packages.provider_adapters.src.adapters.base import BaseLLMAdapter
from packages.shared.src.models.schemas import (
    ChatCompletionChoice,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    Usage,
)


class MockLLMAdapter(BaseLLMAdapter):
    """
    Deterministic mock provider adapter for local development, CI/CD,
    and zero-cost security testing.
    """

    def __init__(self, latency_ms: int = 50, echo_mode: bool = False):
        self.latency_ms = latency_ms
        self.echo_mode = echo_mode

    async def complete(
        self, request: ChatCompletionRequest, correlation_id: str = ""
    ) -> ChatCompletionResponse:
        if self.latency_ms > 0:
            await asyncio.sleep(self.latency_ms / 1000.0)

        last_user_msg = ""
        for msg in reversed(request.messages):
            if msg.role == "user" and isinstance(msg.content, str):
                last_user_msg = msg.content
                break

        if self.echo_mode:
            reply_text = f"[MOCK ECHO]: Processed '{last_user_msg}'"
        else:
            reply_text = (
                f"Hello! I am Aegis Mock LLM. I received your prompt of length "
                f"{len(last_user_msg)} characters safely. Correlation ID: {correlation_id}."
            )

        prompt_tokens = max(1, len(request.get_full_text_for_inspection()) // 4)
        completion_tokens = max(1, len(reply_text) // 4)

        return ChatCompletionResponse(
            id=f"chatcmpl-mock-{uuid.uuid4().hex[:8]}",
            created=int(time.time()),
            model=request.model,
            choices=[
                ChatCompletionChoice(
                    index=0,
                    message=ChatMessage(role="assistant", content=reply_text),
                    finish_reason="stop",
                )
            ],
            usage=Usage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            ),
            system_fingerprint="fp_aegis_mock_v1",
        )

    async def stream_complete(
        self, request: ChatCompletionRequest, correlation_id: str = ""
    ) -> AsyncIterator[Dict[str, Any]]:
        words = ["Hello!", " This", " is", " a", " safe", " streamed", " response", " from", " Aegis", " Mock."]
        req_id = f"chatcmpl-mock-stream-{uuid.uuid4().hex[:8]}"
        created = int(time.time())

        for idx, word in enumerate(words):
            await asyncio.sleep(0.02)
            yield {
                "id": req_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": request.model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": word},
                        "finish_reason": "stop" if idx == len(words) - 1 else None,
                    }
                ],
            }

    async def health_check(self) -> bool:
        return True
