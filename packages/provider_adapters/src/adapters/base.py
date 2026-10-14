from abc import ABC, abstractmethod
from typing import AsyncIterator, Dict, Any
from packages.shared.src.models.schemas import (
    ChatCompletionRequest,
    ChatCompletionResponse,
)


class BaseLLMAdapter(ABC):
    """Abstract interface for all upstream LLM provider adapters."""

    @abstractmethod
    async def complete(
        self, request: ChatCompletionRequest, correlation_id: str = ""
    ) -> ChatCompletionResponse:
        """Executes a standard non-streaming chat completion."""
        pass

    @abstractmethod
    async def stream_complete(
        self, request: ChatCompletionRequest, correlation_id: str = ""
    ) -> AsyncIterator[Dict[str, Any]]:
        """Executes a streaming completion yielding chunk dictionaries."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Returns True if the provider endpoint is healthy and reachable."""
        pass
