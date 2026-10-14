from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool", "function"]
    content: Optional[Union[str, List[Dict[str, Any]]]] = ""
    name: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None


class ToolFunctionDef(BaseModel):
    name: str
    description: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None


class ToolDefinition(BaseModel):
    type: Literal["function"] = "function"
    function: ToolFunctionDef


class ChatCompletionRequest(BaseModel):
    model: str = Field(default="gpt-4o-mini", description="Target model name")
    messages: List[ChatMessage] = Field(..., min_length=1, description="Conversation messages")
    temperature: Optional[float] = Field(default=0.7, ge=0.0, le=2.0)
    top_p: Optional[float] = Field(default=1.0, ge=0.0, le=1.0)
    max_tokens: Optional[int] = Field(default=None, gt=0)
    stream: Optional[bool] = Field(default=False)
    tools: Optional[List[ToolDefinition]] = None
    tool_choice: Optional[Union[str, Dict[str, Any]]] = None
    user: Optional[str] = None

    def get_full_text_for_inspection(self) -> str:
        """Extracts text content across user, system, and tool messages for inspection."""
        text_parts = []
        for msg in self.messages:
            if isinstance(msg.content, str):
                text_parts.append(f"{msg.role}: {msg.content}")
            elif isinstance(msg.content, list):
                for part in msg.content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text_parts.append(f"{msg.role}: {part.get('text', '')}")
        return "\n".join(text_parts)


class Usage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatCompletionChoice(BaseModel):
    index: int = 0
    message: ChatMessage
    finish_reason: Optional[str] = "stop"


class ChatCompletionResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[ChatCompletionChoice]
    usage: Usage = Field(default_factory=Usage)
    system_fingerprint: Optional[str] = None


class SecurityInspectionRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Text content to inspect")
    context: Optional[str] = Field(default="prompt", description="Inspection context: prompt or output")
    project_id: Optional[str] = None
    tools_called: Optional[List[Dict[str, Any]]] = None


class SecurityInspectionResponse(BaseModel):
    action: str
    risk_score: float
    risk_level: str
    sanitized_text: str
    redaction_count: int
    detections: List[Dict[str, Any]]
    correlation_id: str
