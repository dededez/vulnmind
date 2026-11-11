"""Provider-neutral model interface for agents.

No provider is bundled: deployments inject a client that speaks this small
request/response contract. The runtime never logs prompt or response text.
"""
from __future__ import annotations

from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

_MAX_MESSAGES = 64
_MAX_CONTENT = 200_000


class ModelError(RuntimeError):
    """The provider failed or returned an unusable response."""


class ModelMessage(BaseModel):
    model_config = ConfigDict(frozen=True)
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=_MAX_CONTENT)


class ModelRequest(BaseModel):
    model_config = ConfigDict(frozen=True)
    messages: list[ModelMessage] = Field(min_length=1, max_length=_MAX_MESSAGES)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0, allow_inf_nan=False)
    max_output_tokens: int = Field(default=2000, ge=1, le=32_000)

    @model_validator(mode="after")
    def roles_are_usable(self):
        if not any(message.role == "user" for message in self.messages):
            raise ValueError("a request needs at least one user message")
        if len({message.role for message in self.messages}) > 3:
            raise ValueError("unsupported role set")
        return self


class ModelUsage(BaseModel):
    model_config = ConfigDict(frozen=True)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)


class ModelResponse(BaseModel):
    model_config = ConfigDict(frozen=True)
    text: str = Field(min_length=1, max_length=_MAX_CONTENT)
    usage: ModelUsage = Field(default_factory=ModelUsage)


class ModelClient(Protocol):
    def complete(self, request: ModelRequest) -> ModelResponse: ...
