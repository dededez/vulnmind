"""Initial in-process registry for explicitly trusted, side-effect-free tools only.

This is not a sandbox. Never register an untrusted function or a tool that reads,
writes, starts a process, or uses the network. Such tools need an enforceable
runtime isolation and approval design before they can be enabled.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable, Protocol
from uuid import uuid4

from pydantic import BaseModel, ValidationError
from vulnmind.schemas import Authorization, Target, TargetType
from vulnmind.security.scope import ScopeDenied, check_target


class ToolDenied(Exception):
    pass


class TransientToolError(Exception):
    """A trusted pure tool explicitly reports a retryable failure."""


class AuditSink(Protocol):
    def record(self, event: dict) -> None: ...


class Permission(str, Enum):
    PURE = "pure"
    READ = "read"
    EXECUTE = "execute"
    NETWORK = "network"
    WRITE = "write"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class ToolContext:
    """Identity of the caller for tools that need the target and scope."""
    actor: str
    target: Target
    scope: Authorization


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    input_schema: type[BaseModel]
    invoke: Callable[..., Awaitable[BaseModel]]
    description: str
    timeout_seconds: float = 5.0
    permission: Permission = Permission.PURE
    risk_level: RiskLevel = RiskLevel.LOW
    approval_required: bool = False
    idempotent: bool = False
    max_retries: int = 0
    hash_arguments: bool = True
    target_types: tuple[TargetType, ...] = (TargetType.REPOSITORY, TargetType.WEB)
    context_aware: bool = False

    def __post_init__(self):
        if not self.name.strip() or not self.description.strip() or not (0 < self.timeout_seconds <= 60):
            raise ValueError("tool requires a name, description and timeout in (0, 60]")
        if not isinstance(self.permission, Permission) or not isinstance(self.risk_level, RiskLevel):
            raise ValueError("permission and risk_level must be declared enum values")
        if not isinstance(self.input_schema, type) or not issubclass(self.input_schema, BaseModel) or not callable(self.invoke):
            raise ValueError("tool needs a Pydantic input schema and callable")
        if not 0 <= self.max_retries <= 2 or (self.max_retries and not self.idempotent):
            raise ValueError("only declared idempotent tools may use at most two retries")
        if not isinstance(self.hash_arguments, bool) or not isinstance(self.context_aware, bool):
            raise ValueError("hash_arguments and context_aware must be booleans")
        if (not isinstance(self.target_types, tuple) or not self.target_types
                or any(not isinstance(item, TargetType) or item is TargetType.BOTH for item in self.target_types)
                or len(set(self.target_types)) != len(self.target_types)):
            raise ValueError("target_types must contain distinct concrete target types")


ToolPolicy = Callable[[ToolDefinition, Target], bool]


def pure_only_policy(definition: ToolDefinition, target: Target) -> bool:
    """Default policy: only trusted, side-effect-free low-risk tools."""
    return (definition.permission is Permission.PURE and definition.risk_level is RiskLevel.LOW
            and not definition.approval_required)


class ToolRegistry:
    """Policy-gated tool calls; the default policy allows only pure tools."""

    def __init__(self, audit: AuditSink, *, policy: ToolPolicy | None = None):
        if policy is not None and not callable(policy):
            raise ValueError("policy must be callable")
        self._audit = audit
        self._policy = policy or pure_only_policy
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        if tool.name in self._tools:
            raise ValueError("duplicate tool name")
        self._tools[tool.name] = tool

    def describe(self) -> list[dict]:
        """Expose schemas and policy declarations without callable objects."""
        return [{"name": tool.name, "description": tool.description,
                 "input_schema": tool.input_schema.model_json_schema(),
                 "permission": tool.permission.value, "risk_level": tool.risk_level.value,
                 "scope_required": True, "approval_required": tool.approval_required,
                 "timeout_seconds": tool.timeout_seconds, "idempotent": tool.idempotent,
                 "max_retries": tool.max_retries, "hash_arguments": tool.hash_arguments,
                 "target_types": [item.value for item in tool.target_types],
                 "enabled": tool.permission is Permission.PURE and tool.risk_level is RiskLevel.LOW and not tool.approval_required}
                for tool in self._tools.values()]

    async def call(self, name: str, arguments: dict, *, actor: str, target: Target, scope: Authorization) -> BaseModel:
        call_id = str(uuid4())
        # Do not include input, output, locator, exception text, or credentials in audit.
        event = {"call_id": call_id, "tool_name": name, "actor": actor, "target_type": target.type.value}
        self._audit.record({**event, "status": "requested"})
        try:
            if not actor.strip() or name not in self._tools:
                raise ToolDenied("tool or actor not authorized")
            check_target(target, scope)
            definition = self._tools[name]
            if target.type not in definition.target_types:
                raise ToolDenied("tool is not available for this target type")
            if not self._policy(definition, target):
                raise ToolDenied("operation unavailable until isolated execution and approval are implemented")
            try:
                validated = definition.input_schema.model_validate(arguments)
            except ValidationError:
                if not definition.hash_arguments:
                    raise ToolDenied("tool input is invalid") from None
                raise
            # Digest is for correlation only; it does not anonymize low-entropy inputs.
            digest = None
            if definition.hash_arguments:
                canonical = json.dumps(validated.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                digest = hashlib.sha256(canonical.encode()).hexdigest()
            for attempt in range(definition.max_retries + 1):
                # Authorization may expire between attempts.
                check_target(target, scope)
                started = {**event, "status": "started"}
                if digest is not None:
                    started["args_hash"] = digest
                self._audit.record(started)
                context = ToolContext(actor=actor, target=target, scope=scope)
                try:
                    if definition.context_aware:
                        result = await asyncio.wait_for(definition.invoke(validated, context),
                                                        definition.timeout_seconds)
                    else:
                        result = await asyncio.wait_for(definition.invoke(validated),
                                                        definition.timeout_seconds)
                    break
                except TransientToolError:
                    if attempt >= definition.max_retries:
                        raise
                    self._audit.record({**event, "status": "retrying"})
            if not isinstance(result, BaseModel):
                raise TypeError("tool result must be a Pydantic model")
        except asyncio.CancelledError:
            self._audit.record({**event, "status": "cancelled"})
            raise
        except (ScopeDenied, ToolDenied):
            self._audit.record({**event, "status": "denied"})
            raise
        except Exception:
            self._audit.record({**event, "status": "failed"})
            raise
        self._audit.record({**event, "status": "succeeded"})
        return result

    def call_sync(self, name: str, arguments: dict, *, actor: str, target: Target,
                  scope: Authorization) -> BaseModel:
        """Run ``call`` from synchronous code; refuses inside a running loop."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.call(name, arguments, actor=actor, target=target, scope=scope))
        raise ToolDenied("synchronous tool call inside a running event loop is not supported")
