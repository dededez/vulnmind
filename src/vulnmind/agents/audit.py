"""Bridge agent runtime events to the tool-oriented audit sinks.

``AgentRuntime`` records lifecycle events such as ``requested``/``completed``;
the durable sinks only accept the tool audit schema. The bridge keeps the
event's agent/actor/status and drops prompt, response and usage details, so
nothing model-generated reaches the audit table.
"""
from __future__ import annotations

from uuid import UUID, uuid4

_STATUS_MAP = {
    "requested": "requested",
    "invalid_output": "retrying",
    "completed": "succeeded",
    "model_failed": "failed",
    "budget_exceeded": "failed",
    "failed": "failed",
}


class AgentAuditBridge:
    def __init__(self, sink, *, target_type: str = "repository"):
        if not callable(getattr(sink, "record", None)):
            raise ValueError("an audit sink is required")
        if target_type not in {"repository", "web", "knowledge"}:
            raise ValueError("unsupported audit target type")
        self._sink = sink
        self._target_type = target_type

    def record(self, event: dict) -> None:
        if not isinstance(event, dict):
            return
        status = _STATUS_MAP.get(str(event.get("status", "")))
        actor = event.get("actor")
        agent = event.get("agent")
        if status is None or not isinstance(actor, str) or not isinstance(agent, str):
            return
        try:
            call_id = UUID(str(event["call_id"])) if "call_id" in event else uuid4()
        except (TypeError, ValueError, AttributeError):
            # Do not persist arbitrary strings from an untrusted caller.
            raise ValueError("invalid agent audit call ID") from None
        self._sink.record({"call_id": str(call_id),
                           "tool_name": f"agent.{agent}"[:255],
                           "actor": actor.strip()[:255] or "unknown",
                           "target_type": self._target_type,
                           "status": status})
