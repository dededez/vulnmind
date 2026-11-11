"""Single-attempt tool planning with an atomically committed plan receipt."""
import hashlib
import json
import re
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from vulnmind.agents.audit import AgentAuditBridge
from vulnmind.agents.runtime import AgentRuntime
from vulnmind.agents.tool_plan import ALLOWED, select_repository_tools
from vulnmind.persistence.audit import DatabaseAuditSink, MAX_VERIFY_EVENTS, SessionAuditSink, verify_audit_chain
from vulnmind.persistence.models import AuditEvent, WorkflowOperation, WorkflowToolPlan
from vulnmind.persistence.scan_audit import CorrelatedAuditSink


def _selection_digest(input_digest: str, selected: list[str]) -> str:
    if not isinstance(input_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", input_digest):
        raise ValueError("invalid bound request digest")
    payload = {"input_digest": input_digest, "selected_tools": selected}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()


def load_tool_plan(engine, *, plan_id: UUID, operation_id: UUID, enabled: set[str]) -> tuple[str, ...]:
    if not isinstance(plan_id, UUID) or not isinstance(operation_id, UUID) or not isinstance(enabled, set) or not enabled <= ALLOWED:
        raise ValueError("invalid plan identity")
    with Session(engine) as session:
        plan = session.get(WorkflowToolPlan, plan_id)
        if plan is None or plan.operation_id != operation_id:
            raise ValueError("stored plan is unavailable")
        operation = session.get(WorkflowOperation, operation_id)
        if (operation is None or operation.stage != "repository_plan" or operation.status != "completed"
                or operation.result_ref != str(plan_id)):
            raise ValueError("stored plan operation is invalid")
        selected = plan.selected_tools
        if (not isinstance(selected, list) or any(not isinstance(item, str) or item not in enabled for item in selected)
                or len(selected) != len(set(selected)) or selected != sorted(selected)):
            raise ValueError("stored plan is invalid")
        chain = verify_audit_chain(session.connection(), limit=MAX_VERIFY_EVENTS)
        events = session.execute(select(AuditEvent.status, AuditEvent.args_hash).where(
            AuditEvent.call_id == operation_id, AuditEvent.tool_name == "repository.plan.transaction"
        ).order_by(AuditEvent.created_at, AuditEvent.id)).all()
        if (not chain.valid or not chain.complete or chain.unhashed or len(events) != 2
                or events[0].status != "requested" or events[1].status != "succeeded"
                or events[1].args_hash != _selection_digest(operation.input_digest, selected)):
            raise ValueError("stored plan audit does not verify")
        return tuple(selected)


def execute_tool_plan(engine, *, operation_id: UUID, owner_token: UUID, input_digest: str, enabled: set[str],
                      actor: str, client) -> UUID:
    """Commit the plan, its claim and terminal audit in one DB transaction.

    A failed or uncertain model call is never retried by this function. The
    graph retains the started claim and must not infer that no call was sent.
    """
    if not isinstance(operation_id, UUID) or not isinstance(owner_token, UUID) or not isinstance(enabled, set) or not enabled or not enabled <= ALLOWED:
        raise ValueError("invalid planning request")
    _selection_digest(input_digest, [])  # Validate the original bound identity before any model call.
    with Session(engine) as session:
        operation = session.get(WorkflowOperation, operation_id)
        if (operation is None or operation.owner_token != owner_token or operation.stage != "repository_plan"
                or operation.status != "started" or operation.input_digest != input_digest):
            raise ValueError("planning operation is not owned")
    audit = DatabaseAuditSink(engine)
    root = {"call_id": str(operation_id), "tool_name": "repository.plan.transaction",
            "actor": actor, "target_type": "repository"}
    audit.record({**root, "status": "requested"})
    correlated = CorrelatedAuditSink(audit, operation_id)
    selection_event = {"call_id": str(uuid4()), "tool_name": "repository.plan.selection",
                       "actor": actor, "target_type": "repository"}
    committing = False
    try:
        correlated.record({**selection_event, "status": "requested"})
        try:
            runtime = AgentRuntime(client, AgentAuditBridge(correlated, target_type="repository"))
            selected = select_repository_tools(runtime, enabled=enabled, actor=actor)
        except Exception:
            correlated.record({**selection_event, "status": "failed"})
            raise
        correlated.record({**selection_event, "status": "succeeded"})
        plan_id = uuid4()
        with Session(engine) as session:
            session.begin()
            operation = session.get(WorkflowOperation, operation_id)
            if operation is None:
                raise ValueError("planning operation is not owned")
            if operation.input_digest != input_digest:
                raise ValueError("planning request changed")
            plan_digest = _selection_digest(input_digest, list(selected))
            changed = session.execute(update(WorkflowOperation).where(
                WorkflowOperation.id == operation_id, WorkflowOperation.owner_token == owner_token,
                WorkflowOperation.stage == "repository_plan", WorkflowOperation.status == "started",
                WorkflowOperation.input_digest == input_digest
            ).values(status="completed", result_ref=str(plan_id)))
            if changed.rowcount != 1:
                raise ValueError("planning operation is not owned")
            session.add(WorkflowToolPlan(id=plan_id, operation_id=operation_id, selected_tools=list(selected)))
            session.flush()
            SessionAuditSink(session).record({**root, "status": "succeeded", "args_hash": plan_digest})
            committing = True
            session.commit()
    except Exception:
        if not committing:
            audit.record({**root, "status": "failed"})
        raise
    return plan_id
