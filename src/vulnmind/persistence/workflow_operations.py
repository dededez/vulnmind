"""Durable single-attempt stage claims; not a transaction for external effects.

Callers must commit the claim before an effect, and only complete it after the
effect and its durable result are known. An unfinished claim is *unknown* and
is never automatically retried. This module does not provide reconciliation.
"""
from dataclasses import dataclass
import re
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vulnmind.persistence.models import WorkflowOperation


@dataclass(frozen=True)
class StageClaim:
    status: str
    operation_id: UUID
    owner_token: UUID | None = None
    result_id: UUID | None = None


def claim_stage(engine, *, workflow_id: UUID, stage: str, input_digest: str) -> StageClaim:
    if (not isinstance(workflow_id, UUID) or not isinstance(stage, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", stage)
            or not isinstance(input_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", input_digest)):
        raise ValueError("invalid workflow operation identity")
    operation_id, owner = uuid4(), uuid4()
    try:
        with Session(engine) as session, session.begin():
            session.add(WorkflowOperation(id=operation_id, workflow_id=workflow_id, stage=stage,
                                          input_digest=input_digest, owner_token=owner, status="started"))
            session.flush()
    except IntegrityError:
        with Session(engine) as session:
            row = session.scalar(select(WorkflowOperation).where(
                WorkflowOperation.workflow_id == workflow_id, WorkflowOperation.stage == stage))
            if row is None:
                raise
            if row.input_digest != input_digest:
                raise ValueError("workflow stage identity does not match") from None
            if row.status == "completed" and row.result_ref:
                return StageClaim("completed", row.id, result_id=UUID(row.result_ref))
            return StageClaim("unknown", row.id)
    return StageClaim("claimed", operation_id, owner_token=owner)


def complete_stage(engine, *, operation_id: UUID, owner_token: UUID, result_id: UUID) -> None:
    if not all(isinstance(item, UUID) for item in (operation_id, owner_token, result_id)):
        raise ValueError("invalid workflow operation receipt")
    with Session(engine) as session, session.begin():
        updated = session.execute(update(WorkflowOperation).where(
            WorkflowOperation.id == operation_id, WorkflowOperation.owner_token == owner_token,
            WorkflowOperation.status == "started").values(status="completed", result_ref=str(result_id)))
        if updated.rowcount != 1:
            # A concurrent evidence-based reconciliation may already have
            # written exactly the same result; do not misreport that race.
            row = session.get(WorkflowOperation, operation_id)
            if not (row is not None and row.owner_token == owner_token and row.status == "completed"
                    and row.result_ref == str(result_id)):
                raise ValueError("workflow operation is not owned or already completed")


def lookup_stage(engine, *, workflow_id: UUID, stage: str, input_digest: str) -> StageClaim | None:
    """Read an existing bound stage without creating or retrying one."""
    if (not isinstance(workflow_id, UUID) or not isinstance(stage, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", stage)
            or not isinstance(input_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", input_digest)):
        raise ValueError("invalid workflow operation identity")
    with Session(engine) as session:
        row = session.scalar(select(WorkflowOperation).where(
            WorkflowOperation.workflow_id == workflow_id, WorkflowOperation.stage == stage))
        if row is None:
            return None
        if row.input_digest != input_digest:
            raise ValueError("workflow stage identity does not match")
        if row.status == "completed" and row.result_ref:
            return StageClaim("completed", row.id, result_id=UUID(row.result_ref))
        return StageClaim("unknown", row.id)
