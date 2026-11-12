"""Durable stage execution with process-death locks and explicit uncertain recovery.

No checkpoint is trusted as proof of an effect. A stage receipt, business writes
and terminal audit commit together. Locks span compute without holding a write
transaction. An interrupted external operation is never automatically repeated.
"""
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from uuid import UUID, uuid4, uuid5
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from vulnmind.persistence.audit import AuditError, DatabaseAuditSink, SessionAuditSink, verify_complete_audit_chain
from vulnmind.persistence.models import AuditEvent, DurableStep, Scan


class StepUnknown(AuditError):
    pass


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    if len(raw) > 32_000_000:
        raise ValueError("stage payload exceeds limit")
    return sha256(raw).hexdigest()


@contextmanager
def workflow_lock(engine, workflow_id):
    """Fail immediately on contention; OS/PG releases the lock after death."""
    if engine.dialect.name == "postgresql":
        key = int.from_bytes(sha256(str(workflow_id).encode()).digest()[:8], "big", signed=True)
        with engine.connect() as conn:
            if not conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key}).scalar_one():
                raise StepUnknown("workflow is already running")
            try:
                yield
            finally:
                try:
                    conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})
                except Exception:
                    conn.invalidate()
    elif engine.dialect.name == "sqlite":
        db = engine.url.database
        if not db or db == ":memory:":
            raise ValueError("durable workflows require a file database")
        directory = Path(db).resolve().parent / (Path(db).name + ".locks")
        directory.mkdir(exist_ok=True)
        with (directory / str(workflow_id)).open("a+b") as handle:
            if os.fstat(handle.fileno()).st_size == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise StepUnknown("workflow is already running") from None
            try:
                yield
            finally:
                handle.seek(0)
                if os.name == "nt":
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(handle, fcntl.LOCK_UN)
    else:
        raise ValueError("unsupported durable database")


class LinkedAudit:
    def __init__(self, engine, parent, target_type):
        self.sink = DatabaseAuditSink(engine)
        self.parent, self.target_type = parent, target_type
        self.linked = set()

    def record(self, event):
        call_id = event["call_id"]
        if call_id not in self.linked:
            self.sink.record({"call_id": call_id, "tool_name": f"correlation.{self.parent}",
                              "actor": event["actor"], "target_type": self.target_type, "status": "requested"})
            self.linked.add(call_id)
        self.sink.record(event)


class Journal:
    """Caller holds workflow_lock for the entire graph or recovery command."""
    def __init__(self, engine, workflow_id, binding, actor, target_type="repository"):
        self.engine, self.workflow_id = engine, UUID(str(workflow_id))
        self.binding, self.actor, self.target_type = digest(binding), actor, target_type

    def _event(self, row, status, args_hash=None):
        return {"call_id": str(row.id), "tool_name": f"workflow.{row.stage}", "actor": self.actor,
                "target_type": self.target_type, "status": status, "args_hash": args_hash or row.input_digest}

    def _row(self, session, stage):
        return session.scalar(select(DurableStep).where(DurableStep.workflow_id == self.workflow_id,
                                                       DurableStep.stage == stage))

    def run(self, stage, inputs, compute, *, persist=None, replay_safe=False, read_only=False):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", stage):
            raise ValueError("invalid stage")
        bound = digest({"workflow": self.binding, "stage": stage, "inputs": inputs})
        with Session(self.engine) as session, session.begin():
            row = self._row(session, stage)
            if row is not None and row.input_digest != bound:
                raise ValueError("workflow input changed: " + stage)
            if row is not None and row.status == "completed":
                output = digest(row.payload)
                receipt = digest({"input": bound, "output": output, "attempt": row.attempt})
                # Hot resume path: only appended rows are re-checked (the authoritative
                # full pass is used by verify_job and the audit CLI).
                chain = verify_complete_audit_chain(session.connection(), use_cache=True)
                audit = session.scalar(select(AuditEvent.id).where(AuditEvent.call_id == row.id,
                    AuditEvent.tool_name == f"workflow.{stage}", AuditEvent.status == "succeeded",
                    AuditEvent.args_hash == receipt))
                if output != row.output_digest or not audit or not chain.valid or chain.unhashed:
                    raise StepUnknown("stage receipt failed verification")
                return row.payload
            if read_only:
                raise StepUnknown("stage has not completed")
            if row is not None and (row.status == "aborted" or (row.status == "running" and not replay_safe)):
                raise StepUnknown("stage requires explicit recovery")
            if row is None:
                row = DurableStep(id=uuid4(), workflow_id=self.workflow_id, stage=stage, input_digest=bound,
                                  status="ready", attempt=0)
                session.add(row)
            row.status = "running"
            row.attempt += 1
            SessionAuditSink(session).record(self._event(row, "started"))
            operation, attempt = row.id, row.attempt
        # No business transaction or audit-chain lock during model/tool IO.
        try:
            output = compute(LinkedAudit(self.engine, operation, self.target_type))
        except Exception as exc:
            # A deterministic failure must not look like an in-flight stage. Persist
            # the failure first, then record the audit best-effort so a broken audit
            # chain cannot hide the original error.
            try:
                with Session(self.engine) as session, session.begin():
                    row = session.get(DurableStep, operation)
                    if row is not None and row.status == "running" and row.attempt == attempt:
                        row.status = "failed"
                        row.payload = {"error_type": type(exc).__name__, "error": str(exc)[:300]}
                try:
                    DatabaseAuditSink(self.engine).record(self._event(row, "failed"))
                except AuditError:
                    pass
            except Exception:
                pass
            raise
        if not isinstance(output, dict):
            raise ValueError("stage output must be an object")
        digest(output)
        with Session(self.engine) as session, session.begin():
            row = session.get(DurableStep, operation)
            if row.status != "running" or row.attempt != attempt:
                raise StepUnknown("stage ownership changed")
            if persist:
                output = persist(session, output)
            row.payload, row.output_digest = output, digest(output)
            row.status = "completed"
            receipt = digest({"input": bound, "output": row.output_digest, "attempt": attempt})
            SessionAuditSink(session).record(self._event(row, "succeeded", receipt))
        return output


def recover_step(engine, workflow_id, stage, action, actor, reason, acknowledged=False):
    if action not in {"retry", "abort"} or not reason.strip() or len(reason) > 500:
        raise ValueError("invalid recovery decision")
    if action == "retry" and not acknowledged:
        raise ValueError("retry requires acknowledgement of possible repeated effects")
    with workflow_lock(engine, workflow_id), Session(engine) as session, session.begin():
        row = session.scalar(select(DurableStep).where(DurableStep.workflow_id == workflow_id,
                                                      DurableStep.stage == stage))
        if row is None or row.status not in {"running", "failed"}:
            raise ValueError("only interrupted or failed stages can be recovered")
        row.status = "ready" if action == "retry" else "aborted"
        if action == "abort":
            scan = session.get(Scan, uuid5(workflow_id, "scan-v2"))
            if scan is not None and scan.status != "finished":
                scan.status = "aborted"
                scan.finished_at = datetime.now(timezone.utc)
        SessionAuditSink(session).record({"call_id": str(row.id), "tool_name": "workflow.recovery",
            "actor": actor, "target_type": "web" if stage.startswith("http_") else "repository",
            "status": "retrying" if action == "retry" else "cancelled",
            "args_hash": digest({"action": action, "reason": reason, "attempt": row.attempt})})
        return {"stage": stage, "status": row.status, "operation_id": str(row.id)}
