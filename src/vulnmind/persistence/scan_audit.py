"""CLI scan transactions with independently committed lifecycle audits.

An absent final event is an unknown outcome, not proof of failure or success.
SQLite child events remain transaction-bound and can be rolled back.
"""
from contextlib import contextmanager
from threading import Lock
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from vulnmind.persistence.audit import AuditError, DatabaseAuditSink, SessionAuditSink


class ScanCommitUnknown(RuntimeError):
    """An audit or commit outcome is uncertain; do not retry blindly."""


class CorrelatedAuditSink:
    """Add tamper-evident parent links without changing historic event hashes."""
    def __init__(self, sink, parent_id):
        self._sink = sink
        self._parent_id = UUID(str(parent_id))
        self._linked = set()
        self._lock = Lock()

    def record(self, event):
        # All events must have a valid stable call ID; do not log arbitrary text.
        try:
            child = UUID(str(event["call_id"]))
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ValueError("invalid audit call ID") from None
        with self._lock:
            if child not in self._linked:
                self._sink.record({"call_id": str(child), "tool_name": f"correlation.{self._parent_id}",
                                   "actor": event["actor"], "target_type": event["target_type"],
                                   "status": "requested"})
                self._linked.add(child)
            self._sink.record(event)


@contextmanager
def repository_scan_transaction(engine, *, actor, target_type="repository", action="scan", call_id=None):
    if (target_type not in {"repository", "web"} or action not in {"scan", "validation-plan"}
            or (action == "validation-plan" and target_type != "web")):
        raise ValueError("invalid scan audit target")
    if call_id is not None and not isinstance(call_id, UUID):
        raise ValueError("audit call ID must be a UUID")
    independent = engine.dialect.name == "postgresql"
    sink = DatabaseAuditSink(engine)
    event = {"call_id": str(call_id or uuid4()), "tool_name": f"{target_type}.{action}.transaction",
             "actor": actor, "target_type": target_type}
    # Fail closed: no business transaction or tool call if this fails.
    sink.record({**event, "status": "requested"})
    body_completed = False
    try:
        with Session(engine) as session, session.begin():
            child_sink = sink if independent else SessionAuditSink(session)
            yield session, CorrelatedAuditSink(child_sink, event["call_id"]), event["call_id"]
            body_completed = True
    except BaseException as exc:
        if body_completed:
            # Commit itself may have reached the server despite a lost reply.
            raise ScanCommitUnknown("scan commit could not be confirmed") from exc
        if isinstance(exc, AuditError):
            # An earlier tool or model request may have run even though its
            # completion event could not be committed. Leave the root open.
            raise ScanCommitUnknown("scan audit could not be confirmed") from exc
        # Business rollback has finished before this event is written.
        try:
            sink.record({**event, "status": "failed"})
        except Exception as audit_exc:
            raise ScanCommitUnknown("failure audit could not be confirmed") from audit_exc
        raise
    else:
        # If this write fails the committed outcome is unknown to the audit;
        # do not replace it with a misleading failed event or retry the scan.
        try:
            sink.record({**event, "status": "succeeded"})
        except Exception as exc:
            raise ScanCommitUnknown("scan committed but final audit is unavailable") from exc
