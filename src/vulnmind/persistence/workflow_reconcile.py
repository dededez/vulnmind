"""Conservative recovery of a committed repository scan receipt.

Only a finished scan with the same operation ID, an intact report and a
complete, valid audit trail with a committed root can be reconciled. This does
not infer that absent work never ran and never executes a scan or network call.
"""
from pathlib import Path
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from vulnmind.persistence.audit import MAX_VERIFY_EVENTS, SessionAuditSink, trace_scan_audit, verify_audit_chain
from vulnmind.persistence.models import Scan, WorkflowOperation
from vulnmind.reports.loader import load_report
from vulnmind.reports.identity import matches_scan
from vulnmind.reports.store import ReportStore


def _trace_is_complete(trace: dict, operation_id: UUID) -> bool:
    return (trace["complete"] and trace["outcome"] == "committed"
            and not trace["operations_may_be_missing"]
            and not any(item["outcome"] == "unknown" for item in trace["operations"])
            and any(event["tool_name"] == "repository.scan.transaction" and event["status"] == "succeeded"
                    and event["call_id"] == str(operation_id) for event in trace["events"])
            and any(item["tool_name"] == "repository.scan" and item["outcome"] == "pending_commit"
                    for item in trace["operations"]))


def reconcile_repository_scan(engine, *, workflow_id: UUID, operation_id: UUID,
                              input_digest: str, project_id: UUID, report_root: Path,
                              actor: str) -> bool:
    """Finalize only an independently verifiable already-committed result.

    Exceptions or a false result leave the operation uncertain. Identity and
    authorization must be checked by the caller before this function is used.
    """
    if not all(isinstance(item, UUID) for item in (workflow_id, operation_id, project_id)):
        raise ValueError("invalid recovery identity")
    if not Path(report_root).is_dir():
        return False
    with Session(engine) as session, session.begin():
        row = session.scalar(select(WorkflowOperation).where(
            WorkflowOperation.id == operation_id, WorkflowOperation.workflow_id == workflow_id,
            WorkflowOperation.stage == "repository_scan", WorkflowOperation.input_digest == input_digest))
        if row is None:
            return False
        if row.status == "completed":
            return row.result_ref == str(operation_id)
        if row.status != "started":
            return False
        scan = session.get(Scan, operation_id)
        if scan is None or scan.project_id != project_id or scan.status != "finished" or scan.mode != "analysis":
            return False
        loaded = load_report(session, ReportStore(report_root), operation_id)
        if (loaded.content is None or loaded.scan_status != "finished"
                or not matches_scan(loaded.content, loaded.format, scan_id=operation_id, project_id=project_id)):
            return False
        connection = session.connection()
        chain = verify_audit_chain(connection, limit=MAX_VERIFY_EVENTS)
        trace = trace_scan_audit(connection, operation_id, limit=MAX_VERIFY_EVENTS)
        if (not chain.valid or not chain.complete or chain.unhashed or not chain.checked
                or not _trace_is_complete(trace, operation_id)):
            return False
        updated = session.execute(update(WorkflowOperation).where(
            WorkflowOperation.id == operation_id, WorkflowOperation.status == "started",
            WorkflowOperation.input_digest == input_digest).values(status="completed", result_ref=str(operation_id)))
        if updated.rowcount != 1:
            return False
        SessionAuditSink(session).record({"call_id": str(operation_id), "tool_name": "workflow.reconcile",
                                          "actor": actor, "target_type": "repository", "status": "succeeded"})
        # Audit writers acquire a database-level chain lock when recording; a
        # second verification under that lock prevents accepting a chain that
        # changed or became incomplete during the preceding reads.
        final_chain = verify_audit_chain(connection, limit=MAX_VERIFY_EVENTS)
        final_trace = trace_scan_audit(connection, operation_id, limit=MAX_VERIFY_EVENTS)
        if (not final_chain.valid or not final_chain.complete or final_chain.unhashed
                or not _trace_is_complete(final_trace, operation_id)):
            raise ValueError("audit chain cannot be verified")
    return True
