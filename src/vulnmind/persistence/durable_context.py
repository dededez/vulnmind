"""Verified metadata-only knowledge lookup for v2 workflows."""
from uuid import uuid5
from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from vulnmind.persistence.audit import verify_complete_audit_chain
from vulnmind.persistence.durable import digest
from vulnmind.persistence.models import AuditEvent, DurableStep, Scan, ContextManifestRecord


def read_durable_context(engine, workflow_id):
    if not inspect(engine).has_table("durable_steps"):
        return None
    with engine.connect() as connection:
        if connection.dialect.name == "postgresql":
            connection = connection.execution_options(isolation_level="REPEATABLE READ")
        else:
            connection.exec_driver_sql("BEGIN")
        with Session(bind=connection) as session:
            rows = session.scalars(select(DurableStep).where(DurableStep.workflow_id == workflow_id,
                DurableStep.stage.in_(("initialize", "analyze", "knowledge")))).all()
            if not rows:
                return None
            stages = {row.stage: row for row in rows}
            if set(stages) != {"initialize", "analyze", "knowledge"} or any(row.status != "completed" for row in rows):
                raise ValueError("knowledge stage is incomplete")
            chain = verify_complete_audit_chain(connection)
            if not chain.valid or chain.unhashed:
                raise ValueError("audit chain is invalid")
            for row in rows:
                output = digest(row.payload)
                receipt = digest({"input": row.input_digest, "output": output, "attempt": row.attempt})
                event = session.scalar(select(AuditEvent.id).where(AuditEvent.call_id == row.id,
                    AuditEvent.tool_name == f"workflow.{row.stage}", AuditEvent.status == "succeeded",
                    AuditEvent.args_hash == receipt))
                if output != row.output_digest or event is None:
                    raise ValueError("stage receipt is invalid")
            scan_id = uuid5(workflow_id, "scan-v2")
            scan = session.get(Scan, scan_id)
            if (scan is None or stages["initialize"].payload["scan_id"] != str(scan_id)
                    or stages["analyze"].payload["scan_id"] != str(scan_id)
                    or stages["analyze"].payload["project_id"] != str(scan.project_id)):
                raise ValueError("scan identity mismatch")
            knowledge = stages["knowledge"].payload
            manifest = session.get(ContextManifestRecord, uuid5(workflow_id, "manifest"))
            if (manifest is None or "manifest" not in knowledge
                    or manifest.run_id != uuid5(workflow_id, "run:knowledge")
                    or manifest.selected_refs != knowledge["manifest"]["selected_refs"]
                    or manifest.token_estimate != knowledge["manifest"]["token_estimate"]):
                raise ValueError("knowledge manifest is unavailable")
            return {"workflow_id": str(workflow_id), "scan_id": str(scan_id), "manifest_id": str(manifest.id),
                "selected_refs": manifest.selected_refs, "token_estimate": manifest.token_estimate,
                "interpretation": "historical_untrusted_context_not_vulnerability_verification"}
