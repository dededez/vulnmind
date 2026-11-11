"""Persist an opt-in post-scan knowledge manifest with a single-attempt receipt."""
from hashlib import sha256
import json
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from vulnmind.analysis.repository import RepositoryAnalysis
from vulnmind.persistence.audit import (DatabaseAuditSink, MAX_VERIFY_EVENTS, SessionAuditSink,
                                        trace_scan_audit, verify_audit_chain)
from vulnmind.persistence.models import AgentRun, AuditEvent, ContextManifestRecord, Scan, ScanTask, WorkflowOperation
from vulnmind.persistence.repositories import ContextManifestRepository
from vulnmind.reports.regenerate import rebuild_groups


def _manifest_digest(manifest, *, scan_id: UUID, input_digest: str) -> str:
    payload = {"scan_id": str(scan_id), "input_digest": input_digest, "manifest_id": str(manifest.id),
               "run_id": str(manifest.run_id), "agent_name": manifest.agent_name,
               "selected_refs": manifest.selected_refs, "token_estimate": manifest.token_estimate}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(encoded) > 1_000_000:
        raise ValueError("knowledge manifest exceeds size limit")
    return sha256(encoded).hexdigest()


def _scan_run(session, *, scan_id: UUID, project_id: UUID):
    scan = session.get(Scan, scan_id)
    if scan is None or scan.project_id != project_id or scan.status != "finished" or scan.mode != "analysis":
        raise ValueError("completed scan is unavailable")
    runs = session.execute(select(AgentRun, ScanTask).join(ScanTask, AgentRun.task_id == ScanTask.id).where(
        ScanTask.scan_id == scan_id, ScanTask.phase == "analysis",
        ScanTask.agent_name == "repository-analysis", AgentRun.agent_name == "repository-analysis").limit(2)).all()
    if len(runs) != 1 or runs[0][0].status != "succeeded" or runs[0][1].status != "finished":
        raise ValueError("scan analysis run is unavailable")
    return runs[0][0]


def save_knowledge_stage(engine, *, operation_id: UUID, owner_token: UUID, input_digest: str,
                         scan_id: UUID, project_id: UUID, target_id: str, actor: str, encoder) -> UUID:
    """Reconstruct committed findings and atomically persist manifest/receipt/audit.

    Encoder and retrieval operate locally. Unknown outcomes are never retried
    automatically; a completed receipt can be independently checked later.
    """
    if not all(isinstance(item, UUID) for item in (operation_id, owner_token, scan_id, project_id)):
        raise ValueError("invalid knowledge stage identity")
    from vulnmind.context.scan_manifest import knowledge_manifest_provider
    from vulnmind.knowledge.hybrid import PostgresHybridRetriever
    from vulnmind.knowledge.postgres_adapters import DatabaseChunkStore
    if engine.dialect.name != "postgresql":
        raise ValueError("knowledge stage requires PostgreSQL")
    root = {"call_id": str(operation_id), "tool_name": "repository.knowledge.transaction",
            "actor": actor, "target_type": "repository"}
    audit = DatabaseAuditSink(engine)
    audit.record({**root, "status": "requested"})
    committing = False
    try:
        with Session(engine) as session:
            session.begin()
            operation = session.get(WorkflowOperation, operation_id)
            if (operation is None or operation.owner_token != owner_token or operation.status != "started"
                    or operation.stage != "knowledge_context" or operation.input_digest != input_digest):
                raise ValueError("knowledge operation is not owned")
            run = _scan_run(session, scan_id=scan_id, project_id=project_id)
            # Do not silently add a second manifest to an ambiguous scan run.
            existing = session.scalar(select(ContextManifestRecord.id).where(
                ContextManifestRecord.run_id == run.id).limit(1))
            if existing is not None:
                raise ValueError("scan run already has a knowledge manifest")
            groups = rebuild_groups(session, scan_id)
            findings = [candidate for group in groups for candidate in group.candidates]
            analysis = RepositoryAnalysis(scan_id=str(scan_id), project_id=str(project_id), target_id=target_id,
                                          files_examined=0, files_skipped=0, findings=findings, groups=groups)
            retriever = PostgresHybridRetriever(session, encoder=encoder)
            provider = knowledge_manifest_provider(retriever, DatabaseChunkStore(session), retrieval_method="hybrid")
            payload = provider(analysis)
            manifest = ContextManifestRepository(session).create(run_id=run.id, agent_name="repository-analysis",
                selected_refs=payload["selected_refs"], token_estimate=payload["token_estimate"])
            session.flush()
            receipt_digest = _manifest_digest(manifest, scan_id=scan_id, input_digest=input_digest)
            changed = session.execute(update(WorkflowOperation).where(
                WorkflowOperation.id == operation_id, WorkflowOperation.owner_token == owner_token,
                WorkflowOperation.stage == "knowledge_context", WorkflowOperation.status == "started",
                WorkflowOperation.input_digest == input_digest
            ).values(status="completed", result_ref=str(manifest.id)))
            if changed.rowcount != 1:
                raise ValueError("knowledge operation changed")
            SessionAuditSink(session).record({**root, "status": "succeeded", "args_hash": receipt_digest})
            manifest_id = manifest.id
            committing = True
            session.commit()
    except Exception:
        if not committing:
            audit.record({**root, "status": "failed"})
        raise
    return manifest_id


def _verified_manifest(session, *, operation_id: UUID, manifest_id: UUID, input_digest: str,
                       scan_id: UUID, project_id: UUID):
    if not all(isinstance(item, UUID) for item in (operation_id, manifest_id, scan_id, project_id)):
        return None
    operation = session.get(WorkflowOperation, operation_id)
    if (operation is None or operation.stage != "knowledge_context" or operation.status != "completed"
            or operation.input_digest != input_digest or operation.result_ref != str(manifest_id)):
        return None
    run = _scan_run(session, scan_id=scan_id, project_id=project_id)
    manifest = session.get(ContextManifestRecord, manifest_id)
    if manifest is None or manifest.run_id != run.id or manifest.agent_name != "repository-analysis":
        return None
    chain = verify_audit_chain(session.connection(), limit=MAX_VERIFY_EVENTS)
    scan_trace = trace_scan_audit(session.connection(), scan_id, limit=MAX_VERIFY_EVENTS)
    events = session.execute(select(AuditEvent.status, AuditEvent.args_hash).where(
        AuditEvent.call_id == operation_id, AuditEvent.tool_name == "repository.knowledge.transaction"
    ).order_by(AuditEvent.created_at, AuditEvent.id)).all()
    if (not chain.valid or not chain.complete or chain.unhashed
            or not scan_trace["complete"] or scan_trace["outcome"] != "committed"
            or scan_trace["operations_may_be_missing"]
            or not any(event["call_id"] == str(scan_id) and event["tool_name"] == "repository.scan.transaction"
                       and event["status"] == "succeeded" for event in scan_trace["events"])
            or any(item["outcome"] == "unknown" for item in scan_trace["operations"])
            or not any(item["tool_name"] == "repository.scan" and item["outcome"] == "pending_commit"
                       for item in scan_trace["operations"])
            or len(events) != 2
            or events[0].status != "requested" or events[1].status != "succeeded"
            or events[1].args_hash != _manifest_digest(manifest, scan_id=scan_id, input_digest=input_digest)):
        return None
    return manifest


def verify_knowledge_stage(engine, *, operation_id: UUID, manifest_id: UUID, input_digest: str,
                           scan_id: UUID, project_id: UUID) -> bool:
    """Check stage, scan linkage, manifest digest and complete audit chain."""
    with engine.connect() as connection:
        if connection.dialect.name == "postgresql":
            connection = connection.execution_options(isolation_level="REPEATABLE READ")
        elif connection.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN")
        else:
            raise ValueError("unsupported database")
        with Session(bind=connection) as session:
            return _verified_manifest(session, operation_id=operation_id, manifest_id=manifest_id,
                input_digest=input_digest, scan_id=scan_id, project_id=project_id) is not None


def read_workflow_context(engine, workflow_id: UUID) -> dict:
    """Read verified historical context from one consistent DB snapshot."""
    if not isinstance(workflow_id, UUID):
        raise ValueError("invalid workflow ID")
    from vulnmind.persistence.durable_context import read_durable_context
    durable = read_durable_context(engine, workflow_id)
    if durable is not None:
        return durable
    with engine.connect() as connection:
        if connection.dialect.name == "postgresql":
            connection = connection.execution_options(isolation_level="REPEATABLE READ")
        elif connection.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN")
        else:
            raise ValueError("unsupported database")
        with Session(bind=connection) as session:
            rows = session.scalars(select(WorkflowOperation).where(
                WorkflowOperation.workflow_id == workflow_id,
                WorkflowOperation.stage.in_(("repository_scan", "knowledge_context")))).all()
            stages = {row.stage: row for row in rows}
            scan_op, knowledge_op = stages.get("repository_scan"), stages.get("knowledge_context")
            if (scan_op is None or knowledge_op is None or scan_op.status != "completed"
                    or knowledge_op.status != "completed" or scan_op.input_digest != knowledge_op.input_digest
                    or scan_op.result_ref != str(scan_op.id)):
                raise ValueError("completed workflow context is unavailable")
            scan = session.get(Scan, scan_op.id)
            if scan is None:
                raise ValueError("scan is unavailable")
            manifest_id = UUID(knowledge_op.result_ref)
            manifest = _verified_manifest(session, operation_id=knowledge_op.id, manifest_id=manifest_id,
                input_digest=knowledge_op.input_digest, scan_id=scan_op.id, project_id=scan.project_id)
            if manifest is None:
                raise ValueError("workflow context could not be verified")
            return {"workflow_id": str(workflow_id), "scan_id": str(scan_op.id),
                    "manifest_id": str(manifest.id), "selected_refs": manifest.selected_refs,
                    "token_estimate": manifest.token_estimate,
                    "interpretation": "historical_untrusted_context_not_vulnerability_verification"}
