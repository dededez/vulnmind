"""ORM mappings for the tables created by the Alembic revisions in migrations/versions."""
from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text,
    UniqueConstraint, Uuid, false, func, true,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from pgvector.sqlalchemy import Vector
from sqlalchemy.orm import Mapped, mapped_column

from vulnmind.knowledge.vector import EMBEDDING_DIMENSIONS
from vulnmind.persistence.base import Base


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    tech_stack: Mapped[dict | list | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class WorkflowOperation(Base):
    """Durable single-attempt stage claim; an unfinished claim is uncertain."""
    __tablename__ = "workflow_operations"
    __table_args__ = (
        UniqueConstraint("workflow_id", "stage", name="uq_workflow_operation_stage"),
        CheckConstraint("status IN ('started', 'completed')", name="ck_workflow_operation_status"),
        CheckConstraint("(status = 'started' AND result_ref IS NULL) OR "
                        "(status = 'completed' AND result_ref IS NOT NULL)",
                        name="ck_workflow_operation_result"),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    workflow_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    stage: Mapped[str] = mapped_column(String(64), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_token: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    result_ref: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class DurableStep(Base):
    """V2 stage journal: payload and business writes commit with the receipt."""
    __tablename__ = "durable_steps"
    __table_args__ = (
        UniqueConstraint("workflow_id", "stage", name="uq_durable_step"),
        CheckConstraint("status IN ('ready', 'running', 'completed', 'aborted')", name="ck_durable_step_status"),
        CheckConstraint("attempt >= 1", name="ck_durable_step_attempt"),
        CheckConstraint("(status = 'completed' AND payload IS NOT NULL AND output_digest IS NOT NULL) OR "
                        "(status != 'completed' AND output_digest IS NULL)", name="ck_durable_step_receipt"),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    workflow_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    stage: Mapped[str] = mapped_column(String(64), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict | None] = mapped_column(JSON)
    output_digest: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class WorkflowToolPlan(Base):
    """A committed planner selection bound to its single-attempt operation."""
    __tablename__ = "workflow_tool_plans"
    __table_args__ = (UniqueConstraint("operation_id", name="uq_workflow_tool_plan_operation"),)
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    operation_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("workflow_operations.id"), nullable=False)
    selected_tools: Mapped[list] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class TargetRecord(Base):
    __tablename__ = "targets"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    project_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("projects.id"), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    locator: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_: Mapped[dict | list | None] = mapped_column("metadata", JSONB)


class ScopeRecord(Base):
    __tablename__ = "scopes"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    target_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("targets.id"), nullable=False)
    allowlist: Mapped[dict | list] = mapped_column(JSONB, nullable=False)
    denylist: Mapped[dict | list | None] = mapped_column(JSONB)
    rate_limit: Mapped[dict | list | None] = mapped_column(JSONB)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False)
    authorization_source: Mapped[str] = mapped_column(Text, nullable=False)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    project_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("projects.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanTask(Base):
    __tablename__ = "scan_tasks"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    scan_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("scans.id"), nullable=False)
    parent_id: Mapped[UUID | None] = mapped_column(Uuid, ForeignKey("scan_tasks.id"))
    phase: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_name: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    scope: Mapped[dict | list | None] = mapped_column(JSONB)
    acceptance: Mapped[dict | list | None] = mapped_column(JSONB)


class AgentRun(Base):
    __tablename__ = "agent_runs"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    task_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("scan_tasks.id"), nullable=False)
    agent_name: Mapped[str] = mapped_column(String(128), nullable=False)
    model: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    input_ref: Mapped[str | None] = mapped_column(Text)
    output_ref: Mapped[str | None] = mapped_column(Text)
    usage: Mapped[dict | None] = mapped_column(JSONB)


class ToolInvocation(Base):
    __tablename__ = "tool_invocations"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    run_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("agent_runs.id"), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    args_hash: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    exit_code: Mapped[int | None]
    duration: Mapped[float | None]
    output_ref: Mapped[str | None] = mapped_column(Text)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_fingerprint"),)
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    scan_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("scans.id"), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    vuln_type: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(32))
    confidence: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    location: Mapped[dict | None] = mapped_column(JSONB)
    needs_retriage: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=true())
    observation_revision: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    observation_history_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=false())


class FindingObservation(Base):
    """Source claims; evidence references here are not verified evidence."""
    __tablename__ = "finding_observations"
    __table_args__ = (UniqueConstraint("finding_id", "observation_hash", name="uq_finding_observation_identity"),)
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    finding_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("findings.id"), nullable=False)
    observation_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_tool: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    source_status_claim: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(32))
    evidence_refs: Mapped[list] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class FindingFeedback(Base):
    """Append-only operator verdict; the highest revision wins.

    A verdict is an operator decision, not a verification result. Rows are never
    updated in place: history is preserved and concurrency is bounded by the
    unique ``(finding_id, revision)`` constraint.
    """
    __tablename__ = "finding_feedback"
    __table_args__ = (UniqueConstraint("finding_id", "revision", name="uq_finding_feedback_revision"),)
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    scan_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("scans.id"), nullable=False)
    finding_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("findings.id"), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    finding_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("findings.id"), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    locator: Mapped[str | None] = mapped_column(Text)
    content_ref: Mapped[str] = mapped_column(Text, nullable=False)
    hash: Mapped[str | None] = mapped_column(String(128))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    scan_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("scans.id"), nullable=False)
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    storage_uri: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    scan_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("scans.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    approver: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    operation_hash: Mapped[str | None] = mapped_column(String(64))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    call_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    args_hash: Mapped[str | None] = mapped_column(String(64))
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    entry_hash: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class KnowledgeDocument(Base):
    __tablename__ = "knowledge_documents"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_url: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(String(64))
    trust_level: Mapped[str | None] = mapped_column(String(32))
    metadata_: Mapped[dict | list | None] = mapped_column("metadata", JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class KnowledgeChunk(Base):
    __tablename__ = "knowledge_chunks"
    __table_args__ = (
        UniqueConstraint("document_id", "chunk_index", name="uq_knowledge_chunks_document_chunk"),
        Index("ix_knowledge_chunks_document_id", "document_id"),
        Index("ix_knowledge_chunks_tsvector", "tsvector", postgresql_using="gin"),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    document_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("knowledge_documents.id"), nullable=False)
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    tsvector: Mapped[str | None] = mapped_column(TSVECTOR)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBEDDING_DIMENSIONS))
    metadata_: Mapped[dict | list | None] = mapped_column("metadata", JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class SkillRecord(Base):
    __tablename__ = "skills"
    __table_args__ = (UniqueConstraint("name", "version", name="uq_skills_name_version"),)
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(32))
    vuln_type: Mapped[str | None] = mapped_column(String(128))
    stage: Mapped[str | None] = mapped_column(String(64))
    content_uri: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_: Mapped[dict | list | None] = mapped_column("metadata", JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class MemoryRecordRow(Base):
    __tablename__ = "memory_records"
    __table_args__ = (
        CheckConstraint("level IN ('short_term', 'working', 'long_term')", name="ck_memory_records_level"),
        Index("ix_memory_records_project_task", "project_id", "task_id"),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    level: Mapped[str] = mapped_column(String(16), nullable=False)
    project_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("projects.id"), nullable=False)
    task_id: Mapped[UUID | None] = mapped_column(Uuid, ForeignKey("scan_tasks.id"))
    memory_type: Mapped[str | None] = mapped_column(String(64))
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source_refs: Mapped[list] = mapped_column(JSONB, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    validated_by: Mapped[str | None] = mapped_column(String(255))
    invalidated: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=false())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ContextManifestRecord(Base):
    __tablename__ = "context_manifests"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    run_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("agent_runs.id"), nullable=False)
    agent_name: Mapped[str] = mapped_column(String(128), nullable=False)
    selected_refs: Mapped[list | dict] = mapped_column(JSONB, nullable=False)
    token_estimate: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class WebEndpoint(Base):
    """A method+URL discovered during an authorized crawl of one scan.

    Rows are observations, not proof that the endpoint is reachable or
    vulnerable. ``source_url`` records the page whose HTML contained the link.
    """
    __tablename__ = "web_endpoints"
    __table_args__ = (
        UniqueConstraint("scan_id", "method", "url", name="uq_web_endpoints_scan_method_url"),
        Index("ix_web_endpoints_scan_id", "scan_id"),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    scan_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("scans.id"), nullable=False)
    project_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("projects.id"), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    parameters: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="discovered")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class WorkbenchJob(Base):
    __tablename__ = 'workbench_jobs'
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    project_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey('projects.id'), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    config: Mapped[dict] = mapped_column(JSON, nullable=False)
    result: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
