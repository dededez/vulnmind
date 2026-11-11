"""Scan lifecycle orchestration: scan row → analysis → report file → finish.

The orchestrator owns the scan record and the stored report reference. It does
not commit: the caller provides the transaction. A failed run marks the scan
``failed`` in the open transaction; the caller still decides whether to roll
back or keep that record.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.orm import Session

from vulnmind.analysis.repository import Analyzer, RepositoryAnalysis
from vulnmind.analysis.service import RepositoryScanRequest, RepositoryScanService
from vulnmind.analysis.persistence import StoredFindings
from vulnmind.evidence.store import EvidenceStore
from vulnmind.persistence.models import AgentRun, ScanTask
from vulnmind.persistence.repositories import ContextManifestRepository, ReportRepository, ScanRepository
from vulnmind.reports.store import ReportRef, ReportStore
from vulnmind.schemas import Authorization, Target
from vulnmind.tools.registry import AuditSink


class ScanRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    project_id: UUID
    actor: str = Field(min_length=1)
    target: Target | None = None
    scope: Authorization | None = None
    scope_id: UUID | None = None
    stored_target_id: UUID | None = None
    target_id: str | None = None
    max_files: int = Field(default=200, ge=1, le=5000)
    max_bytes: int = Field(default=200_000, ge=1, le=1_000_000)
    report_format: Literal["markdown", "json"] = "markdown"

    @model_validator(mode="after")
    def one_scope_source(self):
        stored = self.scope_id is not None or self.stored_target_id is not None
        direct = self.target is not None or self.scope is not None
        if stored and direct:
            raise ValueError("provide either stored scope ids or target and scope, not both")
        if stored and (self.scope_id is None or self.stored_target_id is None):
            raise ValueError("both stored scope and target ids are required")
        if not stored and (self.target is None or self.scope is None):
            raise ValueError("target and scope are required when no stored ids are given")
        return self


class ScanOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)
    scan_id: UUID
    status: str
    report: ReportRef
    stored: StoredFindings
    files_examined: int
    files_skipped: int
    groups: int
    evidence_stored: int = 0
    task_id: UUID | None = None
    run_id: UUID | None = None
    context_manifest_id: UUID | None = None
    agent_review_status: str | None = None
    agent_verdicts: int = 0


class ScanOrchestrator:
    def __init__(self, session: Session, audit: AuditSink, analyzers: Sequence[Analyzer],
                 report_store: ReportStore, evidence_store: EvidenceStore | None = None,
                 manifest_provider: Callable[[RepositoryAnalysis], dict] | None = None,
                 repo_analyzers: Sequence = (), agent_runtime=None, knowledge_advisor=None,
                 additional_limitations=()):
        if not analyzers and not repo_analyzers:
            raise ValueError("at least one analyser must be configured")
        if not isinstance(report_store, ReportStore):
            raise ValueError("a report store is required")
        if evidence_store is not None and not isinstance(evidence_store, EvidenceStore):
            raise ValueError("the evidence store must be an EvidenceStore")
        if manifest_provider is not None and not callable(manifest_provider):
            raise ValueError("manifest provider must be callable")
        if agent_runtime is not None and not callable(getattr(agent_runtime, "run", None)):
            raise ValueError("agent runtime must expose a run method")
        self._session = session
        self._report_store = report_store
        self._manifest_provider = manifest_provider
        self._service = RepositoryScanService(audit, analyzers, evidence_store=evidence_store,
                                              repo_analyzers=repo_analyzers,
                                              agent_runtime=agent_runtime, knowledge_advisor=knowledge_advisor,
                                              additional_limitations=additional_limitations)

    def run(self, request: ScanRunRequest, *, scan_id: UUID | None = None) -> ScanOutcome:
        scans = ScanRepository(self._session)
        scan = scans.create(request.project_id, "analysis")
        if scan_id is not None:
            if not isinstance(scan_id, UUID):
                raise ValueError("scan ID must be a UUID")
            scan.id = scan_id
        self._session.flush()
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        self._session.flush()
        task = ScanTask(id=uuid4(), scan_id=scan.id, phase="analysis",
                        agent_name="repository-analysis", status="running")
        self._session.add(task)
        self._session.flush()
        run = AgentRun(id=uuid4(), task_id=task.id, agent_name="repository-analysis", status="running")
        self._session.add(run)
        self._session.flush()
        manifest_id = None
        try:
            # Roll back scan outputs even if the caller catches and commits.
            # Files created by content-addressed stores are outside this savepoint.
            with self._session.begin_nested():
                if request.scope_id is not None and request.stored_target_id is not None:
                    result = self._service.run_stored(
                        scan_id=str(scan.id), project_id=str(request.project_id), actor=request.actor,
                        scan_uuid=scan.id, scope_id=request.scope_id,
                        target_id=request.stored_target_id, session=self._session,
                        max_files=request.max_files, max_bytes=request.max_bytes,
                        report_format=request.report_format)
                else:
                    assert request.target is not None and request.scope is not None
                    result = self._service.run(
                        RepositoryScanRequest(
                            scan_id=str(scan.id), project_id=str(request.project_id), actor=request.actor,
                            target=request.target, scope=request.scope, scan_uuid=scan.id,
                            target_id=request.target_id, max_files=request.max_files,
                            max_bytes=request.max_bytes),
                        session=self._session, report_format=request.report_format)
                if self._manifest_provider is not None:
                    payload = self._manifest_provider(result.analysis)
                    manifest = ContextManifestRepository(self._session).create(
                        run_id=run.id, agent_name="repository-analysis",
                        selected_refs=payload.get("selected_refs", []),
                        token_estimate=payload.get("token_estimate", 0))
                    manifest_id = manifest.id
                reference = self._report_store.put(result.report.content, format=result.report.format)
                ReportRepository(self._session).create(scan.id, format=result.report.format,
                                                       storage_uri=reference.uri)
                scan.status = "finished"
                scan.finished_at = datetime.now(timezone.utc)
                task.status = "finished"
                run.status = "succeeded"
                self._session.flush()
        except BaseException:
            scan.status = "failed"
            scan.finished_at = datetime.now(timezone.utc)
            task.status = "failed"
            run.status = "failed"
            self._session.flush()
            raise
        assert result.stored is not None
        review = result.agent_review
        return ScanOutcome(scan_id=scan.id, status=scan.status, report=reference,
                           stored=result.stored, files_examined=result.analysis.files_examined,
                           files_skipped=result.analysis.files_skipped,
                           groups=len(result.analysis.groups),
                           evidence_stored=result.evidence_stored, task_id=task.id,
                           run_id=run.id, context_manifest_id=manifest_id,
                           agent_review_status=review.status if review is not None else None,
                           agent_verdicts=len(review.items) if review is not None else 0)
