"""Web snapshot scan lifecycle: scan row → analysis → report file → finish.

Mirrors the repository orchestrator. No network access happens here: the input
is a captured snapshot. The caller owns the transaction; a failure marks the
scan failed in that transaction.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from vulnmind.analysis.persistence import StoredFindings
from vulnmind.analysis.web_service import WebAnalysis, WebScanRequest, WebScanService, WebSnapshot
from vulnmind.evidence.store import EvidenceStore
from vulnmind.persistence.models import AgentRun, ScanTask
from vulnmind.persistence.repositories import ReportRepository, ScanRepository
from vulnmind.reports.store import ReportRef, ReportStore
from vulnmind.schemas import Authorization, Target
from vulnmind.tools.registry import AuditSink


class WebScanRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    project_id: UUID
    actor: str = Field(min_length=1)
    target: Target
    scope: Authorization
    snapshot: WebSnapshot
    target_id: str | None = None
    report_format: Literal["markdown", "json"] = "markdown"


class WebScanOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)
    scan_id: UUID
    status: str
    report: ReportRef
    stored: StoredFindings
    analysis: WebAnalysis
    task_id: UUID
    run_id: UUID
    evidence_stored: int = 0
    validation_requests: int = 0
    agent_review_status: str | None = None
    agent_verdicts: int = 0


class WebScanOrchestrator:
    def __init__(self, session: Session, audit: AuditSink, report_store: ReportStore,
                 evidence_store: EvidenceStore | None = None, approvals=None, agent_runtime=None):
        if not isinstance(report_store, ReportStore):
            raise ValueError("a report store is required")
        if evidence_store is not None and not isinstance(evidence_store, EvidenceStore):
            raise ValueError("the evidence store must be an EvidenceStore")
        self._session = session
        self._store = report_store
        self._service = WebScanService(audit, evidence_store=evidence_store,
                                       approvals=approvals, agent_runtime=agent_runtime)

    def run(self, request: WebScanRunRequest) -> WebScanOutcome:
        scan = ScanRepository(self._session).create(request.project_id, "web")
        self._session.flush()
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        self._session.flush()
        task = ScanTask(id=uuid4(), scan_id=scan.id, phase="web-analysis",
                        agent_name="web-analysis", status="running")
        self._session.add(task)
        self._session.flush()
        run = AgentRun(id=uuid4(), task_id=task.id, agent_name="web-analysis", status="running")
        self._session.add(run)
        self._session.flush()
        try:
            with self._session.begin_nested():
                result = self._service.run(WebScanRequest(
                    scan_id=str(scan.id), project_id=str(request.project_id), actor=request.actor,
                    target=request.target, scope=request.scope, snapshot=request.snapshot,
                    scan_uuid=scan.id, target_id=request.target_id),
                    session=self._session, report_format=request.report_format)
                reference = self._store.put(result.report.content, format=result.report.format)
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
        return WebScanOutcome(scan_id=scan.id, status=scan.status, report=reference,
                              stored=result.stored, analysis=result.analysis, task_id=task.id,
                              run_id=run.id, evidence_stored=result.evidence_stored,
                              validation_requests=result.validation_requests,
                              agent_review_status=review.status if review is not None else None,
                              agent_verdicts=len(review.items) if review is not None else 0)
