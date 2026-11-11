"""End-to-end repository scan orchestration (analysis → triage → persist → report).

This is the service the LangGraph node will call. It performs no detection of
its own: analyzers are injected, and the only side effects are the optional
finding rows and the report document.
"""
from __future__ import annotations

from collections.abc import Sequence
from contextlib import nullcontext
from datetime import timedelta
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnmind.analysis.persistence import FindingWriter, StoredFindings
from vulnmind.analysis.repository import Analyzer, RepositoryAnalysis, RepositoryPipeline
from vulnmind.analysis.triage import TriageDecision, triage_groups
from vulnmind.agents.review import AgentReview, review_findings
from vulnmind.evidence.ingest import EvidenceItem, ingest_evidence
from vulnmind.evidence.store import EvidenceStore
from vulnmind.persistence.models import Evidence, Finding, Scan
from vulnmind.reports.generator import (AgentReviewItem, AgentReviewSummary, DecisionSummary,
                                        ReportDocument, ReportInput, generate)
from vulnmind.reports.evidence_snapshot import MAX_SNAPSHOT_IDS
from vulnmind.schemas import Authorization, Target
from vulnmind.security.approvals import ApprovalService
from vulnmind.security.scope import ScopeDenied, check_target
from vulnmind.tools.repo_files import RepositoryReader
from vulnmind.tools.repo_access import RepositoryAccess
from vulnmind.tools.registry import AuditSink

MAX_REPORT_EVIDENCE_RECORDS = MAX_SNAPSHOT_IDS


class RepositoryScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    scan_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    target: Target
    scope: Authorization
    scan_uuid: UUID | None = None
    target_id: str | None = None
    max_files: int = Field(default=200, ge=1, le=5000)
    max_bytes: int = Field(default=200_000, ge=1, le=1_000_000)


class RepositoryScanResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    analysis: RepositoryAnalysis
    decisions: list[TriageDecision]
    report: ReportDocument
    stored: StoredFindings | None
    evidence_stored: int = 0
    validation_requests: int = 0
    agent_review: AgentReview | None = None


def _report_review(review: AgentReview) -> AgentReviewSummary:
    return AgentReviewSummary(
        status=review.status, summary=review.summary, ignored=review.ignored,
        total_groups=review.total_groups, selected_groups=review.selected_groups,
        omitted_groups=review.omitted_groups, groups_without_verdict=review.groups_without_verdict,
        items=tuple(AgentReviewItem(fingerprint=item.fingerprint, verdict=item.verdict,
                                    rationale=item.rationale, note=item.note)
                    for item in review.items))


class RepositoryScanService:
    def __init__(self, audit: AuditSink, analyzers: Sequence[Analyzer],
                 evidence_store: EvidenceStore | None = None,
                 approvals: ApprovalService | None = None,
                 repo_analyzers: Sequence = (),
                 agent_runtime=None, knowledge_advisor=None, additional_limitations=()):
        if not analyzers and not repo_analyzers:
            raise ValueError("at least one analyser must be configured")
        if agent_runtime is not None and not callable(getattr(agent_runtime, "run", None)):
            raise ValueError("agent runtime must expose a run method")
        self._audit = audit
        self._evidence_store = evidence_store
        self._approvals = approvals
        self._agent_runtime = agent_runtime
        if knowledge_advisor is not None and not callable(knowledge_advisor):
            raise ValueError("knowledge advisor must be callable")
        if (not isinstance(additional_limitations, (list, tuple)) or len(additional_limitations) > 5
                or any(not isinstance(item, str) or not item.strip() or len(item) > 300
                       for item in additional_limitations)):
            raise ValueError("additional limitations are invalid")
        self._knowledge_advisor = knowledge_advisor
        self._additional_limitations = tuple(additional_limitations)
        reader = RepositoryReader(audit)
        # File access goes through the governed READ tools in the registry.
        self._pipeline = RepositoryPipeline(reader, analyzers,
                                            access=RepositoryAccess(reader, audit),
                                            repo_analyzers=repo_analyzers)

    def run(self, request: RepositoryScanRequest, *, session: Session | None = None,
            report_format: str = "markdown") -> RepositoryScanResult:
        if session is not None and request.scan_uuid is None:
            raise ValueError("persisting findings requires the scan UUID")
        if session is not None and self._approvals is not None and self._approvals.session is not session:
            raise ValueError("approval service must use the scan session")
        event = {"call_id": str(uuid4()), "tool_name": "repository.scan", "actor": request.actor,
                 "target_type": request.target.type.value}
        self._audit.record({**event, "status": "requested"})
        try:
            # SQLite's legacy driver can release a first SAVEPOINT as a commit
            # when no physical outer transaction has started. Start it explicitly
            # before nesting so the caller retains rollback control.
            if session is not None:
                connection = session.connection()
                if (connection.dialect.name == "sqlite"
                        and not connection.connection.driver_connection.in_transaction):
                    connection.exec_driver_sql("BEGIN")
            with session.begin_nested() if session is not None else nullcontext():
                if session is not None:
                    scan = session.get(Scan, request.scan_uuid)
                    try:
                        matches = (scan is not None and UUID(request.scan_id) == scan.id
                                   and UUID(request.project_id) == scan.project_id)
                    except (ValueError, TypeError, AttributeError):
                        matches = False
                    if not matches:
                        raise ValueError("scan and project identities do not match the stored scan")
                check_target(request.target, request.scope)
                self._audit.record({**event, "status": "started"})
                analysis = self._pipeline.run(scan_id=request.scan_id, project_id=request.project_id,
                                              target=request.target, scope=request.scope, actor=request.actor,
                                              max_files=request.max_files, max_bytes=request.max_bytes,
                                              target_id=request.target_id)
                decisions = triage_groups(analysis.groups)
                review = None
                limitations = ["仅静态分析，未执行主动验证",
                               "未确认的发现仍需人工验证"]
                limitations.extend(self._additional_limitations)
                if self._agent_runtime is not None and analysis.groups:
                    review = review_findings(self._agent_runtime, actor=request.actor,
                                             groups=analysis.groups)
                    limitations.append("模型复核仅为建议，不构成验证")
                knowledge_review = None
                if self._knowledge_advisor is not None and analysis.groups:
                    from vulnmind.agents.runtime import AgentBudgetError, AgentError
                    try:
                        knowledge_review = self._knowledge_advisor(analysis, request.actor)
                    except (AgentError, AgentBudgetError, ValueError):
                        limitations.append("知识辅助失败，报告不包含知识模型建议")
                    else:
                        if knowledge_review is None or knowledge_review.status == "no_context":
                            limitations.append("知识辅助未获得可用引用，未调用知识模型")
                        elif knowledge_review.status == "insufficient_evidence":
                            limitations.append("知识模型认为现有参考资料不足以支持回答")
                        else:
                            limitations.append("知识模型建议仅供参考，不构成漏洞验证；引用内容为不可信数据")
                stored = None
                evidence_stored = 0
                evidence_record_ids: dict[str, list[UUID]] = {}
                evidence_snapshot = "unavailable"
                evidence_snapshot_truncated = False
                validation_requests = 0
                if session is not None and request.scan_uuid is not None:
                    stored = FindingWriter(session).store(request.scan_uuid, analysis)
                    if self._evidence_store is not None and analysis.evidence:
                        # Evidence is linked only to findings that were just written;
                        # fingerprints without a finding are reported by ingest_evidence.
                        evidence_stored = ingest_evidence(
                            session, self._evidence_store, scan_id=request.scan_uuid,
                            items=[EvidenceItem(fingerprint=item.fingerprint, content=item.content,
                                                evidence_type=item.evidence_type, locator=item.locator)
                                   for item in analysis.evidence]).stored
                    if self._approvals is not None:
                        # Groups that need validation become explicit pending requests;
                        # nothing is executed and the operator decides later. Re-running
                        # the same scan must not enqueue the same request twice.
                        pending = {(row.action, row.target) for row in self._approvals.list_pending(request.scan_uuid)}
                        for group, decision in zip(analysis.groups, decisions):
                            if not decision.requires_validation:
                                continue
                            action = f"validation:{group.candidates[0].vulnerability_type}"[:255]
                            key = (action, group.fingerprint)
                            if key in pending:
                                continue
                            self._approvals.request(scan_id=request.scan_uuid, action=action,
                                                    target=group.fingerprint, valid_for=timedelta(hours=72))
                            pending.add(key)
                            validation_requests += 1
                    # Read actual rows within the same transaction, scoped to
                    # this scan. The IDs are references, not proof of integrity.
                    rows = session.execute(select(Finding.fingerprint, Evidence.id)
                                           .join(Evidence, Evidence.finding_id == Finding.id)
                                           .where(Finding.scan_id == request.scan_uuid)
                                           .order_by(Finding.fingerprint, Evidence.id)
                                           .limit(MAX_REPORT_EVIDENCE_RECORDS + 1)).all()
                    evidence_snapshot = "available"
                    evidence_snapshot_truncated = len(rows) > MAX_REPORT_EVIDENCE_RECORDS
                    reported_fingerprints = {group.fingerprint for group in analysis.groups}
                    for fingerprint, evidence_id in rows[:MAX_REPORT_EVIDENCE_RECORDS]:
                        if fingerprint in reported_fingerprints:
                            evidence_record_ids.setdefault(fingerprint, []).append(evidence_id)
                report_input = analysis.to_report_input(
                    limitations=limitations,
                    decisions=[DecisionSummary(fingerprint=item.fingerprint, severity=item.severity,
                                               confidence=item.confidence,
                                               requires_validation=item.requires_validation,
                                               rationale=item.rationale) for item in decisions],
                    agent_review=_report_review(review) if review is not None else None)
                report_input = report_input.model_copy(update={"evidence_record_ids": evidence_record_ids,
                                                               "evidence_snapshot": evidence_snapshot,
                                                               "evidence_snapshot_truncated": evidence_snapshot_truncated,
                                                               "knowledge_review": knowledge_review})
                report = generate(report_input, format=report_format)
                result = RepositoryScanResult(analysis=analysis, decisions=decisions, report=report, stored=stored,
                                              evidence_stored=evidence_stored,
                                              validation_requests=validation_requests,
                                              agent_review=review)
                # This status is not proof of an outer transaction commit.
                self._audit.record({**event, "status": "pending_commit" if session is not None else "succeeded"})
        except ScopeDenied:
            self._audit.record({**event, "status": "denied"})
            raise
        except Exception:
            self._audit.record({**event, "status": "failed"})
            raise
        return result

    def run_stored(self, *, scan_id: str, project_id: str, actor: str, scan_uuid: UUID,
                   scope_id: UUID, target_id: UUID, session: Session, max_files: int = 200,
                   max_bytes: int = 200_000, report_format: str = "markdown") -> RepositoryScanResult:
        """Load the stored target and authorization, then run the normal path.

        The association check proves the scan, target and scope rows share one
        project; it is not caller authentication and does not detect later
        changes between this load and the file reads.
        """
        from vulnmind.persistence.repositories import ScopeRepository

        target, scope = ScopeRepository(session).load_for_scan(scope_id, target_id=target_id,
                                                               scan_id=scan_uuid)
        return self.run(RepositoryScanRequest(scan_id=scan_id, project_id=project_id, actor=actor,
                                              target=target, scope=scope, scan_uuid=scan_uuid,
                                              max_files=max_files, max_bytes=max_bytes),
                        session=session, report_format=report_format)


