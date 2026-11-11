"""Rebuild a report from stored findings, observations and operator feedback.

The regenerator never re-runs a scanner, never contacts a target and never
changes a finding row. It reconstructs the same groups the report would have
contained, re-applies deterministic triage, attaches the newest operator verdict
per finding and writes a new report document (the earlier report is kept).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnmind.analysis.triage import TriageDecision, triage_group
from vulnmind.findings import FindingCandidate, FindingGroup, group_findings
from vulnmind.persistence.models import Evidence, Finding, FindingObservation, Scan
from vulnmind.persistence.repositories import FeedbackRepository, ReportRepository
from vulnmind.reports.evidence_snapshot import MAX_SNAPSHOT_IDS
from vulnmind.reports.generator import (DecisionSummary, FeedbackSummary, ReportDocument, ReportInput, generate)
from vulnmind.reports.store import ReportRef, ReportStore

MAX_FINDINGS = 1000
MAX_OBSERVATIONS = 5000


class ReportRebuildError(ValueError):
    """Stored findings cannot be turned into a trustworthy report."""


@dataclass(frozen=True)
class RegeneratedReport:
    report: ReportDocument
    reference: ReportRef
    groups: int
    decisions: tuple[TriageDecision, ...]
    feedback_applied: int
    evidence_ids: int


def rebuild_groups(session: Session, scan_id: UUID, *, max_findings: int = MAX_FINDINGS,
                   max_observations: int = MAX_OBSERVATIONS) -> list[FindingGroup]:
    """Reconstruct groups from stored observations; fail closed on any gap."""
    if isinstance(max_findings, bool) or not 1 <= max_findings <= MAX_FINDINGS:
        raise ValueError(f"max_findings must be between 1 and {MAX_FINDINGS}")
    if isinstance(max_observations, bool) or not 1 <= max_observations <= MAX_OBSERVATIONS:
        raise ValueError(f"max_observations must be between 1 and {MAX_OBSERVATIONS}")
    rows = list(session.scalars(select(Finding).where(Finding.scan_id == scan_id)
                                .order_by(Finding.fingerprint).limit(max_findings + 1)))
    if len(rows) > max_findings:
        raise ReportRebuildError("too many findings to rebuild a report")
    groups: list[FindingGroup] = []
    for row in rows:
        if not row.observation_history_complete:
            raise ReportRebuildError("a finding has an incomplete observation history")
        observations = list(session.scalars(
            select(FindingObservation).where(FindingObservation.finding_id == row.id)
            .order_by(FindingObservation.created_at, FindingObservation.id)
            .limit(max_observations + 1)))
        if not observations or len(observations) > max_observations:
            raise ReportRebuildError("a finding has no usable observations")
        location = row.location
        if (not isinstance(location, dict) or not isinstance(location.get("target_id"), str)
                or not isinstance(location.get("location"), str)):
            raise ReportRebuildError("a finding location is incomplete")
        candidates = [FindingCandidate(
            title=item.title, vulnerability_type=row.vuln_type,
            target_id=location["target_id"], location=location["location"],
            source_tool=item.source_tool, status=item.source_status_claim,
            severity=item.severity, evidence_refs=list(item.evidence_refs))
            for item in observations]
        found = group_findings(candidates)
        if len(found) != 1 or found[0].fingerprint != row.fingerprint:
            raise ReportRebuildError("stored observations do not match the finding identity")
        groups.append(found[0])
    return groups


class ReportRegenerator:
    def __init__(self, session: Session, report_store: ReportStore,
                 *, max_findings: int = MAX_FINDINGS, max_observations: int = MAX_OBSERVATIONS):
        if not isinstance(report_store, ReportStore):
            raise ValueError("a report store is required")
        self._session = session
        self._store = report_store
        self._max_findings = max_findings
        self._max_observations = max_observations

    def regenerate(self, scan_id: UUID, *, report_format: str = "markdown", actor: str = "cli",
                   now: datetime | None = None, validation_context: dict | None = None) -> RegeneratedReport:
        if report_format not in {"markdown", "json"}:
            raise ValueError("unsupported report format")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("actor is required")
        generated_at = now or datetime.now(timezone.utc)
        if generated_at.utcoffset() is None:
            raise ValueError("report timestamp must be timezone-aware")
        scan = self._session.get(Scan, scan_id)
        if scan is None:
            raise ValueError("scan is not stored")
        groups = rebuild_groups(self._session, scan_id, max_findings=self._max_findings,
                                max_observations=self._max_observations)
        decisions = [triage_group(group) for group in groups]
        latest = FeedbackRepository(self._session).latest_for_scan(scan_id)
        feedback = tuple(FeedbackSummary(
            fingerprint=fingerprint, verdict=row.verdict, actor=row.actor, note=row.note,
            recorded_at=_aware(row.created_at), revision=row.revision)
            for fingerprint, row in sorted(latest.items()))
        evidence_ids, truncated = _evidence_ids(self._session, scan_id,
                                                {group.fingerprint for group in groups})
        report_input = ReportInput(
            scan_id=str(scan.id), project_id=str(scan.project_id), mode="analysis",
            groups=groups, generated_at=generated_at,
            decisions=[DecisionSummary(fingerprint=item.fingerprint, severity=item.severity,
                                       confidence=item.confidence,
                                       requires_validation=item.requires_validation,
                                       rationale=item.rationale) for item in decisions],
            feedback=feedback, evidence_record_ids=evidence_ids,
            evidence_snapshot="available", evidence_snapshot_truncated=truncated,
            limitations=["报告由已存储的发现与观察重建；未重新执行扫描或验证",
                         "人工判定为操作者记录，不是系统的漏洞验证结论",
                         "此前报告中的模型复核内容不会重建"])
        document = generate(report_input, format=report_format)
        if validation_context is None and self._session.scalar(select(Evidence.id).join(Finding,Evidence.finding_id==Finding.id)
                .where(Finding.scan_id==scan_id,Evidence.evidence_type=='validation_result').limit(1)) is not None:
            validation_context={'interpretation':'stored_bounded_probe_observations_not_exploitability_proof'}
        from vulnmind.config import Settings
        settings=Settings()
        from vulnmind.reports.signing import resolve_signing_key, sign_configured
        from vulnmind.analysis.attestation import verified_for_scan
        attestations=[]
        if any((row.location or {}).get('attestation_id') for row in self._session.scalars(select(Finding).where(Finding.scan_id==scan_id))):
            key,_=resolve_signing_key(key=settings.report_signing_key,key_file=settings.report_signing_key_file)
            attestations=verified_for_scan(self._session,scan_id,settings.evidence_root,key)
        if attestations or validation_context is not None:
            import json, hashlib
            if report_format=='json':
                data=json.loads(document.content)
                data['attestations']=attestations
                data['attested_counts']={state:sum(a['verdict']==state for a in attestations) for state in ('confirmed','not_reproduced')}
                if validation_context is not None:
                    data['validation_performed']=True
                    data['validation_context']=validation_context
                content=json.dumps(data,ensure_ascii=False,indent=2,sort_keys=True)
            else:
                content=document.content+'\n\n## 人工证据确认（本机签名）\n'+ '\n'.join(f"- {a['fingerprint']}: {a['verdict']} ({a['attestation_id']})" for a in attestations)+'\n'
            document=document.model_copy(update={'content':content,'sha256':hashlib.sha256(content.encode()).hexdigest()})
        reference = self._store.put(document.content, format=report_format)
        sign_configured(self._store,reference.uri)
        ReportRepository(self._session).create(scan.id, format=report_format,
                                               storage_uri=reference.uri)
        return RegeneratedReport(report=document, reference=reference, groups=len(groups),
                                 decisions=tuple(decisions), feedback_applied=len(feedback),
                                 evidence_ids=sum(len(values) for values in evidence_ids.values()))


def _evidence_ids(session: Session, scan_id: UUID,
                  fingerprints: set[str]) -> tuple[dict[str, list[UUID]], bool]:
    rows = session.execute(select(Finding.fingerprint, Evidence.id)
                           .join(Evidence, Evidence.finding_id == Finding.id)
                           .where(Finding.scan_id == scan_id)
                           .order_by(Finding.fingerprint, Evidence.id)
                           .limit(MAX_SNAPSHOT_IDS + 1)).all()
    truncated = len(rows) > MAX_SNAPSHOT_IDS
    grouped: dict[str, list[UUID]] = {}
    for fingerprint, evidence_id in rows[:MAX_SNAPSHOT_IDS]:
        if fingerprint in fingerprints:
            grouped.setdefault(fingerprint, []).append(evidence_id)
    return grouped, truncated


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
