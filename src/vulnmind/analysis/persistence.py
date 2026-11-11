"""Persist grouped analysis results into the findings table.

One row per fingerprint per scan. The writer never creates evidence rows: a
reference without stored content is not evidence, and inventing one would make
the report claim proof that does not exist. Disagreeing candidates keep the
``unverified`` status instead of being resolved silently.
"""
from __future__ import annotations

import hashlib
import json
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from vulnmind.analysis.repository import RepositoryAnalysis
from vulnmind.analysis.triage import TriageDecision, triage_group
from vulnmind.findings import FindingCandidate, FindingGroup, group_findings
from vulnmind.persistence.models import Finding, FindingObservation

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")


class StoredFindings(BaseModel):
    model_config = ConfigDict(frozen=True)
    stored: list[UUID]
    duplicated: int
    evidence_pending: int
    observations_stored: int = 0


class FindingWriter:
    def __init__(self, session: Session):
        self.session = session

    def store(self, scan_id: UUID, analysis: RepositoryAnalysis) -> StoredFindings:
        return self.store_groups(scan_id, analysis.groups)

    def store_groups(self, scan_id: UUID, groups: list[FindingGroup]) -> StoredFindings:
        dialect = self.session.get_bind().dialect.name
        if dialect not in {"postgresql", "sqlite"}:
            raise ValueError("finding persistence requires PostgreSQL or SQLite")
        insert = pg_insert if dialect == "postgresql" else sqlite_insert
        stored: list[UUID] = []
        duplicated = 0
        pending = 0
        observations_stored = 0
        for group in groups:
            finding_id = uuid4()
            representative = _representative(group)
            decision = triage_group(group)
            statement = insert(Finding).values(
                id=finding_id, scan_id=scan_id, fingerprint=group.fingerprint,
                title=representative.title, vuln_type=representative.vulnerability_type,
                severity=decision.severity, confidence=f"{decision.confidence:.2f}", status=decision.status,
                # Fail closed if a caller catches a later write error and commits.
                needs_retriage=True,
                observation_history_complete=False,
                location={"target_id": representative.target_id, "location": representative.location,
                          "candidates": len(group.candidates), "source_tools": group.source_tools,
                          "source_tools_revision": 0,
                          "requires_validation": decision.requires_validation}
            ).on_conflict_do_nothing(index_elements=["scan_id", "fingerprint"]).returning(Finding.id)
            inserted = self.session.execute(statement).scalar_one_or_none()
            if inserted is None:
                duplicated += 1
                resolved_id = self.session.scalar(select(Finding.id).where(Finding.scan_id == scan_id, Finding.fingerprint == group.fingerprint))
                if resolved_id is None:
                    raise RuntimeError("conflicting finding could not be resolved")
            else:
                stored.append(inserted)
                resolved_id = inserted
            claims = []
            for candidate in group.candidates:
                claim = {"source_tool": candidate.source_tool, "title": candidate.title,
                         "source_status_claim": candidate.status, "severity": candidate.severity,
                         "evidence_refs": candidate.evidence_refs}
                serialized = json.dumps(claim, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                observation_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
                claims.append((observation_hash, claim))
            restore_complete_at_revision = None
            if inserted is None:
                # Mark stale before writing any new observation, so even a caller
                # who catches a later error and commits cannot expose a fresh-looking
                # summary alongside a partially written batch.
                hashes = list(dict.fromkeys(item[0] for item in claims))
                existing_hashes = set()
                for start in range(0, len(hashes), 500):
                    existing_hashes.update(self.session.scalars(select(FindingObservation.observation_hash).where(
                        FindingObservation.finding_id == resolved_id,
                        FindingObservation.observation_hash.in_(hashes[start:start + 500]))))
                if any(value not in existing_hashes for value in hashes):
                    locked = self.session.execute(select(Finding.observation_history_complete, Finding.observation_revision)
                                                  .where(Finding.id == resolved_id).with_for_update()).one()
                    prior_complete, prior_revision = locked
                    marked = self.session.execute(update(Finding).where(Finding.id == resolved_id,
                        Finding.observation_revision == prior_revision).values(needs_retriage=True,
                        observation_history_complete=False, observation_revision=prior_revision + 1))
                    if marked.rowcount != 1:
                        raise RuntimeError("finding changed while recording observations")
                    if prior_complete:
                        restore_complete_at_revision = prior_revision + 1
            for observation_hash, claim in claims:
                statement = insert(FindingObservation).values(id=uuid4(), finding_id=resolved_id,
                    observation_hash=observation_hash, **claim).on_conflict_do_nothing(
                        index_elements=["finding_id", "observation_hash"]).returning(FindingObservation.id)
                if self.session.execute(statement).scalar_one_or_none() is not None:
                    observations_stored += 1
            if inserted is not None:
                # Only a fully written initial batch establishes complete history.
                finalization = self.session.execute(update(Finding).where(Finding.id == resolved_id,
                    Finding.observation_revision == 0, Finding.observation_history_complete.is_(False)).values(
                        needs_retriage=False, observation_history_complete=True))
                if finalization.rowcount != 1:
                    raise RuntimeError("initial observation history could not be finalized")
            elif restore_complete_at_revision is not None:
                finalization = self.session.execute(update(Finding).where(Finding.id == resolved_id,
                    Finding.observation_revision == restore_complete_at_revision,
                    Finding.observation_history_complete.is_(False)).values(observation_history_complete=True))
                if finalization.rowcount != 1:
                    raise RuntimeError("observation history could not be finalized")
            pending += len(group.evidence_refs)
        return StoredFindings(stored=stored, duplicated=duplicated, evidence_pending=pending,
                              observations_stored=observations_stored)

    def retriage(self, finding_id: UUID, *, max_observations: int = 5000) -> TriageDecision:
        """Rebuild a stale summary with optimistic protection against new claims.

        The caller owns the transaction. Claims and references remain unverified;
        this method never creates evidence or performs vulnerability validation.
        """
        if not 1 <= max_observations <= 5000:
            raise ValueError("observation limit must be between 1 and 5000")
        row = self.session.get(Finding, finding_id, populate_existing=True)
        if row is None:
            raise ValueError("finding not found")
        if not row.needs_retriage:
            raise ValueError("finding is not marked for retriage")
        if not row.observation_history_complete:
            raise ValueError("finding observation history is incomplete; verified backfill is required")
        revision = row.observation_revision
        observations = list(self.session.scalars(select(FindingObservation).where(
            FindingObservation.finding_id == finding_id).order_by(FindingObservation.created_at, FindingObservation.id)
            .limit(max_observations + 1)))
        if not observations or len(observations) > max_observations:
            raise ValueError("observations are missing or exceed the review limit")
        if not isinstance(row.location, dict) or not isinstance(row.location.get("target_id"), str) or not isinstance(row.location.get("location"), str):
            raise ValueError("finding location is incomplete")
        candidates = [FindingCandidate(title=item.title, vulnerability_type=row.vuln_type,
                         target_id=row.location["target_id"], location=row.location["location"],
                         source_tool=item.source_tool, status=item.source_status_claim,
                         severity=item.severity, evidence_refs=item.evidence_refs) for item in observations]
        groups = group_findings(candidates)
        if len(groups) != 1 or groups[0].fingerprint != row.fingerprint:
            raise ValueError("stored observations do not match finding identity")
        group = groups[0]
        decision = triage_group(group)
        location = {**row.location, "candidates": len(candidates), "source_tools": group.source_tools,
                    "source_tools_revision": revision, "requires_validation": decision.requires_validation}
        location.pop("source_tools_complete", None)
        result = self.session.execute(update(Finding).where(
            Finding.id == finding_id, Finding.needs_retriage.is_(True), Finding.observation_revision == revision,
            Finding.observation_history_complete.is_(True)
        ).values(status=decision.status, severity=decision.severity, confidence=f"{decision.confidence:.2f}",
                 location=location, needs_retriage=False).execution_options(synchronize_session="fetch"))
        if result.rowcount != 1:
            raise RuntimeError("finding changed during retriage; retry in a new transaction")
        return decision


def _representative(group: FindingGroup) -> FindingCandidate:
    return group.candidates[0]
