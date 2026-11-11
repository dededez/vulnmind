"""Attach stored evidence bytes to existing findings.

Analyzers produce locations and snippets; this helper turns a snippet into a
content-addressed evidence file plus a database row linked to the finding with
the same fingerprint. A fingerprint with no finding in this scan is reported,
never invented as a new finding.
"""
from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnmind.evidence.store import EvidenceStore
from vulnmind.persistence.models import Finding
from vulnmind.persistence.repositories import EvidenceRepository


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    fingerprint: str = Field(min_length=64, max_length=64)
    content: bytes = Field(min_length=1)
    evidence_type: str = Field(default="text", min_length=1, max_length=64)
    locator: str = Field(min_length=1, max_length=1000)

    @field_validator("fingerprint")
    @classmethod
    def hex_digest(cls, value: str) -> str:
        if any(character not in "0123456789abcdef" for character in value):
            raise ValueError("fingerprint must be a lowercase SHA-256 hex digest")
        return value

    @field_validator("locator")
    @classmethod
    def single_line(cls, value: str) -> str:
        if not value.strip() or "\n" in value or "\r" in value:
            raise ValueError("evidence locator must be a single non-blank line")
        return value


class EvidenceIngestResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    stored: int
    missing_findings: list[str]
    references: list[str]


def ingest_evidence(session: Session, store: EvidenceStore, *, scan_id: UUID,
                    items: Sequence[EvidenceItem]) -> EvidenceIngestResult:
    if not isinstance(store, EvidenceStore):
        raise ValueError("an evidence store is required")
    if not items:
        return EvidenceIngestResult(stored=0, missing_findings=[], references=[])
    from vulnmind.evidence.coordination import lock_evidence_transaction
    lock_evidence_transaction(session)
    repository = EvidenceRepository(session)
    stored = 0
    missing: list[str] = []
    references: list[str] = []
    for item in items:
        finding = session.scalar(select(Finding).where(Finding.scan_id == scan_id,
                                                       Finding.fingerprint == item.fingerprint))
        if finding is None:
            missing.append(item.fingerprint)
            continue
        reference = store.put(item.content, evidence_type=item.evidence_type)
        repository.create(finding.id, evidence_type=item.evidence_type, locator=item.locator,
                          content_ref=reference.uri, hash=reference.sha256)
        stored += 1
        references.append(reference.uri)
    return EvidenceIngestResult(stored=stored, missing_findings=missing, references=references)
