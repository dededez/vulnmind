"""Deterministic triage: severity, confidence and validation need per group.

The rules are heuristic and deliberately conservative. They never turn an
unverified tool result into a confirmed finding, and every number is explained
in ``rationale`` so a later reviewer can see why a score was chosen.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from vulnmind.findings import FindingGroup

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")
_BASE_CONFIDENCE = {"confirmed": 0.9, "not_reproduced": 0.8, "insufficient_evidence": 0.4, "unverified": 0.3}


class TriageDecision(BaseModel):
    model_config = ConfigDict(frozen=True)
    fingerprint: str
    status: str
    severity: str
    confidence: float = Field(ge=0, le=1)
    requires_validation: bool
    rationale: tuple[str, ...]


def triage_groups(groups: list[FindingGroup]) -> list[TriageDecision]:
    return [_triage_group(group) for group in groups]


def triage_group(group: FindingGroup) -> TriageDecision:
    return _triage_group(group)


def _triage_group(group: FindingGroup) -> TriageDecision:
    group = FindingGroup.model_validate(group.model_dump())
    distinct = {candidate.status for candidate in group.candidates}
    disagree = len(distinct) > 1
    reported_status = next(iter(distinct)) if not disagree else "unverified"
    # An evidence reference alone does not prove either existence or validation.
    # A trusted validation/attestation path is not implemented yet.
    status = "unverified" if reported_status in {"confirmed", "not_reproduced"} else reported_status
    rationale = ["candidates disagree; triage keeps the group unverified"] if disagree else [
        f"reported status={reported_status} from {len(group.candidates)} candidate(s)"]
    if status != reported_status:
        rationale.append("reported validation status is not independently verified")

    declared = [candidate.severity for candidate in group.candidates if candidate.severity]
    severity = min(declared, key=_SEVERITY_ORDER.index) if declared else "unknown"
    rationale.append(f"severity={severity} (most severe declared value)")

    confidence = _BASE_CONFIDENCE[status]
    rationale.append(f"base confidence {confidence:.2f} for {status}")
    rationale.append("heuristic ranking score, not a calibrated probability")
    if len(group.source_tools) > 1:
        rationale.append("multiple tool labels; independence is not established")
    if group.evidence_refs:
        rationale.append("evidence references are not independently verified")
    if disagree:
        confidence = min(confidence, 0.5)
        rationale.append("capped at 0.50 while candidates disagree")

    requires_validation = status in {"unverified", "insufficient_evidence"}
    rationale.append("validation required" if requires_validation else "validation recorded for this group")
    return TriageDecision(fingerprint=group.fingerprint, status=status, severity=severity,
                          confidence=round(confidence, 2), requires_validation=requires_validation,
                          rationale=tuple(rationale))
