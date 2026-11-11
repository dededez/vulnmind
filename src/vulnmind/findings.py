"""Evidence-aware finding contracts and conservative grouping; no detection."""
import hashlib
import json
from collections import defaultdict
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class FindingCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1)
    vulnerability_type: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    location: str = Field(min_length=1)
    source_tool: str = Field(min_length=1, max_length=255)
    status: Literal["unverified", "confirmed", "not_reproduced", "insufficient_evidence"] = "unverified"
    severity: Literal["critical", "high", "medium", "low", "info", "unknown"] | None = None
    evidence_refs: list[str] = Field(default_factory=list)

    @field_validator("title", "vulnerability_type", "target_id", "location", "source_tool")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("finding fields must not be blank")
        return value

    @model_validator(mode="after")
    def evidence_required_for_verified_outcomes(self):
        if any(not ref.strip() for ref in self.evidence_refs):
            raise ValueError("evidence references must not be blank")
        if self.status in {"confirmed", "not_reproduced"} and not self.evidence_refs:
            raise ValueError("verified outcomes require evidence references")
        return self

    def fingerprint(self) -> str:
        # Exact target/location identity; no heuristic matching across code paths.
        identity = [self.vulnerability_type.strip().casefold(), self.target_id, self.location]
        return hashlib.sha256(json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


class FindingGroup(BaseModel):
    fingerprint: str
    candidates: list[FindingCandidate] = Field(min_length=1)
    evidence_refs: list[str]
    source_tools: list[str]

    @model_validator(mode="after")
    def consistent_with_candidates(self):
        if any(candidate.fingerprint() != self.fingerprint for candidate in self.candidates):
            raise ValueError("finding group fingerprint does not match candidates")
        refs = list(dict.fromkeys(ref for candidate in self.candidates for ref in candidate.evidence_refs))
        tools = list(dict.fromkeys(candidate.source_tool for candidate in self.candidates))
        if self.evidence_refs != refs or self.source_tools != tools:
            raise ValueError("finding group provenance does not match candidates")
        return self


def group_findings(candidates: list[FindingCandidate]) -> list[FindingGroup]:
    """Group exact identities without inventing an overall status or severity."""
    grouped: dict[str, list[FindingCandidate]] = defaultdict(list)
    for candidate in candidates:
        grouped[candidate.fingerprint()].append(candidate)
    return [FindingGroup(fingerprint=fingerprint, candidates=items,
                         evidence_refs=list(dict.fromkeys(ref for item in items for ref in item.evidence_refs)),
                         source_tools=list(dict.fromkeys(item.source_tool for item in items)))
            for fingerprint, items in grouped.items()]
