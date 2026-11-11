"""Advisory model review of triage decisions.

The review is opt-in and never changes deterministic severity, confidence or
validation requirements. Model output is treated as untrusted data: unknown
fingerprints are dropped, duplicates are ignored, and any ``confirmed`` verdict
is demoted because evidence contents are not supplied. Reports label the whole
block as a model opinion, not verification.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vulnmind.agents.model import ModelUsage
from vulnmind.agents.prompts import TRIAGE_REVIEWER
from vulnmind.agents.runtime import AgentBudgetError, AgentError, AgentRuntime, AgentSpec
from vulnmind.context.builder import ContextItem
from vulnmind.findings import FindingGroup

MAX_REVIEW_GROUPS = 25
MAX_RATIONALE_CHARS = 500
MAX_SUMMARY_CHARS = 1000
MAX_LOCATIONS = 3
_ERROR_TEXT = "model review was unavailable"
_SAFE_VULNERABILITY_TYPES = frozenset({
    "secret", "dependency_vulnerability", "tls_certificate_verification_disabled",
    "sqli", "xss", "ssrf", "missing_header", "technology_disclosure", "cookie_attribute_missing",
    "missing_content_security_policy", "missing_x_content_type_options", "missing_x_frame_options",
    "missing_referrer_policy", "missing_permissions_policy", "missing_strict_transport_security",
})

Verdict = Literal["confirmed", "likely", "false_positive"]


def _clean(value: str, limit: int) -> str:
    return " ".join(str(value).split())[:limit]


class ReviewItem(BaseModel):
    """One model opinion; validation is permissive so a usable reply is not lost."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    fingerprint: str = Field(min_length=1, max_length=128)
    verdict: Verdict
    rationale: str = Field(min_length=1, max_length=4000)

    @field_validator("fingerprint", "rationale")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("review fields must not be blank")
        return value


class TriageReview(BaseModel):
    """Output schema requested from the model."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    summary: str = Field(min_length=1, max_length=4000)
    items: list[ReviewItem] = Field(default_factory=list, max_length=200)


class ReviewedFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    fingerprint: str = Field(min_length=1, max_length=128)
    verdict: Verdict
    rationale: str = Field(min_length=1, max_length=MAX_RATIONALE_CHARS)
    note: str | None = Field(default=None, max_length=300)


class AgentReview(BaseModel):
    """Outcome of one advisory review; failures never abort the scan."""

    model_config = ConfigDict(frozen=True)
    status: Literal["completed", "failed", "skipped"]
    summary: str = Field(default="", max_length=MAX_SUMMARY_CHARS)
    items: tuple[ReviewedFinding, ...] = ()
    ignored: int = Field(default=0, ge=0)
    attempts: int = Field(default=0, ge=0, le=3)
    usage: ModelUsage | None = None
    error: str | None = Field(default=None, max_length=120)
    total_groups: int = Field(default=0, ge=0)
    selected_groups: int = Field(default=0, ge=0)
    omitted_groups: int = Field(default=0, ge=0)
    groups_without_verdict: int = Field(default=0, ge=0)


def _context_item(index: int, group: FindingGroup) -> ContextItem:
    first = group.candidates[0]
    # Rule IDs are supplied by scanners and may contain sensitive input or
    # instructions. Only fixed, known labels leave this process.
    vulnerability_type = first.vulnerability_type if first.vulnerability_type in _SAFE_VULNERABILITY_TYPES else "other"
    text = "\n".join([
        f"fingerprint: {group.fingerprint}",
        f"vulnerability_type: {vulnerability_type}",
        f"reported_status: {', '.join(sorted({candidate.status for candidate in group.candidates}))}",
        f"declared_severity: {', '.join(sorted({str(candidate.severity) for candidate in group.candidates}))}",
        f"evidence_reference_count: {len(group.evidence_refs)}",
    ])
    return ContextItem(ref=f"finding:{index}", kind="execution", text=text)


def _task(selected: int, truncated: bool) -> str:
    parts = [f"Review {selected} candidate finding(s) from an automated scan.",
             "Return one entry per fingerprint, plus a short overall summary.",
             "Metadata only is supplied: no source code, responses or exploit output.",
             "Evidence contents are not supplied, so never use confirmed; use likely instead.",
             "Never invent evidence, files or vulnerabilities."]
    if truncated:
        parts.append("Only the first batch is shown; do not speculate about the rest.")
    return " ".join(parts)


def review_findings(runtime: AgentRuntime, *, actor: str, groups: Sequence[FindingGroup],
                    spec: AgentSpec = TRIAGE_REVIEWER,
                    max_groups: int = MAX_REVIEW_GROUPS, advisory_context: str | None = None) -> AgentReview:
    """Run one review call; failures and unusable entries are reported, not raised."""
    if not isinstance(runtime, AgentRuntime):
        raise ValueError("an AgentRuntime is required")
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("actor is required")
    if isinstance(max_groups, bool) or not isinstance(max_groups, int) or not 1 <= max_groups <= MAX_REVIEW_GROUPS:
        raise ValueError("max_groups is out of range")
    if not all(isinstance(group, FindingGroup) for group in groups):
        raise ValueError("review input must contain finding groups")
    selected = [FindingGroup.model_validate(group.model_dump()) for group in list(groups)[:max_groups]]
    total, selected_count = len(groups), len(selected)
    counts = {"total_groups": total, "selected_groups": selected_count,
              "omitted_groups": total - selected_count}
    if not selected:
        return AgentReview(status="skipped")
    context = [_context_item(index, group) for index, group in enumerate(selected)]
    if advisory_context is not None:
        if not isinstance(advisory_context, str) or len(advisory_context) > 1500:
            raise ValueError("invalid advisory context")
        context.append(ContextItem(ref="agent:repository-analyst", kind="execution", text=advisory_context))
    try:
        output = runtime.run(spec, task=_task(len(selected), len(groups) > max_groups),
                             context=context, schema=TriageReview, actor=actor)
    except (AgentError, AgentBudgetError):
        return AgentReview(status="failed", error=_ERROR_TEXT, groups_without_verdict=selected_count, **counts)
    has_evidence = {group.fingerprint: bool(group.evidence_refs) for group in selected}
    known = set(has_evidence)
    items: list[ReviewedFinding] = []
    ignored = 0
    seen: set[str] = set()
    for item in output.data.items:
        if item.fingerprint not in known or item.fingerprint in seen:
            ignored += 1
            continue
        seen.add(item.fingerprint)
        verdict: Verdict = item.verdict
        note = None
        if verdict == "confirmed":
            verdict = "likely"
            note = "demoted: evidence contents were not provided for verification"
        items.append(ReviewedFinding(fingerprint=item.fingerprint, verdict=verdict,
                                     rationale=_clean(item.rationale, MAX_RATIONALE_CHARS),
                                     note=note))
    return AgentReview(status="completed", summary=_clean(output.data.summary, MAX_SUMMARY_CHARS),
                       items=tuple(items), ignored=ignored, attempts=output.attempts,
                       usage=output.usage, groups_without_verdict=selected_count - len(items), **counts)
