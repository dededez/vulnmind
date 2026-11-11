"""Model-assisted selection of non-destructive validation probes.

The model only chooses among probes that ``plan_probes`` already derived for
the authorized endpoints; it cannot introduce a URL, parameter or payload. Its
selection is advisory: nothing is sent, and the operator still has to approve
the resulting plan (bound to its digest) before any request.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from vulnmind.agents.form_candidates import MAX_CANDIDATE_URLS
from vulnmind.agents.prompts import WEB_VALIDATOR
from vulnmind.agents.runtime import AgentBudgetError, AgentError, AgentRuntime, AgentSpec
from vulnmind.analysis.validation import MAX_PROBES, Probe, plan_digest, plan_probes_with_coverage
from vulnmind.context.builder import ContextItem

MAX_SELECTIONS = 10
MAX_SUMMARY_CHARS = 1000
MAX_REASON_CHARS = 300
_ERROR_TEXT = "model validation plan was unavailable"


class ProbeSelection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    index: int = Field(strict=True, ge=0)
    reason: str = Field(min_length=1, max_length=4000)


class ValidationPlanDraft(BaseModel):
    """Output schema requested from the model."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    summary: str = Field(min_length=1, max_length=4000)
    selections: list[ProbeSelection] = Field(default_factory=list, max_length=MAX_PROBES)


class SelectedProbe(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    probe: Probe
    reason: str = Field(min_length=1, max_length=MAX_REASON_CHARS)


class ValidationPlan(BaseModel):
    model_config = ConfigDict(frozen=True)
    status: Literal["completed", "skipped", "failed"]
    summary: str = Field(default="", max_length=MAX_SUMMARY_CHARS)
    selected: tuple[SelectedProbe, ...] = ()
    candidates: int = Field(default=0, ge=0)
    candidates_truncated: bool = False
    ignored: int = Field(default=0, ge=0)
    attempts: int = Field(default=0, ge=0, le=3)
    error: str | None = Field(default=None, max_length=120)
    digest: str | None = Field(default=None, max_length=64)


def _clean(value: str, limit: int) -> str:
    return " ".join(str(value).split())[:limit]


def select_probes(runtime: AgentRuntime, *, actor: str, urls: Sequence[str],
                  max_selections: int = MAX_SELECTIONS,
                  spec: AgentSpec = WEB_VALIDATOR) -> ValidationPlan:
    """Ask the model to rank a deterministic candidate set; never executes."""
    if not isinstance(runtime, AgentRuntime):
        raise ValueError("an AgentRuntime is required")
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("actor is required")
    if (isinstance(urls, (str, bytes)) or not isinstance(urls, Sequence)
            or len(urls) > MAX_CANDIDATE_URLS):
        raise ValueError("validation planning accepts at most 2000 endpoint URLs")
    if isinstance(max_selections, bool) or not isinstance(max_selections, int) or not 1 <= max_selections <= MAX_SELECTIONS:
        raise ValueError(f"max_selections must be between 1 and {MAX_SELECTIONS}")
    candidates, truncated = plan_probes_with_coverage(urls, max_probes=MAX_PROBES)
    if not candidates:
        return ValidationPlan(status="skipped")
    context = [ContextItem(ref=f"probe:{index}", kind="execution",
                           text=f"index: {index}\nkind: {probe.kind}")
               for index, probe in enumerate(candidates)]
    task = ("\n".join([
        f"Select at most {min(max_selections, len(candidates))} of {len(candidates)} candidate probes.",
        "Return one entry per selected probe with its index and a one-sentence reason.",
        "Select only indexes in the candidate list. URLs and parameter names are withheld.",
        "Selection does not send requests and does not prove any vulnerability.",
    ]))
    try:
        output = runtime.run(spec, task=task, context=context, schema=ValidationPlanDraft, actor=actor)
    except (AgentError, AgentBudgetError):
        return ValidationPlan(status="failed", error=_ERROR_TEXT, candidates=len(candidates),
                              candidates_truncated=truncated)
    selected: list[SelectedProbe] = []
    seen: set[int] = set()
    ignored = 0
    for item in output.data.selections:
        if item.index >= len(candidates) or item.index in seen:
            ignored += 1
            continue
        seen.add(item.index)
        selected.append(SelectedProbe(probe=candidates[item.index],
                                      reason=_clean(item.reason, MAX_REASON_CHARS)))
        if len(selected) >= max_selections:
            break
    digest = plan_digest([item.probe for item in selected]) if selected else None
    return ValidationPlan(status="completed", summary=_clean(output.data.summary, MAX_SUMMARY_CHARS),
                          selected=tuple(selected), candidates=len(candidates), ignored=ignored,
                          candidates_truncated=truncated, attempts=output.attempts, digest=digest)
