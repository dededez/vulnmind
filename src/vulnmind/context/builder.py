"""Deterministic context selection; budget accounting is not a trust boundary."""
from collections import defaultdict
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vulnmind.context.tokens import estimate_tokens


ContextKind = Literal["system", "project", "task", "execution", "skill", "rag", "memory", "evidence"]
PRIORITY = {"system": 0, "task": 1, "evidence": 2, "skill": 3, "project": 4, "execution": 5, "rag": 6, "memory": 7}


class ContextItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    ref: str = Field(min_length=1)
    kind: ContextKind
    text: str = Field(min_length=1)
    relevance: float = Field(default=0, ge=0, le=1, allow_inf_nan=False)
    required: bool = False
    # Optional finer budget bucket; defaults to ``kind`` so old callers are unchanged.
    budget_group: str | None = Field(default=None, min_length=1, max_length=64)

    @model_validator(mode="after")
    def nonblank(self):
        if not self.ref.strip() or not self.text.strip():
            raise ValueError("context reference and text must not be blank")
        if self.budget_group is not None and not self.budget_group.strip():
            raise ValueError("context budget group must not be blank")
        return self


class ContextBudget(BaseModel):
    total: int = Field(gt=0)
    by_kind: dict[ContextKind, int] = Field(default_factory=dict)
    # Explicit unit keeps the historical byte budget intact for existing callers.
    unit: Literal["bytes", "tokens"] = "bytes"
    by_group: dict[str, int] = Field(default_factory=dict)

    @model_validator(mode="after")
    def positive_kind_budgets(self):
        if any(value < 0 for value in self.by_kind.values()):
            raise ValueError("kind budgets cannot be negative")
        if any(not name.strip() or value < 0 for name, value in self.by_group.items()):
            raise ValueError("group budgets must use nonblank names and nonnegative values")
        return self


class ContextOverflow(ValueError):
    pass


def byte_estimate(text: str) -> int:
    """Simple byte count, not a guarantee for every model/tokenizer."""
    return len(text.encode("utf-8"))


def build_context(items: list[ContextItem], budget: ContextBudget,
                  estimate: Callable[[str], int] | None = None) -> tuple[list[ContextItem], dict]:
    items = [ContextItem.model_validate(item.model_dump()) for item in items]
    budget = ContextBudget.model_validate(budget.model_dump())
    if estimate is None:
        estimate = estimate_tokens if budget.unit == "tokens" else byte_estimate
    if len({item.ref for item in items}) != len(items):
        raise ValueError("context references must be unique")
    if not {"system", "task"}.issubset({item.kind for item in items}):
        raise ValueError("system and task contexts are required")
    # Rank mandatory entries first, then use policy priorities and relevance.
    ordered = sorted(enumerate(items), key=lambda pair: (
        0 if pair[1].required or pair[1].kind in {"system", "task"} else 1,
        PRIORITY[pair[1].kind], -pair[1].relevance, pair[0]))
    chosen = []
    manifest = []
    used = 0
    used_by_kind: dict[str, int] = defaultdict(int)
    used_by_group: dict[str, int] = defaultdict(int)
    for _, item in ordered:
        cost = estimate(item.text)
        if not isinstance(cost, int) or isinstance(cost, bool) or cost <= 0:
            raise ValueError("token estimator must return a positive integer")
        group = item.budget_group or item.kind
        kind_limit = budget.by_kind.get(item.kind, budget.total)
        group_limit = budget.by_group.get(group, budget.total)
        fits = (used + cost <= budget.total
                and used_by_kind[item.kind] + cost <= kind_limit
                and used_by_group[group] + cost <= group_limit)
        if not fits and (item.required or item.kind in {"system", "task"}):
            raise ContextOverflow("required context exceeds estimated budget")
        if fits:
            chosen.append(item)
            used += cost
            used_by_kind[item.kind] += cost
            used_by_group[group] += cost
        manifest.append({"ref": item.ref, "kind": item.kind, "group": group,
                         "estimated_tokens": cost, "selected": fits,
                         "reason": "within_budget" if fits else "budget_exceeded"})
    return chosen, {"budget": budget.total, "unit": budget.unit, "estimated_tokens": used,
                    "by_group": dict(used_by_group), "items": manifest}
