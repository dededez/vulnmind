"""Deterministic offline retrieval metrics for caller-supplied labels.

No retriever is called and no benchmark labels are invented. Results measure
only agreement with the supplied relevance judgments at the requested cutoff.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_CASES = 1_000
MAX_IDS = 1_000


class RetrievalCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    case_id: str = Field(min_length=1, max_length=255)
    relevant_ids: tuple[str, ...] = Field(min_length=1, max_length=MAX_IDS)
    retrieved_ids: tuple[str, ...] = Field(max_length=MAX_IDS)

    @field_validator("case_id")
    @classmethod
    def valid_case_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("case ID must not be blank")
        return value

    @field_validator("relevant_ids", "retrieved_ids")
    @classmethod
    def valid_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.strip() or len(item) > 255 for item in value) or len(set(value)) != len(value):
            raise ValueError("chunk IDs must be distinct, nonblank and at most 255 characters")
        return value


class CaseMetrics(BaseModel):
    model_config = ConfigDict(frozen=True)
    case_id: str
    relevant_count: int
    retrieved_count: int
    hits: int
    recall: float
    reciprocal_rank: float


class RetrievalMetrics(BaseModel):
    model_config = ConfigDict(frozen=True)
    cutoff: int
    cases: tuple[CaseMetrics, ...]
    hit_rate: float
    mean_recall: float
    mean_reciprocal_rank: float


def evaluate_retrieval(cases: list[RetrievalCase], *, cutoff: int = 10) -> RetrievalMetrics:
    if isinstance(cutoff, bool) or not isinstance(cutoff, int) or not 1 <= cutoff <= 100:
        raise ValueError("cutoff must be an integer between 1 and 100")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("evaluation requires 1 to 1000 labeled cases")
    validated = [RetrievalCase.model_validate(case.model_dump()) if isinstance(case, RetrievalCase)
                 else RetrievalCase.model_validate(case) for case in cases]
    if len({case.case_id for case in validated}) != len(validated):
        raise ValueError("case IDs must be unique")
    results = []
    for case in validated:
        relevant = set(case.relevant_ids)
        retrieved = case.retrieved_ids[:cutoff]
        hits = sum(item in relevant for item in retrieved)
        first = next((index for index, item in enumerate(retrieved, start=1) if item in relevant), None)
        results.append(CaseMetrics(case_id=case.case_id, relevant_count=len(relevant),
                                   retrieved_count=len(retrieved), hits=hits, recall=hits / len(relevant),
                                   reciprocal_rank=1 / first if first else 0.0))
    count = len(results)
    return RetrievalMetrics(cutoff=cutoff, cases=tuple(results),
                            hit_rate=sum(item.hits > 0 for item in results) / count,
                            mean_recall=sum(item.recall for item in results) / count,
                            mean_reciprocal_rank=sum(item.reciprocal_rank for item in results) / count)
