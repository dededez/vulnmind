"""Reciprocal-rank fusion, independent of any specific retrieval backend."""
from collections import defaultdict
from dataclasses import dataclass


@dataclass(frozen=True)
class FusedResult:
    chunk_id: str
    score: float
    ranks: dict[str, int]


def reciprocal_rank_fusion(rankings: dict[str, list[str]], *, k: int = 60, limit: int | None = None) -> list[FusedResult]:
    if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= 1_000_000:
        raise ValueError("k must be an integer between 1 and 1000000")
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0):
        raise ValueError("limit must be a positive integer")
    if not rankings or any(not isinstance(name, str) or not name.strip() for name in rankings):
        raise ValueError("named rankings are required")
    scores: dict[str, float] = defaultdict(float)
    ranks: dict[str, dict[str, int]] = defaultdict(dict)
    # Stable source ordering avoids tiny order-dependent floating point differences.
    for source in sorted(rankings):
        seen = set()
        for rank, chunk_id in enumerate(rankings[source], start=1):
            if not isinstance(chunk_id, str) or not chunk_id.strip():
                raise ValueError("chunk IDs must be nonblank strings")
            if chunk_id in seen:
                continue
            seen.add(chunk_id)
            scores[chunk_id] += 1 / (k + rank)
            ranks[chunk_id][source] = rank
    ordered = sorted(scores, key=lambda chunk_id: (-scores[chunk_id], chunk_id))
    if limit is not None:
        ordered = ordered[:limit]
    return [FusedResult(chunk_id=chunk_id, score=scores[chunk_id], ranks=dict(ranks[chunk_id])) for chunk_id in ordered]
