"""Dense-vector helpers shared by persistence and retrieval.

The dimension is a deployment decision: migrations 0009/0014 carry the schema
change, and this constant must match what the database actually stores. It
currently matches Qwen3-Embedding-0.6B (1024); changing the model again needs a
new migration plus a re-embed of every chunk.
"""
from __future__ import annotations

from collections.abc import Sequence

EMBEDDING_DIMENSIONS = 1024
MAX_PRECISION = 6
MAX_FLOAT32 = 3.4028234663852886e38
# Conservative lower limit for older externally written vectors; new inputs
# are rounded to six decimals and thus cannot approach float32 underflow.
MIN_COSINE_NORM = 1e-18


def validate_vector(values: Sequence[float], *, dimensions: int = EMBEDDING_DIMENSIONS) -> list[float]:
    if not isinstance(values, (list, tuple)) or len(values) != dimensions:
        raise ValueError(f"embedding must contain exactly {dimensions} numbers")
    result = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("embedding values must be numbers")
        try:
            number = float(value)
        except OverflowError:
            raise ValueError("embedding values must fit in float32") from None
        if number != number or number in (float("inf"), float("-inf")):
            raise ValueError("embedding values must be finite")
        if abs(number) > MAX_FLOAT32:
            raise ValueError("embedding values must fit in float32")
        result.append(round(number, MAX_PRECISION))
    if not any(result):
        raise ValueError("embedding must have a nonzero direction after rounding")
    # pgvector 0.8 cosine accumulation uses float32; leave headroom for
    # accumulation rounding so the squared norm cannot overflow to infinity.
    if sum(value * value for value in result) > MAX_FLOAT32 / 2:
        raise ValueError("embedding squared norm is too large for cosine distance")
    return result
