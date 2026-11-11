"""Hybrid retrieval orchestration; concrete stores and models are injected."""
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from vulnmind.knowledge.fusion import FusedResult, reciprocal_rank_fusion


class KnowledgeChunk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    chunk_id: str = Field(min_length=1)
    document_id: str = Field(min_length=1)
    content: str = Field(min_length=1)
    source: str = Field(min_length=1)
    document_title: str | None = None
    version: str | None = None
    source_type: str | None = None
    vulnerability_type: str | None = None
    language: str | None = None
    framework: str | None = None
    trust_level: str | None = None
    start_offset: int | None = Field(default=None, ge=0)
    end_offset: int | None = Field(default=None, ge=0)

    @field_validator("chunk_id", "document_id", "content", "source")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("knowledge provenance and content must not be blank")
        return value

    @model_validator(mode="after")
    def valid_offsets(self):
        if (self.start_offset is None) != (self.end_offset is None):
            raise ValueError("both offsets must be supplied together")
        if self.start_offset is not None and self.end_offset <= self.start_offset:
            raise ValueError("end offset must follow start offset")
        if self.start_offset is not None and self.end_offset - self.start_offset != len(self.content):
            raise ValueError("offset span must match content length")
        return self


class Retriever(Protocol):
    def search(self, query: str, *, limit: int) -> list[str]: ...


class ChunkStore(Protocol):
    def get(self, chunk_id: str) -> KnowledgeChunk | None: ...


class Reranker(Protocol):
    def rank(self, query: str, candidates: list[KnowledgeChunk]) -> list[str]: ...


class RetrievedChunk(BaseModel):
    chunk: KnowledgeChunk
    rrf_score: float
    ranks: dict[str, int]


def hybrid_search(query: str, *, dense: Retriever, sparse: Retriever, store: ChunkStore, reranker: Reranker,
                  per_retriever: int = 20, candidates: int = 20, final: int = 5, k: int = 60,
                  filters: dict[str, str] | None = None) -> list[RetrievedChunk]:
    if not isinstance(query, str) or not query.strip() or len(query) > 4096:
        raise ValueError("query must contain 1 to 4096 characters")
    for value, maximum in ((per_retriever, 100), (candidates, 200), (final, 200)):
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
            raise ValueError("result limits must be positive integers within configured bounds")
    if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= 1_000_000:
        raise ValueError("k must be an integer between 1 and 1000000")
    allowed_filters = {"source", "version", "source_type", "vulnerability_type", "language", "framework", "trust_level"}
    if filters is None:
        filters = {}
    if not isinstance(filters, dict) or set(filters) - allowed_filters or any(
            not isinstance(v, str) or not v.strip() or len(v) > 255 for v in filters.values()):
        raise ValueError("unsupported or invalid metadata filter")
    def search(retriever: Retriever) -> list[str]:
        filtered = getattr(retriever, "search_filtered", None)
        if filters and callable(filtered):
            return filtered(query, limit=per_retriever, filters=dict(filters))[:per_retriever]
        return retriever.search(query, limit=per_retriever)[:per_retriever]

    fusion: list[FusedResult] = reciprocal_rank_fusion({"dense": search(dense), "sparse": search(sparse)},
                                                       k=k, limit=candidates)
    if not fusion:
        return []
    by_id: dict[str, tuple[KnowledgeChunk, FusedResult]] = {}
    for result in fusion:
        chunk = store.get(result.chunk_id)
        if chunk is None or chunk.chunk_id != result.chunk_id:
            raise ValueError("retrieved chunk is missing or mismatched")
        if any(getattr(chunk, name) != expected for name, expected in filters.items()):
            continue
        by_id[result.chunk_id] = (chunk, result)
    if not by_id:
        return []
    ranked_ids = reranker.rank(query, [pair[0] for pair in by_id.values()])
    if (not isinstance(ranked_ids, list) or len(ranked_ids) > len(by_id)
            or any(not isinstance(item, str) for item in ranked_ids)
            or len(set(ranked_ids)) != len(ranked_ids) or any(chunk_id not in by_id for chunk_id in ranked_ids)):
        raise ValueError("reranker returned duplicate or unknown chunk IDs")
    return [RetrievedChunk(chunk=by_id[chunk_id][0], rrf_score=by_id[chunk_id][1].score,
                           ranks=by_id[chunk_id][1].ranks) for chunk_id in ranked_ids[:final]]


class HybridRetriever:
    """Expose hybrid_search's actual result IDs through the Retriever contract.

    The caller supplies the encoder-backed dense retriever and reranker; this
    adapter does not create or validate a model and does not cache contents.
    """
    def __init__(self, *, dense: Retriever, sparse: Retriever, store: ChunkStore, reranker: Reranker,
                 per_retriever: int = 20, candidates: int = 20, k: int = 60,
                 filters: dict[str, str] | None = None):
        if not all(callable(getattr(value, method, None)) for value, method in (
                (dense, "search"), (sparse, "search"), (store, "get"), (reranker, "rank"))):
            raise ValueError("dense, sparse, store and reranker interfaces are required")
        self._dense, self._sparse, self._store, self._reranker = dense, sparse, store, reranker
        self._per_retriever, self._candidates, self._k = per_retriever, candidates, k
        self._filters = dict(filters) if isinstance(filters, dict) else filters

    def search(self, query: str, *, limit: int) -> list[str]:
        result = hybrid_search(query, dense=self._dense, sparse=self._sparse, store=self._store,
                               reranker=self._reranker, per_retriever=self._per_retriever,
                               candidates=self._candidates, final=limit, k=self._k, filters=self._filters)
        return [item.chunk.chunk_id for item in result]
