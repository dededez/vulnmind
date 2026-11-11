"""Shared fail-closed PostgreSQL vector and keyword retrieval."""
from dataclasses import dataclass

from vulnmind.knowledge.fusion import reciprocal_rank_fusion
from vulnmind.knowledge.postgres_adapters import PostgresDenseRetriever, PostgresSparseRetriever


class LocalQueryEncoder:
    """Load the existing local model once and recheck its files after encoding."""

    def __init__(self):
        from huggingface_hub import snapshot_download
        from sentence_transformers import SentenceTransformer
        from vulnmind.knowledge.model_fingerprint import MODEL, fingerprint, model_identity

        self._fingerprint = fingerprint
        self._manifest = fingerprint()
        self.model_info = model_identity(self._manifest)
        path = snapshot_download(MODEL, revision=self.model_info["revision"], local_files_only=True)
        self._model = SentenceTransformer(path, device="cpu", trust_remote_code=False, local_files_only=True)

    def __call__(self, query: str) -> list[float]:
        vector = [float(value) for value in self._model.encode(
            [query], prompt_name="query", normalize_embeddings=True)[0]]
        if self._fingerprint() != self._manifest:
            raise ValueError("embedding model files changed during query encoding")
        return vector


@dataclass(frozen=True)
class HybridDiagnostics:
    identifiers: tuple[str, ...]
    sparse_count: int
    dense_count: int
    sparse_limit_reached: bool
    dense_limit_reached: bool
    fused: tuple[dict, ...]


class PostgresHybridRetriever:
    """Both retrievers must succeed; never silently downgrade to one source."""

    def __init__(self, session, *, encoder):
        self._sparse = PostgresSparseRetriever(session)
        self._dense = PostgresDenseRetriever(session, encode=encoder, expected_model_info=encoder.model_info)

    def search(self, query: str, *, limit: int) -> list[str]:
        return list(self.search_with_diagnostics(query, limit=limit).identifiers)

    def search_with_diagnostics(self, query: str, *, limit: int) -> HybridDiagnostics:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("search limit must be between 1 and 100")
        sparse = self._sparse.search(query, limit=limit)
        dense = self._dense.search(query, limit=limit)
        if sparse and not dense:
            raise ValueError("dense retrieval returned no candidates for a nonempty keyword result")
        fused = reciprocal_rank_fusion({"sparse": sparse, "dense": dense}, limit=limit)
        return HybridDiagnostics(identifiers=tuple(item.chunk_id for item in fused),
                                 sparse_count=len(sparse), dense_count=len(dense),
                                 sparse_limit_reached=len(sparse) == limit,
                                 dense_limit_reached=len(dense) == limit,
                                 fused=tuple({"chunk_id": item.chunk_id, "score": item.score,
                                              "ranks": dict(item.ranks)} for item in fused))
