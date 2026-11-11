"""Connect hybrid retrieval contracts to PostgreSQL-backed knowledge rows.

The dense adapter needs a caller-supplied query encoder. For provenance-tagged
embeddings the caller must provide the expected model identity. Chunk
identifiers crossing retrievers are database UUID strings.
"""
from collections.abc import Callable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session
from vulnmind.knowledge.retrieval import KnowledgeChunk
from vulnmind.knowledge.vector import validate_vector
from vulnmind.persistence.models import KnowledgeChunk as ChunkRow
from vulnmind.persistence.models import KnowledgeDocument as DocumentRow
from vulnmind.persistence.repositories import KnowledgeRepository, validate_knowledge_filters

Encoder = Callable[[str], list[float]]


class PostgresSparseRetriever:
    def __init__(self, session: Session, *, filters: dict[str, str] | None = None):
        self._repository = KnowledgeRepository(session)
        self._filters = validate_knowledge_filters(filters)

    def search(self, query: str, *, limit: int) -> list[str]:
        return [str(row.id) for row in self._repository.search_chunks(query, limit=limit, filters=self._filters)]

    def search_filtered(self, query: str, *, limit: int, filters: dict[str, str]) -> list[str]:
        selected = _merge_filters(self._filters, filters)
        return [str(row.id) for row in self._repository.search_chunks(query, limit=limit, filters=selected)]


class PostgresDenseRetriever:
    """pgvector cosine retrieval with an injected query encoder.

    The encoder is the only place a model is needed; without it the adapter
    refuses to guess an embedding. Its output is dimension-checked here so a
    misconfigured provider fails before touching the database.
    """

    def __init__(self, session: Session, *, encode: Encoder, filters: dict[str, str] | None = None,
                 expected_model_info: dict[str, str] | None = None):
        if not callable(encode):
            raise ValueError("an encode callable is required for dense retrieval")
        self._repository = KnowledgeRepository(session)
        self._session = session
        self._encode = encode
        self._filters = validate_knowledge_filters(filters)
        if expected_model_info is not None and (not isinstance(expected_model_info, dict)
                or set(expected_model_info) != {"model", "revision", "files_sha256"}
                or any(not isinstance(v, str) or not v.strip() for v in expected_model_info.values())):
            raise ValueError("invalid expected model provenance")
        self._expected_model_info = dict(expected_model_info) if expected_model_info is not None else None

    def search(self, query: str, *, limit: int) -> list[str]:
        return self.search_filtered(query, limit=limit, filters={})

    def search_filtered(self, query: str, *, limit: int, filters: dict[str, str]) -> list[str]:
        if not isinstance(query, str) or not query.strip() or len(query) > 4096:
            raise ValueError("query must contain 1 to 4096 characters")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("search limit must be between 1 and 100")
        selected = _merge_filters(self._filters, filters)
        try:
            vector = validate_vector(self._encode(query))
        except Exception:  # noqa: BLE001 - provider failures are a boundary error
            # Providers may put query text or credentials in their exceptions.
            raise ValueError("query encoder did not return a usable embedding") from None
        rows = self._repository.dense_search(vector, limit=limit, filters=selected)
        if rows:
            self._check_provenance(rows)
        return [str(row.id) for row in rows]

    def _check_provenance(self, rows):
        from vulnmind.knowledge.embedding_batch import KEY, content_hash, vector_hash

        records = self._session.execute(select(ChunkRow.metadata_, DocumentRow.version)
            .join(DocumentRow, DocumentRow.id == ChunkRow.document_id)
            .where(ChunkRow.embedding.is_not(None))).all()
        markers = [(metadata.get(KEY) if isinstance(metadata, dict) else None, version)
                   for metadata, version in records]
        tagged = [marker for marker, _ in markers if marker is not None]
        if not tagged:
            if self._expected_model_info is not None:
                raise ValueError("legacy embeddings have no verified model provenance")
            return  # Legacy mode is available only when the entire corpus is untagged.
        if len(tagged) != len(markers) or self._expected_model_info is None:
            raise ValueError("embedding provenance is mixed or expected model identity is missing")
        for marker, version in markers:
            if (not isinstance(marker, dict) or any(marker.get(k) != v for k, v in self._expected_model_info.items())
                    or marker.get("document_version") != version):
                raise ValueError("embedding model or document provenance mismatch")
        for row in rows:
            marker = row.metadata_[KEY]
            if marker.get("content_sha256") != content_hash(row.content) or marker.get("vector_sha256") != vector_hash(row.embedding):
                raise ValueError("embedding content or vector provenance mismatch")


def _merge_filters(configured: dict[str, str], requested: dict[str, str]) -> dict[str, str]:
    requested = validate_knowledge_filters(requested)
    if any(key in configured and configured[key] != value for key, value in requested.items()):
        raise ValueError("requested metadata filter conflicts with configured filter")
    return {**configured, **requested}


class DatabaseChunkStore:
    def __init__(self, session: Session):
        self._session = session

    def get(self, chunk_id: str) -> KnowledgeChunk | None:
        try:
            identifier = UUID(chunk_id)
        except (ValueError, TypeError, AttributeError):
            return None
        row = self._session.get(ChunkRow, identifier)
        if row is None:
            return None
        document = self._session.get(DocumentRow, row.document_id)
        if document is None:
            raise ValueError("knowledge chunk has no source document")
        metadata = row.metadata_ if row.metadata_ is not None else {}
        if not isinstance(metadata, dict):
            raise ValueError("knowledge chunk metadata must be a mapping")
        return KnowledgeChunk(chunk_id=str(row.id), document_id=str(document.id), content=row.content,
                              document_title=document.title,
                              source=document.source_url or document.title, version=document.version,
                              source_type=document.source_type, trust_level=document.trust_level,
                              vulnerability_type=metadata.get("vulnerability_type"), language=metadata.get("language"),
                              framework=metadata.get("framework"), start_offset=metadata.get("start_offset"),
                              end_offset=metadata.get("end_offset"))
