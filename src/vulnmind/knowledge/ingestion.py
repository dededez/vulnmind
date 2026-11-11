"""Ingest local knowledge text into the knowledge tables.

Chunking is delegated to ``vulnmind.knowledge.chunking`` so the same deterministic
offsets and chunk identities are reused. Chunk offsets and document metadata are
kept per row; on PostgreSQL the ``tsvector`` column is populated server-side so
``KnowledgeRepository.search_chunks`` can find the content immediately.
"""
from __future__ import annotations

from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from vulnmind.knowledge.chunking import KnowledgeDocument, chunk_document
from vulnmind.persistence.repositories import KnowledgeRepository


class IngestedDocument(BaseModel):
    model_config = ConfigDict(frozen=True)
    document_id: UUID
    chunk_count: int
    has_sparse_index: bool


def ingest_document(session: Session, *, title: str, content: str, source_type: str,
                    source_url: str | None = None, version: str | None = None,
                    trust_level: str | None = None, metadata: dict | None = None,
                    size: int = 1000, overlap: int = 100) -> IngestedDocument:
    if not content.strip():
        raise ValueError("knowledge content cannot be blank")
    # Validate and split before any database write, even if the caller catches
    # a validation error and commits the surrounding transaction.
    document_id = uuid4()
    chunk_source = KnowledgeDocument(document_id=str(document_id), content=content,
                                     source=source_url or title, version=version, source_type=source_type,
                                     trust_level=trust_level)
    chunks = chunk_document(chunk_source, size=size, overlap=overlap)
    repository = KnowledgeRepository(session)
    document = repository.create_document(title=title, source_type=source_type, source_url=source_url,
                                          version=version, trust_level=trust_level, metadata=metadata,
                                          document_id=document_id)
    session.flush()
    if not chunks:
        return IngestedDocument(document_id=document.id, chunk_count=0, has_sparse_index=False)
    rows = repository.add_chunks(
        document.id,
        [(index, chunk.content) for index, chunk in enumerate(chunks)],
        chunk_metadata=[{**{key: metadata[key] for key in ("vulnerability_type", "language", "framework")
                            if metadata and isinstance(metadata.get(key), str) and metadata[key].strip()},
                         "start_offset": chunk.start_offset, "end_offset": chunk.end_offset,
                         "chunk_id": chunk.chunk_id} for chunk in chunks])
    sparse = session.get_bind().dialect.name == "postgresql"
    if sparse:
        session.flush()
    return IngestedDocument(document_id=document.id, chunk_count=len(rows), has_sparse_index=sparse)
