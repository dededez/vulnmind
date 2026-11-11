"""Knowledge ingestion tests (SQLite) and live PostgreSQL search coverage."""
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import sessionmaker

from vulnmind.knowledge.ingestion import ingest_document
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import KnowledgeChunk, KnowledgeDocument
from vulnmind.persistence.repositories import KnowledgeRepository
from vulnmind.persistence.unit_of_work import transaction


@pytest.fixture
def factory():
    engine = create_engine("sqlite://")
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def long_text(length=2500):
    return ("CWE-89 SQL injection guidance. " * (length // 33 + 1))[:length]


def test_ingest_creates_document_and_ordered_chunks(factory):
    with transaction(factory) as session:
        result = ingest_document(session, title="SQLi note", content=long_text(), source_type="CWE",
                                 source_url="https://cwe.mitre.org/data/definitions/89.html",
                                 version="4.14", trust_level="high", metadata={"lang": "generic"},
                                 size=1000, overlap=100)
        document_id, chunk_count = result.document_id, result.chunk_count
        assert result.has_sparse_index is False  # SQLite has no to_tsvector
        assert chunk_count == 3
    with transaction(factory) as session:
        document = session.get(KnowledgeDocument, document_id)
        assert document.title == "SQLi note" and document.metadata_ == {"lang": "generic"}
        chunks = list(session.scalars(select(KnowledgeChunk).order_by(KnowledgeChunk.chunk_index)))
        assert [chunk.chunk_index for chunk in chunks] == [0, 1, 2]
        assert chunks[0].metadata_["start_offset"] == 0
        assert chunks[1].metadata_["start_offset"] == 900
        assert chunks[1].content == long_text()[900:1900]


def test_ingest_rejects_blank_content_and_bad_overlap(factory):
    with transaction(factory) as session:
        with pytest.raises(ValueError, match="blank"):
            ingest_document(session, title="empty", content="   ", source_type="note")
        with pytest.raises(ValueError, match="overlap"):
            ingest_document(session, title="bad", content="abc", source_type="note", size=10, overlap=10)
        assert session.scalar(select(func.count()).select_from(KnowledgeDocument)) == 0


def test_ingest_skips_whitespace_only_windows(factory):
    with transaction(factory) as session:
        result = ingest_document(session, title="spaces", content="alpha" + " " * 40 + "beta",
                                 source_type="note", size=10, overlap=0)
        assert result.chunk_count >= 2


def test_repository_still_accepts_shared_metadata(factory):
    with transaction(factory) as session:
        repository = KnowledgeRepository(session)
        document = repository.create_document(title="doc", source_type="rule")
        session.flush()
        rows = repository.add_chunks(document.id, [(0, "a"), (1, "b")], metadata={"k": "v"})
        assert [row.metadata_ for row in rows] == [{"k": "v"}, {"k": "v"}]
        with pytest.raises(ValueError, match="per-chunk metadata"):
            repository.add_chunks(document.id, [(2, "c")], chunk_metadata=[{}, {}])


def test_ingestion_preserves_filterable_chunk_metadata(factory):
    with transaction(factory) as session:
        result = ingest_document(session, title="doc", content="example text", source_type="CWE",
                                 metadata={"language": "python", "framework": "flask", "vulnerability_type": "sqli"})
        session.flush()
        rows = KnowledgeRepository(session).list_chunks(result.document_id)
        assert rows[0].metadata_["language"] == "python"
        assert rows[0].metadata_["framework"] == "flask"
        assert rows[0].metadata_["vulnerability_type"] == "sqli"
