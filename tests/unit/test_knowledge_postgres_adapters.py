from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from vulnmind.knowledge.postgres_adapters import DatabaseChunkStore, PostgresSparseRetriever
from vulnmind.knowledge.retrieval import hybrid_search
from vulnmind.persistence.base import Base
from vulnmind.persistence.repositories import KnowledgeRepository
from vulnmind.persistence.unit_of_work import transaction


def test_database_chunk_store_preserves_provenance():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with transaction(factory) as session:
        repository = KnowledgeRepository(session)
        doc = repository.create_document(title="Title", source_type="CWE", version="1", trust_level="high")
        session.flush()
        row = repository.add_chunks(doc.id, [(0, "content")], metadata={"language": "python", "start_offset": 0, "end_offset": 7})[0]
        session.flush()
        chunk_id = str(row.id)
        doc_id = str(doc.id)
    with transaction(factory) as session:
        store = DatabaseChunkStore(session)
        chunk = store.get(chunk_id)
        assert chunk.chunk_id == chunk_id and chunk.document_id == doc_id
        assert chunk.source == "Title" and chunk.source_type == "CWE"
        assert chunk.language == "python" and (chunk.start_offset, chunk.end_offset) == (0, 7)
        assert store.get("not-a-uuid") is None and store.get(str(uuid4())) is None
    engine.dispose()


def test_sparse_adapter_passes_query_limits_and_filter_to_repository(monkeypatch):
    captured = []
    ids = [uuid4(), uuid4()]
    def fake_search(self, query, *, limit, filters):
        captured.append((query, limit, filters))
        return [type("Row", (), {"id": identifier})() for identifier in ids]
    monkeypatch.setattr(KnowledgeRepository, "search_chunks", fake_search)
    adapter = PostgresSparseRetriever(object(), filters={"source_type": "CWE"})
    assert adapter.search("query", limit=3) == list(map(str, ids))
    assert captured == [("query", 3, {"source_type": "CWE"})]


def test_store_rejects_non_mapping_chunk_metadata():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with transaction(factory) as session:
        repo = KnowledgeRepository(session)
        doc = repo.create_document(title="Title", source_type="CWE")
        session.flush()
        row = repo.add_chunks(doc.id, [(0, "content")], metadata=["unexpected"])[0]
        session.flush()
        with pytest.raises(ValueError, match="mapping"):
            DatabaseChunkStore(session).get(str(row.id))
    engine.dispose()


def test_adapters_connect_to_hybrid_contract_without_fabricating_sources(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with transaction(factory) as session:
        repo = KnowledgeRepository(session)
        doc = repo.create_document(title="Document", source_type="CWE")
        session.flush()
        row = repo.add_chunks(doc.id, [(0, "SQL injection")])[0]
        session.flush()
        monkeypatch.setattr(KnowledgeRepository, "search_chunks", lambda self, query, *, limit, filters: [row])
        class Dense:
            def search(self, query, *, limit): return [str(row.id)]
        class Reranker:
            def rank(self, query, candidates): return [item.chunk_id for item in candidates]
        results = hybrid_search("SQL", dense=Dense(), sparse=PostgresSparseRetriever(session),
                                store=DatabaseChunkStore(session), reranker=Reranker())
        assert len(results) == 1
        assert results[0].ranks == {"dense": 1, "sparse": 1}
        assert results[0].chunk.document_id == str(doc.id)
        assert results[0].chunk.source == "Document"
    engine.dispose()
