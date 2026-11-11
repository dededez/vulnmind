from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session
from vulnmind.persistence.repositories import KnowledgeRepository, build_sparse_statement


def test_sparse_query_uses_stored_vector_and_parameterized_filters():
    query = "input ' OR true --"
    statement = build_sparse_statement(query, filters={"source_type": "CWE", "language": "python"})
    compiled = statement.compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert "knowledge_chunks.tsvector @@" in sql
    assert "to_tsvector" not in sql
    assert "JOIN knowledge_documents" in sql
    assert query not in sql and query in compiled.params.values()
    assert "python" in compiled.params.values() and "CWE" in compiled.params.values()


@pytest.mark.parametrize("filters", [{"bad_field": "x"}, {"language": " "}])
def test_sparse_query_rejects_invalid_filters(filters):
    with pytest.raises(ValueError, match="filter"):
        build_sparse_statement("query", filters=filters)


def test_sparse_search_fails_closed_on_non_postgres():
    with Session(create_engine("sqlite://")) as session:
        with pytest.raises(ValueError, match="PostgreSQL"):
            KnowledgeRepository(session).search_chunks("query")


def test_postgres_chunk_creation_populates_tsvector_expression():
    class FakeSession:
        def get(self, model, identifier): return object()
        def get_bind(self): return SimpleNamespace(dialect=postgresql.dialect())
        def add_all(self, rows): self.rows = rows
    session = FakeSession()
    rows = KnowledgeRepository(session).add_chunks(uuid4(), [(0, "untrusted query content")])
    compiled = rows[0].tsvector.compile(dialect=postgresql.dialect())
    assert "to_tsvector" in str(compiled)
    assert "untrusted query content" in compiled.params.values()
