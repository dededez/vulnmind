"""Dense retriever adapter tests (SQLite guards, offline)."""
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import sessionmaker

from vulnmind.knowledge.postgres_adapters import PostgresDenseRetriever
from vulnmind.knowledge.vector import EMBEDDING_DIMENSIONS
from vulnmind.persistence.base import Base
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.persistence.repositories import build_dense_statement


def unit_vector(index: int) -> list[float]:
    values = [0.0] * EMBEDDING_DIMENSIONS
    values[index] = 1.0
    return values


@pytest.fixture
def factory():
    engine = create_engine("sqlite://")
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def test_encoder_is_required():
    with pytest.raises(ValueError, match="encode callable"):
        PostgresDenseRetriever(None, encode=None)


def test_dense_search_rejects_non_postgresql(factory):
    with transaction(factory) as session:
        retriever = PostgresDenseRetriever(session, encode=lambda query: unit_vector(0))
        with pytest.raises(ValueError, match="pgvector"):
            retriever.search("query", limit=5)


def test_bad_encoder_output_is_reported_before_the_query(factory):
    def short(query):
        return [1.0, 2.0]

    def raises(query):
        raise RuntimeError("provider down")

    with transaction(factory) as session:
        with pytest.raises(ValueError, match="usable embedding"):
            PostgresDenseRetriever(session, encode=short).search("query", limit=5)
        with pytest.raises(ValueError, match="usable embedding"):
            PostgresDenseRetriever(session, encode=raises).search("query", limit=5)


def test_encoder_exception_does_not_leak_into_traceback(factory):
    import traceback

    def raises(query):
        raise RuntimeError("sensitive-provider-detail")

    with transaction(factory) as session:
        with pytest.raises(ValueError) as error:
            PostgresDenseRetriever(session, encode=raises).search("query", limit=5)
    rendered = "".join(traceback.format_exception(error.value))
    assert "usable embedding" in rendered
    assert "sensitive-provider-detail" not in rendered


def test_query_validation(factory):
    with transaction(factory) as session:
        retriever = PostgresDenseRetriever(session, encode=lambda query: unit_vector(0))
        with pytest.raises(ValueError, match="1 to 4096"):
            retriever.search(" ", limit=5)


def test_dense_filters_are_bound_and_applied_before_limit():
    value = "python' OR true --"
    statement = build_dense_statement(unit_vector(0), limit=1, filters={"language": value, "source_type": "CWE"})
    compiled = statement.compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert "JOIN knowledge_documents" in sql and "WHERE " in sql and "LIMIT " in sql
    assert sql.index("WHERE ") < sql.index("LIMIT ")
    assert value not in sql and value in compiled.params.values()


def test_invalid_limits_or_conflicting_filters_do_not_call_encoder(factory):
    called = []
    def encode(query):
        called.append(query)
        return unit_vector(0)
    with transaction(factory) as session:
        retriever = PostgresDenseRetriever(session, encode=encode, filters={"language": "python"})
        with pytest.raises(ValueError, match="limit"):
            retriever.search("query", limit=0)
        with pytest.raises(ValueError, match="conflicts"):
            retriever.search_filtered("query", limit=1, filters={"language": "go"})
    assert called == []
