"""Dense-vector validation and PostgreSQL-only guards (offline)."""
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from vulnmind.knowledge.vector import EMBEDDING_DIMENSIONS, validate_vector
from vulnmind.persistence.base import Base
from vulnmind.persistence.repositories import KnowledgeRepository, ProjectRepository
from vulnmind.persistence.unit_of_work import transaction


def vector(value: float = 0.1):
    return [value] * EMBEDDING_DIMENSIONS


def test_validate_vector_enforces_dimension_and_finiteness():
    assert len(validate_vector(vector())) == EMBEDDING_DIMENSIONS
    assert validate_vector([0.123456789] + [0.0] * (EMBEDDING_DIMENSIONS - 1))[0] == 0.123457
    with pytest.raises(ValueError, match="exactly"):
        validate_vector([0.0] * (EMBEDDING_DIMENSIONS - 1))
    with pytest.raises(ValueError, match="numbers"):
        validate_vector(["x"] * EMBEDDING_DIMENSIONS)
    with pytest.raises(ValueError, match="finite"):
        validate_vector([float("nan")] + [0.0] * (EMBEDDING_DIMENSIONS - 1))
    with pytest.raises(ValueError, match="numbers"):
        validate_vector([True] * EMBEDDING_DIMENSIONS)


@pytest.mark.parametrize("value", [0.0, 0.0000001, -0.0000001])
def test_cosine_vectors_require_direction_after_rounding(value):
    with pytest.raises(ValueError, match="nonzero direction"):
        validate_vector(vector(value))


def test_vectors_reject_values_outside_float32_range():
    for value in (1e100, -(10 ** 400)):
        with pytest.raises(ValueError, match="float32"):
            validate_vector(vector(value))


def test_vectors_reject_cosine_norm_overflow_before_database():
    with pytest.raises(ValueError, match="squared norm"):
        validate_vector([1e20] + [0.0] * (EMBEDDING_DIMENSIONS - 1))
    assert validate_vector([1e10] + [0.0] * (EMBEDDING_DIMENSIONS - 1))[0] == 1e10


@pytest.fixture
def factory():
    engine = create_engine("sqlite://")
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def test_dense_operations_require_postgresql(factory):
    with transaction(factory) as session:
        project = ProjectRepository(session).create("vectors")
        session.flush()
        repository = KnowledgeRepository(session)
        document = repository.create_document(title="doc", source_type="note")
        session.flush()
        chunks = repository.add_chunks(document.id, [(0, "alpha")])
        session.flush()
        with pytest.raises(ValueError, match="pgvector"):
            repository.set_embedding(chunks[0].id, vector())
        with pytest.raises(ValueError, match="pgvector"):
            repository.dense_search(vector())
        assert project is not None
