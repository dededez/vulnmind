"""Let ORM tests create PostgreSQL-typed tables on SQLite."""
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.ext.compiler import compiles


@compiles(JSONB, "sqlite")
def _jsonb_as_json(type_, compiler, **kw):
    return "JSON"


@compiles(TSVECTOR, "sqlite")
def _tsvector_as_text(type_, compiler, **kw):
    return "TEXT"


@compiles(Vector, "sqlite")
def _vector_as_text(type_, compiler, **kw):
    return "TEXT"
