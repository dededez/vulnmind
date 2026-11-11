"""Check the first migration and ORM describe the same four tables."""
import importlib.util
import re
from pathlib import Path

from pgvector.sqlalchemy import Vector
from sqlalchemy import Column
from sqlalchemy.dialects import postgresql
from vulnmind.persistence.base import Base
import vulnmind.persistence.models  # noqa: F401


class _FakeResult:
    @staticmethod
    def scalar_one() -> int:
        return 0


class _FakeBind:
    @staticmethod
    def execute(*_args, **_kwargs):
        return _FakeResult()


def test_migration_columns_match_orm(monkeypatch):
    captured = {}
    constraints = []
    statements = []

    def create_table(name, *columns):
        captured[name] = {column.name: column for column in columns if isinstance(column, Column)}

    def add_column(table, column):
        captured.setdefault(table, {})[column.name] = column

    def add_unique(name, table, columns):
        constraints.append((name, table, tuple(columns)))

    def create_index(*args, **kwargs):
        # Indexes are not compared here; the live tests check them in PostgreSQL.
        return None

    versions = Path(__file__).resolve().parents[2] / "migrations/versions"
    for index, migration in enumerate(sorted(versions.glob("[0-9]*.py"))):
        spec = importlib.util.spec_from_file_location(f"test_migration_{index}", migration)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        monkeypatch.setattr(module.op, "create_table", create_table)
        monkeypatch.setattr(module.op, "add_column", add_column)
        monkeypatch.setattr(module.op, "create_unique_constraint", add_unique)
        monkeypatch.setattr(module.op, "create_index", create_index)
        monkeypatch.setattr(module.op, "drop_index", lambda *args, **kwargs: None)
        monkeypatch.setattr(module.op, "execute", lambda statement: statements.append(str(statement)))
        # A dimension-changing migration checks for stored vectors first; the
        # offline replay has no database, so it reports "no vectors".
        monkeypatch.setattr(module.op, "get_bind", _FakeBind)
        module.upgrade()
        # Replay column resizes so the captured schema reflects later migrations.
        for statement in statements:
            match = re.search(r"ALTER TABLE knowledge_chunks ALTER COLUMN embedding TYPE vector\((\d+)\)", statement)
            if match:
                captured["knowledge_chunks"]["embedding"].type = Vector(int(match.group(1)))
    assert set(captured) == set(Base.metadata.tables)
    assert ("uq_findings_scan_fingerprint", "findings", ("scan_id", "fingerprint")) in constraints
    assert any("CREATE TRIGGER vulnmind_knowledge_tsvector_sync" in statement for statement in statements)
    assert any("UPDATE knowledge_chunks SET tsvector" in statement for statement in statements)
    dialect = postgresql.dialect()
    for name, columns in captured.items():
        mapped = Base.metadata.tables[name].columns
        assert set(columns) == set(mapped.keys())
        for key, column in columns.items():
            orm = mapped[key]
            assert column.type.compile(dialect=dialect) == orm.type.compile(dialect=dialect)
            assert column.nullable == orm.nullable
            assert column.primary_key == orm.primary_key
            assert {fk.target_fullname for fk in column.foreign_keys} == {fk.target_fullname for fk in orm.foreign_keys}
