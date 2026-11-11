"""Exercise the endpoint-parameter migration on a real SQLite database."""
import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect, text


def test_endpoint_parameter_migration_preserves_old_rows_and_downgrades():
    path = Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0013_endpoint_parameters.py"
    spec = importlib.util.spec_from_file_location("endpoint_parameters_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE web_endpoints (id INTEGER PRIMARY KEY)"))
            connection.execute(text("INSERT INTO web_endpoints (id) VALUES (1)"))
            context = MigrationContext.configure(connection)
            with Operations.context(context):
                migration.upgrade()
                assert connection.execute(text("SELECT parameters FROM web_endpoints WHERE id=1")).scalar_one() is None
                connection.execute(text("UPDATE web_endpoints SET parameters='[\"q\"]' WHERE id=1"))
                migration.downgrade()
            assert {column["name"] for column in inspect(connection).get_columns("web_endpoints")} == {"id"}
            assert connection.execute(text("SELECT id FROM web_endpoints")).scalar_one() == 1
    finally:
        engine.dispose()
