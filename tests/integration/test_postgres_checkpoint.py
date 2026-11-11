"""Opt-in live test; only touches a randomly named schema in a test DB."""
from datetime import datetime, timedelta, timezone
import os
from uuid import uuid4

import pytest
pytest.importorskip("langgraph.checkpoint.postgres")
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from vulnmind.graph.postgres_checkpoint import postgres_checkpointer
from vulnmind.graph.workflow import build_graph


@pytest.mark.skipif(not os.getenv("VULNMIND_TEST_DATABASE_URL"), reason="dedicated PostgreSQL test database not configured")
def test_checkpoint_reopen_in_isolated_schema():
    url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
    if url.get_backend_name() != "postgresql":
        pytest.fail("VULNMIND_TEST_DATABASE_URL must be PostgreSQL")
    schema = "vulnmind_cp_" + uuid4().hex
    engine = create_engine(url, isolation_level="AUTOCOMMIT")
    dsn = url.set(drivername="postgresql").update_query_dict({"options": f"-csearch_path={schema}"}).render_as_string(hide_password=False)
    with engine.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    try:
        now = datetime.now(timezone.utc)
        state = {"task_id": "t", "project_id": "p", "targets": [{"type": "web", "locator": "https://example.test"}], "authorized_scope": {"authorization_source": "test", "approved_by": "owner", "starts_at": (now-timedelta(hours=1)).isoformat(), "expires_at": (now+timedelta(hours=1)).isoformat(), "web_origins": ["https://example.test"]}}
        config = {"configurable": {"thread_id": "reopen"}}
        with postgres_checkpointer(dsn, initialize=True) as saver:
            assert build_graph(saver).invoke(state, config)["status"] == "planned"
        with postgres_checkpointer(dsn) as saver:
            assert build_graph(saver).get_state(config).values["status"] == "planned"
    finally:
        with engine.connect() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()
