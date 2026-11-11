"""Opt-in PostgreSQL verification that retains its uniquely named schema.

Set VULNMIND_RETAINED_TEST_DATABASE_URL to a dedicated loopback PostgreSQL
database named vulnmind_test. No tables, schemas, or files are removed. Each
run leaves one schema and test data for a human to inspect and manage later.
"""
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from vulnmind.knowledge.ingestion import ingest_document
from vulnmind.persistence.models import Approval, KnowledgeChunk, Project, Scan
from vulnmind.persistence.repositories import KnowledgeRepository, ScopeRepository, TargetRepository
from vulnmind.schemas import Authorization, Target
from vulnmind.security.approvals import ApprovalService, operation_digest


def validate_test_url(value):
    url = make_url(value)
    if (url.drivername != "postgresql+psycopg" or url.host not in {"127.0.0.1", "::1"}
            or url.database != "vulnmind_test" or url.query):
        raise ValueError("test requires a query-free psycopg URL to loopback database vulnmind_test")
    return url


@pytest.mark.parametrize("url", ["postgresql+psycopg://u:p@remote.test/vulnmind_test",
                                  "postgresql+psycopg://u:p@127.0.0.1/production",
                                  "postgresql+psycopg://u:p@127.0.0.1/vulnmind_test?host=remote.test",
                                  "postgresql://u:p@127.0.0.1/vulnmind_test"])
def test_retained_database_safety_rejects_other_targets(url):
    with pytest.raises(ValueError):
        validate_test_url(url)


def test_retained_database_safety_accepts_explicit_loopback_database():
    url = validate_test_url("postgresql+psycopg://test@127.0.0.1:5432/vulnmind_test")
    assert url.host == "127.0.0.1" and url.database == "vulnmind_test"


@pytest.mark.skipif(not os.getenv("VULNMIND_RETAINED_TEST_DATABASE_URL"),
                    reason="retained-schema PostgreSQL test database not configured")
def test_live_migrations_fts_and_single_consumption_without_cleanup(monkeypatch, record_property):
    url = validate_test_url(os.environ["VULNMIND_RETAINED_TEST_DATABASE_URL"])
    schema = "vulnmind_retained_" + uuid4().hex
    record_property("retained_schema", schema)
    print(f"Retained PostgreSQL schema: {schema}")
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    scoped_engine = None
    try:
        with admin.connect() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        scoped = url.update_query_dict({"options": f"-csearch_path={schema},public"})
        monkeypatch.setenv("VULNMIND_DATABASE_URL", scoped.render_as_string(hide_password=False))
        root = Path(__file__).resolve().parents[2]
        config = Config(str(root / "alembic.ini"))
        config.set_main_option("script_location", str(root / "migrations"))
        command.upgrade(config, "head")
        assert "finding_observations" in inspect(admin).get_table_names(schema=schema)
        scoped_engine = create_engine(scoped)
        digest = operation_digest({"operation": "test"})
        now = datetime.now(timezone.utc)
        with Session(scoped_engine) as session, session.begin():
            project = Project(id=uuid4(), name="retained integration test")
            session.add(project)
            session.flush()
            scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
            session.add(scan)
            session.flush()
            target = TargetRepository(session).create(project.id, Target(type="web", locator="https://example.test/api"))
            session.flush()
            policy = Authorization(authorization_source="integration-test", approved_by="test",
                                   starts_at=now-timedelta(minutes=1), expires_at=now+timedelta(minutes=5),
                                   web_origins=["https://example.test"])
            scope = ScopeRepository(session).create(target.id, policy)
            approval = Approval(id=uuid4(), scan_id=scan.id, action="test", target="test",
                                operation_hash=digest, status="approved", approver="test",
                                approved_at=now, expires_at=now + timedelta(minutes=5))
            session.add(approval)
            document = ingest_document(session, title="retained test", source_type="test",
                                       content="parameterized query example", size=100, overlap=0)
            approval_id, scan_id, document_id = approval.id, scan.id, document.document_id
            target_id, scope_id = target.id, scope.id
        with Session(scoped_engine) as session:
            assert any(row.document_id == document_id for row in KnowledgeRepository(session).search_chunks("parameterized"))
            loaded_target, loaded_scope = ScopeRepository(session).load_for_scan(
                scope_id, target_id=target_id, scan_id=scan_id)
            assert loaded_target.locator == "https://example.test/api" and loaded_scope == policy
        with Session(scoped_engine) as session, session.begin():
            chunk = session.scalar(select(KnowledgeChunk).where(KnowledgeChunk.document_id == document_id))
            chunk.content = "updateduniqueterm"
        with Session(scoped_engine) as session:
            assert KnowledgeRepository(session).search_chunks("updateduniqueterm")

        barrier = Barrier(2, timeout=10)
        def consume():
            with Session(scoped_engine) as session, session.begin():
                barrier.wait()
                return ApprovalService(session).consume_bound(str(approval_id), scan_id=scan_id,
                                                               action="test", target="test", operation_hash=digest)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: consume(), range(2)))
        assert sorted(results) == [False, True]
    finally:
        if scoped_engine is not None:
            scoped_engine.dispose()
        admin.dispose()

