"""SQLite tests transaction behavior, not PostgreSQL compatibility."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Project, ScopeRecord
from vulnmind.persistence.repositories import ProjectRepository, ScanRepository, ScopeRepository, TargetRepository
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import ScopeDenied


@compiles(JSONB, "sqlite")
def compile_jsonb_for_test(type_, compiler, **kw):
    return "JSON"


@pytest.fixture
def factory():
    engine = create_engine("sqlite://")
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def authorization():
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner", starts_at=now-timedelta(hours=1), expires_at=now+timedelta(hours=1), web_origins=["https://example.test"], allowed_web_paths={"https://example.test": ["/api"]}, denied_web_paths={"https://example.test": ["/api/private"]})


def test_repositories_commit_and_preserve_scope_fields(factory):
    with transaction(factory) as session:
        project = ProjectRepository(session).create("example")
        session.flush()
        target = TargetRepository(session).create(project.id, Target(type="web", locator="https://example.test/api"))
        scan = ScanRepository(session).create(project.id, "simulation")
        session.flush()
        scope = ScopeRepository(session).create(target.id, authorization())
        ids = project.id, target.id, scope.id, scan.id
    with transaction(factory) as session:
        project_id, target_id, scope_id, scan_id = ids
        assert ProjectRepository(session).get(project_id).name == "example"
        assert TargetRepository(session).get(target_id).project_id == project_id
        assert ScanRepository(session).get(scan_id).project_id == project_id
        stored = ScopeRepository(session).get(scope_id)
        assert stored.allowlist["allowed_web_paths"] == {"https://example.test": ["/api"]}
        assert stored.denylist["denied_web_paths"] == {"https://example.test": ["/api/private"]}
        with pytest.raises(ValueError, match="different target"):
            ScopeRepository(session).load_authorization(scope_id, target_id=uuid4())
        # SQLite does not preserve timezone offsets, so restoring fails closed.
        with pytest.raises(ValidationError):
            ScopeRepository(session).load_authorization(scope_id, target_id=target_id)


def test_transaction_rolls_back_everything_on_exception(factory):
    with pytest.raises(RuntimeError):
        with transaction(factory) as session:
            ProjectRepository(session).create("rollback")
            session.flush()
            raise RuntimeError("abort")
    with transaction(factory) as session:
        assert session.scalar(select(func.count()).select_from(Project)) == 0


def test_incomplete_stored_scope_is_not_widened(factory):
    with transaction(factory) as session:
        project = ProjectRepository(session).create("scope")
        session.flush()
        target = TargetRepository(session).create(project.id, Target(type="web", locator="https://example.test"))
        session.flush()
        stored = ScopeRepository(session).create(target.id, authorization())
        session.flush()
        stored.allowlist = {"web_origins": ["https://example.test"]}
        with pytest.raises(ValueError, match="incomplete"):
            ScopeRepository(session).load_authorization(stored.id, target_id=target.id)


def test_scope_record_does_not_share_mutable_input(factory):
    policy = authorization()
    with transaction(factory) as session:
        project = ProjectRepository(session).create("snapshot")
        session.flush()
        target = TargetRepository(session).create(project.id, Target(type="web", locator="https://example.test"))
        session.flush()
        stored = ScopeRepository(session).create(target.id, policy)
        policy.allowed_web_paths["https://example.test"].append("/")
        assert stored.allowlist["allowed_web_paths"]["https://example.test"] == ["/api"]


def test_mutated_invalid_authorization_not_persisted(factory):
    policy = authorization()
    policy.authorization_source = " "
    with pytest.raises(ValidationError):
        with transaction(factory) as session:
            ScopeRepository(session).create(uuid4(), policy)


def test_load_stored_scope_binds_scan_target_and_project(factory):
    with transaction(factory) as session:
        first = ProjectRepository(session).create("first")
        other = ProjectRepository(session).create("other")
        session.flush()
        target = TargetRepository(session).create(first.id, Target(type="web", locator="https://example.test/api"))
        scan = ScanRepository(session).create(first.id, "analysis")
        foreign_scan = ScanRepository(session).create(other.id, "analysis")
        session.flush()
        policy = authorization()
        scope = ScopeRepository(session).create(target.id, policy)
        session.flush()
        loaded_target, loaded_scope = ScopeRepository(session).load_for_scan(
            scope.id, target_id=target.id, scan_id=scan.id)
        assert loaded_target.locator == "https://example.test/api" and loaded_scope == policy
        with pytest.raises(ValueError, match="same project"):
            ScopeRepository(session).load_for_scan(scope.id, target_id=target.id, scan_id=foreign_scan.id)
        with pytest.raises(ValueError, match="same project"):
            ScopeRepository(session).load_for_scan(scope.id, target_id=uuid4(), scan_id=scan.id)
        with pytest.raises(ValueError, match="different target"):
            ScopeRepository(session).load_for_scan(uuid4(), target_id=target.id, scan_id=scan.id)
        with pytest.raises(ScopeDenied, match="time window"):
            ScopeRepository(session).load_for_scan(scope.id, target_id=target.id, scan_id=scan.id,
                                                   now=policy.expires_at)
        target.locator = "https://example.test/admin"
        with pytest.raises(ScopeDenied, match="outside authorization"):
            ScopeRepository(session).load_for_scan(scope.id, target_id=target.id, scan_id=scan.id)
