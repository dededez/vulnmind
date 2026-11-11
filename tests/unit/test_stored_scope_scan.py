"""Stored-scope scans.

SQLite drops timezone offsets, so restoring an authorization from SQLite fails
closed by design (``authorization times must include timezone``). These tests
therefore lock in two things: the wiring and association checks, and the
fail-closed behaviour. A real end-to-end stored-scope run needs PostgreSQL and
is covered by the opt-in live tests.
"""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from vulnmind.analysis.orchestrator import ScanOrchestrator, ScanRunRequest
from vulnmind.analysis.service import RepositoryScanService
from vulnmind.findings import FindingCandidate
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Finding, Project, Scan
from vulnmind.persistence.repositories import ProjectRepository, ScopeRepository, TargetRepository
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.reports.store import ReportStore
from vulnmind.schemas import Authorization, Target


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


def authorization(root):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)])


def analyzer(content):
    return [FindingCandidate(title="stub", vulnerability_type="misconfig", target_id="x",
                             location=f"{content.path}:1", source_tool="stub")]


@pytest.fixture
def factory():
    engine = create_engine("sqlite://")
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def stored_scope(factory, tmp_path):
    (tmp_path / "app.py").write_bytes(b"print('ok')\n")
    with transaction(factory) as session:
        project = ProjectRepository(session).create("stored scope")
        session.flush()
        target = TargetRepository(session).create(project.id, Target(type="repository", locator=str(tmp_path)))
        session.flush()
        scope = ScopeRepository(session).create(target.id, authorization(tmp_path))
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="created", mode="analysis")
        session.add(scan)
        session.flush()
        other_project = ProjectRepository(session).create("other project")
        session.flush()
        return project.id, target.id, scope.id, scan.id, other_project.id


def test_stored_scope_fails_closed_when_timezone_is_lost(factory, stored_scope):
    project_id, target_id, scope_id, scan_id, _ = stored_scope
    with transaction(factory) as session:
        with pytest.raises(ValidationError, match="timezone"):
            RepositoryScanService(Recorder(), [analyzer]).run_stored(
                scan_id=str(scan_id), project_id=str(project_id), actor="tester", scan_uuid=scan_id,
                scope_id=scope_id, target_id=target_id, session=session)
    with transaction(factory) as session:
        assert session.scalar(select(Finding)) is None


def test_orchestrator_stored_scope_marks_the_scan_failed(factory, stored_scope, tmp_path):
    project_id, target_id, scope_id, _, _ = stored_scope
    store = ReportStore(tmp_path / "reports")
    with factory() as session:
        with pytest.raises(ValidationError):
            ScanOrchestrator(session, Recorder(), [analyzer], store).run(
                ScanRunRequest(project_id=project_id, actor="tester", scope_id=scope_id,
                               stored_target_id=target_id))
        assert session.scalar(select(Scan).where(Scan.started_at.is_not(None))).status == "failed"
        session.rollback()


def test_association_checks_run_before_restoration(factory, stored_scope):
    project_id, target_id, scope_id, scan_id, other_project = stored_scope
    with transaction(factory) as session:
        second_target = TargetRepository(session).create(
            project_id, Target(type="repository", locator="C:\\second-target"))
        session.flush()
        with pytest.raises(ValueError, match="different target"):
            ScopeRepository(session).load_for_scan(scope_id, target_id=second_target.id, scan_id=scan_id)
        with pytest.raises(ValueError, match="same project"):
            ScopeRepository(session).load_for_scan(scope_id, target_id=target_id, scan_id=uuid4())
        other_scan = Scan(id=uuid4(), project_id=other_project, status="created", mode="analysis")
        session.add(other_scan)
        session.flush()
        with pytest.raises(ValueError, match="same project"):
            ScopeRepository(session).load_for_scan(scope_id, target_id=target_id, scan_id=other_scan.id)


def test_request_rejects_ambiguous_scope_sources(stored_scope):
    project_id, target_id, scope_id, _, _ = stored_scope
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner",
                          starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                          repository_roots=["/tmp"])
    with pytest.raises(ValidationError, match="either stored scope ids or target and scope"):
        ScanRunRequest(project_id=project_id, actor="a", target=Target(type="repository", locator="/tmp"),
                       scope=scope, scope_id=scope_id, stored_target_id=target_id)
    with pytest.raises(ValidationError, match="both stored scope and target ids"):
        ScanRunRequest(project_id=project_id, actor="a", scope_id=scope_id)
    with pytest.raises(ValidationError, match="target and scope are required"):
        ScanRunRequest(project_id=project_id, actor="a")
