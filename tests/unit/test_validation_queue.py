"""Validation queue tests: triage decisions become pending approval requests."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from vulnmind.analysis.service import RepositoryScanRequest, RepositoryScanService
from vulnmind.findings import FindingCandidate
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Approval, Project, Scan
from vulnmind.persistence.repositories import ProjectRepository
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.schemas import Authorization, Target
from vulnmind.security.approvals import ApprovalService


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


def mixed_analyzer(content):
    if content.path != "a.py":
        return []
    return [
        FindingCandidate(title="Unverified lead", vulnerability_type="sqli", target_id="x",
                         location="a.py:1", source_tool="stub", status="unverified"),
        FindingCandidate(title="Different lead", vulnerability_type="xss", target_id="x",
                         location="a.py:2", source_tool="stub", status="insufficient_evidence"),
    ]


@pytest.fixture
def factory():
    engine = create_engine("sqlite://")
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def test_unverified_groups_create_pending_validation_requests(factory, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    with transaction(factory) as session:
        project = ProjectRepository(session).create("queue")
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
        session.add(scan)
        session.flush()
        result = RepositoryScanService(Recorder(), [mixed_analyzer],
                                       approvals=ApprovalService(session)).run(
            RepositoryScanRequest(scan_id=str(scan.id), project_id=str(project.id), actor="tester",
                                  target=Target(type="repository", locator=str(tmp_path)),
                                  scope=authorization(tmp_path), scan_uuid=scan.id),
            session=session)
        assert result.validation_requests == 2
    with transaction(factory) as session:
        pending = list(session.scalars(select(Approval).where(Approval.status == "pending")))
        assert len(pending) == 2
        actions = sorted(approval.action for approval in pending)
        assert actions == ["validation:sqli", "validation:xss"]
        assert all(len(approval.target) == 64 for approval in pending)


def test_analyzer_claimed_confirmed_still_needs_validation(factory, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")

    def claimed_confirmed(content):
        return [] if content.path != "a.py" else [
            FindingCandidate(title="Confirmed", vulnerability_type="sqli", target_id="x",
                             location="a.py:1", source_tool="stub", status="confirmed",
                             evidence_refs=["evidence:1"])]

    with transaction(factory) as session:
        project = ProjectRepository(session).create("queue")
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
        session.add(scan)
        session.flush()
        result = RepositoryScanService(Recorder(), [claimed_confirmed],
                                       approvals=ApprovalService(session)).run(
            RepositoryScanRequest(scan_id=str(scan.id), project_id=str(project.id), actor="tester",
                                  target=Target(type="repository", locator=str(tmp_path)),
                                  scope=authorization(tmp_path), scan_uuid=scan.id),
            session=session)
        # Analyzer claims are downgraded to unverified, so validation is still queued.
        assert result.validation_requests == 1
        assert result.analysis.findings[0].status == "unverified"
    with transaction(factory) as session:
        pending = list(session.scalars(select(Approval)))
        assert [approval.action for approval in pending] == ["validation:sqli"]


def test_rerunning_the_same_scan_does_not_duplicate_requests(factory, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    with transaction(factory) as session:
        project = ProjectRepository(session).create("queue")
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
        session.add(scan)
        session.flush()
        service = RepositoryScanService(Recorder(), [mixed_analyzer], approvals=ApprovalService(session))
        request = RepositoryScanRequest(scan_id=str(scan.id), project_id=str(project.id), actor="tester",
                                        target=Target(type="repository", locator=str(tmp_path)),
                                        scope=authorization(tmp_path), scan_uuid=scan.id)
        first = service.run(request, session=session)
        second = service.run(request, session=session)
        assert first.validation_requests == 2 and second.validation_requests == 0
    with transaction(factory) as session:
        assert len(list(session.scalars(select(Approval)))) == 2


def test_no_approvals_service_records_nothing(factory, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    with transaction(factory) as session:
        project = ProjectRepository(session).create("queue")
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
        session.add(scan)
        session.flush()
        result = RepositoryScanService(Recorder(), [mixed_analyzer]).run(
            RepositoryScanRequest(scan_id=str(scan.id), project_id=str(project.id), actor="tester",
                                  target=Target(type="repository", locator=str(tmp_path)),
                                  scope=authorization(tmp_path), scan_uuid=scan.id),
            session=session)
        assert result.validation_requests == 0


def test_failed_report_does_not_leave_approval_requests(factory, tmp_path):
    from vulnmind.persistence.models import Finding

    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    with transaction(factory) as session:
        project = ProjectRepository(session).create("queue-failure")
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
        session.add(scan)
        session.flush()
        service = RepositoryScanService(Recorder(), [mixed_analyzer], approvals=ApprovalService(session))
        request = RepositoryScanRequest(scan_id=str(scan.id), project_id=str(project.id), actor="tester",
                                        target=Target(type="repository", locator=str(tmp_path)),
                                        scope=authorization(tmp_path), scan_uuid=scan.id)
        with pytest.raises(ValueError):
            service.run(request, session=session, report_format="invalid")
    with transaction(factory) as session:
        assert session.scalar(select(Approval)) is None
        assert session.scalar(select(Finding)) is None
