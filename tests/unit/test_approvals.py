"""Approval workflow and its use as a shell gate (SQLite)."""
from datetime import datetime, timedelta, timezone
import sys
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Project, Scan
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.security.approvals import ApprovalService, operation_digest
from vulnmind.schemas import Authorization, Target
from vulnmind.tools.shell import ShellDenied, ShellExecutor, ShellToolInput


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


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
def scan_id(factory):
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="approval test")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="created", mode="test")
        session.add(scan)
        session.flush()
        return scan.id


def authorization(root):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)])


def test_request_and_approve(factory, scan_id):
    with transaction(factory) as session:
        service = ApprovalService(session)
        pending = service.request(scan_id=scan_id, action="shell.exec", target="/repo")
        session.flush()
        approval_id = pending.id
        assert pending.status == "pending" and pending.approver is None
        assert [row.id for row in service.list_pending(scan_id)] == [approval_id]
        approved = service.decide(approval_id, approver="security-lead", approved=True)
        assert approved.status == "approved" and approved.approver == "security-lead"
        assert approved.approved_at is not None
        assert service.list_pending(scan_id) == []
    with transaction(factory) as session:
        service = ApprovalService(session)
        assert service.is_approved(str(approval_id), scan_id=scan_id, action="shell.exec", target="/repo") is True
        assert service.is_approved(str(approval_id), scan_id=scan_id, action="shell.exec", target="/other") is False
        assert service.is_approved(str(approval_id), scan_id=scan_id, action="http.request", target="/repo") is False
        assert service.is_approved("not-a-uuid", scan_id=scan_id, action="shell.exec", target="/repo") is False
        assert service.is_approved(str(uuid4()), scan_id=scan_id, action="shell.exec", target="/repo") is False


def test_denied_and_double_decision(factory, scan_id):
    with transaction(factory) as session:
        service = ApprovalService(session)
        approval = service.request(scan_id=scan_id, action="shell.exec", target="/repo")
        session.flush()
        approval_id = approval.id
        assert service.decide(approval_id, approver="lead", approved=False).status == "denied"
        assert service.is_approved(str(approval_id), scan_id=scan_id, action="shell.exec", target="/repo") is False
        with pytest.raises(ValueError, match="already decided"):
            service.decide(approval_id, approver="lead", approved=True)
        with pytest.raises(KeyError):
            service.decide(uuid4(), approver="lead", approved=True)


def test_expired_approval_is_no_longer_valid(factory, scan_id):
    with transaction(factory) as session:
        service = ApprovalService(session)
        approval = service.request(scan_id=scan_id, action="shell.exec", target="/repo",
                                   valid_for=timedelta(hours=1))
        session.flush()
        service.decide(approval.id, approver="lead", approved=True)
        approval_id = approval.id
        assert service.is_approved(str(approval_id), scan_id=scan_id, action="shell.exec", target="/repo") is True
        approval.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    with transaction(factory) as session:
        assert ApprovalService(session).is_approved(str(approval_id), scan_id=scan_id, action="shell.exec", target="/repo") is False
        with pytest.raises(ValueError, match="positive duration"):
            ApprovalService(session).request(scan_id=scan_id, action="a", target="t", valid_for=timedelta(0))


def test_approval_validation(factory, scan_id):
    with transaction(factory) as session:
        service = ApprovalService(session)
        with pytest.raises(ValueError, match="action"):
            service.request(scan_id=scan_id, action=" ", target="/repo")
        with pytest.raises(ValueError, match="target"):
            service.request(scan_id=scan_id, action="shell.exec", target=" ")
        approval = service.request(scan_id=scan_id, action="shell.exec", target="/repo")
        session.flush()
        with pytest.raises(ValueError, match="approver"):
            service.decide(approval.id, approver=" ", approved=True)


def test_shell_medium_risk_uses_the_database_approval(factory, scan_id, tmp_path):
    with transaction(factory) as session:
        approval = ApprovalService(session).request(scan_id=scan_id, action="shell.exec", target=str(tmp_path))
        session.flush()
        ApprovalService(session).decide(approval.id, approver="lead", approved=True)
        approval_id = str(approval.id)
    payload = ShellToolInput(argv=[sys.executable, "-c", "print('approved')"], cwd=str(tmp_path),
                             purpose="medium risk test", risk_level="medium", approval_token=approval_id)
    with transaction(factory) as session:
        with pytest.raises(ShellDenied, match="disabled"):
            ShellExecutor(Recorder(), approvals=ApprovalService(session)).run(
                payload, actor="tester", target=Target(type="repository", locator=str(tmp_path)),
                scope=authorization(tmp_path))

    unapproved = ShellToolInput(argv=[sys.executable, "-c", "print('nope')"], cwd=str(tmp_path),
                                purpose="medium risk test", risk_level="medium", approval_token=str(uuid4()))
    with transaction(factory) as session:
        with pytest.raises(ShellDenied, match="disabled"):
            ShellExecutor(Recorder(), approvals=ApprovalService(session)).run(
                unapproved, actor="tester", target=Target(type="repository", locator=str(tmp_path)),
                scope=authorization(tmp_path))


def test_expired_pending_request_cannot_be_decided(factory, scan_id):
    with transaction(factory) as session:
        service = ApprovalService(session)
        row = service.request(scan_id=scan_id, action="shell.exec", target="/repo")
        session.flush()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.flush()
        with pytest.raises(ValueError, match="expired"):
            service.decide(row.id, approver="lead", approved=True)
        assert row.status == "pending"


def test_stale_session_cannot_overwrite_decision(factory, scan_id):
    with transaction(factory) as session:
        item = ApprovalService(session).request(scan_id=scan_id, action="shell.exec", target="/repo")
        session.flush()
        approval_id = item.id
    with factory() as first, factory() as second:
        assert ApprovalService(second).get(approval_id).status == "pending"
        ApprovalService(first).decide(approval_id, approver="first", approved=True)
        first.commit()
        with pytest.raises(ValueError, match="already decided"):
            ApprovalService(second).decide(approval_id, approver="second", approved=False)
        second.rollback()
    with transaction(factory) as session:
        assert ApprovalService(session).get(approval_id).approver == "first"


def test_bound_approval_is_consumed_once_and_rejects_changed_operation(factory, scan_id):
    original = operation_digest({"argv": ["scanner", "--version"], "cwd": "/repo"})
    changed = operation_digest({"argv": ["scanner", "--other"], "cwd": "/repo"})
    with transaction(factory) as session:
        service = ApprovalService(session)
        record = service.request(scan_id=scan_id, action="shell.exec", target="/repo", operation_hash=original)
        session.flush()
        service.decide(record.id, approver="reviewer", approved=True)
        approval_id = str(record.id)
    with transaction(factory) as session:
        service = ApprovalService(session)
        assert not service.consume_bound(approval_id, scan_id=scan_id, action="shell.exec", target="/repo", operation_hash=changed)
        assert not service.consume_bound(approval_id, scan_id=uuid4(), action="shell.exec", target="/repo", operation_hash=original)
        assert not service.consume_bound(approval_id, scan_id=scan_id, action="other", target="/repo", operation_hash=original)
        assert not service.consume_bound(approval_id, scan_id=scan_id, action="shell.exec", target="/other", operation_hash=original)
        assert service.consume_bound(approval_id, scan_id=scan_id, action="shell.exec", target="/repo", operation_hash=original)
    with transaction(factory) as session:
        service = ApprovalService(session)
        assert not service.consume_bound(approval_id, scan_id=scan_id, action="shell.exec", target="/repo", operation_hash=original)
        assert service.get(UUID(approval_id)).consumed_at is not None


def test_legacy_unbound_approval_cannot_be_consumed(factory, scan_id):
    with transaction(factory) as session:
        service = ApprovalService(session)
        record = service.request(scan_id=scan_id, action="shell.exec", target="/repo")
        session.flush()
        service.decide(record.id, approver="reviewer", approved=True)
        assert not service.consume_bound(str(record.id), scan_id=scan_id, action="shell.exec", target="/repo", operation_hash=operation_digest({"x": 1}))


def test_consumption_rollback_does_not_burn_approval(factory, scan_id):
    digest = operation_digest({"operation": "test"})
    with transaction(factory) as session:
        service = ApprovalService(session)
        record = service.request(scan_id=scan_id, action="test", target="target", operation_hash=digest)
        session.flush()
        service.decide(record.id, approver="reviewer", approved=True)
        approval_id = str(record.id)
    with factory() as session:
        assert ApprovalService(session).consume_bound(approval_id, scan_id=scan_id, action="test", target="target", operation_hash=digest)
        session.rollback()
    with transaction(factory) as session:
        assert ApprovalService(session).consume_bound(approval_id, scan_id=scan_id, action="test", target="target", operation_hash=digest)


def test_operation_digest_is_deterministic_and_rejects_invalid_input():
    assert operation_digest({"a": 1, "b": [2]}) == operation_digest({"b": [2], "a": 1})
    assert operation_digest({"a": 1}) != operation_digest({"a": 2})
    for value in ({}, {"value": float("nan")}, {"value": object()}, {"nested": {1: "ambiguous"}}):
        with pytest.raises(ValueError):
            operation_digest(value)
    cyclic = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError, match="nested or complex"):
        operation_digest({"cycle": cyclic})


def test_bound_consumption_rejects_expiry_and_stale_sessions(factory, scan_id):
    digest = operation_digest({"operation": "test"})
    with transaction(factory) as session:
        service = ApprovalService(session)
        record = service.request(scan_id=scan_id, action="test", target="target", operation_hash=digest)
        session.flush()
        service.decide(record.id, approver="reviewer", approved=True)
        approval_id = record.id
    with factory() as first, factory() as second:
        assert ApprovalService(second).get(approval_id).status == "approved"
        assert ApprovalService(first).consume_bound(str(approval_id), scan_id=scan_id, action="test", target="target", operation_hash=digest)
        first.commit()
        assert not ApprovalService(second).consume_bound(str(approval_id), scan_id=scan_id, action="test", target="target", operation_hash=digest)
        second.rollback()
    with transaction(factory) as session:
        service = ApprovalService(session)
        expired = service.request(scan_id=scan_id, action="test", target="target", operation_hash=digest)
        session.flush()
        service.decide(expired.id, approver="reviewer", approved=True)
        expired.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.flush()
        assert not service.consume_bound(str(expired.id), scan_id=scan_id, action="test", target="target", operation_hash=digest)


def test_bound_consumption_rejects_approval_without_decision_metadata(factory, scan_id):
    digest = operation_digest({"operation": "test"})
    with transaction(factory) as session:
        service = ApprovalService(session)
        record = service.request(scan_id=scan_id, action="test", target="target", operation_hash=digest)
        session.flush()
        record.status = "approved"  # simulate inconsistent legacy or tampered data
        session.flush()
        assert not service.consume_bound(str(record.id), scan_id=scan_id, action="test", target="target", operation_hash=digest)
