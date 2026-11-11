"""Approval credential tests: HMAC binding and service enforcement."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Project, Scan
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.security.approval_tokens import ApprovalTokenError, ApprovalTokenSigner
from vulnmind.security.approvals import ApprovalService

SECRET = "0123456789abcdef0123456789abcdef"
TOKEN_ID = uuid4()


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
        project = Project(id=uuid4(), name="tokens")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="test")
        session.add(scan)
        session.flush()
        return scan.id


def test_signer_round_trip_and_binding():
    signer = ApprovalTokenSigner(SECRET)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    target = uuid4()
    token = signer.sign(approval_id=TOKEN_ID, operation_hash=None, approved=True, scan_id=target, action="shell.exec", target="/repo", expires_at=expires)
    assert signer.verify(token, approval_id=TOKEN_ID, operation_hash=None, approved=True, scan_id=target, action="shell.exec", target="/repo", expires_at=expires)
    assert not signer.verify(token, approval_id=TOKEN_ID, operation_hash=None, approved=True, scan_id=uuid4(), action="shell.exec", target="/repo", expires_at=expires)
    assert not signer.verify(token, approval_id=TOKEN_ID, operation_hash=None, approved=True, scan_id=target, action="http.request", target="/repo", expires_at=expires)
    assert not signer.verify(token, approval_id=TOKEN_ID, operation_hash=None, approved=True, scan_id=target, action="shell.exec", target="/other", expires_at=expires)
    assert not signer.verify(token, approval_id=TOKEN_ID, operation_hash=None, approved=True, scan_id=target, action="shell.exec", target="/repo", expires_at=None)
    tampered = token[:-1] + ("1" if token[-1] != "1" else "2")
    assert not signer.verify(tampered, approval_id=TOKEN_ID, operation_hash=None, approved=True, scan_id=target, action="shell.exec", target="/repo",
                             expires_at=expires)
    assert not signer.verify("not-a-token", approval_id=TOKEN_ID, operation_hash=None, approved=True, scan_id=target, action="shell.exec", target="/repo",
                             expires_at=expires)


def test_expired_and_future_credentials_are_rejected():
    signer = ApprovalTokenSigner(SECRET)
    when = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    expires = when + timedelta(hours=1)
    scan = uuid4()
    token = signer.sign(approval_id=TOKEN_ID, operation_hash=None, approved=True, scan_id=scan, action="a", target="t", expires_at=expires)
    assert signer.verify(token, approval_id=TOKEN_ID, operation_hash=None, approved=True, scan_id=scan, action="a", target="t", expires_at=expires,
                         now=when + timedelta(minutes=30))
    assert not signer.verify(token, approval_id=TOKEN_ID, operation_hash=None, approved=True, scan_id=scan, action="a", target="t", expires_at=expires,
                             now=expires + timedelta(seconds=1))


def test_short_secrets_are_refused():
    for value in ("", "short", b"123456789012345"):
        with pytest.raises(ApprovalTokenError):
            ApprovalTokenSigner(value)


def test_service_requires_a_valid_credential_when_configured(factory, scan_id):
    signer = ApprovalTokenSigner(SECRET)
    with transaction(factory) as session:
        service = ApprovalService(session, signer)
        approval = service.request(scan_id=scan_id, action="shell.exec", target="/repo",
                                   operation_hash="a" * 64)
        session.flush()
        with pytest.raises(ValueError, match="credential"):
            service.decide(approval.id, approver="lead", approved=True)
        token = signer.sign(approval_id=approval.id, operation_hash=approval.operation_hash, approved=True, scan_id=scan_id, action="shell.exec", target="/repo",
                            expires_at=approval.expires_at)
        decided = service.decide(approval.id, approver="lead", approved=True, credential=token)
        assert decided.status == "approved" and decided.approver == "lead"


def test_service_rejects_a_credential_for_another_request(factory, scan_id):
    signer = ApprovalTokenSigner(SECRET)
    other_scan = uuid4()
    with transaction(factory) as session:
        service = ApprovalService(session, signer)
        approval = service.request(scan_id=scan_id, action="shell.exec", target="/repo")
        session.flush()
        wrong = signer.sign(approval_id=approval.id, operation_hash=approval.operation_hash, approved=True, scan_id=other_scan, action="shell.exec", target="/repo",
                            expires_at=approval.expires_at)
        with pytest.raises(ValueError, match="credential"):
            service.decide(approval.id, approver="lead", approved=True, credential=wrong)


def test_service_without_a_signer_keeps_the_prototype_behaviour(factory, scan_id):
    with transaction(factory) as session:
        service = ApprovalService(session)
        approval = service.request(scan_id=scan_id, action="shell.exec", target="/repo")
        session.flush()
        assert service.decide(approval.id, approver="lead", approved=True).status == "approved"


def test_credential_binds_request_and_operation_and_encodes_fields_unambiguously():
    signer = ApprovalTokenSigner(SECRET)
    expiry = datetime.now(timezone.utc) + timedelta(hours=1)
    scan, approval = uuid4(), uuid4()
    args = dict(approval_id=approval, scan_id=scan, action="a\nb", target="c", expires_at=expiry, operation_hash="a" * 64, approved=True)
    token = signer.sign(**args)
    assert signer.verify(token, **args)
    assert not signer.verify(token, **{**args, "approval_id": uuid4()})
    assert not signer.verify(token, **{**args, "operation_hash": "b" * 64})
    assert not signer.verify(token, **{**args, "approved": False})
    assert not signer.verify(token, **{**args, "action": "a", "target": "b\nc"})
