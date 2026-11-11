"""OpenSSH approval tests using the real ssh-keygen binary."""
import base64
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Approval, Project, Scan
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.security.ssh_approvals import (
    ApprovalStatement, SshSignatureVerifier, allowed_signers_line, credential, decode_credential,
    sign_statement, statement_for,
)

pytestmark = pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen is not available")


@pytest.fixture
def keys(tmp_path):
    key = tmp_path / "approver"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key)], check=True,
                   capture_output=True)
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(allowed_signers_line("approver@example.test", tmp_path / "approver.pub"),
                       encoding="utf-8")
    return key, allowed


def statement(**overrides):
    payload = {"approval_id": str(uuid4()), "scan_id": str(uuid4()), "action": "shell.exec",
               "target": "/repo", "expires_at": "2026-11-04T00:00:00+00:00", "operation_hash": "a" * 64, "approved": True}
    payload.update(overrides)
    return ApprovalStatement(**payload)


def test_signed_statement_verifies(keys):
    key, allowed = keys
    payload = statement()
    signature = sign_statement(payload, key)
    verifier = SshSignatureVerifier(allowed)
    assert verifier.verify(payload, signature, principal="approver@example.test") is True
    assert verifier.verify(payload, signature, principal="someone@example.test") is False


def test_tampered_statement_and_bad_signature_fail(keys):
    key, allowed = keys
    payload = statement()
    signature = sign_statement(payload, key)
    verifier = SshSignatureVerifier(allowed)
    tampered = statement(**{**payload.model_dump(), "target": "/other"})
    assert verifier.verify(tampered, signature, principal="approver@example.test") is False
    assert verifier.verify(payload, b"not-a-signature", principal="approver@example.test") is False
    assert verifier.verify(payload, base64.b64encode(b"garbage"), principal="approver@example.test") is False
    assert verifier.verify(payload, signature, principal=" ") is False


def test_credential_round_trip_and_validation(keys):
    key, _ = keys
    signature = sign_statement(statement(), key)
    encoded = credential(signature)
    assert encoded.startswith("ssh-sig:") and decode_credential(encoded) == signature
    with pytest.raises(ValueError):
        decode_credential("hmac:value")
    with pytest.raises(ValueError):
        decode_credential("ssh-sig:!!!")
    with pytest.raises(ValueError):
        allowed_signers_line("principal", Path("missing.pub"))


def test_verifier_requires_an_allowed_signers_file(tmp_path):
    with pytest.raises((ValueError, OSError)):
        SshSignatureVerifier(tmp_path / "missing")
    target = tmp_path / "allowed"
    target.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="namespace"):
        SshSignatureVerifier(target, namespace=" ")


@pytest.fixture
def factory(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'ssh.db').as_posix()}")
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def test_statement_matches_the_approval_row(factory):
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="ssh")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
        session.add(scan)
        session.flush()
        approval = Approval(id=uuid4(), scan_id=scan.id, action="validation:sqli", target="f" * 64,
                            status="pending", operation_hash="b" * 64,
                            expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        session.add(approval)
        session.flush()
        payload = statement_for(approval, approved=True)
        assert payload.approval_id == str(approval.id)
        assert payload.scan_id == str(scan.id)
        assert payload.action == "validation:sqli" and payload.operation_hash == "b" * 64
        approval.expires_at = None
        with pytest.raises(ValueError, match="no expiry"):
            statement_for(approval, approved=True)


def test_service_requires_a_valid_ssh_signature(factory, keys):
    from vulnmind.security.approvals import ApprovalService

    key, allowed = keys
    verifier = SshSignatureVerifier(allowed)
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="ssh decide")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
        session.add(scan)
        session.flush()
        service = ApprovalService(session, ssh_verifier=verifier)
        approval = service.request(scan_id=scan.id, action="shell.exec", target="/repo",
                                   operation_hash="a" * 64)
        session.flush()
        with pytest.raises(ValueError, match="signature is missing"):
            service.decide(approval.id, approver="approver@example.test", approved=True)
        signature = sign_statement(statement_for(approval, approved=True), key)
        with pytest.raises(ValueError, match="signature is missing"):
            service.decide(approval.id, approver="intruder@example.test", approved=True,
                           credential=credential(signature))
        decided = service.decide(approval.id, approver="approver@example.test", approved=True,
                                 credential=credential(signature))
        assert decided.status == "approved" and decided.approver == "approver@example.test"


def test_signed_rejection_cannot_authorize_approval(factory, keys):
    from vulnmind.security.approvals import ApprovalService
    key, allowed = keys
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="decision binding")
        session.add(project); session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="test")
        session.add(scan); session.flush()
        service = ApprovalService(session, ssh_verifier=SshSignatureVerifier(allowed))
        row = service.request(scan_id=scan.id, action="shell.exec", target="/repo")
        session.flush()
        signature = sign_statement(statement_for(row, approved=False), key)
        with pytest.raises(ValueError, match="signature"):
            service.decide(row.id, approver="approver@example.test", approved=True, credential=credential(signature))
        assert service.decide(row.id, approver="approver@example.test", approved=False, credential=credential(signature)).status == "denied"
