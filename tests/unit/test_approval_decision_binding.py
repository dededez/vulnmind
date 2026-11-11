"""Approval decisions must match the exact signed choice."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from vulnmind.persistence.base import Base
from vulnmind.security.approvals import ApprovalService
from vulnmind.security.approval_tokens import ApprovalTokenSigner
from vulnmind.security.ssh_approvals import SshSignatureVerifier, credential


def test_ssh_rejection_cannot_be_replayed_as_approval(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    verifier = object.__new__(SshSignatureVerifier)
    monkeypatch.setattr(SshSignatureVerifier, "verify", lambda self, statement, signature, *, principal: statement.approved is False and signature == b"signature")
    with Session(engine) as session:
        service = ApprovalService(session, ssh_verifier=verifier)
        row = service.request(scan_id=uuid4(), action="shell.exec", target="/repo")
        session.flush()
        token = credential(b"signature")
        with pytest.raises(ValueError, match="signature"):
            service.decide(row.id, approver="lead", approved=True, credential=token)
        assert service.decide(row.id, approver="lead", approved=False, credential=token).status == "denied"
    engine.dispose()


def test_hmac_rejection_cannot_be_replayed_as_approval():
    signer = ApprovalTokenSigner(b"x" * 32)
    fields = dict(approval_id=uuid4(), scan_id=uuid4(), action="shell.exec", target="/repo", expires_at=datetime.now(timezone.utc)+timedelta(minutes=5), operation_hash=None)
    token = signer.sign(**fields, approved=False)
    assert signer.verify(token, **fields, approved=False)
    assert not signer.verify(token, **fields, approved=True)


def test_real_ssh_signature_cannot_change_decision(tmp_path, monkeypatch):
    import shutil
    import subprocess
    import vulnmind.security.ssh_approvals as ssh
    if not shutil.which("ssh-keygen"):
        pytest.skip("ssh-keygen unavailable")
    class RetainedDirectory:
        def __init__(self, prefix):
            self.path = tmp_path / (prefix + uuid4().hex)
        def __enter__(self):
            self.path.mkdir()
            return str(self.path)
        def __exit__(self, *args):
            return False
    monkeypatch.setattr(ssh.tempfile, "TemporaryDirectory", RetainedDirectory)
    key = tmp_path / "signing_key"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key)], check=True, capture_output=True)
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(ssh.allowed_signers_line("lead", tmp_path / "signing_key.pub"), encoding="utf-8")
    fields = dict(approval_id=str(uuid4()), scan_id=str(uuid4()), action="shell.exec", target="/repo", expires_at="2030-01-01T00:00:00+00:00", operation_hash=None)
    rejection = ssh.ApprovalStatement(**fields, approved=False)
    approval = ssh.ApprovalStatement(**fields, approved=True)
    signature = ssh.sign_statement(rejection, key)
    verifier = ssh.SshSignatureVerifier(allowed)
    assert verifier.verify(rejection, signature, principal="lead")
    assert not verifier.verify(approval, signature, principal="lead")
