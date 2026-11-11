"""CLI approvals tests against a SQLite database."""
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Project, Scan
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.security.approval_tokens import ApprovalTokenSigner

SECRET = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def seeded(tmp_path):
    database = tmp_path / "approvals.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(timezone.utc)
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="cli approvals")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
        session.add(scan)
        session.flush()
        from vulnmind.persistence.models import Approval
        approval = Approval(id=uuid4(), scan_id=scan.id, action="validation:sqli", target="a" * 64,
                            status="pending", expires_at=now + timedelta(hours=1))
        session.add(approval)
        session.flush()
        scan_id, approval_id, expires_at = scan.id, approval.id, approval.expires_at
    engine.dispose()
    return database, scan_id, approval_id, expires_at


def run_approvals(*arguments, env_overrides=None):
    env = os.environ.copy()
    env.update(env_overrides or {})
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-m", "vulnmind", "approvals", *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=20)


def test_list_shows_pending_requests(seeded):
    database, scan_id, approval_id, _ = seeded
    result = run_approvals("list", "--scan-id", scan_id,
                           env_overrides={"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"})
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert [item["id"] for item in payload["pending"]] == [str(approval_id)]
    assert payload["pending"][0]["action"] == "validation:sqli"
    assert payload["pending"][0]["expires_at"].endswith("+00:00")


def test_decide_without_a_configured_secret(seeded):
    database, _, approval_id, _ = seeded
    result = run_approvals("decide", "--id", approval_id, "--approver", "lead",
                           env_overrides={"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"})
    assert result.returncode == 2, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"


def test_decide_requires_a_matching_credential_when_a_secret_is_set(seeded):
    database, scan_id, approval_id, expires_at = seeded
    env = {"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}", "VULNMIND_APPROVAL_SECRET": SECRET}
    blocked = run_approvals("decide", "--id", approval_id, "--approver", "lead", env_overrides=env)
    assert blocked.returncode == 2 and json.loads(blocked.stdout)["status"] == "blocked"

    signer = ApprovalTokenSigner(SECRET)
    credential = signer.sign(approval_id=approval_id, operation_hash=None, approved=True, scan_id=scan_id, action="validation:sqli", target="a" * 64,
                             expires_at=expires_at)
    ok = run_approvals("decide", "--id", approval_id, "--approver", "lead", "--credential", credential,
                       env_overrides=env)
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["status"] == "approved"


def test_deny_and_error_paths(seeded):
    database, scan_id, approval_id, expires_at = seeded
    env = {"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}", "VULNMIND_APPROVAL_SECRET": SECRET}
    credential = ApprovalTokenSigner(SECRET).sign(approval_id=approval_id, scan_id=scan_id,
        action="validation:sqli", target="a" * 64, expires_at=expires_at, operation_hash=None, approved=False)
    denied = run_approvals("decide", "--id", approval_id, "--approver", "lead", "--deny", "--credential", credential, env_overrides=env)
    assert json.loads(denied.stdout)["status"] == "denied"
    missing = run_approvals("decide", "--id", uuid4(), "--approver", "lead", env_overrides=env)
    assert missing.returncode == 2
    no_db = run_approvals("list", "--scan-id", uuid4(), env_overrides={"VULNMIND_DATABASE_URL": ""})
    assert no_db.returncode == 2


def test_cli_ssh_verifier_binds_principal_and_decision(seeded, tmp_path, monkeypatch, capsys):
    from argparse import Namespace
    from vulnmind.__main__ import _approvals
    from vulnmind.security.ssh_approvals import SshSignatureVerifier, credential
    database, _, approval_id, _ = seeded
    allowed = tmp_path / "allowed_signers"
    allowed.write_text("fixture", encoding="utf-8")
    monkeypatch.setenv("VULNMIND_DATABASE_URL", f"sqlite:///{database.as_posix()}")
    monkeypatch.setenv("VULNMIND_APPROVAL_SECRET", "")
    monkeypatch.setenv("VULNMIND_APPROVAL_ALLOWED_SIGNERS", str(allowed))
    monkeypatch.setattr(SshSignatureVerifier, "verify", lambda self, statement, signature, *, principal: principal == "lead" and not statement.approved and signature == b"test")
    args = Namespace(approvals_command="decide", id=str(approval_id), approver="lead", deny=False, credential=credential(b"test"))
    assert _approvals(args) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"
    args.deny = True
    assert _approvals(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "denied"


def test_cli_rejects_ambiguous_auth_configuration(seeded, tmp_path, monkeypatch, capsys):
    from argparse import Namespace
    from vulnmind.__main__ import _approvals
    database, _, approval_id, _ = seeded
    allowed = tmp_path / "allowed_signers"
    allowed.write_text("fixture", encoding="utf-8")
    monkeypatch.setenv("VULNMIND_DATABASE_URL", f"sqlite:///{database.as_posix()}")
    monkeypatch.setenv("VULNMIND_APPROVAL_SECRET", SECRET)
    monkeypatch.setenv("VULNMIND_APPROVAL_ALLOWED_SIGNERS", str(allowed))
    args = Namespace(approvals_command="decide", id=str(approval_id), approver="lead", deny=False, credential="")
    assert _approvals(args) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"


def test_cli_real_ssh_signature_decides_with_retained_files(seeded, tmp_path, monkeypatch, capsys):
    import shutil
    from argparse import Namespace
    from vulnmind.__main__ import _approvals
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
    database, scan_id, approval_id, expires_at = seeded
    key = tmp_path / "key"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key)],
                   check=True, capture_output=True)
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(ssh.allowed_signers_line("lead", tmp_path / "key.pub"), encoding="utf-8")
    monkeypatch.setenv("VULNMIND_DATABASE_URL", f"sqlite:///{database.as_posix()}")
    monkeypatch.setenv("VULNMIND_APPROVAL_SECRET", "")
    monkeypatch.setenv("VULNMIND_APPROVAL_ALLOWED_SIGNERS", str(allowed))
    assert _approvals(Namespace(approvals_command="list", scan_id=str(scan_id))) == 0
    item = json.loads(capsys.readouterr().out)["pending"][0]
    statement = ssh.ApprovalStatement(approval_id=item["id"], scan_id=str(scan_id),
                                      action=item["action"], target=item["target"],
                                      expires_at=item["expires_at"], operation_hash=item["operation_hash"],
                                      approved=True)
    token = ssh.credential(ssh.sign_statement(statement, key))
    args = Namespace(approvals_command="decide", id=str(approval_id), approver="lead",
                     deny=False, credential=token)
    assert _approvals(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "approved"
