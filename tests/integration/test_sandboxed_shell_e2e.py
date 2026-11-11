"""End-to-end: shell-request → operator approval → sandboxed shell-run.

Skipped unless the WSL sandbox distro is installed. This exercises the real
approval consumption, the read-only mount and the BusyBox applet allowlist.
"""
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Approval, Project, Scan
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.security.approvals import ApprovalService

DISTRO = "VulnMindSandbox"
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _distro_available() -> bool:
    if shutil.which("wsl.exe") is None:
        return False
    try:
        completed = subprocess.run(["wsl.exe", "-l", "-q"], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    names = completed.stdout.decode("utf-16-le", "ignore").replace("\x00", "")
    return DISTRO in names


pytestmark = pytest.mark.skipif(not _distro_available(), reason="WSL sandbox distro is not installed")


@pytest.fixture
def workspace(tmp_path):
    database = tmp_path / "e2e.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "app.py").write_text("print('ok')\n", encoding="utf-8")
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="shell e2e")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="analysis")
        session.add(scan)
        session.flush()
        scan_id = scan.id
    engine.dispose()
    now = datetime.now(timezone.utc)
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({
        "authorization_source": "local test", "approved_by": "owner",
        "starts_at": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "repository_roots": [str(repo)]}), encoding="utf-8")
    env = os.environ.copy()
    env.update({"PYTHONPATH": str(PROJECT_ROOT / "src"), "PYTHONIOENCODING": "utf-8",
                "VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"})
    return {"database": database, "repo": repo, "scan_id": scan_id, "scope_file": scope_file,
            "factory": factory, "env": env}


def run_cli(kind, *arguments, env):
    return subprocess.run([sys.executable, "-m", "vulnmind", kind, *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=180)


def test_request_approval_then_run_in_the_sandbox(workspace):
    args = ["--scan-id", workspace["scan_id"], "--cwd", str(workspace["repo"] / "pkg"),
            "--argv", "ls", "--argv", "app.py"]
    requested = run_cli("shell-request", *args, env=workspace["env"])
    assert requested.returncode == 0, requested.stdout + requested.stderr
    approval_id = json.loads(requested.stdout)["approval_id"]
    with transaction(workspace["factory"]) as session:
        ApprovalService(session).decide(UUID(approval_id), approver="owner", approved=True)
    run = run_cli("shell-run", *args, "--repository", workspace["repo"],
                  "--scope-file", workspace["scope_file"], "--approval-token", approval_id,
                  env=workspace["env"])
    assert run.returncode == 0, run.stdout + run.stderr
    payload = json.loads(run.stdout)
    assert payload["status"] == "completed" and payload["exit_code"] == 0
    assert "app.py" in payload["output"]
    assert payload["timed_out"] is False
    with transaction(workspace["factory"]) as session:
        row = session.scalar(select(Approval))
        assert row.status == "consumed" and row.consumed_at is not None
    replay = run_cli("shell-run", *args, "--repository", workspace["repo"],
                     "--scope-file", workspace["scope_file"], "--approval-token", approval_id,
                     env=workspace["env"])
    assert replay.returncode == 2
    assert json.loads(replay.stdout)["status"] == "blocked"
