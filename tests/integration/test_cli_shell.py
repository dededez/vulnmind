"""CLI shell-request / shell-run validation paths (SQLite, no sandbox needed)."""
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Approval, Project, Scan
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.tools.shell import SHELL_ACTION, ShellToolInput, shell_operation_digest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def workspace(tmp_path):
    database = tmp_path / "shell.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "app.py").write_text("print('ok')\n", encoding="utf-8")
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="shell cli")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="analysis")
        session.add(scan)
        session.flush()
        scan_id = scan.id
    engine.dispose()
    now = datetime.now(timezone.utc)
    scope = {"authorization_source": "local test", "approved_by": "owner",
             "starts_at": (now - timedelta(hours=1)).isoformat(),
             "expires_at": (now + timedelta(hours=1)).isoformat(),
             "repository_roots": [str(repo)]}
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(scope), encoding="utf-8")
    return database, repo, scan_id, scope_file


def env_for(workspace):
    database, _, _, _ = workspace
    env = os.environ.copy()
    env.update({"PYTHONPATH": str(PROJECT_ROOT / "src"), "PYTHONIOENCODING": "utf-8",
                "VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"})
    return env


def run_cli(kind, *arguments, env):
    return subprocess.run([sys.executable, "-m", "vulnmind", kind, *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=120)


def request_args(workspace):
    _, repo, scan_id, scope_file = workspace
    return ["--scan-id", scan_id, "--cwd", str(repo / "pkg"), "--argv", "ls", "--argv", "-1"]


def test_shell_request_records_a_bound_pending_approval(workspace):
    database, repo, scan_id, _ = workspace
    result = run_cli("shell-request", *request_args(workspace), env=env_for(workspace))
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "requested" and payload["action"] == SHELL_ACTION
    request = ShellToolInput(scan_id=scan_id, argv=["ls", "-1"], cwd=str(repo / "pkg"),
                             purpose="operator-requested read-only command")
    assert payload["operation_digest"] == shell_operation_digest(request)
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        row = session.scalar(select(Approval))
        assert row.status == "pending" and row.operation_hash == payload["operation_digest"]
    engine.dispose()


def test_shell_request_without_database_is_blocked(workspace):
    env = env_for(workspace)
    env["VULNMIND_DATABASE_URL"] = ""
    result = run_cli("shell-request", *request_args(workspace), env=env)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"


def test_shell_request_with_unknown_scan_is_blocked(workspace):
    _, repo, _, _ = workspace
    result = run_cli("shell-request", "--scan-id", uuid4(), "--cwd", str(repo / "pkg"),
                     "--argv", "ls", env=env_for(workspace))
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"


def test_shell_run_without_a_valid_approval_is_blocked(workspace):
    _, repo, scan_id, scope_file = workspace
    result = run_cli("shell-run", *request_args(workspace), "--repository", repo,
                     "--scope-file", scope_file, "--approval-token", uuid4(),
                     env=env_for(workspace))
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"


def test_shell_run_rejects_a_disallowed_program_before_approval(workspace):
    _, repo, scan_id, scope_file = workspace
    result = run_cli("shell-run", "--scan-id", scan_id, "--cwd", str(repo / "pkg"),
                     "--argv", "sh", "--argv", "id",
                     "--repository", repo, "--scope-file", scope_file,
                     "--approval-token", uuid4(), env=env_for(workspace))
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"


def test_shell_run_requires_a_scope_file(workspace):
    _, repo, _, _ = workspace
    result = run_cli("shell-run", *request_args(workspace), "--repository", repo,
                     "--approval-token", uuid4(), env=env_for(workspace))
    assert result.returncode == 2
    assert "scope-file" in result.stderr
