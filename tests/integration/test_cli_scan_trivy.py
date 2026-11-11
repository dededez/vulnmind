"""End-to-end scan with Trivy inside the filesystem-isolated WSL sandbox."""
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Project

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DISTRO = "VulnMindSandbox"


def sandbox_trivy_ready() -> bool:
    if not shutil.which("wsl.exe"):
        return False
    try:
        result = subprocess.run(
            ["wsl.exe", "-d", DISTRO, "-u", "root", "--", "/bin/sh", "-c",
             "test -x /usr/local/bin/trivy && test -s /var/cache/trivy/db/trivy.db"],
            capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


pytestmark = pytest.mark.skipif(not sandbox_trivy_ready(), reason="sandbox Trivy DB is not prepared")


@pytest.fixture
def workspace(tmp_path):
    database = tmp_path / "trivy.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.19.0\nflask==1.0\n", encoding="utf-8")
    with factory() as session:
        project = Project(id=uuid4(), name="trivy e2e")
        session.add(project)
        session.commit()
        project_id = project.id
    engine.dispose()
    now = datetime.now(timezone.utc)
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({
        "authorization_source": "local e2e", "approved_by": "owner",
        "starts_at": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "repository_roots": [str(repo)]}), encoding="utf-8")
    return database, repo, project_id, scope_file, tmp_path


def run_scan(workspace, *arguments):
    database, repo, project_id, scope_file, root = workspace
    env = os.environ.copy()
    env.update({"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
                "VULNMIND_REPORT_ROOT": str(root / "reports"),
                "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "PYTHONIOENCODING": "utf-8"})
    return subprocess.run([sys.executable, "-m", "vulnmind", "scan",
                           "--repository", str(repo), "--project-id", str(project_id),
                           "--scope-file", str(scope_file), *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=300)


def test_scan_uses_the_isolated_trivy_runner(workspace):
    database, repo, project_id, scope_file, root = workspace
    result = run_scan(workspace, "--trivy-sandbox")
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "finished"
    assert payload["findings_stored"] >= 1
    report = (root / "reports").joinpath(*Path(payload["report_uri"]).parts)
    content = report.read_text(encoding="utf-8")
    assert "dependency_vulnerability" in content or "requests" in content
    assert "trivy" in content


def test_workflow_runs_trivy_once_and_reuses_result(workspace):
    from sqlalchemy import select
    from vulnmind.persistence.models import Finding, Scan
    database, repo, project_id, scope_file, root = workspace
    workflow_id = uuid4()
    env = os.environ.copy()
    env.update({"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
                "VULNMIND_REPORT_ROOT": str(root / "reports"), "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "PYTHONIOENCODING": "utf-8"})
    args = [sys.executable, "-m", "vulnmind", "workflow-scan", "--workflow-id", str(workflow_id),
            "--repository", str(repo), "--project-id", str(project_id), "--scope-file", str(scope_file),
            "--trivy-sandbox"]
    first = subprocess.run(args, capture_output=True, encoding="utf-8", env=env, timeout=300)
    second = subprocess.run(args, capture_output=True, encoding="utf-8", env=env, timeout=300)
    assert first.returncode == second.returncode == 0, first.stdout + first.stderr + second.stdout + second.stderr
    assert json.loads(first.stdout)["scan_id"] == json.loads(second.stdout)["scan_id"]
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert len(session.scalars(select(Scan)).all()) == 1
        assert "dependency_vulnerability" in {row.vuln_type for row in session.scalars(select(Finding))}
    engine.dispose()
