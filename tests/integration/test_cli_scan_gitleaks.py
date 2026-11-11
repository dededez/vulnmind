"""End-to-end scan with Gitleaks in the isolated WSL environment."""
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets
import subprocess
import sys
import shutil
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Finding, Project

PROJECT_ROOT = Path(__file__).resolve().parents[2]
GITLEAKS = PROJECT_ROOT / ".devtools" / "scanners" / "gitleaks.exe"

def sandbox_available():
    if not shutil.which("wsl.exe"):
        return False
    try:
        result = subprocess.run(["wsl.exe", "-l", "-q"], capture_output=True, timeout=30)
        return "VulnMindSandbox" in result.stdout.decode("utf-16-le", "ignore").replace("\x00", "")
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = pytest.mark.skipif(not sandbox_available(), reason="WSL sandbox distro is not installed")


def fake_aws_key():
    return "AKIA" + "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(16))


@pytest.fixture
def workspace(tmp_path):
    database = tmp_path / "scan.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "settings.py").write_text(f"aws_access_key_id = '{fake_aws_key()}'\n", encoding="utf-8")
    (repo / "client.py").write_text("import requests\n\n\ndef fetch(url):\n    return requests.get(url, verify=False)\n",
                                    encoding="utf-8")
    with factory() as session:
        project = Project(id=uuid4(), name="gitleaks e2e")
        session.add(project)
        session.commit()
        project_id = project.id
    engine.dispose()
    now = datetime.now(timezone.utc)
    scope = {"authorization_source": "local e2e", "approved_by": "owner",
             "starts_at": (now - timedelta(hours=1)).isoformat(),
             "expires_at": (now + timedelta(hours=1)).isoformat(),
             "repository_roots": [str(repo)]}
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(scope), encoding="utf-8")
    return database, repo, project_id, scope_file, tmp_path


def run_scan(workspace, *arguments):
    database, repo, project_id, scope_file, root = workspace
    env = os.environ.copy()
    env.update({"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
                "VULNMIND_REPORT_ROOT": str(root / "reports"),
                "PYTHONPATH": str(PROJECT_ROOT / "src"), "PYTHONIOENCODING": "utf-8",
                "PYTHONDONTWRITEBYTECODE": "1"})
    return subprocess.run([sys.executable, "-m", "vulnmind", "scan",
                           "--repository", str(repo), "--project-id", str(project_id),
                           "--scope-file", str(scope_file), "--gitleaks-sandbox",
                           *[str(item) for item in arguments]],
                          capture_output=True, encoding="utf-8", env=env, timeout=180)


def test_scan_runs_gitleaks_and_stores_a_secret_finding(workspace):
    result = run_scan(workspace)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "finished"
    assert payload["groups"] >= 2 and payload["findings_stored"] >= 2

    database, _, _, _, root = workspace
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as session:
        types = {row.vuln_type for row in session.scalars(select(Finding))}
    engine.dispose()
    assert "secret" in types and "tls_certificate_verification_disabled" in types


def test_report_mentions_both_sources(workspace):
    result = run_scan(workspace)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    _, _, _, _, root = workspace
    report = (root / "reports").joinpath(*Path(payload["report_uri"]).parts).read_text(encoding="utf-8")
    # Markdown escapes underscores in field values, so compare the unescaped text.
    plain = report.replace("\\", "")
    assert "gitleaks" in plain and "python_tls" in plain
    assert "未独立验证" in plain


def test_workflow_runs_gitleaks_once_and_reuses_result(workspace):
    from vulnmind.persistence.models import Scan
    database, repo, project_id, scope_file, root = workspace
    workflow_id = uuid4()
    env = os.environ.copy()
    env.update({"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
                "VULNMIND_REPORT_ROOT": str(root / "reports"), "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "PYTHONIOENCODING": "utf-8"})
    args = [sys.executable, "-m", "vulnmind", "workflow-scan", "--workflow-id", str(workflow_id),
            "--repository", str(repo), "--project-id", str(project_id), "--scope-file", str(scope_file),
            "--gitleaks-sandbox"]
    first = subprocess.run(args, capture_output=True, encoding="utf-8", env=env, timeout=180)
    second = subprocess.run(args, capture_output=True, encoding="utf-8", env=env, timeout=180)
    assert first.returncode == second.returncode == 0, first.stdout + first.stderr + second.stdout + second.stderr
    assert json.loads(first.stdout)["scan_id"] == json.loads(second.stdout)["scan_id"]
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert len(session.scalars(select(Scan)).all()) == 1
        assert "secret" in {row.vuln_type for row in session.scalars(select(Finding))}
    engine.dispose()
