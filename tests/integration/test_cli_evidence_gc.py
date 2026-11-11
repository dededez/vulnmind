"""CLI evidence-gc: dry run by default, --apply deletes only old orphans."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from vulnmind.evidence.store import EvidenceStore
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Evidence, Finding, Project, Scan

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def workspace(tmp_path):
    database = tmp_path / "gc.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    @event.listens_for(engine, "connect")
    def enable_fk(dbapi_connection, _):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    store = EvidenceStore(tmp_path / "evidence")
    kept = store.put(b"kept")
    with factory() as session, session.begin():
        project = Project(id=uuid4(), name="gc cli")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="analysis")
        session.add(scan)
        session.flush()
        finding = Finding(id=uuid4(), scan_id=scan.id, fingerprint="a" * 64, title="t",
                          vuln_type="secret", status="unverified")
        session.add(finding)
        session.flush()
        session.add(Evidence(id=uuid4(), finding_id=finding.id, evidence_type="text",
                             locator="x", content_ref=kept.uri, hash=kept.sha256))
    old = store.put(b"orphan")
    old_path = tmp_path / "evidence" / old.uri
    os.utime(old_path, (time.time() - 3 * 86400, time.time() - 3 * 86400))
    engine.dispose()
    return database, old_path, tmp_path


def run_cli(workspace, *arguments):
    database, _, root = workspace
    env = os.environ.copy()
    env.update({"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
                "VULNMIND_EVIDENCE_ROOT": str(root / "evidence"),
                "PYTHONPATH": str(PROJECT_ROOT / "src"), "PYTHONIOENCODING": "utf-8",
                "PYTHONDONTWRITEBYTECODE": "1"})
    return subprocess.run([sys.executable, "-m", "vulnmind", "evidence-gc", *arguments],
                          capture_output=True, encoding="utf-8", env=env, timeout=120)


def test_dry_run_reports_without_deleting(workspace):
    result = run_cli(workspace)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["dry_run"] is True and payload["orphans"] == 1 and payload["deleted"] == 0
    assert workspace[1].exists()


@pytest.mark.skipif(os.name != 'nt', reason='Windows handle deletion')
def test_apply_deletes_only_unreferenced_old_files(workspace):
    result = run_cli(workspace, "--apply", "--grace-hours", "24")
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok" and payload['deleted'] == 1
    assert not workspace[1].exists()
    assert any((workspace[2] / "evidence").rglob("*.*"))


def test_missing_configuration_is_blocked(workspace, monkeypatch):
    database, _, root = workspace
    env = os.environ.copy()
    env.update({"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
                "VULNMIND_EVIDENCE_ROOT": "", "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "PYTHONIOENCODING": "utf-8"})
    result = subprocess.run([sys.executable, "-m", "vulnmind", "evidence-gc"],
                            capture_output=True, encoding="utf-8", env=env, timeout=120)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"
