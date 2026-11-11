"""CLI evidence listing tests against a SQLite database."""
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Evidence, Finding, Project, Scan
from vulnmind.persistence.unit_of_work import transaction


@pytest.fixture
def seeded(tmp_path):
    database = tmp_path / "evidence.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="evidence cli")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="analysis")
        session.add(scan)
        session.flush()
        finding = Finding(id=uuid4(), scan_id=scan.id, fingerprint="9" * 64, title="t",
                          vuln_type="secret", status="unverified")
        session.add(finding)
        session.flush()
        session.add(Evidence(id=uuid4(), finding_id=finding.id, evidence_type="code",
                             locator="config.py:1", content_ref="ab/abcdef.code", hash="c" * 64))
        scan_id = scan.id
    engine.dispose()
    return database, scan_id


def run_evidence(*arguments, env_overrides):
    env = os.environ.copy()
    env.update(env_overrides)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-m", "vulnmind", "evidence", *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=20)


def test_lists_evidence_with_fingerprint(seeded):
    database, scan_id = seeded
    result = run_evidence("--scan-id", scan_id,
                          env_overrides={"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"})
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert len(payload["evidence"]) == 1
    row = payload["evidence"][0]
    assert row["fingerprint"] == "9" * 64 and row["evidence_type"] == "code"
    assert row["content_ref"] == "ab/abcdef.code" and row["hash"] == "c" * 64


def test_errors_are_fixed_and_exit_two(seeded):
    database, scan_id = seeded
    env = {"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"}
    assert run_evidence("--scan-id", uuid4(), env_overrides=env).returncode == 2
    assert run_evidence("--scan-id", scan_id, env_overrides={"VULNMIND_DATABASE_URL": ""}).returncode == 2
    assert run_evidence("--scan-id", "not-a-uuid", env_overrides=env).returncode == 2
