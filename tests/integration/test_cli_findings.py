"""CLI findings listing tests against a SQLite database."""
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
from vulnmind.persistence.models import Finding, Project, Scan
from vulnmind.persistence.unit_of_work import transaction


@pytest.fixture
def seeded(tmp_path):
    database = tmp_path / "findings.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="findings cli")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="analysis")
        session.add(scan)
        session.flush()
        session.add_all([
            Finding(id=uuid4(), scan_id=scan.id, fingerprint="f" * 64, title="SQL injection",
                    vuln_type="sqli", severity="high", confidence="0.40", status="unverified",
                    location={"target_id": "repo", "location": "app.py:1"}),
            Finding(id=uuid4(), scan_id=scan.id, fingerprint="a" * 64, title="Secret",
                    vuln_type="secret", severity="unknown", confidence="0.30", status="unverified",
                    location={"target_id": "repo", "location": "config.py:2"}),
        ])
        scan_id = scan.id
    engine.dispose()
    return database, scan_id


def run_findings(*arguments, env_overrides):
    env = os.environ.copy()
    env.update(env_overrides)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-m", "vulnmind", "findings", *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=20)


def test_lists_findings_with_location(seeded):
    database, scan_id = seeded
    result = run_findings("--scan-id", scan_id,
                          env_overrides={"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"})
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert [item["vuln_type"] for item in payload["findings"]] == ["secret", "sqli"]
    assert payload["findings"][1]["location"] == {"target_id": "repo", "location": "app.py:1"}
    assert payload["findings"][0]["confidence"] == "0.30"


def test_limit_and_error_paths(seeded):
    database, scan_id = seeded
    env = {"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"}
    limited = run_findings("--scan-id", scan_id, "--limit", "1", env_overrides=env)
    assert len(json.loads(limited.stdout)["findings"]) == 1
    assert run_findings("--scan-id", scan_id, "--limit", "0", env_overrides=env).returncode == 2
    assert run_findings("--scan-id", uuid4(), env_overrides=env).returncode == 2
    assert run_findings("--scan-id", scan_id, env_overrides={"VULNMIND_DATABASE_URL": ""}).returncode == 2
