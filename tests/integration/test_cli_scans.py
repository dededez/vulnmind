"""CLI scans listing tests against a SQLite database."""
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Project, Scan
from vulnmind.persistence.unit_of_work import transaction


@pytest.fixture
def seeded(tmp_path):
    database = tmp_path / "scans.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(timezone.utc)
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="cli scans")
        session.add(project)
        session.flush()
        older = Scan(id=uuid4(), project_id=project.id, status="finished", mode="analysis",
                     started_at=now - timedelta(hours=2), finished_at=now - timedelta(hours=1))
        newer = Scan(id=uuid4(), project_id=project.id, status="failed", mode="analysis",
                     started_at=now - timedelta(minutes=5))
        session.add_all([older, newer])
        session.flush()
        project_id = project.id
    engine.dispose()
    return database, project_id


def run_scans(*arguments, env_overrides):
    env = os.environ.copy()
    env.update(env_overrides)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-m", "vulnmind", "scans", *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=20)


def test_lists_scans_newest_first(seeded):
    database, project_id = seeded
    result = run_scans("--project-id", project_id,
                       env_overrides={"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"})
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "listed"
    assert [scan["status"] for scan in payload["scans"]] == ["failed", "finished"]


def test_limit_and_errors(seeded):
    database, project_id = seeded
    env = {"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"}
    limited = run_scans("--project-id", project_id, "--limit", "1", env_overrides=env)
    assert len(json.loads(limited.stdout)["scans"]) == 1
    bad_limit = run_scans("--project-id", project_id, "--limit", "0", env_overrides=env)
    assert bad_limit.returncode == 2
    no_db = run_scans("--project-id", project_id, env_overrides={"VULNMIND_DATABASE_URL": ""})
    assert no_db.returncode == 2
    unknown = run_scans("--project-id", uuid4(), env_overrides=env)
    assert json.loads(unknown.stdout)["scans"] == []
