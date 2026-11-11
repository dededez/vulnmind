"""CLI report command tests against a SQLite database and a report store."""
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
from vulnmind.persistence.models import Finding, Project, Scan
from vulnmind.persistence.repositories import ReportRepository
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.reports.store import ReportStore


@pytest.fixture
def seeded(tmp_path):
    database = tmp_path / "cli.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    store = ReportStore(tmp_path / "reports")
    reference = store.put("# Stored report\n\nHardcoded password at config.py:1\n", format="markdown")
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="cli")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="analysis")
        session.add(scan)
        session.flush()
        session.add(Finding(id=uuid4(), scan_id=scan.id, fingerprint="d" * 64, title="Hardcoded password",
                            vuln_type="secret", status="unverified"))
        ReportRepository(session).create(scan.id, format="markdown", storage_uri=reference.uri)
        scan_id = scan.id
    engine.dispose()
    return database, tmp_path / "reports", scan_id


def run_report(*arguments, env_overrides):
    env = os.environ.copy()
    env.update(env_overrides)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-m", "vulnmind", "report", *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=20)


def test_cli_prints_a_stored_report(seeded):
    database, reports, scan_id = seeded
    result = run_report("--scan-id", scan_id,
                        env_overrides={"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
                                       "VULNMIND_REPORT_ROOT": str(reports)})
    assert result.returncode == 0, result.stderr
    assert "Hardcoded password" in result.stdout


def test_cli_can_wrap_the_report_in_json(seeded):
    database, reports, scan_id = seeded
    result = run_report("--scan-id", scan_id, "--json",
                        env_overrides={"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
                                       "VULNMIND_REPORT_ROOT": str(reports)})
    payload = json.loads(result.stdout)
    assert payload["status"] == "loaded" and payload["findings"] == 1
    assert "Stored report" in payload["content"]


def test_cli_reports_missing_configuration_and_unknown_scans(seeded, tmp_path):
    database, reports, scan_id = seeded
    no_config = run_report("--scan-id", scan_id, env_overrides={
        "VULNMIND_DATABASE_URL": "", "VULNMIND_REPORT_ROOT": ""})
    assert no_config.returncode == 2 and "blocked" in no_config.stdout
    unknown = run_report("--scan-id", uuid4(), env_overrides={
        "VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}", "VULNMIND_REPORT_ROOT": str(reports)})
    assert unknown.returncode == 2 and "blocked" in unknown.stdout
    bad_id = run_report("--scan-id", "not-a-uuid", env_overrides={
        "VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}", "VULNMIND_REPORT_ROOT": str(reports)})
    assert bad_id.returncode == 2


def test_cli_reports_a_scan_without_a_report(seeded):
    database, reports, _ = seeded
    from sqlalchemy import create_engine as create
    from sqlalchemy.orm import Session
    engine = create(f"sqlite:///{database.as_posix()}")
    with Session(engine) as session:
        project = session.query(Project).first()
        scan = Scan(id=uuid4(), project_id=project.id, status="failed", mode="analysis")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    engine.dispose()
    result = run_report("--scan-id", scan_id,
                        env_overrides={"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
                                       "VULNMIND_REPORT_ROOT": str(reports)})
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "missing"
