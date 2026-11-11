"""CLI tests for report signing and verifying against SQLite."""
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Project, Report, Scan
from vulnmind.reports.store import ReportStore

SIGNING_KEY = "k" * 40


def seed(tmp_path):
    database = tmp_path / "signing.db"
    report_root = tmp_path / "reports"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    store = ReportStore(report_root)
    content = json.dumps({"schema_version": 7, "scan_id": "placeholder", "groups": [],
                          "evidence_snapshot": "unavailable",
                          "evidence_snapshot_truncated": False}, sort_keys=True)
    with Session(engine) as session, session.begin():
        project = Project(id=uuid4(), name="signing")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="analysis")
        session.add(scan)
        session.flush()
        content = content.replace("placeholder", str(scan.id))
        reference = store.put(content, format="json")
        session.add(Report(id=uuid4(), scan_id=scan.id, format="json",
                           storage_uri=reference.uri))
        scan_id = scan.id
    engine.dispose()
    return database, report_root, scan_id, reference.uri


def run(command, *arguments, env_overrides):
    env = os.environ.copy()
    env.update(env_overrides)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-m", "vulnmind", command, *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=30)


@pytest.fixture
def seeded(tmp_path):
    database, report_root, scan_id, uri = seed(tmp_path)
    env = {"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
           "VULNMIND_REPORT_ROOT": str(report_root),
           "VULNMIND_REPORT_SIGNING_KEY": SIGNING_KEY}
    return scan_id, uri, report_root, env


def test_sign_then_verify(seeded):
    scan_id, uri, report_root, env = seeded
    signed = run("report-sign", "--scan-id", scan_id, "--actor", "alice", env_overrides=env)
    assert signed.returncode == 0, signed.stderr
    payload = json.loads(signed.stdout)
    assert payload["status"] == "signed" and len(payload["key_id"]) == 16
    assert Path(report_root, payload["signature_uri"]).is_file()

    verified = run("report-verify", "--scan-id", scan_id, env_overrides=env)
    assert verified.returncode == 0, verified.stdout
    result = json.loads(verified.stdout)
    assert result["status"] == "verified" and result["sha256"] == payload["sha256"]

    full = run("verify", "--scan-id", scan_id, env_overrides=env)
    assert full.returncode == 0, full.stdout
    assert json.loads(full.stdout)["signature_integrity"] == "valid"


def test_unsigned_report_is_not_verified(seeded):
    scan_id, uri, report_root, env = seeded
    result = run("report-verify", "--scan-id", scan_id, env_overrides=env)
    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == "unsigned"


def test_tampered_signature_is_broken(seeded):
    scan_id, uri, report_root, env = seeded
    assert run("report-sign", "--scan-id", scan_id, env_overrides=env).returncode == 0
    signature = Path(report_root, Path(uri).with_suffix(".sig").as_posix())
    payload = json.loads(signature.read_text(encoding="utf-8"))
    payload["signature"] = "0" * 64
    signature.write_text(json.dumps(payload), encoding="utf-8")

    result = run("report-verify", "--scan-id", scan_id, env_overrides=env)
    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == "broken"
    full = run("verify", "--scan-id", scan_id, env_overrides=env)
    assert full.returncode == 1
    assert json.loads(full.stdout)["signature_integrity"] == "broken"


def test_missing_key_or_report_is_blocked_or_missing(seeded, tmp_path):
    scan_id, uri, report_root, env = seeded
    without_key = {**env, "VULNMIND_REPORT_SIGNING_KEY": ""}
    assert run("report-sign", "--scan-id", scan_id, env_overrides=without_key).returncode == 2
    assert run("report-verify", "--scan-id", scan_id, env_overrides=without_key).returncode == 2
    assert run("report-sign", "--scan-id", uuid4(), env_overrides=env).returncode == 2

    key_file = tmp_path / "key.txt"
    key_file.write_text(SIGNING_KEY, encoding="utf-8")
    file_env = {**env, "VULNMIND_REPORT_SIGNING_KEY": "",
                "VULNMIND_REPORT_SIGNING_KEY_FILE": str(key_file)}
    assert run("report-sign", "--scan-id", scan_id, env_overrides=file_env).returncode == 0
    assert run("report-verify", "--scan-id", scan_id, env_overrides=file_env).returncode == 0


def test_signature_without_configured_key_is_incomplete(seeded):
    scan_id, uri, report_root, env = seeded
    assert run("report-sign", "--scan-id", scan_id, env_overrides=env).returncode == 0
    full = run("verify", "--scan-id", scan_id,
               env_overrides={**env, "VULNMIND_REPORT_SIGNING_KEY": ""})
    assert full.returncode == 1
    assert json.loads(full.stdout)["signature_integrity"] == "not_configured"
