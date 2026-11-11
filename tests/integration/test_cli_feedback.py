"""CLI tests for operator feedback and report regeneration against SQLite."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from vulnmind.findings import FindingCandidate
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Finding, FindingObservation, Project, Scan
from vulnmind.reports.store import ReportStore


def seed(database: Path, *, complete: bool = True):
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    with Session(engine) as session, session.begin():
        project = Project(id=uuid4(), name="feedback cli")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="analysis")
        session.add(scan)
        session.flush()
        candidate = FindingCandidate(title="Reflected marker", vulnerability_type="reflected_input",
                                     target_id="https://example.test", location="/search?q=x",
                                     source_tool="builtin.reflection", status="unverified",
                                     severity="medium")
        finding = Finding(id=uuid4(), scan_id=scan.id, fingerprint=candidate.fingerprint(),
                          title=candidate.title, vuln_type=candidate.vulnerability_type,
                          severity="medium", confidence="0.30", status="unverified",
                          location={"target_id": candidate.target_id,
                                    "location": candidate.location},
                          needs_retriage=False, observation_history_complete=complete,
                          observation_revision=0)
        session.add(finding)
        session.flush()
        claim = {"source_tool": "builtin.reflection", "title": candidate.title,
                 "source_status_claim": "unverified", "severity": "medium", "evidence_refs": []}
        serialized = json.dumps(claim, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        session.add(FindingObservation(id=uuid4(), finding_id=finding.id,
                                       observation_hash=hashlib.sha256(serialized.encode()).hexdigest(),
                                       **claim))
        scan_id = scan.id
    engine.dispose()
    return scan_id, candidate.fingerprint()


def run(command, *arguments, env_overrides):
    env = os.environ.copy()
    env.update(env_overrides)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-m", "vulnmind", command, *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=30)


@pytest.fixture
def seeded(tmp_path):
    database = tmp_path / "feedback.db"
    scan_id, fingerprint = seed(database)
    report_root = tmp_path / "reports"
    env = {"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
           "VULNMIND_REPORT_ROOT": str(report_root)}
    return scan_id, fingerprint, env, report_root


def test_feedback_flow_and_regenerated_report(seeded):
    scan_id, fingerprint, env, report_root = seeded
    first = run("finding-feedback", "--scan-id", scan_id, "--fingerprint", fingerprint,
                "--verdict", "false_positive", "--note", "test data", "--actor", "alice",
                env_overrides=env)
    assert first.returncode == 0, first.stderr
    payload = json.loads(first.stdout)
    assert payload["status"] == "recorded" and payload["revision"] == 1
    assert payload["note_present"] is True

    second = run("finding-feedback", "--scan-id", scan_id, "--fingerprint", fingerprint,
                 "--verdict", "confirmed", "--actor", "bob", env_overrides=env)
    assert second.returncode == 0 and json.loads(second.stdout)["revision"] == 2

    listed = run("feedback", "--scan-id", scan_id, env_overrides=env)
    assert listed.returncode == 0
    entries = json.loads(listed.stdout)["feedback"]
    assert len(entries) == 1
    assert entries[0]["fingerprint"] == fingerprint
    assert entries[0]["verdict"] == "confirmed" and entries[0]["revision"] == 2
    assert entries[0]["actor"] == "bob" and entries[0]["note"] is None

    regenerated = run("report-regenerate", "--scan-id", scan_id, "--report-format", "json",
                      env_overrides=env)
    assert regenerated.returncode == 0, regenerated.stderr
    result = json.loads(regenerated.stdout)
    assert result["status"] == "regenerated" and result["feedback_applied"] == 1
    stored = ReportStore(report_root).read(result["uri"])
    document = json.loads(stored)
    assert document["schema_version"] == 7
    assert document["feedback"][0]["verdict"] == "confirmed"
    assert document["open_validation_required"] == 0

    loaded = run("report", "--scan-id", scan_id, "--json", env_overrides=env)
    assert loaded.returncode == 0
    assert json.loads(loaded.stdout)["format"] == "json"


def test_invalid_verdict_is_rejected_by_the_parser(seeded):
    scan_id, fingerprint, env, _ = seeded
    result = run("finding-feedback", "--scan-id", scan_id, "--fingerprint", fingerprint,
                 "--verdict", "looks_bad", env_overrides=env)
    assert result.returncode == 2


def test_missing_scan_or_configuration_is_blocked(seeded):
    scan_id, fingerprint, env, _ = seeded
    assert run("finding-feedback", "--scan-id", uuid4(), "--fingerprint", fingerprint,
               "--verdict", "confirmed", env_overrides=env).returncode == 2
    assert run("finding-feedback", "--scan-id", scan_id, "--fingerprint", "0" * 64,
               "--verdict", "confirmed", env_overrides=env).returncode == 2
    assert run("feedback", "--scan-id", scan_id,
               env_overrides={**env, "VULNMIND_DATABASE_URL": ""}).returncode == 2


def test_regeneration_fails_closed_on_incomplete_history(tmp_path):
    database = tmp_path / "incomplete.db"
    scan_id, _ = seed(database, complete=False)
    env = {"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
           "VULNMIND_REPORT_ROOT": str(tmp_path / "reports")}
    result = run("report-regenerate", "--scan-id", scan_id, env_overrides=env)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"
