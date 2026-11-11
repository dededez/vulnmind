"""CLI verify tests: report and evidence integrity against a SQLite database."""
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from vulnmind.evidence.store import EvidenceStore
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Evidence, Finding, Project, Scan
from vulnmind.persistence.repositories import ReportRepository
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.reports.store import ReportStore


@pytest.fixture
def seeded(tmp_path):
    database = tmp_path / "verify.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    report_store = ReportStore(tmp_path / "reports")
    evidence_store = EvidenceStore(tmp_path / "evidence")
    report = report_store.put("# report\n", format="markdown")
    evidence = evidence_store.put(b"proof\n", evidence_type="text")
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="verify")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="analysis")
        session.add(scan)
        session.flush()
        finding = Finding(id=uuid4(), scan_id=scan.id, fingerprint="e" * 64, title="t",
                          vuln_type="secret", status="unverified")
        session.add(finding)
        session.flush()
        session.add(Evidence(id=uuid4(), finding_id=finding.id, evidence_type="text",
                             locator="a.py:1", content_ref=evidence.uri, hash=evidence.sha256))
        ReportRepository(session).create(scan.id, format="markdown", storage_uri=report.uri)
        scan_id = scan.id
    engine.dispose()
    return database, tmp_path, scan_id


def run_verify(scan_id, env_overrides):
    env = os.environ.copy()
    env.update(env_overrides)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-m", "vulnmind", "verify", "--scan-id", str(scan_id)],
                          capture_output=True, encoding="utf-8", env=env, timeout=20)


def env_for(database, root):
    return {"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
            "VULNMIND_REPORT_ROOT": str(root / "reports"),
            "VULNMIND_EVIDENCE_ROOT": str(root / "evidence")}


def test_verify_reports_ok_for_intact_records(seeded):
    database, root, scan_id = seeded
    result = run_verify(scan_id, env_for(database, root))
    assert result.returncode == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok" and payload["evidence_checked"] == 1
    assert payload["evidence_broken"] == []
    assert payload["findings_without_evidence"] == 0
    assert payload["evidence_snapshot_integrity"] == "not_checked"


def test_verify_detects_deleted_report_evidence_even_if_another_remains(seeded):
    from sqlalchemy import delete, select, update
    from vulnmind.persistence.models import Report

    database, root, scan_id = seeded
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.begin() as connection:
        evidence = connection.execute(select(Evidence.__table__)).mappings().one()
        record_id = evidence["id"]
        report_data = {"schema_version": 5, "scan_id": str(scan_id), "evidence_snapshot": "available",
                       "evidence_snapshot_truncated": False,
                       "groups": [{"fingerprint": "e" * 64, "stored_evidence_ids": [str(record_id)]}]}
        report = ReportStore(root / "reports").put(json.dumps(report_data), format="json")
        connection.execute(update(Report).where(Report.scan_id == scan_id).values(
            format="json", storage_uri=report.uri))
    intact = run_verify(scan_id, env_for(database, root))
    assert json.loads(intact.stdout)["evidence_snapshot_integrity"] == "valid"
    assert intact.returncode == 0
    with engine.begin() as connection:
        connection.execute(delete(Evidence).where(Evidence.id == record_id))
        connection.execute(Evidence.__table__.insert().values(
            id=uuid4(), finding_id=evidence["finding_id"], evidence_type=evidence["evidence_type"],
            locator=evidence["locator"], content_ref=evidence["content_ref"], hash=evidence["hash"]))
    engine.dispose()
    result = run_verify(scan_id, env_for(database, root))
    payload = json.loads(result.stdout)
    assert result.returncode == 1 and payload["status"] == "broken"
    assert payload["findings_without_evidence"] == 0 and payload["evidence_checked"] == 1
    assert payload["evidence_snapshot_integrity"] == "broken"
    assert payload["evidence_snapshot_missing"] == [str(record_id)]


@pytest.mark.parametrize(("snapshot", "truncated", "expected_status", "expected_integrity"), [
    ("available", True, "incomplete", "partial"),
    ("unavailable", False, "ok", "not_checked"),
    ("unexpected", False, "broken", "invalid"),
])
def test_verify_distinguishes_partial_unavailable_and_invalid_snapshot(
        seeded, snapshot, truncated, expected_status, expected_integrity):
    from sqlalchemy import update
    from vulnmind.persistence.models import Report

    database, root, scan_id = seeded
    report_data = {"schema_version": 5, "scan_id": str(scan_id), "evidence_snapshot": snapshot,
                   "evidence_snapshot_truncated": truncated,
                   "groups": [{"fingerprint": "e" * 64, "stored_evidence_ids": []}]}
    report = ReportStore(root / "reports").put(json.dumps(report_data), format="json")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.begin() as connection:
        connection.execute(update(Report).where(Report.scan_id == scan_id).values(
            format="json", storage_uri=report.uri))
    engine.dispose()
    result = run_verify(scan_id, env_for(database, root))
    payload = json.loads(result.stdout)
    assert payload["status"] == expected_status
    assert payload["evidence_snapshot_integrity"] == expected_integrity
    assert result.returncode == (0 if expected_status == "ok" else 1)


def test_verify_marks_findings_without_evidence_incomplete(seeded):
    from sqlalchemy import delete

    database, root, scan_id = seeded
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.begin() as connection:
        connection.execute(delete(Evidence))
    engine.dispose()
    result = run_verify(scan_id, env_for(database, root))
    payload = json.loads(result.stdout)
    assert result.returncode == 1 and payload["status"] == "incomplete"
    assert payload["findings_without_evidence"] == 1
    assert payload["evidence_checked"] == payload["evidence_unchecked"] == 0


def test_verify_allows_a_scan_without_findings(seeded):
    from sqlalchemy import delete

    database, root, scan_id = seeded
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.begin() as connection:
        connection.execute(delete(Evidence))
        connection.execute(delete(Finding))
    engine.dispose()
    result = run_verify(scan_id, env_for(database, root))
    payload = json.loads(result.stdout)
    assert result.returncode == 0 and payload["status"] == "ok"
    assert payload["findings_without_evidence"] == 0


def test_verify_counts_only_unlinked_findings_in_requested_scan(seeded):
    database, root, scan_id = seeded
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session, session.begin():
        scan = session.get(Scan, scan_id)
        other = Scan(id=uuid4(), project_id=scan.project_id, status="finished", mode="analysis")
        session.add(other)
        session.flush()
        session.add_all([
            Finding(id=uuid4(), scan_id=scan_id, fingerprint="f" * 64, title="no evidence",
                    vuln_type="secret", status="unverified"),
            Finding(id=uuid4(), scan_id=other.id, fingerprint="a" * 64, title="other scan",
                    vuln_type="secret", status="unverified"),
        ])
    engine.dispose()
    result = run_verify(scan_id, env_for(database, root))
    payload = json.loads(result.stdout)
    assert result.returncode == 1 and payload["status"] == "incomplete"
    assert payload["findings_without_evidence"] == 1 and payload["evidence_checked"] == 1


def test_verify_uses_one_sqlite_read_snapshot_during_concurrent_update(seeded, monkeypatch, capsys):
    from types import SimpleNamespace
    from vulnmind.__main__ import _verify
    import vulnmind.reports.loader as loader

    database, root, scan_id = seeded
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA journal_mode=WAL").scalar_one().lower() == "wal"
    original_load = loader.load_report

    def load_then_write(session, store, requested_id):
        loaded = original_load(session, store, requested_id)
        with engine.begin() as connection:
            connection.execute(Finding.__table__.insert().values(
                id=uuid4(), scan_id=scan_id, fingerprint="a" * 64, title="later",
                vuln_type="secret", status="unverified"))
        return loaded

    monkeypatch.setattr(loader, "load_report", load_then_write)
    for key, value in env_for(database, root).items():
        monkeypatch.setenv(key, value)
    assert _verify(SimpleNamespace(scan_id=str(scan_id))) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ok" and result["findings_without_evidence"] == 0
    with engine.connect() as connection:
        assert len(connection.execute(select(Finding.id)).all()) == 2
    engine.dispose()


def test_verify_limits_evidence_and_reports_exact_unchecked_count(seeded, monkeypatch, capsys):
    from types import SimpleNamespace
    import vulnmind.__main__ as cli

    database, root, scan_id = seeded
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.begin() as connection:
        item = connection.execute(select(Evidence.__table__)).mappings().one()
        for _ in range(2):
            connection.execute(Evidence.__table__.insert().values(
                id=uuid4(), finding_id=item["finding_id"], evidence_type=item["evidence_type"],
                locator=item["locator"], content_ref=item["content_ref"], hash=item["hash"]))
    engine.dispose()
    for key, value in env_for(database, root).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(cli, "_MAX_VERIFY_EVIDENCE", 1)
    assert cli._verify(SimpleNamespace(scan_id=str(scan_id))) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "incomplete" and payload["evidence_limit_reached"] is True
    assert payload["evidence_checked"] == 1 and payload["evidence_unchecked"] == 2
    assert payload["evidence_snapshot_integrity"] == "not_checked_limit"
    assert payload["evidence_broken"] == []
    monkeypatch.setenv("VULNMIND_EVIDENCE_ROOT", "")
    assert cli._verify(SimpleNamespace(scan_id=str(scan_id))) == 1
    unchecked = json.loads(capsys.readouterr().out)
    assert unchecked["evidence_checked"] == 0 and unchecked["evidence_unchecked"] == 3


def test_verified_damage_takes_precedence_over_the_limit(seeded, monkeypatch, capsys):
    from types import SimpleNamespace
    import vulnmind.__main__ as cli

    database, root, scan_id = seeded
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.begin() as connection:
        item = connection.execute(select(Evidence.__table__)).mappings().one()
        connection.execute(Evidence.__table__.insert().values(
            id=uuid4(), finding_id=item["finding_id"], evidence_type=item["evidence_type"],
            locator=item["locator"], content_ref=item["content_ref"], hash=item["hash"]))
    engine.dispose()
    next((root / "evidence").rglob("*.text")).write_bytes(b"tampered")
    for key, value in env_for(database, root).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(cli, "_MAX_VERIFY_EVIDENCE", 1)
    assert cli._verify(SimpleNamespace(scan_id=str(scan_id))) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "broken" and payload["evidence_limit_reached"] is True
    assert len(payload["evidence_broken"]) == 1 and payload["evidence_unchecked"] == 1


def test_verify_finding_limit_never_claims_full_snapshot_check(seeded, monkeypatch, capsys):
    from types import SimpleNamespace
    import vulnmind.__main__ as cli

    database, root, scan_id = seeded
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.begin() as connection:
        connection.execute(Finding.__table__.insert().values(
            id=uuid4(), scan_id=scan_id, fingerprint="a" * 64, title="later",
            vuln_type="secret", status="unverified"))
    engine.dispose()
    for key, value in env_for(database, root).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(cli, "_MAX_VERIFY_FINDINGS", 1)
    assert cli._verify(SimpleNamespace(scan_id=str(scan_id))) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "incomplete" and payload["finding_limit_reached"] is True
    assert payload["finding_snapshot_integrity"] == "not_checked_limit"


def test_verify_reports_finding_snapshot_drift_without_exposing_fingerprints(seeded):
    from sqlalchemy import update
    from vulnmind.persistence.models import Report

    database, root, scan_id = seeded
    report_data = {"schema_version": 6, "scan_id": str(scan_id), "evidence_snapshot": "available",
                   "evidence_snapshot_truncated": False,
                   "groups": [{"fingerprint": "f" * 64, "stored_evidence_ids": []}]}
    report = ReportStore(root / "reports").put(json.dumps(report_data), format="json")
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.begin() as connection:
        connection.execute(update(Report).where(Report.scan_id == scan_id).values(
            format="json", storage_uri=report.uri))
    engine.dispose()
    result = run_verify(scan_id, env_for(database, root))
    payload = json.loads(result.stdout)
    assert result.returncode == 1 and payload["status"] == "incomplete"
    assert payload["finding_snapshot_integrity"] == "incomplete"
    assert payload["findings_only_in_report"] == payload["findings_only_in_database"] == 1
    assert "f" * 64 not in result.stdout and "e" * 64 not in result.stdout


def test_verify_detects_tampered_evidence(seeded):
    database, root, scan_id = seeded
    (root / "evidence").joinpath(*next((root / "evidence").rglob("*.text")).parts[-2:]).write_text(
        "tampered", encoding="utf-8")
    result = run_verify(scan_id, env_for(database, root))
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "broken" and payload["evidence_broken"]


def test_verify_reports_missing_evidence_by_record_id(seeded):
    database, root, scan_id = seeded
    evidence = next((root / "evidence").rglob("*.text"))
    evidence.unlink()  # The test fixture created this file inside its temporary directory.
    result = run_verify(scan_id, env_for(database, root))
    payload = json.loads(result.stdout)
    assert result.returncode == 1 and payload["status"] == "broken"
    assert len(payload["evidence_broken"]) == 1 and payload["evidence_checked"] == 1
    assert payload["report_integrity"] == "valid"


@pytest.mark.parametrize("missing", [False, True])
def test_verify_classifies_invalid_or_missing_report_as_broken(seeded, missing):
    database, root, scan_id = seeded
    report = next((root / "reports").rglob("*.md"))
    if missing:
        report.unlink()  # This file was created by the test fixture in its own temporary directory.
    else:
        report.write_text("tampered report", encoding="utf-8")
    result = run_verify(scan_id, env_for(database, root))
    payload = json.loads(result.stdout)
    assert result.returncode == 1 and payload["status"] == "broken"
    assert payload["report_integrity"] == "missing_unreadable_or_invalid"
    assert payload["report_present"] is False and payload["evidence_checked"] == 1


def test_verify_does_not_echo_invalid_evidence_reference(seeded):
    from sqlalchemy import update

    database, root, scan_id = seeded
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.begin() as connection:
        connection.execute(update(Evidence).values(content_ref="../../sensitive-path"))
    engine.dispose()
    result = run_verify(scan_id, env_for(database, root))
    payload = json.loads(result.stdout)
    assert result.returncode == 1 and payload["status"] == "broken"
    assert len(payload["evidence_broken"]) == 1
    assert str(__import__("uuid").UUID(payload["evidence_broken"][0])) == payload["evidence_broken"][0]
    assert "sensitive-path" not in result.stdout + result.stderr


def test_verify_requires_configuration_and_a_known_scan(seeded):
    database, root, scan_id = seeded
    missing = run_verify(scan_id, {"VULNMIND_DATABASE_URL": "", "VULNMIND_REPORT_ROOT": ""})
    assert missing.returncode == 2
    unknown = run_verify(uuid4(), env_for(database, root))
    assert unknown.returncode == 2


def test_verify_does_not_claim_unchecked_evidence_is_valid(seeded):
    database, root, scan_id = seeded
    env = env_for(database, root)
    env["VULNMIND_EVIDENCE_ROOT"] = ""
    result = run_verify(scan_id, env)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "incomplete"
    assert payload["evidence_checked"] == 0 and payload["evidence_unchecked"] == 1
