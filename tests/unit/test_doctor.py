"""Doctor self-check: database, schema, audit chain, roots and credentials."""
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, update

from vulnmind.doctor import run_checks
from vulnmind.persistence.audit import DatabaseAuditSink
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import AuditEvent


def build_db(tmp_path):
    database = tmp_path / "doctor.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    sink = DatabaseAuditSink(engine)
    for status in ("requested", "succeeded"):
        sink.record({"call_id": str(uuid4()), "tool_name": "doctor", "actor": "tester",
                     "target_type": "repository", "status": status})
    return database, engine


def by_name(report):
    return {check.name: check for check in report.checks}


def test_healthy_database_and_roots_report_degraded(tmp_path):
    database, engine = build_db(tmp_path)
    report = run_checks(database_url=f"sqlite:///{database.as_posix()}", report_root=str(tmp_path),
                        evidence_root=str(tmp_path), env={})
    engine.dispose()
    checks = by_name(report)
    assert report.status == "degraded"
    assert checks["database"].status == "ok" and checks["audit_chain"].status == "ok"
    assert checks["report_root"].status == "ok" and checks["evidence_root"].status == "ok"
    assert checks["schema"].status == "warn"  # create_all has no alembic_version
    assert checks["approvals"].status == "warn" and checks["model_key"].status == "warn"


def test_missing_database_is_a_failure():
    report = run_checks(database_url=None, report_root=None, evidence_root=None, env={})
    assert report.status == "failed"
    assert by_name(report)["database"].status == "fail"


def test_invalid_database_url_is_a_failure(tmp_path):
    report = run_checks(database_url="not-a-url", report_root=str(tmp_path),
                        evidence_root=None, env={})
    assert report.status == "failed" and by_name(report)["database"].status == "fail"


def test_unwritable_report_root_is_a_failure(tmp_path):
    database, engine = build_db(tmp_path)
    file_path = tmp_path / "not-a-directory"
    file_path.write_text("x", encoding="utf-8")
    report = run_checks(database_url=f"sqlite:///{database.as_posix()}", report_root=str(file_path),
                        evidence_root=None, env={})
    engine.dispose()
    assert report.status == "failed" and by_name(report)["report_root"].status == "fail"


def test_conflicting_approval_configuration_fails(tmp_path):
    database, engine = build_db(tmp_path)
    report = run_checks(database_url=f"sqlite:///{database.as_posix()}", report_root=str(tmp_path),
                        evidence_root=None,
                        env={"VULNMIND_APPROVAL_SECRET": "x", "VULNMIND_APPROVAL_ALLOWED_SIGNERS": "y"})
    engine.dispose()
    assert report.status == "failed"
    assert "not both" in by_name(report)["approvals"].detail


def test_present_credentials_are_reported_without_values(tmp_path):
    database, engine = build_db(tmp_path)
    report = run_checks(database_url=f"sqlite:///{database.as_posix()}", report_root=str(tmp_path),
                        evidence_root=None,
                        env={"VULNMIND_APPROVAL_SECRET": "super-secret-value",
                             "DEEPSEEK_API_KEY": "key-value"})
    engine.dispose()
    checks = by_name(report)
    assert checks["approvals"].status == "ok" and checks["model_key"].status == "ok"
    assert "super-secret-value" not in str(report.model_dump())


def test_tampered_audit_chain_fails_the_check(tmp_path):
    database, engine = build_db(tmp_path)
    with engine.begin() as connection:
        target = connection.execute(AuditEvent.__table__.select()).all()[1][0]
        connection.execute(update(AuditEvent).where(AuditEvent.id == target).values(status="denied"))
    report = run_checks(database_url=f"sqlite:///{database.as_posix()}", report_root=str(tmp_path),
                        evidence_root=None, env={})
    engine.dispose()
    assert report.status == "failed"
    assert by_name(report)["audit_chain"].status == "fail"


def test_doctor_handles_more_than_500_valid_audit_events(tmp_path):
    database,engine=build_db(tmp_path)
    from sqlalchemy.orm import Session
    from vulnmind.persistence.audit import SessionAuditSink
    with Session(engine) as session,session.begin():
        sink=SessionAuditSink(session)
        for _ in range(501):
            sink.record(dict(call_id=str(uuid4()),tool_name='owned.regression',actor='test',target_type='web',status='succeeded'))
    report=run_checks(database_url=f'sqlite:///{database.as_posix()}',report_root=str(tmp_path),evidence_root=None,env={})
    assert by_name(report)['audit_chain'].status=='ok'
    assert 'checked=503' in by_name(report)['audit_chain'].detail
    engine.dispose()


def test_report_signing_configuration_is_checked_without_values(tmp_path):
    database, engine = build_db(tmp_path)
    healthy = run_checks(database_url=f"sqlite:///{database.as_posix()}", report_root=str(tmp_path),
                         evidence_root=None, env={"VULNMIND_REPORT_SIGNING_KEY": "k" * 40})
    assert by_name(healthy)["report_signing"].status == "ok"
    short = run_checks(database_url=f"sqlite:///{database.as_posix()}", report_root=str(tmp_path),
                       evidence_root=None, env={"VULNMIND_REPORT_SIGNING_KEY": "short"})
    assert by_name(short)["report_signing"].status == "warn"
    conflict = run_checks(database_url=f"sqlite:///{database.as_posix()}", report_root=str(tmp_path),
                          evidence_root=None,
                          env={"VULNMIND_REPORT_SIGNING_KEY": "k" * 40,
                               "VULNMIND_REPORT_SIGNING_KEY_FILE": "key.txt"})
    engine.dispose()
    assert by_name(conflict)["report_signing"].status == "fail"
    assert "k" * 40 not in str(healthy.model_dump())
