"""Audit hash-chain tests: linking, tamper detection, legacy rows."""
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, insert, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from vulnmind.persistence.audit import (AuditError, DatabaseAuditSink, SessionAuditSink,
                                        entry_hash, verify_audit_chain)
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import AuditEvent


def build_engine():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return engine


def event(status="requested", tool="fake"):
    return {"call_id": str(uuid4()), "tool_name": tool, "actor": "tester",
            "target_type": "web", "status": status}


def test_database_sink_builds_a_valid_chain():
    engine = build_engine()
    sink = DatabaseAuditSink(engine)
    for status in ("requested", "started", "succeeded"):
        sink.record(event(status))
    with engine.connect() as connection:
        report = verify_audit_chain(connection)
        rows = connection.execute(select(AuditEvent).order_by(AuditEvent.created_at)).mappings().all()
    assert report.valid and report.checked == 3 and report.unhashed == 0
    assert rows[1]["prev_hash"] == rows[0]["entry_hash"]
    assert rows[2]["prev_hash"] == rows[1]["entry_hash"]


def test_verification_does_not_claim_a_truncated_chain_is_valid():
    engine = build_engine()
    sink = DatabaseAuditSink(engine)
    sink.record(event())
    sink.record(event())
    with engine.connect() as connection:
        report = verify_audit_chain(connection, limit=1)
    assert not report.valid and not report.complete
    assert report.reason == "verification limit reached"


def test_concurrent_sqlite_writers_do_not_fork_the_chain(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    engine = create_engine(f"sqlite:///{(tmp_path / 'audit.db').as_posix()}")
    Base.metadata.create_all(engine)
    sink = DatabaseAuditSink(engine)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: sink.record(event()), range(40)))
    with engine.connect() as connection:
        report = verify_audit_chain(connection)
    assert report.valid and report.checked == 40


def test_tampering_with_status_breaks_the_chain():
    engine = build_engine()
    sink = DatabaseAuditSink(engine)
    for status in ("requested", "succeeded"):
        sink.record(event(status))
    with engine.begin() as connection:
        target = connection.execute(select(AuditEvent.id).order_by(AuditEvent.created_at)).all()[1][0]
        connection.execute(update(AuditEvent).where(AuditEvent.id == target).values(status="denied"))
    with engine.connect() as connection:
        report = verify_audit_chain(connection)
    assert not report.valid and report.reason == "entry hash mismatch"
    assert report.first_break_id == str(target)


def test_tampering_with_the_previous_link_is_detected():
    engine = build_engine()
    sink = DatabaseAuditSink(engine)
    for status in ("requested", "succeeded"):
        sink.record(event(status))
    with engine.begin() as connection:
        second = connection.execute(select(AuditEvent.id).order_by(AuditEvent.created_at)).all()[1][0]
        connection.execute(update(AuditEvent).where(AuditEvent.id == second).values(prev_hash="0" * 64))
    with engine.connect() as connection:
        report = verify_audit_chain(connection)
    assert not report.valid and report.reason == "previous link mismatch"


def test_legacy_unhashed_rows_are_reported_not_treated_as_hostile():
    engine = build_engine()
    with engine.begin() as connection:
        connection.execute(insert(AuditEvent).values(
            id=uuid4(), call_id=uuid4(), tool_name="legacy", actor="old", target_type="web",
            status="requested", created_at=datetime(2026, 1, 1, tzinfo=timezone.utc)))
    sink = DatabaseAuditSink(engine)
    sink.record(event())
    with engine.connect() as connection:
        report = verify_audit_chain(connection)
    assert report.valid and report.checked == 1 and report.unhashed == 1


def test_session_sink_chains_inside_the_callers_transaction():
    engine = build_engine()
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as session:
        sink = SessionAuditSink(session)
        sink.record(event("requested"))
        sink.record(event("succeeded"))
        report = verify_audit_chain(session.connection())
        assert report.valid and report.checked == 2
        session.rollback()
    with engine.connect() as connection:
        assert connection.execute(select(AuditEvent)).all() == []


def test_entry_hash_is_deterministic_and_chain_dependent():
    values = {"id": str(uuid4()), "call_id": str(uuid4()), "tool_name": "t", "actor": "a",
              "target_type": "web", "status": "requested", "args_hash": None,
              "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc)}
    first = entry_hash(None, values)
    assert first == entry_hash(None, values) and len(first) == 64
    assert entry_hash("f" * 64, values) != first


def test_verification_limits_and_missing_table():
    engine = build_engine()
    with engine.connect() as connection:
        for bad in (0, -1, 10_001, True):
            with pytest.raises(ValueError, match="limit"):
                verify_audit_chain(connection, limit=bad)
    empty = create_engine("sqlite://")
    with pytest.raises(OperationalError):
        with empty.connect() as connection:
            verify_audit_chain(connection)


def test_invalid_events_are_rejected_before_hashing():
    engine = build_engine()
    sink = DatabaseAuditSink(engine)
    with pytest.raises(AuditError, match="invalid audit event"):
        sink.record({**event(), "extra": "secret"})
    with engine.connect() as connection:
        assert connection.execute(select(AuditEvent)).all() == []
