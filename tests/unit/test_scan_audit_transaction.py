from types import SimpleNamespace
from uuid import uuid4

import pytest

from vulnmind.persistence import scan_audit
from vulnmind.persistence.audit import AuditError


class Session:
    def __init__(self, engine):
        pass
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def begin(self):
        return self


def test_audit_unavailable_before_execution_fails_closed(monkeypatch):
    class Sink:
        def __init__(self, engine): pass
        def record(self, event): raise AuditError("unavailable")
    monkeypatch.setattr(scan_audit, "DatabaseAuditSink", Sink)
    ran = False
    with pytest.raises(AuditError):
        with scan_audit.repository_scan_transaction(SimpleNamespace(dialect=SimpleNamespace(name="postgresql")), actor="test"):
            ran = True
    assert not ran


def test_post_commit_audit_failure_does_not_report_business_failure(monkeypatch):
    statuses = []
    class Sink:
        def __init__(self, engine): pass
        def record(self, event):
            statuses.append(event["status"])
            if event["status"] == "succeeded": raise AuditError("unavailable")
    monkeypatch.setattr(scan_audit, "DatabaseAuditSink", Sink)
    monkeypatch.setattr(scan_audit, "Session", Session)
    with pytest.raises(scan_audit.ScanCommitUnknown):
        with scan_audit.repository_scan_transaction(SimpleNamespace(dialect=SimpleNamespace(name="postgresql")), actor="test"):
            pass
    assert statuses == ["requested", "succeeded"]


def test_commit_failure_leaves_outcome_unknown(monkeypatch):
    statuses = []
    class Sink:
        def __init__(self, engine): pass
        def record(self, event): statuses.append(event["status"])
    class Transaction:
        def __enter__(self): return self
        def __exit__(self, *args): raise OSError("commit response lost")
    class CommitSession(Session):
        def begin(self): return Transaction()
    monkeypatch.setattr(scan_audit, "DatabaseAuditSink", Sink)
    monkeypatch.setattr(scan_audit, "Session", CommitSession)
    with pytest.raises(scan_audit.ScanCommitUnknown):
        with scan_audit.repository_scan_transaction(SimpleNamespace(dialect=SimpleNamespace(name="postgresql")), actor="test"):
            pass
    assert statuses == ["requested"]


def test_audit_failure_inside_scan_does_not_mark_root_failed(monkeypatch):
    statuses = []
    class Sink:
        def __init__(self, engine): pass
        def record(self, event): statuses.append(event["status"])
    monkeypatch.setattr(scan_audit, "DatabaseAuditSink", Sink)
    monkeypatch.setattr(scan_audit, "Session", Session)
    with pytest.raises(scan_audit.ScanCommitUnknown):
        with scan_audit.repository_scan_transaction(SimpleNamespace(dialect=SimpleNamespace(name="postgresql")), actor="test"):
            raise AuditError("completion event unavailable")
    assert statuses == ["requested"]


def test_failed_scan_with_unavailable_failure_audit_is_unknown(monkeypatch):
    statuses = []
    class Sink:
        def __init__(self, engine): pass
        def record(self, event):
            statuses.append(event["status"])
            if event["status"] == "failed": raise AuditError("unavailable")
    monkeypatch.setattr(scan_audit, "DatabaseAuditSink", Sink)
    monkeypatch.setattr(scan_audit, "Session", Session)
    with pytest.raises(scan_audit.ScanCommitUnknown):
        with scan_audit.repository_scan_transaction(SimpleNamespace(dialect=SimpleNamespace(name="postgresql")), actor="test"):
            raise RuntimeError("tool failure")
    assert statuses == ["requested", "failed"]


def test_correlation_link_is_written_before_first_event_and_once_per_call():
    events = []
    parent, child = uuid4(), uuid4()
    sink = scan_audit.CorrelatedAuditSink(SimpleNamespace(record=events.append), parent)
    event = {"call_id": str(child), "tool_name": "agent.test", "actor": "tester",
             "target_type": "repository", "status": "requested"}
    sink.record(event)
    sink.record({**event, "status": "failed"})
    assert [e["tool_name"] for e in events] == [f"correlation.{parent}", "agent.test", "agent.test"]
    assert all(e["call_id"] == str(child) for e in events)


def test_link_failure_prevents_child_execution_record():
    events = []
    def broken(event):
        events.append(event)
        raise AuditError("unavailable")
    sink = scan_audit.CorrelatedAuditSink(SimpleNamespace(record=broken), uuid4())
    with pytest.raises(AuditError):
        sink.record({"call_id": str(uuid4()), "tool_name": "agent.test", "actor": "tester",
                     "target_type": "repository", "status": "requested"})
    assert len(events) == 1 and events[0]["tool_name"].startswith("correlation.")


def test_incomplete_lifecycle_and_truncation_are_unknown(tmp_path):
    from sqlalchemy import create_engine
    from vulnmind.persistence.audit import DatabaseAuditSink, recent_scan_audits, trace_scan_audit
    from vulnmind.persistence.models import AuditEvent
    engine = create_engine(f"sqlite:///{(tmp_path / 'audit.db').as_posix()}")
    AuditEvent.__table__.create(engine)
    parent = uuid4()
    sink = DatabaseAuditSink(engine)
    event = {"call_id": str(parent), "tool_name": "repository.scan.transaction", "actor": "tester",
             "target_type": "repository"}
    sink.record({**event, "status": "requested"})
    with engine.connect() as connection:
        assert trace_scan_audit(connection, parent)["outcome"] == "unknown"
        recent = recent_scan_audits(connection)
        assert recent["scans"][0]["audit_call_id"] == str(parent)
        assert recent["scans"][0]["outcome"] == "unknown"
    sink.record({**event, "status": "succeeded"})
    with engine.connect() as connection:
        assert trace_scan_audit(connection, parent, limit=1)["outcome"] == "unknown"
        assert not trace_scan_audit(connection, parent, limit=1)["complete"]
        assert trace_scan_audit(connection, parent)["outcome"] == "committed"
    engine.dispose()


def test_completed_scan_does_not_hide_interrupted_or_conflicting_child(tmp_path):
    from sqlalchemy import create_engine
    from vulnmind.persistence.audit import DatabaseAuditSink, recent_scan_audits, trace_scan_audit
    from vulnmind.persistence.models import AuditEvent
    engine = create_engine(f"sqlite:///{(tmp_path / 'child.db').as_posix()}")
    AuditEvent.__table__.create(engine)
    parent, first, second = uuid4(), uuid4(), uuid4()
    sink = DatabaseAuditSink(engine)
    lifecycle = {"call_id": str(parent), "tool_name": "repository.scan.transaction",
                 "actor": "tester", "target_type": "repository"}
    sink.record({**lifecycle, "status": "requested"})
    child = scan_audit.CorrelatedAuditSink(sink, parent)
    event = {"call_id": str(first), "tool_name": "agent.test", "actor": "tester",
             "target_type": "repository", "status": "requested"}
    child.record(event)
    child.record({**event, "call_id": str(second)})
    child.record({**event, "call_id": str(second), "status": "succeeded"})
    child.record({**event, "call_id": str(second), "status": "failed"})
    sink.record({**lifecycle, "status": "succeeded"})
    with engine.connect() as connection:
        trace = trace_scan_audit(connection, parent)
        assert trace["outcome"] == "committed"
        assert {op["call_id"]: op["outcome"] for op in trace["operations"]} == {
            str(first): "unknown", str(second): "unknown"}
        assert recent_scan_audits(connection)["scans"][0]["operations_unknown"] == 2
    engine.dispose()


def test_sqlite_failure_keeps_lifecycle_but_reports_children_may_be_missing(tmp_path):
    from sqlalchemy import create_engine, text
    from vulnmind.persistence.audit import recent_scan_audits, trace_scan_audit, verify_audit_chain
    from vulnmind.persistence.models import AuditEvent
    engine = create_engine(f"sqlite:///{(tmp_path / 'rollback.db').as_posix()}")
    AuditEvent.__table__.create(engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE business (id INTEGER)"))
    call_id = None
    with pytest.raises(RuntimeError, match="test failure"):
        with scan_audit.repository_scan_transaction(engine, actor="tester") as (session, audit, call_id):
            session.execute(text("INSERT INTO business (id) VALUES (1)"))
            audit.record({"call_id": str(uuid4()), "tool_name": "agent.fake", "actor": "tester",
                          "target_type": "repository", "status": "requested"})
            raise RuntimeError("test failure")
    with engine.connect() as connection:
        from uuid import UUID
        trace = trace_scan_audit(connection, UUID(call_id))
        assert trace["outcome"] == "failed" and trace["operations_may_be_missing"] is True
        assert trace["operations"] == []
        assert recent_scan_audits(connection)["scans"][0]["operations_unknown"] is None
        assert connection.execute(text("SELECT COUNT(*) FROM business")).scalar_one() == 0
        assert verify_audit_chain(connection).valid
    engine.dispose()


def test_sqlite_interrupted_child_does_not_look_complete(tmp_path):
    import os
    import subprocess
    import sys
    from sqlalchemy import create_engine
    from vulnmind.persistence.audit import recent_scan_audits, trace_scan_audit, verify_audit_chain
    from vulnmind.persistence.models import AuditEvent
    from uuid import UUID
    url = f"sqlite:///{(tmp_path / 'interrupted.db').as_posix()}"
    engine = create_engine(url)
    AuditEvent.__table__.create(engine)
    code = """
import os, time
from uuid import uuid4
from sqlalchemy import create_engine
from vulnmind.persistence.scan_audit import repository_scan_transaction
engine = create_engine(os.environ['VULNMIND_TEST_AUDIT_SQLITE'])
with repository_scan_transaction(engine, actor='tester') as (_, audit, _):
    audit.record({'call_id': str(uuid4()), 'tool_name': 'agent.fake', 'actor': 'tester',
                  'target_type': 'repository', 'status': 'requested'})
    print('ready', flush=True)
    time.sleep(60)
"""
    env = {**os.environ, "VULNMIND_TEST_AUDIT_SQLITE": url}
    with pytest.raises(subprocess.TimeoutExpired) as interrupted:
        subprocess.run([sys.executable, "-c", code], env=env, timeout=5, capture_output=True)
    assert b"ready" in interrupted.value.stdout
    with engine.connect() as connection:
        recent = recent_scan_audits(connection)["scans"][0]
        trace = trace_scan_audit(connection, UUID(recent["audit_call_id"]))
        assert trace["outcome"] == "unknown" and trace["operations_may_be_missing"] is True
        assert recent["operations_unknown"] is None
        assert verify_audit_chain(connection).valid
    engine.dispose()


def test_sqlite_success_links_committed_children(tmp_path):
    from sqlalchemy import create_engine
    from vulnmind.persistence.audit import trace_scan_audit, verify_audit_chain
    from vulnmind.persistence.models import AuditEvent
    from uuid import UUID
    engine = create_engine(f"sqlite:///{(tmp_path / 'success.db').as_posix()}")
    AuditEvent.__table__.create(engine)
    child_id = str(uuid4())
    with scan_audit.repository_scan_transaction(engine, actor="tester", target_type="web") as (_, audit, call_id):
        event = {"call_id": child_id, "tool_name": "agent.fake", "actor": "tester", "target_type": "web"}
        audit.record({**event, "status": "requested"})
        audit.record({**event, "status": "succeeded"})
    with engine.connect() as connection:
        trace = trace_scan_audit(connection, UUID(call_id))
        assert trace["outcome"] == "committed" and not trace["operations_may_be_missing"]
        assert trace["operations"] == [{"call_id": child_id, "tool_name": "agent.fake", "outcome": "succeeded"}]
        assert verify_audit_chain(connection).valid
    engine.dispose()
