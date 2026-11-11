"""Independent planner audit survives a read-only scan transaction rollback."""
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from vulnmind.persistence.audit import DatabaseAuditSink, verify_audit_chain
from vulnmind.persistence.models import AuditEvent


@pytest.mark.skipif(not os.getenv("VULNMIND_TEST_DATABASE_URL"), reason="dedicated PostgreSQL test database not configured")
def test_http_audit_survives_business_rollback_without_real_network():
    from datetime import datetime, timedelta, timezone
    from vulnmind.schemas import Authorization, Target
    from vulnmind.tools.http import HttpRequestInput
    from vulnmind.tools.http_single_hop import HopResponse, SingleHopRequester

    url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
    if url.get_backend_name() != "postgresql":
        pytest.fail("dedicated PostgreSQL is required")
    schema = "vulnmind_http_audit_" + uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(url.update_query_dict({"options": f"-csearch_path={schema},public"}))
    try:
        AuditEvent.__table__.create(engine)
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE business (id integer)"))
        now = datetime.now(timezone.utc)
        scope = Authorization(authorization_source="synthetic", approved_by="tester",
            starts_at=now-timedelta(hours=1), expires_at=now+timedelta(hours=1),
            web_origins=["https://example.test"], allowed_ip_networks=["192.0.2.0/24"])
        sensitive = "https://example.test/?token=synthetic-private"
        calls = []
        def fake_transport(**kwargs):
            calls.append(kwargs)
            return HopResponse(status_code=200, body=b"synthetic")
        with Session(engine) as session:
            session.begin()
            session.execute(text("INSERT INTO business (id) VALUES (1)"))
            requester = SingleHopRequester(DatabaseAuditSink(engine),
                                           resolve=lambda _host: ["192.0.2.1"], transport=fake_transport)
            requester.request(HttpRequestInput(url=sensitive), actor="tester",
                              target=Target(type="web", locator=sensitive), scope=scope)
            session.rollback()
        with engine.connect() as connection:
            rows = connection.execute(select(AuditEvent.tool_name, AuditEvent.status)
                                      .order_by(AuditEvent.created_at)).all()
            assert [row.status for row in rows] == ["requested", "started", "succeeded"]
            assert "synthetic-private" not in str(rows)
            assert connection.execute(text("SELECT COUNT(*) FROM business")).scalar_one() == 0
            assert verify_audit_chain(connection).valid and len(calls) == 1
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.mark.skipif(not os.getenv("VULNMIND_TEST_DATABASE_URL"), reason="dedicated PostgreSQL test database not configured")
@pytest.mark.parametrize("failure", [True, False])
def test_validation_plan_has_independent_correlated_audit(tmp_path, monkeypatch, capsys, failure):
    import json
    import sys
    from uuid import UUID
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    from vulnmind.persistence.audit import trace_scan_audit, recent_scan_audits
    from vulnmind.persistence.base import Base
    from vulnmind.persistence.models import Project, Scan
    from vulnmind.persistence.repositories import WebEndpointRepository

    url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
    if url.get_backend_name() != "postgresql":
        pytest.fail("dedicated PostgreSQL is required")
    schema = "vulnmind_plan_" + uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped_url = url.update_query_dict({"options": f"-csearch_path={schema},public"})
    engine = create_engine(scoped_url)
    try:
        Base.metadata.create_all(engine)
        project_id, scan_id = uuid4(), uuid4()
        with Session(engine) as session, session.begin():
            session.add(Project(id=project_id, name="synthetic plan"))
            session.flush()
            session.add(Scan(id=scan_id, project_id=project_id, status="finished", mode="web"))
            session.flush()
            WebEndpointRepository(session).replace_for_scan(scan_id, project_id,
                [{"url": "https://private.test/search", "parameters": ["private_name"]}])
        requests = []
        class FakeModel:
            def complete(self, request):
                requests.append(request)
                if failure:
                    raise RuntimeError("private model failure")
                return ModelResponse(text=json.dumps({"summary": "review", "selections": [{"index": 0, "reason": "review"}]}))
        monkeypatch.setattr(deepseek, "DeepSeekClient", FakeModel)
        monkeypatch.setenv("VULNMIND_DATABASE_URL", scoped_url.render_as_string(hide_password=False))
        monkeypatch.setattr(sys, "argv", ["vulnmind", "validation-plan", "--scan-id", str(scan_id)])
        assert __main__.main() == (1 if failure else 0)
        output = capsys.readouterr().out
        assert "private model failure" not in output
        payload = json.loads(output)
        assert payload["status"] == ("failed" if failure else "completed") and payload["audit_call_id"]
        prompt = " ".join(message.content for message in requests[0].messages)
        assert "private.test" not in prompt and "private_name" not in prompt
        with engine.connect() as connection:
            trace = trace_scan_audit(connection, UUID(payload["audit_call_id"]))
            assert trace["outcome"] == "committed"
            assert any(event["tool_name"].startswith("agent.") for event in trace["events"])
            assert any(event["tool_name"].startswith("agent.") and event["outcome"] == ("failed" if failure else "succeeded")
                       for event in trace["operations"])
            assert recent_scan_audits(connection)["scans"][0]["audit_call_id"] == payload["audit_call_id"]
            assert verify_audit_chain(connection).valid
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.mark.skipif(not os.getenv("VULNMIND_TEST_DATABASE_URL"), reason="dedicated PostgreSQL test database not configured")
@pytest.mark.parametrize("failure", [True, False])
def test_web_cli_independent_audit_survives_rollback(tmp_path, monkeypatch, capsys, failure):
    import json
    import sys
    from datetime import datetime, timedelta, timezone
    from vulnmind import __main__
    from vulnmind.agents.model import ModelResponse
    from vulnmind.agents import deepseek
    from vulnmind.analysis.web_service import WebScanService
    from vulnmind.persistence.base import Base
    from vulnmind.persistence.audit import trace_scan_audit, recent_scan_audits
    from vulnmind.persistence.models import Project, Scan

    url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
    if url.get_backend_name() != "postgresql":
        pytest.fail("dedicated PostgreSQL is required")
    schema = "vulnmind_web_" + uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped_url = url.update_query_dict({"options": f"-csearch_path={schema},public"})
    engine = create_engine(scoped_url)
    try:
        Base.metadata.create_all(engine)
        project_id = uuid4()
        with Session(engine) as session, session.begin():
            session.add(Project(id=project_id, name="synthetic web"))
        now = datetime.now(timezone.utc)
        scope = {"authorization_source": "test", "approved_by": "test",
                 "starts_at": (now - timedelta(hours=1)).isoformat(),
                 "expires_at": (now + timedelta(hours=1)).isoformat(), "web_origins": ["http://example.test"]}
        snapshot = {"version": 1, "target": {"type": "web", "locator": "http://example.test/"},
                    "pages": [{"url": "http://example.test/", "status_code": 200,
                               "content_type": "text/html", "headers": {"server": "test"}, "html": "<p>test</p>"}]}
        scope_file, snapshot_file = tmp_path / "scope.json", tmp_path / "snapshot.json"
        scope_file.write_text(json.dumps(scope), encoding="utf-8")
        snapshot_file.write_text(json.dumps(snapshot), encoding="utf-8")
        monkeypatch.setenv("VULNMIND_DATABASE_URL", scoped_url.render_as_string(hide_password=False))
        monkeypatch.setenv("VULNMIND_REPORT_ROOT", str(tmp_path / "reports"))
        monkeypatch.setenv("VULNMIND_EVIDENCE_ROOT", "")
        class FakeModel:
            def complete(self, request):
                return ModelResponse(text=json.dumps({"summary": "synthetic review", "items": []}))
        monkeypatch.setattr(deepseek, "DeepSeekClient", FakeModel)
        if failure:
            def broken(*args, **kwargs):
                raise RuntimeError("private web error")
            monkeypatch.setattr(WebScanService, "run", broken)
        monkeypatch.setattr(sys, "argv", ["vulnmind", "web-analyze", "--snapshot", str(snapshot_file),
                            "--project-id", str(project_id), "--scope-file", str(scope_file), "--agent-review"])
        assert __main__.main() == (2 if failure else 0)
        output = capsys.readouterr().out
        assert "private web error" not in output
        payload = json.loads(output)
        with Session(engine) as session:
            assert (session.scalar(select(Scan)) is None) is failure
            from uuid import UUID
            trace = trace_scan_audit(session.connection(), UUID(payload["audit_call_id"]))
            assert trace["outcome"] == ("failed" if failure else "committed")
            if not failure:
                assert payload["audit_independent"] is True
                assert any(event["tool_name"].startswith("agent.") for event in trace["events"])
            assert recent_scan_audits(session.connection())["scans"][0]["audit_call_id"] == payload["audit_call_id"]
            assert verify_audit_chain(session.connection()).valid
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.mark.skipif(not os.getenv("VULNMIND_TEST_DATABASE_URL"), reason="dedicated PostgreSQL test database not configured")
@pytest.mark.parametrize("failure", [True, False])
def test_repository_cli_failure_keeps_audit_and_rolls_back_scan(tmp_path, monkeypatch, capsys, failure):
    import json
    import sys
    from datetime import datetime, timedelta, timezone
    from vulnmind import __main__
    from vulnmind.analysis import python_tls
    from vulnmind.persistence.base import Base
    from vulnmind.persistence.models import Project, Scan

    url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
    if url.get_backend_name() != "postgresql":
        pytest.fail("dedicated PostgreSQL is required")
    schema = "vulnmind_cli_" + uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped_url = url.update_query_dict({"options": f"-csearch_path={schema},public"})
    engine = create_engine(scoped_url)
    try:
        Base.metadata.create_all(engine)
        project_id = uuid4()
        with Session(engine) as session, session.begin():
            session.add(Project(id=project_id, name="synthetic"))
        root = tmp_path / "repository"
        root.mkdir()
        (root / "test.py").write_text("x = 1\n", encoding="utf-8")
        now = datetime.now(timezone.utc)
        scope = {"authorization_source": "test", "approved_by": "test",
                 "starts_at": (now - timedelta(hours=1)).isoformat(),
                 "expires_at": (now + timedelta(hours=1)).isoformat(), "repository_roots": [str(root)]}
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(json.dumps(scope), encoding="utf-8")
        monkeypatch.setenv("VULNMIND_DATABASE_URL", scoped_url.render_as_string(hide_password=False))
        monkeypatch.setenv("VULNMIND_REPORT_ROOT", str(tmp_path / "reports"))
        monkeypatch.setenv("VULNMIND_EVIDENCE_ROOT", "")
        def broken(_content):
            raise RuntimeError("private error")
        if failure:
            monkeypatch.setattr(python_tls, "find_python_tls_candidates", broken)
        monkeypatch.setattr(sys, "argv", ["vulnmind", "scan", "--repository", str(root),
                            "--project-id", str(project_id), "--scope-file", str(scope_file)])
        assert __main__.main() == (2 if failure else 0)
        output = capsys.readouterr().out
        assert "private error" not in output
        payload = json.loads(output)
        with Session(engine) as session:
            assert (session.scalar(select(Scan)) is None) is failure
            rows = session.execute(select(AuditEvent.tool_name, AuditEvent.status)
                                   .order_by(AuditEvent.created_at)).all()
            assert ("repository.scan", "failed" if failure else "pending_commit") in rows
            assert ("repository.scan.transaction", "failed" if failure else "succeeded") in rows
            from vulnmind.persistence.audit import trace_scan_audit
            trace = trace_scan_audit(session.connection(), __import__("uuid").UUID(payload["audit_call_id"]))
            assert trace["outcome"] == ("failed" if failure else "committed")
            assert any(event["tool_name"] == "repository.scan" for event in trace["events"])
            assert trace["chain_verified"] is False
            if not failure:
                assert payload["audit_independent"] is True
                assert session.scalar(select(AuditEvent.call_id).where(
                    AuditEvent.tool_name == "repository.scan.transaction",
                    AuditEvent.status == "succeeded")) == __import__("uuid").UUID(payload["audit_call_id"])
            assert verify_audit_chain(session.connection()).valid
        monkeypatch.setattr(sys, "argv", ["vulnmind", "audit-trace", "--call-id", payload["audit_call_id"]])
        assert __main__.main() == 0
        assert json.loads(capsys.readouterr().out)["outcome"] == ("failed" if failure else "committed")
        monkeypatch.setattr(sys, "argv", ["vulnmind", "audit-recent"])
        assert __main__.main() == 0
        assert json.loads(capsys.readouterr().out)["scans"][0]["audit_call_id"] == payload["audit_call_id"]
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.mark.skipif(not os.getenv("VULNMIND_TEST_DATABASE_URL"), reason="dedicated PostgreSQL test database not configured")
def test_planner_audit_survives_scan_rollback():
    from concurrent.futures import ThreadPoolExecutor
    import subprocess
    import sys
    import time
    from vulnmind.persistence.audit import AuditError, recent_scan_audits, trace_scan_audit
    url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
    if url.get_backend_name() != "postgresql":
        pytest.fail("dedicated PostgreSQL is required")
    schema = "vulnmind_audit_" + uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = create_engine(url.update_query_dict({"options": f"-csearch_path={schema},public"}))
    try:
        AuditEvent.__table__.create(scoped)
        event = {"call_id": str(uuid4()), "tool_name": "repository.plan.selection",
                 "actor": "test", "target_type": "repository"}
        with Session(scoped) as session:
            session.begin()
            session.execute(text("SELECT 1"))
            DatabaseAuditSink(scoped).record({**event, "status": "requested"})
            DatabaseAuditSink(scoped).record({**event, "status": "failed"})
            session.rollback()
        with scoped.connect() as connection:
            rows = connection.execute(select(AuditEvent.status).order_by(AuditEvent.created_at)).scalars().all()
            assert rows == ["requested", "failed"]
            assert verify_audit_chain(connection).valid
        def write_one(_):
            DatabaseAuditSink(scoped).record({"call_id": str(uuid4()), "tool_name": "parallel.test",
                                             "actor": "test", "target_type": "repository", "status": "requested"})
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(write_one, range(16)))
        with scoped.connect() as connection:
            chain = verify_audit_chain(connection)
            assert chain.valid and chain.checked == 18
        with scoped.begin() as blocker:
            blocker.execute(text("SELECT pg_advisory_xact_lock(621842500317)"))
            started = time.monotonic()
            with pytest.raises(AuditError, match="unavailable"):
                write_one(0)
            assert time.monotonic() - started < 10
        env = os.environ.copy()
        env["VULNMIND_AUDIT_PROBE_URL"] = url.update_query_dict(
            {"options": f"-csearch_path={schema},public"}).render_as_string(hide_password=False)
        script = """
import os, time
from sqlalchemy import create_engine
from pydantic import BaseModel
from vulnmind.agents.audit import AgentAuditBridge
from vulnmind.agents.model import ModelResponse
from vulnmind.agents.runtime import AgentRuntime, AgentSpec
from vulnmind.persistence.scan_audit import repository_scan_transaction
class Result(BaseModel):
    ok: bool
class HangingModel:
    def complete(self, request):
        print('ready', flush=True)
        time.sleep(60)
class CompletedModel:
    def complete(self, request):
        return ModelResponse(text='{"ok": true}')
engine = create_engine(os.environ['VULNMIND_AUDIT_PROBE_URL'])
with repository_scan_transaction(engine, actor='test') as (_, audit, parent):
    AgentRuntime(CompletedModel(), AgentAuditBridge(audit)).run(
        AgentSpec(name='complete', role='test', system_prompt='test'),
        task='synthetic', context=[], schema=Result, actor='test')
    runtime = AgentRuntime(HangingModel(), AgentAuditBridge(audit))
    runtime.run(AgentSpec(name='interrupt', role='test', system_prompt='test'),
                task='synthetic', context=[], schema=Result, actor='test')
"""
        with pytest.raises(subprocess.TimeoutExpired) as interrupted:
            subprocess.run([sys.executable, "-c", script], env=env, timeout=8, capture_output=True)
        assert b"ready" in interrupted.value.stdout
        with scoped.connect() as connection:
            recent = recent_scan_audits(connection)
            parent = __import__("uuid").UUID(recent["scans"][0]["audit_call_id"])
            trace = trace_scan_audit(connection, parent)
            assert trace["outcome"] == "unknown"
            assert any(item["tool_name"] == "agent.test/interrupt" and item["status"] == "requested" for item in trace["events"])
            assert any(item["tool_name"] == "agent.test/interrupt" and item["outcome"] == "unknown" for item in trace["operations"])
            assert any(item["tool_name"] == "agent.test/complete" and item["outcome"] == "succeeded" for item in trace["operations"])
            assert verify_audit_chain(connection).valid
    finally:
        scoped.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()
