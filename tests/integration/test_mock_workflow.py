import asyncio
from datetime import datetime, timedelta, timezone
from langgraph.checkpoint.memory import InMemorySaver
from sqlalchemy import create_engine, func, select
from vulnmind.graph.mock_workflow import build_mock_graph
from vulnmind.persistence.audit import DatabaseAuditSink
from vulnmind.persistence.models import AuditEvent
from vulnmind.security.scope import ScopeDenied


class Audit:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


def make_state(path, web):
    now = datetime.now(timezone.utc)
    return {"task_id": "test", "project_id": "project", "targets": [{"type": "repository", "locator": str(path)}, {"type": "web", "locator": web}], "authorized_scope": {"authorization_source": "test", "approved_by": "owner", "starts_at": now-timedelta(hours=1), "expires_at": now+timedelta(hours=1), "repository_roots": [str(path)], "web_origins": ["https://example.test"]}}


def test_mixed_simulation_calls_registered_tool_and_marks_result(tmp_path):
    audit = Audit()
    graph = build_mock_graph(audit, InMemorySaver())
    config = {"configurable": {"thread_id": "mixed"}}
    state = asyncio.run(graph.ainvoke(make_state(tmp_path, "https://example.test"), config))
    assert state["status"] == "simulated"
    assert state["report"] == {"mode": "simulation", "scanning_performed": False, "target_count": 2, "findings": []}
    assert [result["target_type"] for result in state["mock_results"]] == ["repository", "web"]
    assert all(not result["analyzed"] for result in state["mock_results"])
    assert [event["status"] for event in audit.events] == ["requested", "started", "succeeded"] * 2


def test_denied_target_never_calls_simulation_tool(tmp_path):
    audit = Audit()
    graph = build_mock_graph(audit)
    state = asyncio.run(graph.ainvoke(make_state(tmp_path, "https://outside.test")))
    assert state["status"] == "blocked"
    assert audit.events == []
    assert state["report"] == {}


def test_mock_workflow_records_durable_audit_in_sqlite(tmp_path):
    engine = create_engine("sqlite://")
    AuditEvent.__table__.create(engine)
    graph = build_mock_graph(DatabaseAuditSink(engine))
    result = asyncio.run(graph.ainvoke(make_state(tmp_path, "https://example.test")))
    assert result["status"] == "simulated"
    with engine.connect() as connection:
        count = connection.execute(select(func.count()).select_from(AuditEvent.__table__)).scalar_one()
    assert count == 6


def test_interrupted_simulation_resumes_once_without_early_tool_calls(tmp_path):
    audit = Audit()
    graph = build_mock_graph(audit, InMemorySaver(), interrupt_before_simulation=True)
    config = {"configurable": {"thread_id": "interrupt-test"}}
    async def scenario():
        paused = await graph.ainvoke(make_state(tmp_path, "https://example.test"), config)
        assert paused["status"] == "planned"
        assert audit.events == []
        resumed = await graph.ainvoke(None, config)
        assert resumed["status"] == "simulated"
        assert len(audit.events) == 6
        await graph.ainvoke(None, config)
        assert len(audit.events) == 6
    asyncio.run(scenario())


def test_audit_failure_stops_simulation_without_report(tmp_path):
    class BrokenAudit:
        def record(self, event):
            raise OSError("not for output")
    result = asyncio.run(build_mock_graph(BrokenAudit()).ainvoke(make_state(tmp_path, "https://example.test")))
    assert result["status"] == "failed"
    assert result["report"] == {}
    assert "not for output" not in str(result["errors"])


def test_new_invocation_clears_prior_report_before_interrupt(tmp_path):
    audit = Audit()
    graph = build_mock_graph(audit, InMemorySaver(), interrupt_before_simulation=True)
    config = {"configurable": {"thread_id": "reuse"}}
    async def scenario():
        await graph.ainvoke(make_state(tmp_path, "https://example.test"), config)
        assert (await graph.ainvoke(None, config))["report"]["scanning_performed"] is False
        paused = await graph.ainvoke(make_state(tmp_path, "https://example.test"), config)
        assert paused["status"] == "planned"
        assert paused["report"] == {}
        assert paused["mock_results"] == []
    asyncio.run(scenario())


def test_scope_is_rechecked_after_resume(tmp_path, monkeypatch):
    audit = Audit()
    graph = build_mock_graph(audit, InMemorySaver(), interrupt_before_simulation=True)
    config = {"configurable": {"thread_id": "recheck"}}
    async def scenario():
        await graph.ainvoke(make_state(tmp_path, "https://example.test"), config)
        def expired(*args, **kwargs):
            raise ScopeDenied("expired")
        monkeypatch.setattr("vulnmind.tools.registry.check_target", expired)
        result = await graph.ainvoke(None, config)
        assert result["status"] == "failed"
        assert result["mock_results"] == []
        assert result["report"] == {}
        assert [event["status"] for event in audit.events] == ["requested", "denied"]
    asyncio.run(scenario())
