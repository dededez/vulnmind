from datetime import datetime, timedelta, timezone
from langgraph.checkpoint.memory import InMemorySaver
from vulnmind.graph.workflow import build_graph


def make_state(origin):
    now = datetime.now(timezone.utc)
    return {"task_id": "t1", "project_id": "p1", "targets": [{"type": "web", "locator": origin}], "authorized_scope": {"authorization_source": "test", "approved_by": "owner", "starts_at": now-timedelta(hours=1), "expires_at": now+timedelta(hours=1), "web_origins": ["https://example.test"]}}


def test_planning_graph_and_checkpoint():
    graph = build_graph(InMemorySaver())
    config = {"configurable": {"thread_id": "test-1"}}
    result = graph.invoke(make_state("https://example.test/api"), config)
    assert result["status"] == "planned"
    assert result["findings"] == []
    assert graph.get_state(config).values["plan"]["target_types"] == ["web"]


def test_denied_target_stops_before_planning():
    result = build_graph().invoke(make_state("https://evil.test"))
    assert result["status"] == "blocked"
    assert result["plan"] == {}


def test_reused_checkpoint_does_not_keep_previous_plan_on_denial():
    graph = build_graph(InMemorySaver())
    config = {"configurable": {"thread_id": "reused"}}
    assert graph.invoke(make_state("https://example.test"), config)["status"] == "planned"
    denied = graph.invoke(make_state("https://evil.test"), config)
    assert denied["status"] == "blocked"
    assert denied["plan"] == {}
    assert denied["findings"] == []


def test_invalid_input_is_not_embedded_in_error_messages():
    state = make_state("https://example.test")
    state["targets"] = [{"type": "not-valid-secret-value", "locator": "https://example.test"}]
    result = build_graph().invoke(state)
    assert result["status"] == "blocked"
    assert "not-valid-secret-value" not in str(result["errors"])
