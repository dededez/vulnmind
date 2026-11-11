"""Repository workflow tests: scope gate, analysis result and safe errors."""
from datetime import datetime, timedelta, timezone

import pytest
from langgraph.checkpoint.memory import InMemorySaver

from vulnmind.analysis.service import RepositoryScanService
from vulnmind.findings import FindingCandidate
from vulnmind.graph.repository_workflow import build_repository_graph
from vulnmind.schemas import Authorization, Target


class Recorder:
    def record(self, event):
        pass


def analyzer(content):
    return [FindingCandidate(title="stub finding", vulnerability_type="misconfig",
                             target_id="x", location=f"{content.path}:1", source_tool="stub")]


def state_for(root, scope_root=None):
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner",
                          starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                          repository_roots=[str(scope_root or root)])
    return {"task_id": "task-1", "project_id": "project-1",
            "targets": [Target(type="repository", locator=str(root)).model_dump(mode="json")],
            "authorized_scope": scope.model_dump(mode="json")}


def build_repo(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


def graph():
    return build_repository_graph(RepositoryScanService(Recorder(), [analyzer]))


def test_valid_scope_runs_the_analysis(tmp_path):
    build_repo(tmp_path)
    result = graph().invoke(state_for(tmp_path))
    assert result["status"] == "analyzed"
    assert result["analysis"]["files_examined"] == 1
    assert len(result["findings"]) == 1
    assert result["report"]["counts"]["unverified"] == 1
    assert "stub finding" in result["report"]["content"]


def test_scope_denial_blocks_without_echoing_the_locator(tmp_path):
    build_repo(tmp_path)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    result = graph().invoke(state_for(tmp_path, scope_root=allowed))
    assert result["status"] == "blocked"
    assert str(tmp_path) not in str(result.get("errors"))
    assert not result.get("report")


def test_web_target_is_blocked(tmp_path):
    build_repo(tmp_path)
    state = state_for(tmp_path)
    state["targets"] = [Target(type="web", locator="https://example.test").model_dump(mode="json")]
    result = graph().invoke(state)
    assert result["status"] == "blocked"


def test_graph_works_with_a_checkpointer(tmp_path):
    build_repo(tmp_path)
    graph_with_saver = build_repository_graph(RepositoryScanService(Recorder(), [analyzer]),
                                              checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "run-1"}}
    result = graph_with_saver.invoke(state_for(tmp_path), config)
    assert result["status"] == "analyzed"
    saved = graph_with_saver.get_state(config).values
    assert saved["status"] == "analyzed" and saved["analysis"]["files_examined"] == 1


def test_service_configuration_is_required():
    with pytest.raises(ValueError, match="analyser"):
        RepositoryScanService(Recorder(), [])


def test_reused_thread_does_not_expose_previous_scan_on_scope_denial(tmp_path):
    build_repo(tmp_path)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    workflow = build_repository_graph(RepositoryScanService(Recorder(), [analyzer]),
                                      checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "reused"}}
    assert workflow.invoke(state_for(tmp_path), config)["report"]["content"]
    blocked = workflow.invoke(state_for(tmp_path, scope_root=allowed), config)
    assert blocked["status"] == "blocked"
    assert not blocked["report"] and not blocked["findings"]
    assert not blocked["analysis"] and not blocked["evidence_refs"]


def test_resumed_analysis_rechecks_authorization(tmp_path):
    from vulnmind.graph.repository_workflow import _analyze

    build_repo(tmp_path)
    state = state_for(tmp_path)
    state["authorized_scope"]["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    result = _analyze(RepositoryScanService(Recorder(), [analyzer]))(state)
    assert result["status"] == "blocked"
    assert not result["report"] and not result["findings"]
