"""LangGraph workflow for an authorized repository analysis run.

The graph only orchestrates: scope validation, then the injected
``RepositoryScanService``, then a terminal status. Findings are persisted by the
caller, so the graph stays checkpoint-friendly and free of database handles.
"""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from vulnmind.analysis.service import RepositoryScanRequest, RepositoryScanService
from vulnmind.graph.state import VulnMindState
from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import ScopeDenied, check_target

_BLOCKED_SCOPE = "target is outside the authorized scope or the authorization is invalid"


def build_repository_graph(service: RepositoryScanService, checkpointer=None):
    graph = StateGraph(VulnMindState)
    graph.add_node("validate_scope", _validate(service))
    graph.add_node("analyze", _analyze(service))
    graph.add_node("blocked", _blocked)
    graph.add_edge(START, "validate_scope")
    graph.add_conditional_edges("validate_scope", _route, {"analyze": "analyze", "blocked": "blocked"})
    graph.add_edge("analyze", END)
    graph.add_edge("blocked", END)
    return graph.compile(checkpointer=checkpointer)


def _validate(service: RepositoryScanService):
    def node(state: VulnMindState) -> dict:
        try:
            targets = [Target.model_validate(item) for item in state.get("targets", [])]
            scope = Authorization.model_validate(state["authorized_scope"])
            if len(targets) != 1 or targets[0].type.value != "repository":
                raise ScopeDenied("exactly one repository target is required")
            check_target(targets[0], scope)
        except (ScopeDenied, KeyError, TypeError, ValueError):
            # Never echo the locator, authorization data or exception text.
            return {"status": "blocked", "errors": [_BLOCKED_SCOPE], **_clear_results()}
        return {"status": "validated", "errors": [], "current_stage": "analysis", **_clear_results()}
    return node


def _clear_results() -> dict:
    # A LangGraph thread may be reused with a different input. Never expose
    # data from its preceding run if the new run is blocked or interrupted.
    return {"findings": [], "decisions": [], "analysis": {}, "report": {},
            "evidence_refs": [], "plan": {}}


def _analyze(service: RepositoryScanService):
    def node(state: VulnMindState) -> dict:
        # Checkpoint resumption can bypass the validation node. Authorization
        # may also have expired since it was last checked.
        validation = _validate(service)(state)
        if validation["status"] != "validated":
            return {**validation, "current_stage": "finished"}
        request = RepositoryScanRequest(
            scan_id=state.get("task_id", "task"), project_id=state.get("project_id", "project"),
            actor="agent", target=Target.model_validate(state["targets"][0]),
            scope=Authorization.model_validate(state["authorized_scope"]),
            max_files=200, max_bytes=200_000)
        result = service.run(request)
        analysis = result.analysis
        return {
            "status": "analyzed",
            "findings": [finding.model_dump(mode="json") for finding in analysis.findings],
            "decisions": [decision.model_dump(mode="json") for decision in result.decisions],
            "analysis": {"target_id": analysis.target_id,
                         "files_examined": analysis.files_examined,
                         "files_skipped": analysis.files_skipped,
                         "groups": len(analysis.groups)},
            "report": {"format": result.report.format, "sha256": result.report.sha256,
                       "counts": result.report.counts, "content": result.report.content},
            "evidence_refs": [ref for group in analysis.groups for ref in group.evidence_refs],
        }
    return node


def _blocked(state: VulnMindState) -> dict:
    return {"status": "blocked", "current_stage": "finished"}


def _route(state: VulnMindState) -> str:
    return "analyze" if state.get("status") == "validated" else "blocked"
