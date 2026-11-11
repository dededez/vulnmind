"""Minimal planning graph; it never invokes tools or accesses targets."""
from langgraph.graph import END, START, StateGraph
from vulnmind.graph.state import VulnMindState
from vulnmind.schemas import AgentContext, ScanRequest
from vulnmind.security.scope import ScopeDenied, check_target
from vulnmind.planner import PlannerAgent


def validate_scope(state: VulnMindState) -> dict:
    try:
        request = ScanRequest.model_validate({"task_id": state["task_id"], "project_id": state["project_id"], "targets": state["targets"], "authorization": state["authorized_scope"]})
        for target in request.targets:
            check_target(target, request.authorization)
    except (ValueError, OSError, RuntimeError, KeyError):
        # A reused checkpoint may contain results from an earlier invocation.
        # Validation and filesystem exceptions may embed credentials or target data.
        return {"status": "blocked", "current_stage": "scope", "errors": ["scope validation failed"], "plan": {}, "findings": [], "evidence_refs": [], "mock_results": [], "report": {}}
    # A new invocation on an existing thread must not expose a previous report.
    return {"status": "authorized_for_planning", "current_stage": "scope", "errors": [], "plan": {}, "findings": [], "evidence_refs": [], "mock_results": [], "report": {}}


def plan(state: VulnMindState) -> dict:
    context = AgentContext(task_id=state["task_id"], project_id=state["project_id"], stage="planning")
    result = PlannerAgent().plan(state, context)
    if result.status != "success":
        return {"status": "blocked", "current_stage": "planning", "plan": {}, "findings": [], "evidence_refs": [], "errors": [result.error or "planning failed"]}
    return {"status": "planned", "current_stage": "planning", "plan": result.updates["plan"], "findings": [], "evidence_refs": []}


def build_graph(checkpointer=None):
    graph = StateGraph(VulnMindState)
    graph.add_node("scope", validate_scope)
    graph.add_node("plan", plan)
    graph.add_edge(START, "scope")
    graph.add_conditional_edges("scope", lambda s: "plan" if s["status"] == "authorized_for_planning" else "stop", {"plan": "plan", "stop": END})
    graph.add_edge("plan", END)
    return graph.compile(checkpointer=checkpointer)
