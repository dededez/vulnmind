"""Explicit simulation graph; no repository or network content is read."""
from pydantic import BaseModel
from langgraph.graph import END, START, StateGraph

from vulnmind.graph.state import VulnMindState
from vulnmind.graph.workflow import plan, validate_scope
from vulnmind.schemas import Authorization, Target
from vulnmind.tools.registry import AuditSink, ToolDefinition, ToolRegistry


class MockInput(BaseModel):
    target_type: str


class MockOutput(BaseModel):
    target_type: str
    mode: str = "simulation"
    analyzed: bool = False


async def _simulate(value: MockInput) -> MockOutput:
    return MockOutput(target_type=value.target_type)


def build_mock_graph(audit: AuditSink, checkpointer=None, *, interrupt_before_simulation: bool = False):
    """Build a synthetic end-to-end orchestration with no scanning side effects."""
    if interrupt_before_simulation and checkpointer is None:
        raise ValueError("interrupting a simulation requires a checkpointer")
    registry = ToolRegistry(audit)
    registry.register(ToolDefinition("mock.analysis", MockInput, _simulate, "No-op simulation"))

    async def run_mock(state: VulnMindState) -> dict:
        results = []
        try:
            scope = Authorization.model_validate(state["authorized_scope"])
            for item in state["targets"]:
                target = Target.model_validate(item)
                result = await registry.call("mock.analysis", {"target_type": target.type.value}, actor="mock_agent", target=target, scope=scope)
                results.append(result.model_dump())
        except Exception:
            return {"status": "failed", "current_stage": "simulation", "errors": ["simulation tool or audit failed"], "mock_results": [], "report": {}}
        return {"status": "simulated", "current_stage": "simulation", "mock_results": results}

    def report(state: VulnMindState) -> dict:
        return {"current_stage": "report", "report": {"mode": "simulation", "scanning_performed": False, "target_count": len(state["mock_results"]), "findings": []}}

    graph = StateGraph(VulnMindState)
    graph.add_node("scope", validate_scope)
    graph.add_node("plan", plan)
    graph.add_node("simulate", run_mock)
    graph.add_node("report", report)
    graph.add_edge(START, "scope")
    graph.add_conditional_edges("scope", lambda state: "plan" if state["status"] == "authorized_for_planning" else "stop", {"plan": "plan", "stop": END})
    graph.add_conditional_edges("plan", lambda state: "simulate" if state["status"] == "planned" else "stop", {"simulate": "simulate", "stop": END})
    graph.add_conditional_edges("simulate", lambda state: "report" if state["status"] == "simulated" else "stop", {"report": "report", "stop": END})
    graph.add_edge("report", END)
    return graph.compile(checkpointer=checkpointer, interrupt_before=["simulate"] if interrupt_before_simulation else None)
