"""Deterministic planning only: no model calls and no target analysis."""
from vulnmind.graph.state import VulnMindState
from vulnmind.schemas import AgentContext, AgentResult, Target, TargetType


def create_plan(targets: list[dict]) -> dict:
    concrete = [Target.model_validate(target) for target in targets]
    if not concrete:
        raise ValueError("at least one target is required")
    kinds = sorted({target.type.value for target in concrete})
    pipelines = []
    for target in concrete:
        pipelines.append({"target_type": target.type.value,
                          "agent": "repository_analysis" if target.type == TargetType.REPOSITORY else "web_analysis",
                          "status": "not_implemented"})
    return {"target_types": kinds, "pipelines": pipelines,
            "note": "Planning only; no analysis or tools executed."}


class PlannerAgent:
    name = "planner"

    def plan(self, state: VulnMindState, context: AgentContext) -> AgentResult:
        if state.get("task_id") != context.task_id or state.get("project_id") != context.project_id:
            return AgentResult(status="blocked", error="context does not match task")
        if context.stage != "planning":
            return AgentResult(status="blocked", error="context does not match stage")
        if state.get("status") != "authorized_for_planning":
            return AgentResult(status="blocked", error="scope has not been validated")
        try:
            plan = create_plan(state["targets"])
        except (KeyError, ValueError):
            return AgentResult(status="failed", error="invalid targets")
        return AgentResult(status="success", updates={"plan": plan}, next_action="analysis_not_implemented")

    async def run(self, state: VulnMindState, context: AgentContext) -> AgentResult:
        return self.plan(state, context)
