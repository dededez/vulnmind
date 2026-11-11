import asyncio

from vulnmind.planner import PlannerAgent
from vulnmind.schemas import AgentContext


def test_planner_requires_scope_and_routes_mixed_targets():
    context = AgentContext(task_id="t", project_id="p", stage="planning")
    state = {"task_id": "t", "project_id": "p", "targets": [{"type": "repository", "locator": "/repo"}, {"type": "web", "locator": "https://example.test"}]}
    agent = PlannerAgent()
    assert asyncio.run(agent.run(state, context)).status == "blocked"
    state["status"] = "authorized_for_planning"
    result = asyncio.run(agent.run(state, context))
    assert result.status == "success"
    assert [step["agent"] for step in result.updates["plan"]["pipelines"]] == ["repository_analysis", "web_analysis"]
    assert all(step["status"] == "not_implemented" for step in result.updates["plan"]["pipelines"])


def test_planner_rejects_mismatched_context():
    context = AgentContext(task_id="other", project_id="p", stage="planning")
    state = {"task_id": "t", "project_id": "p", "status": "authorized_for_planning", "targets": [{"type": "web", "locator": "https://example.test"}]}
    assert asyncio.run(PlannerAgent().run(state, context)).status == "blocked"
