"""Opt-in planner choosing only explicitly enabled repository analyzers."""
from pydantic import BaseModel, ConfigDict, Field

from vulnmind.agents.prompts import PLANNER
from vulnmind.context.builder import ContextItem

ALLOWED = frozenset({"gitleaks_sandbox", "trivy_sandbox", "semgrep_sarif", "bandit_json", "checkov_mcp"})


class ToolPlanDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    selected_tools: list[str] = Field(max_length=5)


def select_repository_tools(runtime, *, enabled: set[str], actor: str) -> tuple[str, ...]:
    """Choose from user-enabled tools; this function performs no tool calls."""
    if not isinstance(enabled, set) or not enabled <= ALLOWED:
        raise ValueError("invalid enabled tool set")
    if not enabled:
        return ()
    context = [ContextItem(ref=f"tool:{i}", kind="execution", text=name)
               for i, name in enumerate(sorted(enabled))]
    output = runtime.run(PLANNER,
        task="Select repository analyzers only from the provided names. Return selected_tools as exact names. "
             "This is selection only; built-in TLS analysis always runs.",
        context=context, schema=ToolPlanDraft, actor=actor)
    selected = output.data.selected_tools
    if len(set(selected)) != len(selected) or any(item not in enabled for item in selected):
        raise ValueError("planner selected unknown or duplicate tools")
    return tuple(sorted(selected))
