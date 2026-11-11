"""Planner selection is bounded by explicitly enabled tools."""
import json

import pytest
from vulnmind.agents.model import ModelResponse
from vulnmind.agents.runtime import AgentRuntime
from vulnmind.agents.tool_plan import select_repository_tools


class Audit:
    def record(self, event): pass


class Model:
    def __init__(self, selected): self.selected, self.requests = selected, []
    def complete(self, request):
        self.requests.append(request)
        return ModelResponse(text=json.dumps({"selected_tools": self.selected}))


def test_selection_is_limited_and_prompt_contains_only_fixed_labels():
    model = Model(["bandit_json"])
    result = select_repository_tools(AgentRuntime(model, Audit()), enabled={"bandit_json", "semgrep_sarif"}, actor="t")
    assert result == ("bandit_json",)
    prompt = "\n".join(message.content for message in model.requests[0].messages)
    assert "bandit_json" in prompt and "semgrep_sarif" in prompt


@pytest.mark.parametrize("selected", [["trivy_sandbox"], ["bandit_json", "bandit_json"]])
def test_unknown_or_duplicate_selection_fails_closed(selected):
    with pytest.raises(ValueError, match="unknown or duplicate"):
        select_repository_tools(AgentRuntime(Model(selected), Audit()), enabled={"bandit_json"}, actor="t")


def test_no_optional_tools_does_not_call_model():
    model = Model([])
    assert select_repository_tools(AgentRuntime(model, Audit()), enabled=set(), actor="t") == ()
    assert model.requests == []
