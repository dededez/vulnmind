import json

from vulnmind.context.builder import ContextItem
from vulnmind.context.profiles import budget_for
from vulnmind.workbench.context_shadow import shadow_report


def test_shadow_reports_selection_without_mutating_items():
    big = "x" * 200_000
    items = [
        ContextItem(ref="candidates", kind="execution", text=big, budget_group="candidates"),
        ContextItem(ref="previous", kind="execution", text=big, budget_group="previous"),
        ContextItem(ref="skill:/s", kind="skill", text="skill text", budget_group="skills"),
        ContextItem(ref="rag:/r", kind="rag", text="rag text", budget_group="rag"),
    ]
    report = shadow_report("planner", "system prompt", "task prompt", items, [big, big])
    assert report["profile"] == "planner"
    assert report["budget"] == 24_000 and report["unit"] == "tokens"
    assert report["legacy_tokens"] > 24_000
    assert report["used_tokens"] <= 24_000
    assert report["dropped_count"] >= 1
    assert "candidates" in report["dropped_refs"] or "previous" in report["dropped_refs"]
    assert report["overflow"] is None
    # The caller's items keep their original text and group.
    assert items[0].text is big and items[0].budget_group == "candidates"
    json.dumps(report)  # JSON-safe for durable payloads


def test_critic_profile_prefers_evidence_over_candidates():
    evidence = "e" * 20_000
    candidates = "c" * 2_000
    report = shadow_report(
        "critic", "system", "task",
        [ContextItem(ref="observations", kind="evidence", text=evidence, budget_group="evidence"),
         ContextItem(ref="candidates", kind="execution", text=candidates, budget_group="candidates")],
        [evidence, candidates])
    assert report["by_group"].get("evidence", 0) > report["by_group"].get("candidates", 0)
    assert budget_for("critic").by_group["evidence"] > budget_for("planner").by_group["evidence"]
