import pytest
from vulnmind.context.builder import ContextBudget, ContextItem, ContextOverflow, build_context
from vulnmind.context.profiles import PROFILES, budget_for
from vulnmind.context.tokens import estimate_tokens


def item(ref, kind, text="xx", **kwargs):
    return ContextItem(ref=ref, kind=kind, text=text, **kwargs)


def test_token_estimator_is_conservative_and_rejects_blank():
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("abcdefgh") == 2
    assert estimate_tokens("你好") == 2
    assert estimate_tokens("中文abcd") >= 3
    with pytest.raises(ValueError):
        estimate_tokens("   ")
    with pytest.raises(TypeError):
        estimate_tokens(123)


def test_byte_budget_remains_the_default_unit():
    selected, manifest = build_context(
        [item("s", "system"), item("t", "task"), item("e", "evidence", "123")],
        ContextBudget(total=7))
    assert manifest["unit"] == "bytes"
    assert manifest["estimated_tokens"] == 7
    assert [value.ref for value in selected] == ["s", "t", "e"]


def test_token_budget_uses_token_estimator_and_records_unit():
    selected, manifest = build_context(
        [item("s", "system", "abcd"), item("t", "task", "abcd"), item("e", "evidence", "abcdefghijkl")],
        ContextBudget(total=4, unit="tokens"))
    assert manifest["unit"] == "tokens"
    assert [value.ref for value in selected] == ["s", "t"]
    assert manifest["items"][-1]["reason"] == "budget_exceeded"


def test_group_budget_separates_execution_items():
    items = [
        item("s", "system", "xx"), item("t", "task", "xx"),
        item("cand", "execution", "abcdefgh", budget_group="candidates", relevance=0.9),
        item("prev", "execution", "abcdefgh", budget_group="previous", relevance=0.5),
    ]
    selected, manifest = build_context(
        items, ContextBudget(total=100, unit="tokens", by_group={"candidates": 2, "previous": 2}))
    refs = [value.ref for value in selected]
    assert "cand" in refs and "prev" in refs
    row = next(row for row in manifest["items"] if row["ref"] == "cand")
    assert row["group"] == "candidates"


def test_required_item_overflow_is_explicit_in_tokens():
    with pytest.raises(ContextOverflow):
        build_context(
            [item("s", "system", "abcdefgh", required=True),
             item("t", "task", "abcdefgh", required=True)],
            ContextBudget(total=1, unit="tokens"))


def test_planner_and_critic_profiles_are_bounded_and_different():
    planner, critic = budget_for("planner"), budget_for("critic")
    assert planner.unit == critic.unit == "tokens"
    assert planner.total == critic.total == 24_000
    assert sum(planner.by_group.values()) < planner.total
    assert sum(critic.by_group.values()) < critic.total
    assert planner.by_group["candidates"] > critic.by_group["candidates"]
    assert critic.by_group["evidence"] > planner.by_group["evidence"]
    assert set(PROFILES) == {"planner", "critic"}
    with pytest.raises(ValueError):
        budget_for("unknown")
