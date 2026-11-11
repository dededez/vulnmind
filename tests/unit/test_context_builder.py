import pytest
from vulnmind.context.builder import ContextBudget, ContextItem, ContextOverflow, build_context


def item(ref, kind, text="xx", **kwargs):
    return ContextItem(ref=ref, kind=kind, text=text, **kwargs)


def test_budget_prioritizes_required_then_evidence_and_records_sources():
    items = [item("m", "memory", "12345"), item("s", "system"), item("t", "task"), item("e", "evidence", "123")]
    selected, manifest = build_context(items, ContextBudget(total=7))
    assert [value.ref for value in selected] == ["s", "t", "e"]
    assert manifest["estimated_tokens"] == 7
    assert next(row for row in manifest["items"] if row["ref"] == "m")["reason"] == "budget_exceeded"
    assert all("text" not in row for row in manifest["items"])


def test_required_context_fails_instead_of_silently_dropping():
    with pytest.raises(ContextOverflow):
        build_context([item("s", "system"), item("t", "task")], ContextBudget(total=3))
    with pytest.raises(ValueError):
        build_context([item("s", "system")], ContextBudget(total=100))


def test_kind_budget_relevance_and_duplicate_ids():
    items = [item("s", "system"), item("t", "task"), item("low", "rag", relevance=0.1), item("high", "rag", relevance=0.9)]
    selected, manifest = build_context(items, ContextBudget(total=20, by_kind={"rag": 2}))
    assert [value.ref for value in selected] == ["s", "t", "high"]
    assert manifest["estimated_tokens"] == 6
    with pytest.raises(ValueError):
        build_context(items + [item("s", "rag")], ContextBudget(total=100))


def test_custom_estimator_validation():
    with pytest.raises(ValueError):
        build_context([item("s", "system"), item("t", "task")], ContextBudget(total=100), estimate=lambda text: 0)


def test_mutated_budget_and_unvalidated_item_are_rejected():
    budget = ContextBudget(total=100, by_kind={"rag": 10})
    budget.by_kind["rag"] = -1
    with pytest.raises(ValueError):
        build_context([item("s", "system"), item("t", "task")], budget)
    invalid = item("s", "system").model_copy(update={"text": " "})
    with pytest.raises(ValueError):
        build_context([invalid, item("t", "task")], ContextBudget(total=100))
