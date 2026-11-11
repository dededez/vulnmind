"""Context accounting for agent calls.

``shadow_report`` compares the legacy prompt with ContextBuilder selection
without changing what is sent. ``manifest_summary`` compacts a real
build_context result for durable stage payloads (P2+).
"""
from vulnmind.context.builder import ContextItem, ContextOverflow, build_context
from vulnmind.context.profiles import budget_for
from vulnmind.context.tokens import estimate_tokens


def shadow_report(profile, system, task, items, legacy_parts):
    """Return a compact, JSON-safe selection report for one agent call."""
    budget = budget_for(profile)
    full = [
        ContextItem(ref="system", kind="system", text=system, required=True,
                    budget_group="system_task"),
        ContextItem(ref="task", kind="task", text=task, required=True,
                    budget_group="system_task"),
        *items,
    ]
    legacy_text = "\n".join([system, task, *[part for part in legacy_parts if part]])
    overflow = None
    try:
        selected, manifest = build_context(full, budget)
    except ContextOverflow as exc:
        selected, manifest, overflow = [], {"items": [], "by_group": {}}, str(exc)
    dropped = [row["ref"] for row in manifest.get("items", []) if not row["selected"]]
    return dict(
        profile=profile,
        budget=budget.total,
        unit=budget.unit,
        legacy_chars=len(legacy_text),
        legacy_tokens=estimate_tokens(legacy_text),
        used_tokens=manifest.get("estimated_tokens", 0),
        selected_count=len(selected),
        dropped_count=len(dropped),
        by_group=manifest.get("by_group", {}),
        selected_refs=[item.ref for item in selected][:30],
        dropped_refs=dropped[:30],
        overflow=overflow,
    )


def manifest_summary(profile, manifest, selected):
    """Compact summary of a real build_context result for stage payloads."""
    dropped = [row["ref"] for row in manifest.get("items", []) if not row["selected"]]
    return dict(
        profile=profile,
        budget=manifest.get("budget"),
        unit=manifest.get("unit"),
        used_tokens=manifest.get("estimated_tokens", 0),
        selected_count=len(selected),
        dropped_count=len(dropped),
        by_group=manifest.get("by_group", {}),
        selected_refs=[item.ref for item in selected][:30],
        dropped_refs=dropped[:30],
        overflow=None,
    )
