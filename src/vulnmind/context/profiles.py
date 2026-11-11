"""Budget profiles for bounded agent context.

Group budgets are per-group maxima, not additive: the total is the hard cap and
the difference to the sum of group maxima is deliberate headroom for schemas,
message wrappers and estimator error. Planner and critic need different splits:
the planner needs candidates and tool routing, the critic needs evidence.
"""
from vulnmind.context.builder import ContextBudget

PLANNER_BUDGET = dict(
    total=24_000, unit="tokens",
    by_group={
        "system_task": 3_000,
        "evidence": 1_000,
        "skills": 3_500,
        "rag": 1_500,
        "candidates": 5_000,
        "previous": 2_000,
        "routing": 1_000,
        "memory": 500,
    },
)
CRITIC_BUDGET = dict(
    total=24_000, unit="tokens",
    by_group={
        "system_task": 3_000,
        "evidence": 8_000,
        "skills": 2_500,
        "rag": 1_000,
        "candidates": 1_000,
        "previous": 2_000,
        "routing": 500,
        "memory": 500,
    },
)
PROFILES = {"planner": PLANNER_BUDGET, "critic": CRITIC_BUDGET}


def budget_for(profile: str) -> ContextBudget:
    if profile not in PROFILES:
        raise ValueError("unknown context profile: " + str(profile))
    return ContextBudget(**PROFILES[profile])
