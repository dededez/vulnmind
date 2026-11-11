from typing import TypedDict


class VulnMindState(TypedDict, total=False):
    task_id: str
    project_id: str
    targets: list[dict]
    authorized_scope: dict
    status: str
    current_stage: str
    plan: dict
    errors: list[str]
    findings: list[dict]
    evidence_refs: list[str]
    mock_results: list[dict]
    report: dict
    decisions: list[dict]
    analysis: dict
    workflow_options: dict
