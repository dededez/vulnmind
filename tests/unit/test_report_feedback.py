"""Report rendering of operator feedback; verdicts never become verification."""
import json
from datetime import datetime, timezone

import pytest

from vulnmind.findings import FindingCandidate, group_findings
from vulnmind.reports.generator import (DecisionSummary, FeedbackSummary, ReportInput, generate)


def candidate():
    return FindingCandidate(title="Reflected input", vulnerability_type="reflected_input",
                            target_id="https://example.test", location="/search?q=marker",
                            source_tool="builtin.reflection", status="unverified", severity="medium")


def build(feedback=(), decisions=None):
    group = group_findings([candidate()])[0]
    return ReportInput(scan_id="scan", project_id="project", mode="analysis", groups=[group],
                       feedback=feedback,
                       decisions=decisions if decisions is not None else [
                           DecisionSummary(fingerprint=group.fingerprint, severity="medium",
                                           confidence=0.3, requires_validation=True,
                                           rationale=("validation required",))])


def feedback(verdict="false_positive"):
    group = group_findings([candidate()])[0]
    return FeedbackSummary(fingerprint=group.fingerprint, verdict=verdict, actor="alice",
                           note="test data", revision=2,
                           recorded_at=datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc))


def test_json_reports_feedback_and_open_validation():
    document = generate(build([feedback()]), format="json")
    payload = json.loads(document.content)
    assert payload["schema_version"] == 7
    assert payload["feedback_interpretation"] == "operator_recorded_decision_not_verification"
    assert payload["validation_required"] == 1
    assert payload["open_validation_required"] == 0
    assert payload["feedback"] == [{
        "fingerprint": feedback().fingerprint, "verdict": "false_positive", "actor": "alice",
        "note": "test data", "revision": 2, "recorded_at": "2026-11-04T12:00:00+00:00"}]


def test_needs_more_info_keeps_validation_open():
    payload = json.loads(generate(build([feedback("needs_more_info")]), format="json").content)
    assert payload["open_validation_required"] == 1


def test_markdown_labels_feedback_as_operator_record():
    content = generate(build([feedback()])).content
    assert "人工判定：误报" in content
    assert "操作者记录" in content
    assert "不是系统的漏洞验证结论" in content
    assert "第 2 次记录" in content
    assert "test data" in content
    assert "排除已记录人工判定后的待验证分组：0" in content


def test_feedback_must_match_a_reported_group():
    with pytest.raises(ValueError):
        build([FeedbackSummary(fingerprint="b" * 64, verdict="confirmed", actor="alice",
                               recorded_at=datetime.now(timezone.utc), revision=1)])


def test_one_verdict_per_finding():
    item = feedback()
    with pytest.raises(ValueError):
        build([item, item.model_copy(update={"revision": 3})])


def test_feedback_timestamp_must_be_aware():
    with pytest.raises(ValueError):
        FeedbackSummary(fingerprint="a" * 64, verdict="confirmed", actor="alice",
                        recorded_at=datetime(2026, 11, 4, 12, 0), revision=1)
