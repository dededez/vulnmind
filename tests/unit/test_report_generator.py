"""Report rendering tests: determinism, banner, counts and sanitisation."""
import hashlib
import json
from datetime import datetime, timezone

import pytest

from vulnmind.findings import FindingCandidate, group_findings
from vulnmind.reports.generator import ReportInput, count_by_status, generate, render_json, render_markdown


def candidate(**overrides):
    payload = {"title": "SQL injection in search", "vulnerability_type": "sqli", "target_id": "t-1",
               "location": "src/search.py:42", "source_tool": "semgrep", "status": "unverified"}
    payload.update(overrides)
    return FindingCandidate(**payload)


def report(groups=None, mode="simulation", **overrides):
    payload = {"scan_id": "scan-1", "project_id": "project-1", "mode": mode,
               "groups": groups if groups is not None else [],
               "generated_at": datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)}
    payload.update(overrides)
    return ReportInput(**payload)


def test_simulation_report_keeps_the_not_scanned_banner():
    document = generate(report([group_findings([candidate()])[0]]))
    assert document.format == "markdown"
    assert "未执行真实扫描" in document.content
    assert "SQL injection in search" in document.content
    assert document.sha256 == hashlib.sha256(document.content.encode("utf-8")).hexdigest()


def test_analysis_report_has_no_simulation_banner():
    document = generate(report([group_findings([candidate(status="confirmed", evidence_refs=["evidence:1"])])[0]],
                               mode="analysis"), format="json")
    assert document.format == "json"
    payload = json.loads(document.content)
    assert payload["not_scanned"] is False
    assert payload["validation_performed"] is False
    assert payload["status_interpretation"] == "source_claim_not_independently_verified"
    assert payload["counts"]["confirmed"] == 1
    assert payload["groups"][0]["evidence_refs"] == ["evidence:1"]


def test_evidence_snapshot_is_distinct_from_source_claims_and_can_be_truncated():
    from uuid import uuid4
    group = group_findings([candidate(evidence_refs=["untrusted:claim"])])[0]
    record_id = uuid4()
    value = report([group], mode="analysis", evidence_snapshot="available", evidence_snapshot_truncated=True,
                   evidence_record_ids={group.fingerprint: [record_id]})
    payload = render_json(value)
    assert payload["groups"][0]["evidence_refs"] == ["untrusted:claim"]
    assert payload["groups"][0]["stored_evidence_ids"] == [str(record_id)]
    assert payload["evidence_snapshot_truncated"] is True
    content = render_markdown(value)
    assert "证据记录清单已截断" in content and "未核验文件完整性" in content
    assert "可能尚未提交" in content and str(record_id) in content
    with pytest.raises(ValueError, match="unavailable"):
        report([group], evidence_record_ids={group.fingerprint: [record_id]})
    with pytest.raises(ValueError, match="reported group"):
        report([group], evidence_snapshot="available", evidence_record_ids={"other": [record_id]})


def test_counts_cover_every_status():
    groups = group_findings([
        candidate(status="unverified"),
        candidate(status="confirmed", evidence_refs=["e:1"], location="b.py:1"),
        candidate(status="not_reproduced", evidence_refs=["e:2"], location="c.py:2"),
        candidate(status="insufficient_evidence", location="d.py:3"),
    ])
    counts = count_by_status(groups)
    assert counts == {"unverified": 1, "confirmed": 1, "not_reproduced": 1, "insufficient_evidence": 1}


def test_empty_report_does_not_claim_the_target_is_clean():
    document = generate(report())
    assert "没有发现不等于不存在漏洞" in document.content
    assert "本次运行没有产生任何发现候选" in document.content


def test_json_is_stable_and_complete():
    document = generate(report([group_findings([candidate(severity="high")])[0]], limitations=["仅静态分析"]), format="json")
    first = document.content
    second = generate(report([group_findings([candidate(severity="high")])[0]], limitations=["仅静态分析"]), format="json").content
    assert first == second
    payload = json.loads(first)
    assert set(payload) == {"schema_version", "scan_id", "project_id", "mode", "generated_at",
                            "not_scanned", "validation_performed", "status_interpretation", "counts",
                            "groups", "limitations", "decisions", "validation_required", "agent_review",
                            "evidence_snapshot", "evidence_snapshot_truncated", "evidence_snapshot_interpretation",
                            "open_validation_required", "feedback", "feedback_interpretation"}
    assert payload["schema_version"] == 7
    assert payload["evidence_snapshot"] == "unavailable"
    assert payload["groups"][0]["stored_evidence_ids"] == []
    assert payload["agent_review"] is None
    assert payload["groups"][0]["source_tools"] == ["semgrep"]
    assert payload["groups"][0]["severities"] == ["high"]
    assert payload["groups"][0]["candidates"][0]["severity"] == "high"


def test_markdown_shows_unassessed_severity():
    content = render_markdown(report([group_findings([candidate()])[0]]))
    assert "- 风险：未评定" in content


def test_agent_review_block_is_advisory_in_json_and_markdown():
    from vulnmind.reports.generator import AgentReviewItem, AgentReviewSummary

    review = AgentReviewSummary(status="completed", summary="one possible issue", ignored=1,
                                items=(AgentReviewItem(fingerprint="a" * 64, verdict="likely",
                                                       rationale="looks real"),))
    group = group_findings([candidate()])[0]
    payload = json.loads(generate(report([group], agent_review=review), format="json").content)
    assert payload["agent_review"]["interpretation"] == "advisory_model_review_not_verification"
    assert payload["agent_review"]["items"][0]["verdict"] == "likely"
    assert payload["agent_review"]["ignored"] == 1
    markdown = render_markdown(report([group], agent_review=review))
    assert "## 模型复核（建议，未验证）" in markdown
    assert "a" * 16 in markdown and "不构成验证" in markdown


def test_agent_review_failure_does_not_claim_verification():
    from vulnmind.reports.generator import AgentReviewSummary

    content = render_markdown(report([group_findings([candidate()])[0]],
                                     agent_review=AgentReviewSummary(status="failed")))
    assert "复核状态：failed" in content
    assert "扫描保留确定性结果" in content


def test_review_coverage_counts_must_be_complete_and_consistent():
    from vulnmind.reports.generator import AgentReviewSummary

    with pytest.raises(ValueError, match="supplied together"):
        AgentReviewSummary(status="failed", total_groups=2)
    with pytest.raises(ValueError, match="inconsistent"):
        AgentReviewSummary(status="failed", total_groups=2, selected_groups=1,
                           omitted_groups=0, groups_without_verdict=1)
    with pytest.raises(ValueError, match="inconsistent"):
        AgentReviewSummary(status="failed", total_groups=2, selected_groups=2,
                           omitted_groups=0, groups_without_verdict=0)


def test_markdown_fields_cannot_inject_structure():
    group = group_findings([candidate(title="bad\n## injected | `code`", location="a|b.py:1", source_tool="tool\n## forged <img src=x>")])[0]
    content = render_markdown(report([group]))
    assert "\n## injected" not in content
    assert "\n## forged" not in content
    assert "<img" not in content
    assert "\\|" in content
    assert "系统尚未独立验证" in content


def test_report_rejects_tampered_group_provenance():
    group = group_findings([candidate()])[0]
    group.evidence_refs.append("fabricated:evidence")
    with pytest.raises(ValueError, match="provenance"):
        report([group])


def test_render_revalidates_report_mutated_after_construction():
    value = report([group_findings([candidate()])[0]])
    value.groups[0].source_tools.append("fabricated")
    with pytest.raises(ValueError, match="provenance"):
        render_json(value)
    with pytest.raises(ValueError, match="provenance"):
        render_markdown(value)


def test_verified_without_evidence_is_rejected_upstream():
    with pytest.raises(ValueError, match="evidence"):
        candidate(status="confirmed")


def test_unknown_format_is_rejected():
    with pytest.raises(ValueError, match="format"):
        generate(report(), format="html")


def test_decisions_are_rendered_with_confidence_and_validation_flag():
    from vulnmind.reports.generator import DecisionSummary

    grouped = group_findings([candidate(severity="high")])[0]
    decision = DecisionSummary(fingerprint=grouped.fingerprint, severity="high", confidence=0.4,
                               requires_validation=True, rationale=("base confidence 0.30 for unverified",))
    payload = json.loads(generate(report([grouped], decisions=[decision]), format="json").content)
    assert payload["validation_required"] == 1
    assert payload["decisions"][0]["confidence"] == 0.4
    assert payload["decisions"][0]["rationale"][0].startswith("base confidence")

    content = render_markdown(report([grouped], decisions=[decision]))
    assert "需要人工验证的分组：1" in content
    assert "- 置信度：0.40（需人工验证：是）" in content


def test_decisions_without_a_matching_group_do_not_appear_in_sections():
    from vulnmind.reports.generator import DecisionSummary

    grouped = group_findings([candidate()])[0]
    orphan = DecisionSummary(fingerprint="f" * 64, severity="low", confidence=0.2)
    content = render_markdown(report([grouped], decisions=[orphan]))
    assert "置信度" not in content
    assert "需要人工验证的分组：1" in content


def test_timestamp_must_be_timezone_aware():
    with pytest.raises(ValueError, match="timezone-aware"):
        report(generated_at=datetime(2026, 11, 3, 12, 0))

