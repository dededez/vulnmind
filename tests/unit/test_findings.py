import pytest
from pydantic import ValidationError
from vulnmind.findings import FindingCandidate, group_findings


def finding(**changes):
    fields = {"title": "Possible injection", "vulnerability_type": "SQLi", "target_id": "repo-1", "location": "src/app.py:12", "source_tool": "tool-a"}
    return FindingCandidate(**{**fields, **changes})


def test_verified_outcomes_require_evidence():
    for status in ("confirmed", "not_reproduced"):
        with pytest.raises(ValidationError):
            finding(status=status)
    assert finding(status="unverified").evidence_refs == []
    assert finding(status="confirmed", evidence_refs=["evidence:1"]).status == "confirmed"


def test_grouping_preserves_sources_evidence_and_disagreement():
    first = finding(status="confirmed", evidence_refs=["evidence:1"])
    second = finding(vulnerability_type="sqli", source_tool="tool-b", status="not_reproduced", evidence_refs=["evidence:2", "evidence:1"])
    other = finding(location="src/app.py:13")
    groups = group_findings([first, second, other])
    assert len(groups) == 2
    assert groups[0].source_tools == ["tool-a", "tool-b"]
    assert groups[0].evidence_refs == ["evidence:1", "evidence:2"]
    assert [candidate.status for candidate in groups[0].candidates] == ["confirmed", "not_reproduced"]
    assert groups[0].fingerprint != groups[1].fingerprint


def test_blank_evidence_and_extra_fields_rejected():
    with pytest.raises(ValidationError):
        finding(evidence_refs=[" "])
    with pytest.raises(ValidationError):
        finding(unknown="unexpected")
