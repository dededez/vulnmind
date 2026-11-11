"""Triage rule tests: deterministic, conservative, explained."""
import pytest

from vulnmind.analysis.triage import triage_group, triage_groups
from vulnmind.findings import FindingCandidate, group_findings


def candidate(**overrides):
    payload = {"title": "Issue", "vulnerability_type": "sqli", "target_id": "t-1",
               "location": "src/app.py:1", "source_tool": "tool-a"}
    payload.update(overrides)
    return FindingCandidate(**payload)


def group(*candidates):
    return group_findings(list(candidates))[0]


def test_unverified_single_tool_requires_validation():
    decision = triage_group(group(candidate()))
    assert decision.status == "unverified" and decision.severity == "unknown"
    assert decision.confidence == 0.3 and decision.requires_validation is True
    assert any("base confidence" in line for line in decision.rationale)


def test_unverified_tool_labels_and_evidence_do_not_raise_confidence():
    decision = triage_group(group(candidate(source_tool="tool-a"), candidate(source_tool="tool-b")))
    assert decision.confidence == 0.3
    with_evidence = triage_group(group(candidate(source_tool="tool-a", evidence_refs=["e:1"]),
                                       candidate(source_tool="tool-b", evidence_refs=["e:1"])))
    assert with_evidence.confidence == 0.3
    assert any("not independently verified" in line for line in with_evidence.rationale)


def test_claimed_confirmation_still_needs_validation():
    decision = triage_group(group(candidate(status="confirmed", evidence_refs=["e:1"])))
    assert decision.status == "unverified" and decision.confidence == 0.3
    assert decision.requires_validation is True


def test_claimed_non_reproduction_still_needs_validation():
    decision = triage_group(group(candidate(status="not_reproduced", evidence_refs=["e:1"])))
    assert decision.status == "unverified"
    assert decision.requires_validation is True


def test_disagreement_caps_confidence_and_stays_unverified():
    decision = triage_group(group(candidate(source_tool="a", status="unverified"),
                                  candidate(source_tool="b", status="confirmed", evidence_refs=["e:1"])))
    assert decision.status == "unverified" and decision.confidence <= 0.5
    assert decision.requires_validation is True
    assert "disagree" in decision.rationale[0]


def test_severity_uses_the_most_severe_declared_value():
    decision = triage_group(group(candidate(severity="low"), candidate(severity="critical")))
    assert decision.severity == "critical"


def test_confidence_is_never_above_the_cap():
    decision = triage_group(group(candidate(status="confirmed", evidence_refs=["e:1"], source_tool="a"),
                                  candidate(status="confirmed", evidence_refs=["e:1"], source_tool="b")))
    assert decision.confidence <= 0.95


def test_batch_triage_preserves_order():
    first = group(candidate(location="a.py:1"))
    second = group(candidate(location="b.py:2", severity="high"))
    decisions = triage_groups([first, second])
    assert [decision.fingerprint for decision in decisions] == [first.fingerprint, second.fingerprint]
    assert decisions[0].severity == "unknown" and decisions[1].severity == "high"


def test_decisions_are_frozen():
    decision = triage_group(group(candidate()))
    with pytest.raises(Exception):
        decision.confidence = 1.0


def test_triage_rejects_mutated_group_metadata():
    value = group(candidate())
    value.source_tools.append("invented")
    with pytest.raises(ValueError, match="provenance"):
        triage_group(value)
