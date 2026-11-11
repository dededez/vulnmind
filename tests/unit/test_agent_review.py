"""Advisory model review: output handling, demotion, failure and service wiring."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from vulnmind.agents.audit import AgentAuditBridge
from vulnmind.agents.model import ModelError, ModelResponse, ModelUsage
from vulnmind.agents.review import MAX_REVIEW_GROUPS, review_findings
from vulnmind.agents.runtime import AgentRuntime
from vulnmind.analysis.service import RepositoryScanRequest, RepositoryScanService
from vulnmind.findings import FindingCandidate, group_findings
from vulnmind.schemas import Authorization, Target


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


class FakeModel:
    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def complete(self, request):
        self.requests.append(request)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return ModelResponse(text=reply, usage=ModelUsage(input_tokens=11, output_tokens=7))


def runtime(replies):
    return AgentRuntime(FakeModel(replies), Recorder())


def reply(*items, summary="reviewed"):
    return json.dumps({"summary": summary, "items": list(items)})


def item(fingerprint, verdict="likely", rationale="metadata suggests a real issue"):
    return {"fingerprint": fingerprint, "verdict": verdict, "rationale": rationale}


def group(location="a.py:1", *, evidence=(), tool="passive"):
    return group_findings([FindingCandidate(title="Missing CSP", vulnerability_type="missing_header",
                                            target_id="web-1", location=location, source_tool=tool,
                                            status="confirmed" if evidence else "unverified",
                                            severity="medium", evidence_refs=list(evidence))])[0]


def test_review_returns_verdicts_and_marks_references_untrusted():
    first, second = group("a.py:1"), group("b.py:2")
    model = FakeModel([reply(item(first.fingerprint, "false_positive", "header present"),
                             item(second.fingerprint))])
    result = review_findings(AgentRuntime(model, Recorder()), actor="tester", groups=[first, second])
    assert result.status == "completed" and result.attempts == 1
    assert [entry.verdict for entry in result.items] == ["false_positive", "likely"]
    assert result.usage.output_tokens == 7
    request = model.requests[0]
    text = "\n".join(message.content for message in request.messages)
    assert "<reference ref=\"finding:0\"" in text
    assert "untrusted data" in text
    assert first.fingerprint in text
    assert "a.py:1" not in text


def test_sensitive_finding_title_and_location_are_not_sent_to_provider():
    candidate = FindingCandidate(title="token=secret-value", vulnerability_type="missing_header",
                                 target_id="web-1", location="https://app.test/?token=secret-value",
                                 source_tool="passive", status="unverified", severity="medium")
    finding = group_findings([candidate])[0]
    model = FakeModel([reply(item(finding.fingerprint))])
    review_findings(AgentRuntime(model, Recorder()), actor="tester", groups=[finding])
    assert "secret-value" not in "\n".join(message.content for message in model.requests[0].messages)


def test_untrusted_rule_id_is_not_sent_to_model():
    candidate = FindingCandidate(title="safe", vulnerability_type="https://example.test/?token=private-rule-secret",
                                 target_id="web-1", location="app.py:1", source_tool="scanner")
    finding = group_findings([candidate])[0]
    model = FakeModel([reply(item(finding.fingerprint))])
    review_findings(AgentRuntime(model, Recorder()), actor="tester", groups=[finding])
    prompt = "\n".join(message.content for message in model.requests[0].messages)
    assert "private-rule-secret" not in prompt and "example.test" not in prompt
    assert "vulnerability_type: other" in prompt


def test_known_vulnerability_type_is_retained_for_model_review():
    finding = group("a.py:1")
    model = FakeModel([reply(item(finding.fingerprint))])
    review_findings(AgentRuntime(model, Recorder()), actor="tester", groups=[finding])
    prompt = "\n".join(message.content for message in model.requests[0].messages)
    assert "vulnerability_type: missing_header" in prompt


def test_unknown_and_duplicate_fingerprints_are_ignored():
    known = group("a.py:1")
    result = review_findings(AgentRuntime(FakeModel([
        reply(item("f" * 64), item(known.fingerprint), item(known.fingerprint))]), Recorder()),
        actor="tester", groups=[known])
    assert result.status == "completed"
    assert len(result.items) == 1 and result.ignored == 2


def test_confirmed_without_evidence_is_demoted():
    plain = group("a.py:1")
    result = review_findings(AgentRuntime(FakeModel([reply(item(plain.fingerprint, "confirmed"))]),
                                          Recorder()), actor="tester", groups=[plain])
    assert result.items[0].verdict == "likely"
    assert result.items[0].note and "demoted" in result.items[0].note


def test_confirmed_with_evidence_reference_is_demoted_without_evidence_contents():
    backed = group("a.py:1", evidence=["evidence:1"])
    result = review_findings(AgentRuntime(FakeModel([reply(item(backed.fingerprint, "confirmed"))]),
                                          Recorder()), actor="tester", groups=[backed])
    assert result.items[0].verdict == "likely" and "demoted" in result.items[0].note


def test_provider_failure_is_reported_not_raised():
    result = review_findings(AgentRuntime(FakeModel([ModelError("provider down")]), Recorder()),
                             actor="tester", groups=[group()])
    assert result.status == "failed" and result.error == "model review was unavailable"
    assert result.items == ()


def test_unexpected_provider_failure_does_not_abort_advisory_review():
    result = review_findings(AgentRuntime(FakeModel([RuntimeError("sensitive-provider-failure")]), Recorder()),
                             actor="tester", groups=[group()])
    assert result.status == "failed" and result.items == ()
    assert "sensitive-provider-failure" not in result.model_dump_json()


def test_two_invalid_replies_end_as_failed():
    result = review_findings(AgentRuntime(FakeModel(["not json", "still not json"]), Recorder()),
                             actor="tester", groups=[group()])
    assert result.status == "failed" and result.attempts == 0


def test_empty_groups_skip_without_calling_the_model():
    model = FakeModel([])
    result = review_findings(AgentRuntime(model, Recorder()), actor="tester", groups=[])
    assert result.status == "skipped" and model.requests == []


def test_review_reports_omitted_groups_and_missing_verdicts():
    from vulnmind.analysis.service import _report_review
    from vulnmind.reports.generator import ReportInput, generate

    groups = [group(f"file{i}.py:1") for i in range(30)]
    model = FakeModel([reply(item(groups[0].fingerprint))])
    review = review_findings(AgentRuntime(model, Recorder()), actor="tester", groups=groups)
    assert review.status == "completed" and len(review.items) == 1
    assert (review.total_groups, review.selected_groups, review.omitted_groups, review.groups_without_verdict) == (30, 25, 5, 24)
    report = ReportInput(scan_id="scan", project_id="project", mode="analysis", groups=groups,
                         agent_review=_report_review(review))
    rendered = json.loads(generate(report, format="json").content)
    assert rendered["schema_version"] == 7
    assert rendered["agent_review"]["omitted_groups"] == 5
    assert rendered["agent_review"]["groups_without_verdict"] == 24
    assert "未选入 5 组" in generate(report, format="markdown").content


def test_failed_review_does_not_claim_any_verdicts():
    groups = [group("a.py:1"), group("b.py:1")]
    review = review_findings(AgentRuntime(FakeModel([ModelError("unavailable")]), Recorder()),
                             actor="tester", groups=groups)
    assert review.status == "failed" and review.items == ()
    assert (review.total_groups, review.selected_groups, review.omitted_groups, review.groups_without_verdict) == (2, 2, 0, 2)


def test_review_revalidates_mutated_group_before_model_call():
    finding = group()
    finding.source_tools.append("forged")
    model = FakeModel([])
    with pytest.raises(ValueError, match="provenance"):
        review_findings(AgentRuntime(model, Recorder()), actor="tester", groups=[finding])
    assert model.requests == []


def test_review_rejects_bad_arguments():
    with pytest.raises(ValueError, match="AgentRuntime"):
        review_findings(object(), actor="tester", groups=[group()])
    with pytest.raises(ValueError, match="actor"):
        review_findings(runtime([]), actor="  ", groups=[group()])
    with pytest.raises(ValueError, match="max_groups"):
        review_findings(runtime([]), actor="tester", groups=[group()], max_groups=MAX_REVIEW_GROUPS + 1)
    with pytest.raises(ValueError, match="max_groups"):
        review_findings(runtime([]), actor="tester", groups=[group()], max_groups=True)
    with pytest.raises(ValueError, match="finding groups"):
        review_findings(runtime([]), actor="tester", groups=[{"not": "a group"}])


def test_audit_bridge_maps_statuses_and_drops_payloads():
    class Sink:
        def __init__(self):
            self.events = []

        def record(self, event):
            self.events.append(event)

    sink = Sink()
    bridge = AgentAuditBridge(sink)
    bridge.record({"agent": "triage/triage-reviewer", "actor": "tester", "status": "completed",
                   "output_tokens": 12})
    bridge.record({"agent": "triage/triage-reviewer", "actor": "tester", "status": "invalid_output"})
    bridge.record({"agent": "triage/triage-reviewer", "actor": "tester", "status": "unknown"})
    bridge.record({"agent": "triage/triage-reviewer", "actor": "tester", "status": "model_failed"})
    assert [event["status"] for event in sink.events] == ["succeeded", "retrying", "failed"]
    assert all(event["tool_name"] == "agent.triage/triage-reviewer" for event in sink.events)
    assert all(set(event) == {"call_id", "tool_name", "actor", "target_type", "status"}
               for event in sink.events)
    with pytest.raises(ValueError, match="audit sink"):
        AgentAuditBridge(object())
    with pytest.raises(ValueError, match="target type"):
        AgentAuditBridge(sink, target_type="database")


def test_runtime_audit_events_share_one_call_id_per_review():
    from sqlalchemy import create_engine, select
    from vulnmind.persistence.audit import DatabaseAuditSink, verify_audit_chain
    from vulnmind.persistence.base import Base
    from vulnmind.persistence.models import AuditEvent

    finding = group("a.py:1")
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    runtime = AgentRuntime(FakeModel(["invalid", reply(item(finding.fingerprint)),
                                      reply(item(finding.fingerprint))]),
                           AgentAuditBridge(DatabaseAuditSink(engine)))
    assert review_findings(runtime, actor="tester", groups=[finding]).status == "completed"
    assert review_findings(runtime, actor="tester", groups=[finding]).status == "completed"
    with engine.connect() as connection:
        rows = connection.execute(select(AuditEvent.call_id, AuditEvent.status).order_by(AuditEvent.created_at)).all()
        assert verify_audit_chain(connection).valid
    engine.dispose()
    assert [row.status for row in rows] == ["requested", "retrying", "succeeded", "requested", "succeeded"]
    assert rows[0].call_id == rows[1].call_id == rows[2].call_id
    assert rows[3].call_id == rows[4].call_id and rows[3].call_id != rows[0].call_id


def test_audit_bridge_rejects_invalid_call_id_without_persisting():
    class Sink:
        def record(self, event):
            pytest.fail("invalid call ID must not be persisted")
    with pytest.raises(ValueError, match="call ID"):
        AgentAuditBridge(Sink()).record({"agent": "triage/reviewer", "actor": "tester", "status": "requested",
                                         "call_id": "sensitive-invalid-id"})


def authorization(root):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)])


def analyzer(content):
    if "password =" in content.content:
        return [FindingCandidate(title="Hardcoded password", vulnerability_type="secret",
                                 target_id="x", location=f"{content.path}:1", source_tool="stub",
                                 severity="high")]
    return []


def test_service_attaches_advisory_review_to_the_report(tmp_path):
    (tmp_path / "settings.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    recorder = Recorder()
    model = FakeModel([reply(item("f" * 64, "false_positive", "looks fine"))])
    service = RepositoryScanService(recorder, [analyzer],
                                    agent_runtime=AgentRuntime(model, Recorder()))
    result = service.run(RepositoryScanRequest(
        scan_id="scan-1", project_id="project-1", actor="tester",
        target=Target(type="repository", locator=str(tmp_path)), scope=authorization(tmp_path)))
    assert result.agent_review is not None and result.agent_review.status == "completed"
    assert result.agent_review.ignored == 1
    assert "模型复核（建议，未验证）" in result.report.content
    assert "不构成验证" in result.report.content
    assert "模型复核仅为建议" in result.report.content
    # Deterministic triage is unchanged by the advisory verdict.
    assert result.decisions[0].severity == "high" and result.decisions[0].status == "unverified"


def test_service_without_a_runtime_keeps_the_deterministic_report(tmp_path):
    (tmp_path / "settings.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    result = RepositoryScanService(Recorder(), [analyzer]).run(RepositoryScanRequest(
        scan_id="scan-1", project_id="project-1", actor="tester",
        target=Target(type="repository", locator=str(tmp_path)), scope=authorization(tmp_path)))
    assert result.agent_review is None
    assert "模型复核" not in result.report.content
