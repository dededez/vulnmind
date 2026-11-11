"""Model-assisted validation planning: selection bounds and plan-file integrity."""
import json

import pytest

from vulnmind.agents.model import ModelError, ModelResponse, ModelUsage
from vulnmind.agents.runtime import AgentRuntime
from vulnmind.agents.validation_plan import MAX_SELECTIONS, select_probes
from vulnmind.analysis.validation import (MAX_PROBES, Probe, plan_digest, plan_probes, load_plan)


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
        return ModelResponse(text=reply, usage=ModelUsage(input_tokens=12, output_tokens=6))


def runtime(replies):
    return AgentRuntime(FakeModel(replies), Recorder())


URL = "https://app.test/search?q=x&page=2"


def candidate(kind, parameter):
    return next(probe for probe in plan_probes([URL])
                if probe.kind == kind and probe.parameter == parameter)


def reply(*selections, summary="selected"):
    return json.dumps({"summary": summary, "selections": list(selections)})


def selection(kind, parameter, reason="worth one request"):
    probe = candidate(kind, parameter)
    return {"index": plan_probes([URL]).index(probe), "reason": reason}


def test_selects_only_known_candidates_and_ignores_inventions():
    valid = selection("reflection", "q")
    duplicate = dict(valid)
    invented = {"index": 999, "reason": "invented"}
    wrong_payload = {"index": 998, "reason": "modified payload"}
    plan = select_probes(runtime([reply(valid, duplicate, invented, wrong_payload)]),
                         actor="tester", urls=[URL], max_selections=5)
    assert plan.status == "completed"
    assert [(item.probe.kind, item.probe.parameter) for item in plan.selected] == [("reflection", "q")]
    assert plan.ignored == 3 and plan.candidates == len(plan_probes([URL]))
    assert plan.digest == plan_digest([plan.selected[0].probe])
    assert plan.summary == "selected"


def test_model_never_receives_sensitive_url_or_parameter():
    model = FakeModel([reply({"index": 0, "reason": "review"})])
    plan = select_probes(AgentRuntime(model, Recorder()), actor="tester",
                         urls=["https://private.example/path?q=x&token=secret-value"])
    request = "\n".join(message.content for message in model.requests[0].messages)
    assert "private.example" not in request and "secret-value" not in request
    assert plan.status == "completed" and len(plan.selected) == 1


def test_model_does_not_receive_form_candidate_names_or_query_values():
    from types import SimpleNamespace
    from vulnmind.agents.form_candidates import form_candidate_urls
    urls, _ = form_candidate_urls([SimpleNamespace(method="GET", url="https://private.example/search?token=secret",
                                                    parameters=["private_form_name"])])
    model = FakeModel([reply({"index": 0, "reason": "review"})])
    plan = select_probes(AgentRuntime(model, Recorder()), actor="tester", urls=urls)
    request = "\n".join(message.content for message in model.requests[0].messages)
    assert all(value not in request for value in ("private.example", "secret", "private_form_name"))
    assert plan.status == "completed"


def test_selection_is_capped():
    selections = [selection(kind, parameter) for kind, parameter in
                  [("reflection", "q"), ("sql_error", "q"), ("xss_reflection", "q"),
                   ("template_injection", "q"), ("reflection", "page"), ("sql_error", "page")]]
    plan = select_probes(runtime([reply(*selections)]), actor="tester", urls=[URL],
                         max_selections=2)
    assert len(plan.selected) == 2 and plan.digest is not None


def test_candidate_limit_is_explicit_even_if_model_fails():
    urls = [f"https://app.test/search/{i}?q=value" for i in range(10)]
    plan = select_probes(runtime([reply({"index": 0, "reason": "review"})]), actor="tester", urls=urls)
    assert plan.candidates == MAX_PROBES and plan.candidates_truncated
    failed = select_probes(runtime([ModelError("unavailable")]), actor="tester", urls=urls)
    assert failed.status == "failed" and failed.candidates_truncated


def test_exact_candidate_limit_does_not_claim_truncation():
    from vulnmind.analysis.validation import plan_probes_with_coverage
    probes, truncated = plan_probes_with_coverage(["https://app.test/?foo=1"], max_probes=3)
    assert len(probes) == 3 and not truncated


def test_empty_or_failed_plan():
    assert select_probes(runtime([]), actor="tester", urls=[]).status == "skipped"
    assert select_probes(runtime([]), actor="tester",
                         urls=["https://app.test/about"]).status == "skipped"
    plan = select_probes(runtime([ModelError("unavailable")]), actor="tester", urls=[URL])
    assert plan.status == "failed" and plan.error and plan.selected == () and plan.digest is None


def test_runtime_and_bounds_are_validated():
    with pytest.raises(ValueError):
        select_probes(object(), actor="tester", urls=[URL])
    with pytest.raises(ValueError):
        select_probes(runtime([]), actor=" ", urls=[URL])
    for bad in (0, MAX_SELECTIONS + 1, True):
        with pytest.raises(ValueError):
            select_probes(runtime([]), actor="tester", urls=[URL], max_selections=bad)
    for bad_urls in (URL, [URL] * 2001):
        with pytest.raises(ValueError, match="endpoint URLs"):
            select_probes(runtime([]), actor="tester", urls=bad_urls)


def test_plan_file_roundtrip_and_tampering():
    probes = [candidate("reflection", "q"), candidate("sql_error", "page")]
    payload = {"version": 1, "digest": plan_digest(probes),
               "probes": [probe.model_dump(mode="json") for probe in probes]}
    assert load_plan(json.dumps(payload)) == probes

    tampered = json.loads(json.dumps(payload))
    tampered["probes"][0]["url"] = tampered["probes"][0]["url"].replace("vmxreflect1a2b", "evil")
    with pytest.raises(ValueError):
        load_plan(json.dumps(tampered))
    wrong_digest = {**payload, "digest": "0" * 64}
    with pytest.raises(ValueError):
        load_plan(json.dumps(wrong_digest))
    with pytest.raises(ValueError):
        load_plan(json.dumps({"version": 2, "probes": payload["probes"]}))
    with pytest.raises(ValueError):
        load_plan(json.dumps([]))
    with pytest.raises(ValueError):
        load_plan(json.dumps({"probes": [payload["probes"][0]] * 2}))
    with pytest.raises(ValueError):
        load_plan(b"not json")
    with pytest.raises(ValueError):
        load_plan(json.dumps({"version": 1, "probes": [{"kind": "reflection", "url": "x",
                                                        "parameter": "q"}]}))


def test_plan_file_rejects_more_than_the_probe_limit():
    probes = [candidate("reflection", "q") for _ in range(MAX_PROBES + 1)]
    with pytest.raises(ValueError):
        load_plan(json.dumps({"probes": [probe.model_dump(mode="json") for probe in probes]}))
    with pytest.raises(ValueError):
        load_plan("x" * 1_000_001)
    with pytest.raises(ValueError):
        load_plan("中" * 333_334)
    with pytest.raises(ValueError):
        load_plan(json.dumps([{**candidate("reflection", "q").model_dump(), "extra": "ignored"}]))
    with pytest.raises(ValueError):
        load_plan("[]", max_probes=MAX_PROBES + 1)
