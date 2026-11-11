"""DeepSeek client tests with an injected transport (no real API call)."""
import json

import pytest

from vulnmind.agents.deepseek import DeepSeekClient
from vulnmind.agents.model import ModelError, ModelMessage, ModelRequest

REQUEST = ModelRequest(messages=[ModelMessage(role="user", content="Review this.")])
CANNED = {"id": "x", "choices": [{"index": 0, "message": {"role": "assistant",
                                                         "content": '{"verdict": "unverified"}'}}],
          "usage": {"prompt_tokens": 12, "completion_tokens": 8}}


class Transport:
    def __init__(self, status=200, payload=None):
        self.status = status
        self.payload = json.dumps(CANNED).encode() if payload is None else payload
        self.calls = []

    def __call__(self, url, headers, body, timeout):
        self.calls.append({"url": url, "headers": dict(headers), "body": json.loads(body), "timeout": timeout})
        return self.status, self.payload


def client(transport):
    return DeepSeekClient("test-key", transport=transport)


def test_request_shape_and_usage_are_translated():
    transport = Transport()
    response = client(transport).complete(REQUEST)
    assert response.text == '{"verdict": "unverified"}'
    assert response.usage.input_tokens == 12 and response.usage.output_tokens == 8
    call = transport.calls[0]
    assert call["url"] == "https://api.deepseek.com/chat/completions"
    assert call["headers"]["Authorization"] == "Bearer test-key"
    assert call["body"]["model"] == "deepseek-chat"
    assert call["body"]["messages"] == [{"role": "user", "content": "Review this."}]
    assert call["body"]["response_format"] == {"type": "json_object"}
    assert call["body"]["stream"] is False


def test_http_and_payload_errors_are_generic():
    with pytest.raises(ModelError, match="HTTP 401"):
        client(Transport(status=401)).complete(REQUEST)
    with pytest.raises(ModelError, match="unparseable"):
        client(Transport(payload=b"not json")).complete(REQUEST)
    with pytest.raises(ModelError, match="no completion"):
        client(Transport(payload=json.dumps({"choices": []}).encode())).complete(REQUEST)
    with pytest.raises(ModelError, match="empty completion"):
        client(Transport(payload=json.dumps({"choices": [{"message": {"content": "  "}}]}).encode())).complete(REQUEST)


def test_malformed_provider_response_is_bounded_and_fails_as_model_error():
    long_completion = {"choices": [{"message": {"content": "x" * 200_001}}]}
    with pytest.raises(ModelError, match="invalid completion"):
        client(Transport(payload=json.dumps(long_completion).encode())).complete(REQUEST)
    with pytest.raises(ModelError, match="unparseable"):
        client(Transport(payload=b"[" * 10_000 + b"]" * 10_000)).complete(REQUEST)
    with pytest.raises(ModelError, match="unparseable"):
        client(Transport(payload=b'{"number":' + b"1" * 5000 + b"}")).complete(REQUEST)


def test_provider_decode_failure_traceback_does_not_echo_payload():
    import traceback
    sensitive = "private-response-secret"
    payload = sensitive.encode() + bytes([255])
    transport = Transport(payload=payload)
    with pytest.raises(ModelError) as error:
        client(transport).complete(REQUEST)
    assert sensitive not in "".join(traceback.format_exception(error.value))


def test_error_messages_never_include_the_key():
    transport = Transport(status=500)
    with pytest.raises(ModelError) as captured:
        client(transport).complete(REQUEST)
    assert "test-key" not in str(captured.value)


def test_oversized_response_is_rejected():
    oversized = {"choices": [{"message": {"content": "x" * 5000}}]}
    with pytest.raises(ModelError, match="size limit"):
        DeepSeekClient("test-key", transport=Transport(payload=json.dumps(oversized).encode()),
                       max_response_bytes=1000).complete(REQUEST)


def test_key_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "env-key")
    transport = Transport()
    DeepSeekClient(transport=transport).complete(REQUEST)
    assert transport.calls[0]["headers"]["Authorization"] == "Bearer env-key"
    monkeypatch.delenv("DEEPSEEK_API_KEY")
    with pytest.raises(ValueError, match="API key"):
        DeepSeekClient(transport=transport)


def test_client_validates_configuration():
    with pytest.raises(ValueError, match="HTTPS"):
        DeepSeekClient("k", base_url="http://insecure.test")
    with pytest.raises(ValueError, match="timeout"):
        DeepSeekClient("k", timeout_seconds=0)
    with pytest.raises(ValueError, match="max_response_bytes"):
        DeepSeekClient("k", max_response_bytes=10)


@pytest.mark.parametrize("url", ["https://", "https://user@host.test", "https://host.test?",
                                 "https://host.test#fragment", "https://host.test:99999",
                                 "https://host.test:0", "https://host.test\\evil", "https://host.test\n"])
def test_client_rejects_ambiguous_endpoint_before_transport(url):
    transport = Transport()
    with pytest.raises(ValueError, match="HTTPS URL"):
        DeepSeekClient("k", base_url=url, transport=transport)
    assert transport.calls == []


def test_client_accepts_explicit_https_proxy_path_without_userinfo():
    transport = Transport()
    DeepSeekClient("k", base_url="https://proxy.example.test:8443/v1", transport=transport).complete(REQUEST)
    assert transport.calls[0]["url"] == "https://proxy.example.test:8443/v1/chat/completions"


def test_client_rejects_control_characters_in_key():
    with pytest.raises(ValueError, match="key is invalid"):
        DeepSeekClient("secret\r\ninjected")


def test_runtime_accepts_the_client_with_a_fake_transport():
    from pydantic import BaseModel

    from vulnmind.agents.runtime import AgentRuntime, AgentSpec

    class Reply(BaseModel):
        verdict: str

    class Recorder:
        def record(self, event):
            pass

    runtime = AgentRuntime(client(Transport()), Recorder())
    output = runtime.run(AgentSpec(name="t", role="triage", system_prompt="Review."),
                         task="Review.", context=[], schema=Reply, actor="tester")
    assert output.data.verdict == "unverified" and output.usage.output_tokens == 8


def test_invalid_completion_does_not_abort_advisory_review():
    from vulnmind.agents.review import review_findings
    from vulnmind.agents.runtime import AgentRuntime
    from vulnmind.findings import FindingCandidate, group_findings

    class Recorder:
        def record(self, event):
            pass

    payload = json.dumps({"choices": [{"message": {"content": "x" * 200_001}}]}).encode()
    runtime = AgentRuntime(client(Transport(payload=payload)), Recorder())
    group = group_findings([FindingCandidate(title="lead", vulnerability_type="secret", target_id="repo",
                                              location="a.py:1", source_tool="fixture")])
    result = review_findings(runtime, actor="tester", groups=group)
    assert result.status == "failed" and result.items == ()
