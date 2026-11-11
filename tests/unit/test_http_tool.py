"""HTTP tool policy tests with an injected transport (no real network)."""
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from vulnmind.schemas import Authorization, Target
from vulnmind.security.ratelimit import RateLimiter
from vulnmind.security.scope import ScopeDenied
from vulnmind.tools.http import HttpDenied, HttpRequestInput, HttpRequester

URL = "https://example.test/api"


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


def authorization(origin="https://example.test"):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         web_origins=[origin])


def transport(status=200, body=b"ok", headers=None, history=()):
    calls = []

    def fake(method, url, request_headers, timeout):
        calls.append((method, url, dict(request_headers), timeout))
        return status, headers or {"content-type": "text/plain", "set-cookie": "secret=1"}, body, list(history)

    fake.calls = calls
    return fake


def make_requester(recorder, fake=None, limiter=None):
    return HttpRequester(recorder, transport=fake, rate_limiter=limiter)


def target(url=URL):
    return Target(type="web", locator=url)


def test_default_transport_refuses_every_call():
    recorder = Recorder()
    with pytest.raises(HttpDenied, match="network transport"):
        HttpRequester(recorder).request(HttpRequestInput(url=URL), actor="tester",
                                        target=target(), scope=authorization())
    assert [event["status"] for event in recorder.events] == ["requested", "denied"]


def test_authorized_request_returns_filtered_headers():
    recorder, fake = Recorder(), transport(body=b"hello")
    response = make_requester(recorder, fake)._simulate_policy(
        HttpRequestInput(url=URL), actor="tester", target=target(), scope=authorization())
    assert response.status_code == 200 and response.body == "hello"
    assert response.headers == {"content-type": "text/plain"}
    assert fake.calls[0][0] == "GET" and fake.calls[0][1] == URL
    assert [event["status"] for event in recorder.events] == ["requested", "started", "succeeded"]


def test_url_must_match_the_authorized_target():
    with pytest.raises(HttpDenied, match="match the authorized"):
        make_requester(Recorder(), transport())._simulate_policy(
            HttpRequestInput(url="https://other.test/api"), actor="tester",
            target=target(), scope=authorization())


def test_scope_denial_is_enforced():
    with pytest.raises(ScopeDenied):
        make_requester(Recorder(), transport())._simulate_policy(
            HttpRequestInput(url=URL), actor="tester", target=target(),
            scope=authorization("https://different.test"))


def test_methods_and_headers_are_restricted():
    with pytest.raises(ValidationError):
        HttpRequestInput(url=URL, method="POST")
    with pytest.raises(ValidationError, match="credential headers"):
        HttpRequestInput(url=URL, headers={"Authorization": "Bearer token"})
    with pytest.raises(ValidationError):
        HttpRequestInput(url="ftp://example.test/file")


def test_response_is_truncated_and_marked():
    response = make_requester(Recorder(), transport(body=b"x" * 100))._simulate_policy(
        HttpRequestInput(url=URL, max_response_bytes=10), actor="tester", target=target(),
        scope=authorization())
    assert response.truncated is True and response.body == "x" * 10


def test_redirect_hops_must_stay_in_scope():
    recorder = Recorder()
    offsite = transport(history=["https://evil.test/"])
    with pytest.raises(ScopeDenied):
        make_requester(recorder, offsite)._simulate_policy(HttpRequestInput(url=URL, follow_redirects=True),
                                                  actor="tester", target=target(), scope=authorization())
    onboard = transport(history=["/other"])
    with pytest.raises(HttpDenied, match="redirects are disabled"):
        make_requester(Recorder(), onboard)._simulate_policy(HttpRequestInput(url=URL), actor="tester",
                                                    target=target(), scope=authorization())


def test_rate_limit_is_applied_per_target():
    limiter = RateLimiter(capacity=1, refill_per_second=0.001)
    make_requester(Recorder(), transport(), limiter)._simulate_policy(
        HttpRequestInput(url=URL), actor="tester", target=target(), scope=authorization())
    with pytest.raises(HttpDenied, match="rate limit"):
        make_requester(Recorder(), transport(), limiter)._simulate_policy(
            HttpRequestInput(url=URL), actor="tester", target=target(), scope=authorization())


def test_resolved_addresses_are_checked_when_provided():
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner",
                          starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                          web_origins=["https://example.test"], allowed_ip_networks=["10.0.0.0/8"])
    with pytest.raises(ScopeDenied):
        make_requester(Recorder(), transport())._simulate_policy(
            HttpRequestInput(url=URL), actor="tester", target=target(), scope=scope,
            addresses=["192.168.1.1"])
    response = make_requester(Recorder(), transport())._simulate_policy(
        HttpRequestInput(url=URL), actor="tester", target=target(), scope=scope,
        addresses=["10.1.2.3"])
    assert response.status_code == 200


def test_injected_transport_cannot_execute_through_public_request():
    fake = transport()
    audit = Recorder()
    with pytest.raises(HttpDenied, match="network transport"):
        HttpRequester(audit, transport=fake).request(HttpRequestInput(url=URL), actor="tester", target=target(), scope=authorization())
    assert fake.calls == []
    assert [event["status"] for event in audit.events] == ["requested", "denied"]

