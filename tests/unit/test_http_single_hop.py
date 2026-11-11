"""Single-hop HTTP client tests: per-hop validation before each connection."""
from datetime import datetime, timedelta, timezone

import pytest

from vulnmind.schemas import Authorization, Target
from vulnmind.security.ratelimit import RateLimiter
from vulnmind.security.scope import ScopeDenied
from vulnmind.tools.http import HttpDenied, HttpRequestInput
from vulnmind.tools.http_single_hop import HopResponse, SingleHopRequester

URL = "https://example.test/api"


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


def scope(*, networks=("10.0.0.0/8",), origin="https://example.test"):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         web_origins=[origin], allowed_ip_networks=list(networks))


def target(url=URL):
    return Target(type="web", locator=url)


class Connect:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, *, method, url, headers, addresses, timeout):
        self.calls.append((method, url, tuple(addresses)))
        if not self.responses:
            raise AssertionError("unexpected connection attempt")
        return self.responses.pop(0)


def resolver(addresses=("10.1.2.3",)):
    def resolve(host):
        assert host == "example.test"
        return list(addresses)
    return resolve


def test_single_request_validates_addresses_before_connecting():
    recorder = Recorder()
    connect = Connect([HopResponse(status_code=200, headers={"content-type": "text/plain",
                                                             "set-cookie": "secret=1"},
                                   body=b"hello")])
    requester = SingleHopRequester(recorder, resolve=resolver(), transport=connect)
    response = requester.request(HttpRequestInput(url=URL), actor="tester", target=target(), scope=scope())
    assert response.status_code == 200 and response.body == "hello"
    assert response.headers == {"content-type": "text/plain"}
    assert connect.calls == [("GET", URL, ("10.1.2.3",))]
    assert [event["status"] for event in recorder.events] == ["requested", "started", "succeeded"]


def test_http_events_are_independently_persisted_without_sensitive_urls(tmp_path):
    from sqlalchemy import create_engine, select
    from vulnmind.persistence.audit import DatabaseAuditSink, verify_audit_chain
    from vulnmind.persistence.models import AuditEvent
    engine = create_engine(f"sqlite:///{(tmp_path / 'audit.db').as_posix()}")
    AuditEvent.__table__.create(engine)
    sensitive = URL + "?secret=synthetic-private-value"
    connect = Connect([HopResponse(status_code=200, body=b"ok")])
    requester = SingleHopRequester(DatabaseAuditSink(engine), resolve=resolver(), transport=connect)
    requester.request(HttpRequestInput(url=sensitive), actor="tester", target=target(sensitive), scope=scope())
    with engine.connect() as connection:
        rows = connection.execute(select(AuditEvent.tool_name, AuditEvent.status, AuditEvent.args_hash)
                                  .order_by(AuditEvent.created_at)).all()
        assert [row.status for row in rows] == ["requested", "started", "succeeded"]
        assert "synthetic-private-value" not in str(rows)
        assert verify_audit_chain(connection).valid
    engine.dispose()


def test_http_does_not_resolve_or_connect_when_audit_is_unavailable(tmp_path):
    from sqlalchemy import create_engine
    from vulnmind.persistence.audit import AuditError, DatabaseAuditSink
    engine = create_engine(f"sqlite:///{(tmp_path / 'unavailable.db').as_posix()}")
    connect = Connect([])
    def should_not_resolve(_host):
        pytest.fail("resolution must not happen without persistent audit")
    requester = SingleHopRequester(DatabaseAuditSink(engine), resolve=should_not_resolve, transport=connect)
    with pytest.raises(AuditError):
        requester.request(HttpRequestInput(url=URL), actor="tester", target=target(), scope=scope())
    assert connect.calls == []
    engine.dispose()


def test_out_of_allowlist_address_is_refused_before_connecting():
    recorder, connect = Recorder(), Connect([HopResponse(status_code=200)])
    requester = SingleHopRequester(recorder, resolve=resolver(("192.168.1.1",)), transport=connect)
    with pytest.raises(ScopeDenied):
        requester.request(HttpRequestInput(url=URL), actor="tester", target=target(), scope=scope())
    assert connect.calls == []
    assert [event["status"] for event in recorder.events] == ["requested", "denied"]


def test_empty_resolution_is_refused():
    connect = Connect([])
    requester = SingleHopRequester(Recorder(), resolve=resolver(()), transport=connect)
    with pytest.raises(ScopeDenied, match="no addresses"):
        requester.request(HttpRequestInput(url=URL), actor="tester", target=target(), scope=scope())
    assert connect.calls == []


def test_redirects_are_checked_before_the_next_connection():
    connect = Connect([HopResponse(status_code=302, location="/next"),
                       HopResponse(status_code=200, body=b"done")])
    requester = SingleHopRequester(Recorder(), resolve=resolver(), transport=connect)
    response = requester.request(HttpRequestInput(url=URL, follow_redirects=True),
                                 actor="tester", target=target(), scope=scope())
    assert response.final_url == "https://example.test/next" and response.body == "done"
    assert [call[1] for call in connect.calls] == [URL, "https://example.test/next"]


def test_offsite_redirect_is_refused_without_a_second_connection():
    connect = Connect([HopResponse(status_code=302, location="https://evil.test/x")])
    requester = SingleHopRequester(Recorder(), resolve=resolver(), transport=connect)
    with pytest.raises(ScopeDenied):
        requester.request(HttpRequestInput(url=URL, follow_redirects=True),
                          actor="tester", target=target(), scope=scope())
    assert len(connect.calls) == 1


def test_redirects_are_returned_when_disabled():
    connect = Connect([HopResponse(status_code=302, location="/next")])
    requester = SingleHopRequester(Recorder(), resolve=resolver(), transport=connect)
    response = requester.request(HttpRequestInput(url=URL), actor="tester", target=target(), scope=scope())
    assert response.status_code == 302 and response.final_url == URL
    assert len(connect.calls) == 1


def test_redirect_loop_is_bounded():
    responses = [HopResponse(status_code=302, location=f"/hop{i}") for i in range(5)]
    connect = Connect(responses)
    requester = SingleHopRequester(Recorder(), resolve=resolver(), transport=connect, max_hops=2)
    with pytest.raises(HttpDenied, match="too many redirects"):
        requester.request(HttpRequestInput(url=URL, follow_redirects=True),
                          actor="tester", target=target(), scope=scope())


def test_rate_limit_is_checked_before_connecting():
    limiter = RateLimiter(capacity=1, refill_per_second=0.001)
    limiter.acquire(URL)
    connect = Connect([])
    requester = SingleHopRequester(Recorder(), resolve=resolver(), transport=connect, rate_limiter=limiter)
    with pytest.raises(HttpDenied, match="rate limit"):
        requester.request(HttpRequestInput(url=URL), actor="tester", target=target(), scope=scope())
    assert connect.calls == []


def test_response_is_capped_and_marked():
    connect = Connect([HopResponse(status_code=200, body=b"x" * 100)])
    requester = SingleHopRequester(Recorder(), resolve=resolver(), transport=connect)
    response = requester.request(HttpRequestInput(url=URL, max_response_bytes=10),
                                 actor="tester", target=target(), scope=scope())
    assert response.truncated is True and response.body == "x" * 10


def test_constructor_and_input_guardrails():
    with pytest.raises(ValueError, match="callable"):
        SingleHopRequester(Recorder(), resolve=None, transport=lambda **kw: None)
    with pytest.raises(ValueError, match="max_hops"):
        SingleHopRequester(Recorder(), resolve=resolver(), transport=Connect([]), max_hops=0)
    connect = Connect([HopResponse(status_code=200)])
    requester = SingleHopRequester(Recorder(), resolve=resolver(), transport=connect)
    with pytest.raises(HttpDenied, match="match the authorized"):
        requester.request(HttpRequestInput(url="https://other.test/x"), actor="tester",
                          target=target(), scope=scope())
    with pytest.raises(HttpDenied, match="actor"):
        requester.request(HttpRequestInput(url=URL), actor=" ", target=target(), scope=scope())
