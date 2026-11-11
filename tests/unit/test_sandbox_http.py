"""Isolated-egress transport tests: namespace script, parsing, requester wiring."""
from datetime import datetime, timedelta, timezone

import pytest

from vulnmind.analysis.sandbox_egress import build_egress_script
from vulnmind.analysis.sandbox_http import WslCurlTransport, _parse
from vulnmind.schemas import Authorization, Target
from vulnmind.tools.http import HttpDenied, HttpRequestInput
from vulnmind.tools.http_single_hop import SingleHopRequester

URL = "https://example.test/api"


class FakeSandbox:
    def __init__(self, output: bytes = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok",
                 exit_code: int = 0):
        self.output = output
        self.exit_code = exit_code
        self.calls = []
        self.script = ""

    def run(self, argv, *, cwd_windows=None, network=False):
        self.calls.append((list(argv), network))
        return self.exit_code, self.output

    def run_stdin(self, script, *, network=False):
        self.calls.append((["/bin/sh", "-s"], network))
        self.script = script
        return self.exit_code, self.output


class Recorder:
    def record(self, event):
        pass


def authorization():
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         web_origins=["https://example.test"], allowed_ip_networks=["10.0.0.0/8"])


def test_transport_creates_a_private_namespace_and_limited_proxy():
    sandbox = FakeSandbox()
    response = WslCurlTransport(sandbox)(method="GET", url=URL, headers={},
                                        addresses=["10.1.2.3"], timeout=10)
    assert response.status_code == 200 and response.body == b"ok"
    script = sandbox.script
    assert "ip netns add" in script and "type veth" in script
    assert "TCP-LISTEN:$PPORT,bind=$GW" in script
    assert "TCP:$TARGET:$TPORT" in script
    assert "policy drop" in script
    assert "ip daddr $GW tcp dport $PPORT accept" in script
    assert "--connect-to example.test:443:10." in script and ":18443" in script
    assert "/usr/bin/curl -q --noproxy '*'" in script
    assert "if (set -o pipefail) 2>/dev/null; then set -o pipefail; else exit 1; fi" in script
    assert sandbox.calls[0][1] is True


def test_headers_and_methods_are_quoted():
    sandbox = FakeSandbox()
    WslCurlTransport(sandbox)(method="HEAD", url=URL, headers={"X-Note": "a'b"},
                              addresses=["10.1.2.3"], timeout=5)
    script = sandbox.script
    assert "-X HEAD" in script
    assert "X-Note: a" in script and "b" in script


def test_invalid_addresses_urls_and_failures_are_refused():
    sandbox = FakeSandbox()
    transport = WslCurlTransport(sandbox)
    with pytest.raises(HttpDenied, match="invalid address"):
        transport(method="GET", url=URL, headers={}, addresses=["not-an-ip"], timeout=5)
    with pytest.raises(HttpDenied, match="IPv4"):
        transport(method="GET", url=URL, headers={}, addresses=["2001:db8::1"], timeout=5)
    with pytest.raises(HttpDenied, match="at least one"):
        transport(method="GET", url=URL, headers={}, addresses=[], timeout=5)
    with pytest.raises(HttpDenied, match="http"):
        transport(method="GET", url="ftp://example.test/x", headers={}, addresses=["10.1.2.3"], timeout=5)
    assert sandbox.calls == []
    failing = FakeSandbox(exit_code=7)
    with pytest.raises(HttpDenied, match="request failed"):
        WslCurlTransport(failing)(method="GET", url=URL, headers={},
                                  addresses=["10.1.2.3"], timeout=5)


def test_parsing_rejects_bad_output():
    with pytest.raises(HttpDenied, match="no headers"):
        _parse(b"nothing here", max_body=10)
    with pytest.raises(HttpDenied, match="invalid status line"):
        _parse(b"NOTHTTP\r\n\r\nbody", max_body=10)


def test_script_is_unique_per_call():
    first = build_egress_script(method="GET", url=URL, headers={}, host="example.test",
                                port=443, address="10.1.2.3", timeout=5, max_body=1000)
    second = build_egress_script(method="GET", url=URL, headers={}, host="example.test",
                                 port=443, address="10.1.2.3", timeout=5, max_body=1000)
    assert first != second


def test_transport_plugs_into_the_single_hop_requester():
    sandbox = FakeSandbox()
    requester = SingleHopRequester(Recorder(), resolve=lambda host: ["10.1.2.3"],
                                   transport=WslCurlTransport(sandbox))
    response = requester.request(HttpRequestInput(url=URL), actor="tester",
                                 target=Target(type="web", locator=URL), scope=authorization())
    assert response.status_code == 200 and response.body == "ok"
    assert response.final_url == URL
