"""Actual loopback connections; no external target or filesystem needed."""
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import ScopeDenied
from vulnmind.tools.http import HttpDenied, HttpRequestInput
from vulnmind.tools.http_pinned import PinnedHttpTransport
from vulnmind.tools.http_single_hop import SingleHopRequester


class Handler(BaseHTTPRequestHandler):
    calls = []

    def do_GET(self):
        self.calls.append(self.path)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://192.0.2.1/forbidden")
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"abcdefghij")

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    Handler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join()


class Audit:
    def record(self, event):
        pass


def requester(server, *, addresses=None, max_body=5):
    port = server.server_port
    origin = f"http://127.0.0.1:{port}"
    now = datetime.now(timezone.utc)
    auth = Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=5),
                         web_origins=[origin], allowed_ip_networks=["127.0.0.0/8"])
    client = SingleHopRequester(Audit(), resolve=lambda _: addresses or ["127.0.0.1"],
                                transport=PinnedHttpTransport(max_body_bytes=max_body))
    return client, auth, origin


def test_real_loopback_request_is_bounded_and_marked(server):
    client, auth, origin = requester(server)
    response = client.request(HttpRequestInput(url=origin + "/test", max_response_bytes=10),
                              actor="test", target=Target(type="web", locator=origin + "/test"), scope=auth)
    assert response.body == "abcde" and response.truncated
    assert Handler.calls == ["/test"]


def test_out_of_scope_address_is_rejected_before_connection(server):
    client, auth, origin = requester(server, addresses=["192.0.2.1"])
    with pytest.raises(ScopeDenied):
        client.request(HttpRequestInput(url=origin + "/test"), actor="test",
                       target=Target(type="web", locator=origin + "/test"), scope=auth)
    assert Handler.calls == []


def test_connection_does_not_resolve_hostname_a_second_time(server, monkeypatch):
    import socket

    origin = f"http://rebind.test:{server.server_port}"
    now = datetime.now(timezone.utc)
    auth = Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=5),
                         web_origins=[origin], allowed_ip_networks=["127.0.0.0/8"])
    client = SingleHopRequester(Audit(), resolve=lambda _: ["127.0.0.1"],
                                transport=PinnedHttpTransport(max_body_bytes=10))
    def no_lookup(*args, **kwargs):
        raise AssertionError("connection unexpectedly resolved the hostname again")
    monkeypatch.setattr(socket, "getaddrinfo", no_lookup)
    response = client.request(HttpRequestInput(url=origin + "/test"), actor="test",
                              target=Target(type="web", locator=origin + "/test"), scope=auth)
    assert response.status_code == 200 and Handler.calls == ["/test"]


def test_redirect_is_rejected_before_second_connection(server):
    client, auth, origin = requester(server)
    with pytest.raises(ScopeDenied):
        client.request(HttpRequestInput(url=origin + "/redirect", follow_redirects=True), actor="test",
                       target=Target(type="web", locator=origin + "/redirect"), scope=auth)
    assert Handler.calls == ["/redirect"]


def test_pinned_transport_rejects_host_header():
    with pytest.raises(HttpDenied):
        PinnedHttpTransport()(method="GET", url="http://127.0.0.1/", headers={"Host": "other"},
                              addresses=["127.0.0.1"], timeout=1)


def test_tls_certificate_failure_closes_connection_and_uses_original_hostname(monkeypatch):
    import ssl
    from vulnmind.tools import http_pinned

    class Sock:
        closed = False

        def close(self):
            self.closed = True

    sock = Sock()
    seen = {}

    class Context:
        def wrap_socket(self, raw, *, server_hostname):
            seen["host"] = server_hostname
            raise ssl.SSLCertVerificationError("untrusted certificate")

    monkeypatch.setattr(http_pinned, "_connect_numeric", lambda address, port, timeout: sock)
    monkeypatch.setattr(http_pinned.ssl, "create_default_context", lambda: Context())
    with pytest.raises(HttpDenied, match="connection failed"):
        PinnedHttpTransport()(method="GET", url="https://example.test/", headers={},
                              addresses=["127.0.0.1"], timeout=1)
    assert seen["host"] == "example.test" and sock.closed


def test_real_tls_accepts_trusted_name_and_rejects_wrong_name(tmp_path, monkeypatch):
    import ssl
    pytest.importorskip("cryptography", reason="optional certificate-generation library unavailable")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from vulnmind.tools import http_pinned

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(minutes=10))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        default_context = ssl.create_default_context
        transport = PinnedHttpTransport(max_body_bytes=5)
        with pytest.raises(HttpDenied, match="connection failed"):
            transport(method="GET", url=f"https://localhost:{server.server_port}/test", headers={},
                      addresses=["127.0.0.1"], timeout=3)
        monkeypatch.setattr(http_pinned.ssl, "create_default_context", lambda: default_context(cafile=str(cert_path)))
        response = transport(method="GET", url=f"https://localhost:{server.server_port}/test", headers={},
                             addresses=["127.0.0.1"], timeout=3)
        assert response.body == b"abcde" and response.truncated
        with pytest.raises(HttpDenied, match="connection failed"):
            transport(method="GET", url=f"https://wrong.test:{server.server_port}/test", headers={},
                      addresses=["127.0.0.1"], timeout=3)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
