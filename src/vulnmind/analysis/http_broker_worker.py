"""Trusted one-shot Linux broker; stdlib only, launched with an empty environment.

No tunnel or user code is accepted. A single validated TCP socket is retained
after entering an empty network namespace and dropping privileges. Only this
broker constructs HTTP, performs TLS, and reads bounded response data. The
supervising agent receives JSON, never a socket or an executable response.
"""
import base64
import codecs
import ctypes
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import stat
import sys
from urllib.parse import urlsplit


def origin(url):
    p = urlsplit(url)
    if (p.scheme not in {"http", "https"} or not p.hostname or p.username is not None or p.password is not None
            or p.fragment or "\\" in url or any(ord(c) < 33 or ord(c) == 127 for c in url)):
        raise ValueError("invalid origin")
    return p.scheme, p.hostname.encode("idna").decode().lower().rstrip("."), p.port or (443 if p.scheme == "https" else 80)


def safe_path(value):
    path = value or "/"
    if not re.fullmatch(r"/[A-Za-z0-9._~/-]*", path) or "//" in path or any(x in {".", ".."} for x in path.split("/")):
        raise ValueError("invalid path")
    return path.rstrip("/") or "/"


def within(path, prefix):
    return prefix == "/" or path == prefix or path.startswith(prefix + "/")


def validate(data):
    scope, url = data["scope"], data["url"]
    now = datetime.now(timezone.utc)
    if not datetime.fromisoformat(scope["starts_at"]) <= now < datetime.fromisoformat(scope["expires_at"]):
        raise ValueError("expired scope")
    candidate = origin(url)
    allowed = {origin(item) for item in scope["web_origins"]}
    denied = {origin(item) for item in scope["denied_web_origins"]}
    if candidate not in allowed or candidate in denied:
        raise ValueError("origin denied")
    path = safe_path(urlsplit(url).path)
    for field, deny in (("allowed_web_paths", False), ("denied_web_paths", True)):
        entries = {origin(key): [safe_path(p) for p in values] for key, values in scope[field].items()}
        matches = any(within(path, prefix) for prefix in entries.get(candidate, []))
        if (deny and matches) or (not deny and entries and not matches):
            raise ValueError("path denied")
    addresses = [ipaddress.ip_address(item) for item in data["addresses"]]
    networks = [ipaddress.ip_network(item, strict=True) for item in scope["allowed_ip_networks"]]
    deny_networks = [ipaddress.ip_network(item, strict=True) for item in scope["denied_ip_networks"]]
    if not addresses or not networks:
        raise ValueError("explicit IP range required")
    try:
        literal = ipaddress.ip_address(candidate[1])
    except ValueError:
        literal = None
    for address in addresses:
        if "%" in str(address) or literal is not None and address != literal:
            raise ValueError("invalid address")
        mapped = getattr(address, "ipv4_mapped", None) or address
        if any(address in n or mapped in n for n in deny_networks) or not any(mapped in n for n in networks):
            raise ValueError("IP denied")
    profile=data.get('api_profile')
    if profile is not None:
        if profile.get('version')!=1 or origin(profile.get('origin',''))!=candidate or not re.fullmatch(r'[0-9a-f]{64}',profile.get('approval_digest','')):
            raise ValueError('invalid approved API profile')
        if not isinstance(data.get('body',''),str) or len(data.get('body','').encode())>64000:
            raise ValueError('API body exceeds limit')
        if data['method']!='POST' and data.get('body'):
            raise ValueError('unexpected request body')
        if data['method']=='POST' and data['headers'].get('Content-Type') not in {'application/json','application/x-www-form-urlencoded'}:
            raise ValueError('unsupported API encoding')
    if data["method"] not in ({"GET", "HEAD", "POST"} if profile else {"GET", "HEAD"}) or not 1 <= data["max_body"] <= 1_000_000 or not 0 < data["timeout"] <= 60:
        raise ValueError("invalid request limits")
    # Host, credentials, proxy, body, transfer framing and connection control
    # are exclusively owned by this broker.
    if len(data["headers"]) > 20:
        raise ValueError("too many headers")
    for name, value in data["headers"].items():
        accepted={"accept", "accept-language", "user-agent", "range"}
        if profile: accepted|={'authorization','cookie','content-type','origin'}
        if name.lower() not in accepted or len(value)>8192 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("header denied")
    return candidate, addresses[0]


def isolate():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x40000000) != 0:  # CLONE_NEWNET; no interfaces are enabled
        raise OSError("network isolation unavailable")
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError("privilege isolation unavailable")
    # An empty, root-owned filesystem also removes host UNIX sockets and
    # /proc namespace handles. There is no writable file or executable here.
    jail = "/var/empty/vulnmind-http-broker"
    os.makedirs(jail, mode=0o555, exist_ok=True)
    info = os.lstat(jail)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o555 or os.listdir(jail):
        raise OSError("empty broker root is unavailable")
    os.chroot(jail)
    os.chdir("/")
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    if os.geteuid() != 65534:
        raise OSError("privilege drop failed")


def request(data):
    import resource
    (scheme, host, port), address = validate(data)
    signal.alarm(int(data["timeout"]) + 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    context = ssl.create_default_context(cadata=data.get("ca_pem")) if scheme == "https" else None
    for encoding in ("ascii", "utf-8", "iso-8859-1", "idna"):
        codecs.lookup(encoding)
    if context:
        context.keylog_filename = None
    sock = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(data["timeout"])
    # Pin before dropping networking privileges. No HTTP data is sent until
    # isolation succeeds. Failed setup may have sent a TCP handshake only.
    sock.connect((str(address), port))
    try:
        isolate()
        if context:
            sock = context.wrap_socket(sock, server_hostname=host)
        connection = http.client.HTTPConnection(host, port, timeout=data["timeout"])
        connection.sock = sock
        parsed = urlsplit(data["url"])
        path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        validate(data)  # TLS setup may have consumed the remaining authorization window.
        connection.request(data["method"], path, body=data.get('body','').encode() if data.get('api_profile') and data['method']=='POST' else None,
                           headers={**data["headers"], "Connection": "close"})
        response = connection.getresponse()
        body = response.read(data["max_body"] + 1)
        headers = dict(response.getheaders())
        if sum(len(k) + len(v) for k, v in headers.items()) > 65536:
            raise ValueError("response headers too large")
        return {"status_code": response.status, "headers": {k.lower(): v for k, v in headers.items()},
                "body": base64.b64encode(body[:data["max_body"]]).decode(), "truncated": len(body) > data["max_body"]}
    finally:
        sock.close()


def main():
    try:
        raw = sys.stdin.buffer.read(200_001)
        if len(raw) > 200_000:
            raise ValueError("request too large")
        data = json.loads(raw)
        result = request(data)
    except Exception as exc:
        # Bounded reason only: no traceback, paths or target data in the job record.
        detail = (type(exc).__name__ + ": " + str(exc))[:200]
        print(json.dumps({"error": "isolated broker request failed", "detail": detail}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
