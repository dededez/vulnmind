"""HTTP transport that runs curl inside a private WSL network namespace.

Each call creates its own namespace, veth pair and one socat proxy; the
namespace can only reach that proxy, and the proxy only reaches the validated
target address. Global forwarding/NAT is never modified. The transport is only
reachable through ``SingleHopRequester``, which resolves and validates every
hop before this layer runs.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Sequence

from vulnmind.analysis.sandbox_egress import sandbox_http_request
from vulnmind.tools.http_single_hop import HopResponse
from vulnmind.tools.http_single_hop import HttpDenied

MAX_BODY_BYTES = 1_000_000
_SAFE_HEADER_NAME = set("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


class WslCurlTransport:
    """``SingleHopRequester`` transport that runs curl with an allowlist."""

    def __init__(self, sandbox, *, curl: str = "/usr/bin/curl",
                 max_body_bytes: int = 200_000, timeout_seconds: float = 30.0):
        if not callable(getattr(sandbox, "run", None)):
            raise ValueError("a sandbox with a run method is required")
        if not curl.startswith("/"):
            raise ValueError("curl path must be absolute inside the sandbox")
        if not 1 <= max_body_bytes <= MAX_BODY_BYTES:
            raise ValueError("max_body_bytes is out of range")
        if not 1 <= timeout_seconds <= 120:
            raise ValueError("timeout_seconds is out of range")
        self._sandbox = sandbox
        self._curl = curl
        self._max_body = max_body_bytes
        self._timeout = timeout_seconds

    def __call__(self, *, method: str, url: str, headers: dict[str, str],
                 addresses: Sequence[str], timeout: float) -> HopResponse:
        parsed = _split(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        candidates = []
        for address in addresses:
            try:
                candidates.append(str(ipaddress.ip_address(address)))
            except ValueError as exc:
                raise HttpDenied("transport received an invalid address") from exc
        if not candidates:
            raise HttpDenied("transport requires at least one validated address")
        for name in headers:
            if not name or any(character not in _SAFE_HEADER_NAME for character in name):
                raise HttpDenied("header name is not allowed")
        output, truncated = sandbox_http_request(self._sandbox, method=method, url=url,
                                                 headers=headers, host=parsed.hostname, port=port,
                                                 address=candidates[0], timeout=timeout,
                                                 max_body=self._max_body, curl=self._curl)
        return _parse(output, max_body=self._max_body, truncated=truncated)

    def _script(self, *, method: str, url: str, headers: dict[str, str], parsed, addresses,
                timeout: float) -> str:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        lines = [
            "nft delete table inet vulnmind_egress 2>/dev/null || true",
            "nft add table inet vulnmind_egress",
            "nft 'add chain inet vulnmind_egress out { type filter hook output priority 0; policy drop; }'",
            "nft 'add rule inet vulnmind_egress out oif \"lo\" accept'",
            "nft 'add rule inet vulnmind_egress out ct state established,related accept'",
        ]
        family = "ip" if addresses[0].version == 4 else "ip6"
        for address in addresses:
            if address.version != addresses[0].version:
                raise HttpDenied("mixed address families are not supported in one hop")
            lines.append(f"nft 'add rule inet vulnmind_egress out {family} daddr {address} "
                         f"tcp dport {port} accept'")
        resolve_value = f"{parsed.hostname}:{port}:{addresses[0]}"
        command = [
            self._curl, "-sS", "--max-redirs", "0", "--max-time", str(int(timeout)),
            "--max-filesize", str(self._max_body), "--resolve", resolve_value,
            "-X", method.upper(), "-D", "-",
        ]
        for name, value in headers.items():
            if not name or any(character not in _SAFE_HEADER_NAME for character in name):
                raise HttpDenied("header name is not allowed")
            command += ["-H", f"{name}: {value}"]
        command.append(url)
        lines.append(" ".join(shlex.quote(item) for item in command))
        lines.append("status=$?")
        lines.append("nft delete table inet vulnmind_egress 2>/dev/null || true")
        lines.append("exit $status")
        return "\n".join(lines)


class _Parsed:
    __slots__ = ("scheme", "hostname", "port")

    def __init__(self, scheme: str, hostname: str, port: int | None):
        self.scheme = scheme
        self.hostname = hostname
        self.port = port


def _split(url: str) -> _Parsed:
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HttpDenied("URL must be absolute http(s)")
    if parsed.username is not None or parsed.password is not None:
        raise HttpDenied("credentials in the URL are not allowed")
    return _Parsed(parsed.scheme, parsed.hostname, parsed.port)


def _parse(output: bytes, *, max_body: int, truncated: bool = False) -> HopResponse:
    separator = output.find(b"\r\n\r\n")
    if separator < 0:
        raise HttpDenied("transport returned no headers")
    head = output[:separator].decode("iso-8859-1")
    body = output[separator + 4:][:max_body]
    lines = head.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        raise HttpDenied("transport returned an invalid status line")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError) as exc:
        raise HttpDenied("transport returned an invalid status code") from exc
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name:
            headers[name.strip().lower()] = value.strip()
    return HopResponse(status_code=status, headers=headers, body=body,
                       location=headers.get("location"), truncated=truncated)

