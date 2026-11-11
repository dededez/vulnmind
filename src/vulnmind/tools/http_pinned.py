"""One HTTP hop to a caller-validated numeric IP, without proxy or redirect.

Use only behind SingleHopRequester, which checks the authorization and every
DNS answer before calling this transport. This is not process isolation.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from collections.abc import Sequence
from urllib.parse import urlsplit

from vulnmind.tools.http import HttpDenied, HttpRequestInput, MAX_RESPONSE_BYTES
from vulnmind.tools.http_single_hop import HopResponse


def _connect_numeric(address: str, port: int, timeout: float) -> socket.socket:
    ip = ipaddress.ip_address(address)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        endpoint = (str(ip), port, 0, 0) if ip.version == 6 else (str(ip), port)
        sock.connect(endpoint)
        return sock
    except BaseException:
        sock.close()
        raise


class PinnedHttpTransport:
    """Use one validated address, bounded reads, and system TLS verification."""

    def __init__(self, *, max_body_bytes: int = 200_000):
        if not 1 <= max_body_bytes <= MAX_RESPONSE_BYTES:
            raise ValueError("invalid maximum body size")
        self._max_body = max_body_bytes

    def __call__(self, *, method: str, url: str, headers: dict[str, str],
                 addresses: Sequence[str], timeout: float) -> HopResponse:
        # Reuse the same restrictions even for direct calls to this object.
        try:
            HttpRequestInput(method=method, url=url, headers=headers, timeout_seconds=timeout)
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
                raise ValueError("invalid URL")
            if not addresses:
                raise ValueError("address required")
            address = str(ipaddress.ip_address(addresses[0]))
            host = parsed.hostname.encode("idna").decode("ascii")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            # Request targets and header values must not contain control characters.
            if any(ord(c) < 32 or ord(c) == 127 for c in path):
                raise ValueError("invalid request target")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise HttpDenied("invalid pinned HTTP request") from exc

        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        sock = None
        try:
            sock = _connect_numeric(address, port, timeout)
            if parsed.scheme == "https":
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            conn.sock = sock
            conn.request(method, path, headers=headers)
            response = conn.getresponse()
            data = response.read(self._max_body + 1)
            response_headers = {name.lower(): value for name, value in response.getheaders()}
            location = response_headers.get("location") if response.status in {301, 302, 303, 307, 308} else None
            return HopResponse(status_code=response.status, headers=response_headers,
                               body=data[:self._max_body], truncated=len(data) > self._max_body,
                               location=location)
        except (OSError, ssl.SSLError, http.client.HTTPException, UnicodeError, ValueError) as exc:
            raise HttpDenied("pinned HTTP connection failed") from exc
        finally:
            conn.close()
            if sock is not None:
                sock.close()
