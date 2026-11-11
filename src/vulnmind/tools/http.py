"""Controlled HTTP tool; the transport is injected and the default denies.

The public requester denies every call, including injected transports, until an
enforced egress policy exists. The private simulation is only a policy model;
it cannot prevent a supplied callable from making unauthorized connections.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vulnmind.schemas import Authorization, Target, TargetType
from vulnmind.security.ratelimit import RateLimitExceeded, RateLimiter
from vulnmind.security.scope import ScopeDenied, check_redirect, check_resolved_addresses, check_target
from vulnmind.tools.registry import AuditSink

MAX_RESPONSE_BYTES = 1_000_000
_SAFE_HEADERS = {"content-type", "content-length", "location", "server", "x-powered-by",
                 "content-security-policy", "strict-transport-security", "x-content-type-options",
                 "x-frame-options", "referrer-policy", "permissions-policy"}


class HttpDenied(Exception):
    """The request is outside policy or no transport is configured."""


class HttpRequestInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    method: Literal["GET", "HEAD"] = "GET"
    url: str = Field(min_length=1, max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict, max_length=20)
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_response_bytes: int = Field(default=200_000, ge=1, le=MAX_RESPONSE_BYTES)
    follow_redirects: bool = False

    @field_validator("url")
    @classmethod
    def http_url(cls, value: str) -> str:
        if value != value.strip() or not value.lower().startswith(("http://", "https://")):
            raise ValueError("only absolute http(s) URLs are accepted")
        return value

    @field_validator("headers")
    @classmethod
    def safe_headers(cls, value: dict[str, str]) -> dict[str, str]:
        for name, header in value.items():
            if not name.strip() or any(ord(character) < 32 for character in name + header):
                raise ValueError("header names and values must be printable")
            if name.lower() in {"authorization", "cookie", "proxy-authorization", "host"}:
                raise ValueError("credential headers are not accepted here")
        return value


class HttpResponse(BaseModel):
    model_config = ConfigDict(frozen=True)
    call_id: str
    status_code: int
    final_url: str
    headers: dict[str, str]
    body: str
    truncated: bool


Transport = Callable[[str, str, dict[str, str], float], tuple[int, dict[str, str], bytes, list[str]]]


class HttpRequester:
    def __init__(self, audit: AuditSink, *, rate_limiter: RateLimiter | None = None,
                 transport: Transport | None = None):
        self._audit = audit
        self._rate_limiter = rate_limiter
        self._transport = transport

    def request(self, request: HttpRequestInput, *, actor: str, target: Target, scope: Authorization,
                addresses: Sequence[str] = ()) -> HttpResponse:
        """Fail closed until a transport can enforce the network boundary."""
        call_id = str(uuid4())
        event = {"call_id": call_id, "tool_name": "http.request", "actor": actor,
                 "target_type": target.type.value}
        self._audit.record({**event, "status": "requested"})
        self._audit.record({**event, "status": "denied"})
        raise HttpDenied("no enforced network transport is configured")

    def _simulate_policy(self, request: HttpRequestInput, *, actor: str, target: Target, scope: Authorization,
                         addresses: Sequence[str] = ()) -> HttpResponse:
        """Test-only policy prototype; injected callable must never access a network.

        This method does not enforce connection-level restrictions and must not
        be used as a transport interface or exposed as a network capability.
        """
        call_id = str(uuid4())
        event = {"call_id": call_id, "tool_name": "http.request", "actor": actor,
                 "target_type": target.type.value}
        self._audit.record({**event, "status": "requested"})
        try:
            if self._transport is None:
                raise HttpDenied("no enforced network transport is configured")
            if not actor.strip():
                raise HttpDenied("actor is required")
            if target.type is not TargetType.WEB or target.locator != request.url:
                raise HttpDenied("request URL must match the authorized web target")
            check_target(target, scope)
            if addresses:
                check_resolved_addresses(target, scope, list(addresses))
            if self._rate_limiter is not None:
                try:
                    self._rate_limiter.acquire(target.locator)
                except RateLimitExceeded as exc:
                    raise HttpDenied("rate limit exceeded") from exc
            self._audit.record({**event, "status": "started"})
            status, headers, body, history = self._transport(request.method, request.url,
                                                             dict(request.headers), request.timeout_seconds)
            final = target
            for hop in history:
                final = check_redirect(final, hop, scope)
            if final.locator != request.url and not request.follow_redirects:
                raise HttpDenied("redirects are disabled for this call")
        except (HttpDenied, ScopeDenied):
            self._audit.record({**event, "status": "denied"})
            raise
        except BaseException:
            self._audit.record({**event, "status": "failed"})
            raise
        truncated = len(body) > request.max_response_bytes
        safe = {name: value for name, value in headers.items() if name.lower() in _SAFE_HEADERS}
        self._audit.record({**event, "status": "succeeded"})
        return HttpResponse(call_id=call_id, status_code=status, final_url=final.locator, headers=safe,
                            body=body[:request.max_response_bytes].decode("utf-8", "replace"),
                            truncated=truncated)
