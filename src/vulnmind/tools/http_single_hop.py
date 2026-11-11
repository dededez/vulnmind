"""Single-hop HTTP client: resolve, validate, connect, then check the next hop.

Unlike the simulation in ``tools.http``, this client never lets the transport
follow redirects. Each hop is resolved and validated before its connection is
attempted, and the validated addresses are handed to the transport so it can
pin them. The transport is still injected: the client cannot prove that a real
implementation pins the address, so this remains a policy layer, not isolation.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from urllib.parse import urlsplit

from vulnmind.schemas import Authorization, Target, TargetType
from vulnmind.security.ratelimit import RateLimitExceeded, RateLimiter
from vulnmind.security.scope import ScopeDenied, check_redirect, check_resolved_addresses, check_target
from vulnmind.tools.http import HttpDenied, HttpRequestInput, HttpResponse, _SAFE_HEADERS
from vulnmind.tools.registry import AuditSink

MAX_HOPS = 5


class HopResponse(BaseModel):
    """What one connection attempt may return; redirects are never followed."""
    model_config = ConfigDict(frozen=True)
    status_code: int
    headers: dict[str, str] = {}
    body: bytes = b""
    location: str | None = None
    truncated: bool = False


Resolver = Callable[[str], list[str]]
Transport = Callable[..., HopResponse]


class SingleHopRequester:
    def __init__(self, audit: AuditSink, *, resolve: Resolver, transport: Transport,
                 rate_limiter: RateLimiter | None = None, max_hops: int = MAX_HOPS):
        if not callable(resolve) or not callable(transport):
            raise ValueError("resolve and transport must be callable")
        if not 1 <= max_hops <= MAX_HOPS:
            raise ValueError(f"max_hops must be between 1 and {MAX_HOPS}")
        self._audit = audit
        self._resolve = resolve
        self._transport = transport
        self._rate_limiter = rate_limiter
        self._max_hops = max_hops

    def request(self, request: HttpRequestInput, *, actor: str, target: Target,
                scope: Authorization) -> HttpResponse:
        call_id = str(uuid4())
        event = {"call_id": call_id, "tool_name": "http.request", "actor": actor,
                 "target_type": target.type.value}
        self._audit.record({**event, "status": "requested"})
        try:
            if not actor.strip():
                raise HttpDenied("actor is required")
            if target.type is not TargetType.WEB or target.locator != request.url:
                raise HttpDenied("request URL must match the authorized web target")
            check_target(target, scope)
            current = target
            response = None
            for hop in range(self._max_hops + 1):
                if self._rate_limiter is not None:
                    try:
                        self._rate_limiter.acquire(current.locator)
                    except RateLimitExceeded as exc:
                        raise HttpDenied("rate limit exceeded") from exc
                addresses = self._resolve(urlsplit(current.locator).hostname or "")
                if not isinstance(addresses, list) or not addresses:
                    raise ScopeDenied("resolver returned no addresses")
                check_resolved_addresses(current, scope, addresses)
                self._audit.record({**event, "status": "started"})
                response = self._transport(method=request.method, url=current.locator,
                                           headers=dict(request.headers), addresses=tuple(addresses),
                                           timeout=request.timeout_seconds)
                if not isinstance(response, HopResponse):
                    raise HttpDenied("transport returned an unsupported response")
                if not response.location:
                    break
                if not request.follow_redirects:
                    break
                if hop >= self._max_hops:
                    raise HttpDenied("too many redirects")
                current = check_redirect(current, response.location, scope)
        except (HttpDenied, ScopeDenied):
            self._audit.record({**event, "status": "denied"})
            raise
        except BaseException:
            self._audit.record({**event, "status": "failed"})
            raise
        assert response is not None
        body = response.body[:request.max_response_bytes]
        safe = {name: value for name, value in response.headers.items() if name.lower() in _SAFE_HEADERS}
        self._audit.record({**event, "status": "succeeded"})
        return HttpResponse(call_id=call_id, status_code=response.status_code,
                            final_url=current.locator, headers=safe,
                            body=body.decode("utf-8", "replace"),
                            truncated=response.truncated or len(response.body) > request.max_response_bytes)


def hop_transport(connect: Callable[[str, str, dict[str, str], tuple[str, ...], float], Any]) -> Transport:
    """Adapt a positional connect callable to the keyword transport protocol."""
    def transport(*, method: str, url: str, headers: dict[str, str], addresses: tuple[str, ...],
                  timeout: float) -> HopResponse:
        result = connect(method, url, headers, addresses, timeout)
        if isinstance(result, HopResponse):
            return result
        raise HttpDenied("connect callable returned an unsupported response")
    return transport
