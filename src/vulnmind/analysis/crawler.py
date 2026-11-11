"""Breadth-first, GET-only crawl over an authorized web origin.

Network access is injected: the caller supplies a fetch callable that returns a
bounded response. This module never follows redirects itself, never submits
forms, never sends credentials and never leaves the authorized origin. Each
fetched HTML page is passed to ``extract_endpoints`` so the same scope guard
filters every discovered link.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from vulnmind.analysis.active_checks import PageMetadata, check_page
from vulnmind.analysis.web import MAX_FORM_PARAMETERS, EndpointInventory, extract_endpoints
from vulnmind.persistence.audit import AuditError
from vulnmind.schemas import Authorization, Target

MAX_PAGES = 50
MAX_PAGE_BYTES = 2_000_000
_ALLOWED_TYPES = ("text/html", "application/xhtml+xml")


class CrawlError(RuntimeError):
    """The crawl cannot continue safely (invalid start or fetch failure)."""


@dataclass(frozen=True)
class FetchResult:
    status_code: int
    content_type: str
    body: bytes
    final_url: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CrawledPage:
    url: str
    status_code: int
    digest: str
    bytes: int


class CrawlResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    pages: list[CrawledPage] = Field(default_factory=list)
    endpoints: list[dict] = Field(default_factory=list)
    findings: list[dict] = Field(default_factory=list)
    out_of_scope: int = 0
    errors: list[str] = Field(default_factory=list)
    skipped: int = 0
    truncated: bool = False


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, (parsed.hostname or "").lower(), port


def crawl(*, start: Target, scope: Authorization, fetch: Callable[[str], FetchResult],
          max_pages: int = 20, max_page_bytes: int = MAX_PAGE_BYTES,
          max_html_characters: int = 2_000_000) -> CrawlResult:
    if start.type.value != "web":
        raise ValueError("crawl requires a web target")
    if not callable(fetch):
        raise ValueError("a fetch callable is required")
    if not 1 <= max_pages <= MAX_PAGES:
        raise ValueError(f"max_pages must be between 1 and {MAX_PAGES}")
    if not 1 <= max_page_bytes <= MAX_PAGE_BYTES:
        raise ValueError("max_page_bytes is out of range")
    origin = _origin(start.locator)
    queue: list[tuple[str, int]] = [(start.locator, 0)]
    queued = {start.locator}
    pages: list[CrawledPage] = []
    endpoints: list[dict] = []
    findings: list[dict] = []
    seen_endpoints: dict[str, int] = {}
    errors: list[str] = []
    out_of_scope = skipped = 0
    truncated = False
    while queue:
        url, depth = queue.pop(0)
        if len(pages) >= max_pages:
            truncated = True
            break
        try:
            response = fetch(url)
        except AuditError:
            # The request may have happened; never continue without audit.
            raise
        except Exception:  # noqa: BLE001 - fetch failures are recorded, not exposed
            errors.append(url)
            continue
        if response.status_code < 200 or response.status_code >= 300:
            skipped += 1
            continue
        if _origin(response.final_url) != origin:
            out_of_scope += 1
            continue
        content_type = response.content_type.split(";", 1)[0].strip().lower()
        if content_type not in _ALLOWED_TYPES:
            skipped += 1
            continue
        if len(response.body) > max_page_bytes:
            truncated = True
            continue
        html = response.body[:max_html_characters].decode("utf-8", "replace")
        inventory: EndpointInventory = extract_endpoints(base=Target(type="web", locator=response.final_url),
                                                         scope=scope, html=html, max_endpoints=500)
        pages.append(CrawledPage(url=response.final_url, status_code=response.status_code,
                                 digest=hashlib.sha256(response.body).hexdigest(),
                                 bytes=len(response.body)))
        checked = check_page(PageMetadata(url=response.final_url, status_code=response.status_code,
                                          headers=response.headers, content_type=response.content_type))
        findings.extend(item.model_dump() for item in checked.findings)
        out_of_scope += inventory.out_of_scope
        for endpoint in inventory.endpoints:
            key = f"{endpoint.method} {endpoint.url}"
            if key in seen_endpoints:
                existing = endpoints[seen_endpoints[key]]
                parameters = list(dict.fromkeys([*existing["parameters"], *endpoint.parameters]))
                if len(parameters) > MAX_FORM_PARAMETERS:
                    truncated = True
                existing["parameters"] = parameters[:MAX_FORM_PARAMETERS]
                continue
            seen_endpoints[key] = len(endpoints)
            endpoints.append({**endpoint.model_dump(), "source_url": response.final_url})
            if endpoint.method == "GET" and endpoint.url not in queued and len(queued) < max_pages * 5:
                queued.add(endpoint.url)
                queue.append((endpoint.url, depth + 1))
        if inventory.truncated:
            truncated = True
    return CrawlResult(pages=pages, endpoints=endpoints, findings=findings,
                       out_of_scope=out_of_scope, errors=errors, skipped=skipped,
                       truncated=truncated)
