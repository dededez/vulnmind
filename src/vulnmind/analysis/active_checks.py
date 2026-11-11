"""Passive configuration checks over already-fetched HTTP responses.

Only response metadata is inspected: no request is sent, nothing is mutated and
every finding stays ``unverified``. A missing header is evidence of a missing
header, not proof of exploitability.
"""
from __future__ import annotations

from collections.abc import Iterable
import re

from pydantic import BaseModel, ConfigDict, Field

from vulnmind.findings import FindingCandidate

_REQUIRED_HEADERS = {
    "content-security-policy": ("medium", "缺少 Content-Security-Policy"),
    "x-content-type-options": ("low", "缺少 X-Content-Type-Options"),
    "x-frame-options": ("low", "缺少 X-Frame-Options"),
    "referrer-policy": ("low", "缺少 Referrer-Policy"),
    "permissions-policy": ("info", "缺少 Permissions-Policy"),
}
_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version")
_COOKIE_SEPARATOR = re.compile(r",\s*(?=[!#$%&'*+.^_`|~0-9A-Za-z-]+=)")


def _split_cookies(value: str) -> list[str]:
    """Split combined cookie headers without splitting dates or quoted values."""
    parts: list[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, character in enumerate(value):
        if quoted and escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif not quoted and character == "," and _COOKIE_SEPARATOR.match(value, index):
            parts.append(value[start:index])
            start = index + 1
    parts.append(value[start:])
    return parts


class PageMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)
    url: str = Field(min_length=1)
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    content_type: str = ""


class CheckResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    url: str
    findings: list[FindingCandidate] = Field(default_factory=list)
    skipped: int = 0


def _header(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name:
            return value.strip()
    return ""


def _candidate(page: PageMetadata, *, title: str, kind: str, severity: str) -> FindingCandidate:
    return FindingCandidate(title=f"{title} ({page.url})"[:300], vulnerability_type=kind,
                            target_id=page.url, location=page.url[:512],
                            source_tool="builtin.passive_checks", status="unverified",
                            severity=severity)


def check_page(page: PageMetadata) -> CheckResult:
    """Check one response; only HTML pages are examined."""
    content_type = page.content_type.split(";", 1)[0].strip().lower()
    if page.status_code < 200 or page.status_code >= 300 or content_type not in {"text/html", "application/xhtml+xml"}:
        return CheckResult(url=page.url, skipped=1)
    findings: list[FindingCandidate] = []
    secure = page.url.lower().startswith("https://")
    for name, (severity, title) in _REQUIRED_HEADERS.items():
        if not _header(page.headers, name):
            findings.append(_candidate(page, title=title, kind=f"missing_{name.replace('-', '_')}",
                                       severity=severity))
    if secure and not _header(page.headers, "strict-transport-security"):
        findings.append(_candidate(page, title="缺少 Strict-Transport-Security",
                                   kind="missing_strict_transport_security", severity="medium"))
    for name in _DISCLOSURE_HEADERS:
        value = _header(page.headers, name)
        if value:
            findings.append(_candidate(page, title=f"响应头可能泄露技术信息: {name}",
                                       kind="technology_disclosure", severity="info"))
    cookie = _header(page.headers, "set-cookie")
    if cookie:
        # An Expires date contains a comma; split only where another cookie
        # name and '=' follow. Never include cookie names or values in findings.
        for part in _split_cookies(cookie):
            segments = [segment.strip() for segment in part.split(";") if segment.strip()]
            if not segments:
                continue
            lowered = {segment.lower() for segment in segments[1:]}
            missing = []
            if "httponly" not in lowered:
                missing.append("HttpOnly")
            if secure and "secure" not in lowered:
                missing.append("Secure")
            if not any(segment.partition("=")[0].strip() == "samesite"
                       and segment.partition("=")[2].strip() in {"strict", "lax", "none"}
                       for segment in lowered):
                missing.append("SameSite")
            if missing:
                findings.append(_candidate(page, title=f"Cookie 缺少属性: {', '.join(missing)}",
                                           kind="cookie_attribute_missing", severity="medium"))
    return CheckResult(url=page.url, findings=findings)


def check_pages(pages: Iterable[PageMetadata]) -> list[CheckResult]:
    results: list[CheckResult] = []
    for page in pages:
        try:
            results.append(check_page(page))
        except Exception:  # noqa: BLE001 - one malformed page must not stop the scan
            results.append(CheckResult(url=page.url, skipped=1))
    return results
