"""Non-destructive web validation probes with single-use operator approval.

Five narrowly scoped checks are implemented: a reflection probe (a random marker
in one query parameter), a database-error probe (a single quote in one query
parameter), an XSS-context probe (a custom tag that is only a candidate when it
returns without HTML encoding), a template-injection probe (an arithmetic
expression that is only a candidate when the engine evaluates it and does not
echo the source) and an open-redirect probe (a redirect parameter pointed at a
reserved ``.invalid`` host). A path-traversal probe sends one traversal payload
to file-like parameters and only reports a candidate when file content
signatures appear. None of them proves exploitability: a reflection is not
script execution, an error string is not proof of injection, an evaluated
expression is not proof of remote code execution, and a redirect parameter is
not proof of an open redirect without a browser flow. Everything is reported as
``candidate`` or ``inconclusive``; ``inconclusive`` is never proof that the class
is absent.

Network access is injected, exactly like the crawler: this module never opens a
socket itself. The caller must consume a bound ``validation.probes`` approval
before any probe is sent.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vulnmind.analysis.crawler import FetchResult
from vulnmind.persistence.audit import AuditError
from vulnmind.security.approvals import operation_digest

MAX_PROBES = 20
_MAX_PARAMS_PER_URL = 3
MARKER = "vmxreflect1a2b"
XSS_MARKER = "<vulnmind-probe-8f3a>"
SSTI_PAYLOAD = "{{7788*3}}"
SSTI_RESULT = "23364"
_REDIRECT_PARAMS = frozenset({"url", "next", "redirect", "redirect_uri", "return", "returnurl",
                              "dest", "destination", "continue", "target", "r", "u"})
_FILE_PARAMS = frozenset({"file", "filename", "filepath", "path", "page", "template", "doc",
                          "document", "download", "load", "include", "view", "folder", "dir"})
_SSTI_PARAMS = frozenset({"q", "query", "search", "name", "page", "template", "view", "lang",
                          "title", "message", "content", "input", "text", "email", "user"})
_FILE_SIGNATURES = (
    "root:x:0:0",
    "daemon:x:",
    "[boot loader]",
    "for 16-bit app support",
    "[fonts]",
    "[extensions]",
)
_ERROR_SIGNATURES = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate[",
    "ora-00933",
    "ora-01756",
    "postgresql: syntax error",
    "syntax error at or near",
    "microsoft ole db",
)
ProbeKind = Literal["reflection", "sql_error", "xss_reflection", "template_injection",
                    "open_redirect", "path_traversal"]


class Probe(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: ProbeKind
    url: str = Field(min_length=1, max_length=2048)
    parameter: str = Field(min_length=1, max_length=128)


class ProbeResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    kind: ProbeKind
    url: str
    verdict: Literal["candidate", "inconclusive", "error"]
    detail: str


class ValidationReport(BaseModel):
    model_config = ConfigDict(frozen=True)
    results: list[ProbeResult]
    candidates: int
    inconclusive: int
    errors: int
    approval_digest: str


class ValidationDenied(Exception):
    """The plan has no valid, single-use approval; nothing was sent."""


class ValidationStateUnknown(RuntimeError):
    """Approval consumption could not be confirmed; do not retry blindly."""


def _parameter_names(url: str) -> list[str]:
    return [name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)][:_MAX_PARAMS_PER_URL]


def _with_value(url: str, parameter: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = [(name, value if name == parameter else current)
             for name, current in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs, doseq=True), parts.fragment))


def plan_probes(urls: Sequence[str], *, max_probes: int = MAX_PROBES) -> list[Probe]:
    """Build deterministic probes for endpoint URLs that carry query parameters."""
    probes, _ = _plan_probes(urls, max_probes=max_probes, detect_truncation=False)
    return probes


def plan_probes_with_coverage(urls: Sequence[str], *, max_probes: int = MAX_PROBES) -> tuple[list[Probe], bool]:
    """Build a bounded plan and report whether another unique probe was omitted."""
    return _plan_probes(urls, max_probes=max_probes, detect_truncation=True)


def _plan_probes(urls: Sequence[str], *, max_probes: int, detect_truncation: bool) -> tuple[list[Probe], bool]:
    if isinstance(max_probes, bool) or not isinstance(max_probes, int) or not 1 <= max_probes <= MAX_PROBES:
        raise ValueError(f"max_probes must be between 1 and {MAX_PROBES}")
    probes: list[Probe] = []
    seen: set[tuple[str, str]] = set()
    for url in urls:
        if not isinstance(url, str):
            raise ValueError("endpoint URLs must be strings")
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.netloc or not parts.query:
            continue
        for parameter in _parameter_names(url):
            variants = [("reflection", MARKER), ("sql_error", "1'"),
                        ("xss_reflection", XSS_MARKER)]
            if parameter.casefold() in _SSTI_PARAMS:
                variants.append(("template_injection", SSTI_PAYLOAD))
            if parameter.casefold() in _REDIRECT_PARAMS:
                variants.append(("open_redirect", "https://redirect.invalid/vmx"))
            if parameter.casefold() in _FILE_PARAMS:
                variants.append(("path_traversal", "../../../../etc/passwd"))
            for kind, value in variants:
                probe_url = _with_value(url, parameter, value)
                key = (kind, probe_url)
                if key in seen:
                    continue
                seen.add(key)
                if len(probes) >= max_probes:
                    return probes, True
                probes.append(Probe(kind=kind, url=probe_url, parameter=parameter))
                if len(probes) >= max_probes and not detect_truncation:
                    return probes, False
    return probes, False


def plan_digest(probes: Sequence[Probe]) -> str:
    """Digest the exact plan; the approval must bind this value."""
    if not probes:
        raise ValueError("a validation plan needs at least one probe")
    return operation_digest({"tool": "web.validation",
                             "probes": [probe.model_dump(mode="json") for probe in probes]})


def load_plan(data: str | bytes, *, max_probes: int = MAX_PROBES) -> list[Probe]:
    """Parse a plan file and prove every probe is a deterministic plan member.

    A plan file may reorder or subset the deterministic probes, but it cannot
    introduce a new URL, parameter or payload: each entry must equal an entry
    that ``plan_probes`` derives for that same URL. A declared digest, when
    present, must match the recomputed plan.
    """
    if isinstance(max_probes, bool) or not isinstance(max_probes, int) or not 1 <= max_probes <= MAX_PROBES:
        raise ValueError(f"max_probes must be between 1 and {MAX_PROBES}")
    if isinstance(data, (bytes, bytearray)):
        if len(data) > 1_000_000:
            raise ValueError("plan file is too large")
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeError:
            raise ValueError("plan file is not UTF-8 text") from None
    elif isinstance(data, str):
        text = data
    else:
        raise ValueError("plan file must be text")
    if len(text.encode("utf-8")) > 1_000_000:
        raise ValueError("plan file is too large")
    try:
        payload = json.loads(text)
    except (ValueError, RecursionError):
        raise ValueError("plan file is not valid JSON") from None
    declared = None
    if isinstance(payload, dict):
        if set(payload) - {"version", "digest", "probes", "summary"}:
            raise ValueError("plan file has unsupported fields")
        if "version" in payload and payload["version"] != 1:
            raise ValueError("plan file version is not supported")
        declared = payload.get("digest")
        entries = payload.get("probes")
    else:
        entries = payload
    if not isinstance(entries, list) or not entries:
        raise ValueError("plan file needs a nonempty probe list")
    if len(entries) > max_probes:
        raise ValueError(f"a validation plan allows at most {max_probes} probes")
    probes: list[Probe] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("each plan probe must be an object")
        try:
            probe = Probe.model_validate(entry)
        except (KeyError, ValidationError):
            raise ValueError("plan probe does not match the expected schema") from None
        allowed = plan_probes([probe.url], max_probes=MAX_PROBES)
        if not any(item.kind == probe.kind and item.url == probe.url
                   and item.parameter == probe.parameter for item in allowed):
            raise ValueError("plan probe is not part of the deterministic plan")
        key = (probe.kind, probe.url, probe.parameter)
        if key in seen:
            raise ValueError("plan probes must be unique")
        seen.add(key)
        probes.append(probe)
    if declared is not None:
        if not isinstance(declared, str) or declared != plan_digest(probes):
            raise ValueError("plan digest does not match the probes")
    return probes


def _headers(fetch_result: FetchResult) -> dict[str, str]:
    return {str(name).lower(): value for name, value in (fetch_result.headers or {}).items()}


def _classify(probe: Probe, response: FetchResult) -> ProbeResult:
    body = response.body.decode("utf-8", "replace") if isinstance(response.body, (bytes, bytearray)) else ""
    if probe.kind == "reflection":
        if MARKER in body:
            return ProbeResult(kind=probe.kind, url=probe.url, verdict="candidate",
                               detail="marker reflected verbatim; this is not proof of script execution")
    elif probe.kind == "sql_error":
        lowered = body.casefold()
        if any(signature in lowered for signature in _ERROR_SIGNATURES):
            return ProbeResult(kind=probe.kind, url=probe.url, verdict="candidate",
                               detail="database error signature present; manual confirmation required")
    elif probe.kind == "xss_reflection":
        # Only an unencoded custom tag is a signal; escaped output is not.
        if XSS_MARKER in body:
            return ProbeResult(kind=probe.kind, url=probe.url, verdict="candidate",
                               detail="custom tag reflected without HTML encoding; not proof of script execution")
    elif probe.kind == "template_injection":
        if SSTI_RESULT in body and SSTI_PAYLOAD not in body:
            return ProbeResult(kind=probe.kind, url=probe.url, verdict="candidate",
                               detail="template expression evaluated; manual confirmation required")
    elif probe.kind == "open_redirect":
        location = _headers(response).get("location", "")
        target = urlsplit(location)
        base = urlsplit(probe.url)
        if target.scheme in {"http", "https"} and target.hostname and target.hostname != base.hostname:
            return ProbeResult(kind=probe.kind, url=probe.url, verdict="candidate",
                               detail="redirect parameter returned another host; not followed")
    elif probe.kind == "path_traversal":
        lowered = body.casefold()
        if any(signature in lowered for signature in _FILE_SIGNATURES):
            return ProbeResult(kind=probe.kind, url=probe.url, verdict="candidate",
                               detail="file content signature present; manual confirmation required")
    return ProbeResult(kind=probe.kind, url=probe.url, verdict="inconclusive",
                       detail="no signal for this probe; not proof that the class is absent")


class ValidationEngine:
    """Runs one approved plan; approval consumption is committed before probing."""

    def __init__(self, audit, *, approvals, session):
        if not callable(getattr(audit, "record", None)):
            raise ValueError("an audit sink is required")
        if not callable(getattr(approvals, "consume_bound", None)):
            raise ValueError("an approval service with consume_bound is required")
        if not callable(getattr(session, "commit", None)) or not callable(getattr(session, "rollback", None)):
            raise ValueError("a dedicated session is required")
        self._audit = audit
        self._approvals = approvals
        self._session = session

    def run(self, probes: Sequence[Probe], *, fetch: Callable[[str], FetchResult], actor: str,
            scan_id, approval_token: str) -> ValidationReport:
        plan = [Probe.model_validate(probe.model_dump()) for probe in probes]
        if not plan:
            raise ValueError("a validation plan needs at least one probe")
        if len(plan) > MAX_PROBES:
            raise ValueError(f"a validation plan allows at most {MAX_PROBES} probes")
        if not callable(fetch):
            raise ValueError("a fetch callable is required")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("actor is required")
        digest = plan_digest(plan)
        event = {"call_id": str(uuid4()), "tool_name": "web.validation", "actor": actor,
                 "target_type": "web"}
        self._audit.record({**event, "status": "requested"})
        if not approval_token or not self._approvals.consume_bound(
                approval_token, scan_id=scan_id, action="validation.probes", target=digest,
                operation_hash=digest):
            # The dedicated approval transaction may hold SQLite's writer
            # lock even when no row was updated. Release it before the
            # independent denied audit, and never execute a probe.
            self._session.rollback()
            self._audit.record({**event, "status": "denied"})
            raise ValidationDenied("a valid single-use validation approval is required")
        try:
            self._session.commit()
        except Exception as exc:
            # The commit may have reached the database despite a lost reply.
            # No probe has been sent, but approval state must be inspected.
            raise ValidationStateUnknown("approval consumption is uncertain") from exc
        self._audit.record({**event, "status": "started"})
        results: list[ProbeResult] = []
        for probe in plan:
            try:
                response = fetch(probe.url)
            except AuditError:
                # The request may already have happened. Never continue to
                # another probe when its audit outcome cannot be established.
                raise
            except Exception:  # noqa: BLE001 - a failed probe is recorded, not retried
                results.append(ProbeResult(kind=probe.kind, url=probe.url, verdict="error",
                                           detail="probe request failed"))
                continue
            results.append(_classify(probe, response))
        candidates = sum(1 for item in results if item.verdict == "candidate")
        self._audit.record({**event, "status": "succeeded"})
        return ValidationReport(results=results, candidates=candidates,
                                inconclusive=sum(1 for item in results if item.verdict == "inconclusive"),
                                errors=sum(1 for item in results if item.verdict == "error"),
                                approval_digest=digest)
