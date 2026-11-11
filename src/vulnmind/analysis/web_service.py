"""Offline web analysis: authorized snapshot → checks → findings → report.

The service sends no HTTP request. It consumes responses captured elsewhere,
re-checks every page URL against the authorization, runs the passive checks and
the same endpoint extractor used by the crawler, and persists findings,
endpoints, evidence and a report through the caller's transaction. Snapshot
content is treated as untrusted input with strict size and shape limits.
"""
from __future__ import annotations

import json
from contextlib import nullcontext
from datetime import timedelta
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnmind.agents.review import AgentReview, review_findings
from vulnmind.analysis.active_checks import PageMetadata, check_page
from vulnmind.analysis.persistence import FindingWriter, StoredFindings
from vulnmind.analysis.repository import EvidenceAttachment
from vulnmind.analysis.triage import TriageDecision, triage_groups
from vulnmind.analysis.web import MAX_FORM_PARAMETERS, EndpointInventory, extract_endpoints
from vulnmind.evidence.ingest import EvidenceItem, ingest_evidence
from vulnmind.evidence.store import EvidenceStore
from vulnmind.findings import FindingCandidate, FindingGroup, group_findings
from vulnmind.persistence.models import Evidence, Finding, Scan
from vulnmind.persistence.repositories import WebEndpointRepository
from vulnmind.reports.evidence_snapshot import MAX_SNAPSHOT_IDS
from vulnmind.reports.generator import (AgentReviewItem, AgentReviewSummary, DecisionSummary,
                                        ReportDocument, ReportInput, generate)
from vulnmind.schemas import Authorization, Target, TargetType
from vulnmind.security.scope import ScopeDenied, check_target
from vulnmind.tools.registry import AuditSink

MAX_SNAPSHOT_BYTES = 10_000_000
MAX_PAGES = 100
MAX_HTML_CHARACTERS = 2_000_000
MAX_HEADERS = 100
MAX_HEADER_CHARS = 8192
MAX_URL_CHARS = 2048

_HTML_TYPES = {"text/html", "application/xhtml+xml"}


class SnapshotError(ValueError):
    """The snapshot is oversized, malformed or outside the supported schema."""


class WebPageSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    url: str = Field(min_length=1, max_length=MAX_URL_CHARS)
    status_code: int = Field(ge=100, le=599)
    content_type: str = Field(default="", max_length=255)
    headers: dict[str, str] = Field(default_factory=dict)
    html: str = Field(default="", max_length=MAX_HTML_CHARACTERS)

    @field_validator("url")
    @classmethod
    def absolute_http_url(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("page URL must be a single-line absolute http(s) URL")
        try:
            parts = urlsplit(value)
            if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
                raise ValueError("page URL must be absolute")
            if parts.username is not None or parts.password is not None or parts.fragment:
                raise ValueError("page URL must not contain credentials or a fragment")
        except ValueError:
            raise ValueError("page URL must be absolute") from None
        return value

    @field_validator("headers")
    @classmethod
    def bounded_headers(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > MAX_HEADERS:
            raise ValueError("too many response headers")
        for name, header in value.items():
            if (not isinstance(name, str) or not name.strip() or len(name) > 256
                    or not isinstance(header, str) or len(header) > MAX_HEADER_CHARS):
                raise ValueError("response header is invalid")
            if any(character in header for character in ("\r", "\n", "\x00")):
                raise ValueError("response header must not contain line breaks")
        return value

    @field_validator("html")
    @classmethod
    def no_nul(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("page body must not contain NUL bytes")
        return value


class WebSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal[1] = 1
    target: Target
    pages: list[WebPageSnapshot] = Field(min_length=1, max_length=MAX_PAGES)

    @model_validator(mode="after")
    def web_target_and_unique_pages(self):
        if self.target.type != TargetType.WEB:
            raise ValueError("a web snapshot requires a web target")
        urls = [page.url for page in self.pages]
        if len(urls) != len(set(urls)):
            raise ValueError("snapshot pages must have unique URLs")
        return self


def parse_snapshot(data: bytes) -> WebSnapshot:
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise SnapshotError("snapshot is empty")
    if len(data) > MAX_SNAPSHOT_BYTES:
        raise SnapshotError("snapshot exceeds the size limit")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeError:
        raise SnapshotError("snapshot is not UTF-8 text") from None
    try:
        payload = json.loads(text)
    except (ValueError, RecursionError):
        raise SnapshotError("snapshot is not valid JSON") from None
    try:
        return WebSnapshot.model_validate(payload)
    except ValidationError:
        raise SnapshotError("snapshot does not match the expected schema") from None


class WebAnalysis(BaseModel):
    model_config = ConfigDict(frozen=True)
    scan_id: str
    project_id: str
    target_id: str
    pages_analyzed: int = 0
    pages_skipped: int = 0
    out_of_scope: int = 0
    truncated: bool = False
    findings: list[FindingCandidate] = Field(default_factory=list)
    groups: list[FindingGroup] = Field(default_factory=list)
    evidence: list[EvidenceAttachment] = Field(default_factory=list)
    endpoints: list[dict] = Field(default_factory=list)
    coverage_limitations: list[str] = Field(default_factory=list)

    def to_report_input(self, *, mode: str = "analysis", limitations=(), decisions=(),
                        agent_review: AgentReviewSummary | None = None) -> ReportInput:
        return ReportInput(scan_id=self.scan_id, project_id=self.project_id, mode=mode,
                           groups=self.groups, decisions=list(decisions),
                           limitations=[*limitations, *self.coverage_limitations],
                           agent_review=agent_review)


class WebScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    scan_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    target: Target
    scope: Authorization
    snapshot: WebSnapshot
    scan_uuid: UUID | None = None
    target_id: str | None = None


class WebScanResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    analysis: WebAnalysis
    decisions: list[TriageDecision]
    report: ReportDocument
    stored: StoredFindings | None
    evidence_stored: int = 0
    validation_requests: int = 0
    agent_review: AgentReview | None = None


def _review_summary(review: AgentReview) -> AgentReviewSummary:
    return AgentReviewSummary(
        status=review.status, summary=review.summary, ignored=review.ignored,
        total_groups=review.total_groups, selected_groups=review.selected_groups,
        omitted_groups=review.omitted_groups, groups_without_verdict=review.groups_without_verdict,
        items=tuple(AgentReviewItem(fingerprint=item.fingerprint, verdict=item.verdict,
                                    rationale=item.rationale, note=item.note)
                    for item in review.items))


class WebScanService:
    def __init__(self, audit: AuditSink, evidence_store: EvidenceStore | None = None,
                 approvals=None, agent_runtime=None):
        if agent_runtime is not None and not callable(getattr(agent_runtime, "run", None)):
            raise ValueError("agent runtime must expose a run method")
        if approvals is not None and not callable(getattr(approvals, "request", None)):
            raise ValueError("an approval service with request is required")
        self._audit = audit
        self._evidence_store = evidence_store
        self._approvals = approvals
        self._agent_runtime = agent_runtime

    def run(self, request: WebScanRequest, *, session: Session | None = None,
            report_format: str = "markdown") -> WebScanResult:
        if session is not None and request.scan_uuid is None:
            raise ValueError("persisting findings requires the scan UUID")
        if session is not None and self._approvals is not None and self._approvals.session is not session:
            raise ValueError("approval service must use the scan session")
        event = {"call_id": str(uuid4()), "tool_name": "web.scan", "actor": request.actor,
                 "target_type": "web"}
        self._audit.record({**event, "status": "requested"})
        try:
            if session is not None:
                connection = session.connection()
                if (connection.dialect.name == "sqlite"
                        and not connection.connection.driver_connection.in_transaction):
                    connection.exec_driver_sql("BEGIN")
            with session.begin_nested() if session is not None else nullcontext():
                if session is not None:
                    scan = session.get(Scan, request.scan_uuid)
                    try:
                        matches = (scan is not None and UUID(request.scan_id) == scan.id
                                   and UUID(request.project_id) == scan.project_id)
                    except (ValueError, TypeError, AttributeError):
                        matches = False
                    if not matches:
                        raise ValueError("scan and project identities do not match the stored scan")
                check_target(request.target, request.scope)
                self._audit.record({**event, "status": "started"})
                analysis = self._analyse(request)
                decisions = triage_groups(analysis.groups)
                review = None
                limitations = ["基于离线快照分析，本次运行未发送任何 HTTP 请求",
                               "快照由外部采集，未验证采集来源、完整性或时间",
                               "未执行主动验证；配置类发现只说明响应缺少对应属性"]
                if self._agent_runtime is not None and analysis.groups:
                    review = review_findings(self._agent_runtime, actor=request.actor,
                                             groups=analysis.groups)
                    limitations.append("模型复核仅为建议，不构成验证")
                stored = None
                evidence_stored = 0
                validation_requests = 0
                evidence_record_ids: dict[str, list[UUID]] = {}
                evidence_snapshot = "unavailable"
                evidence_snapshot_truncated = False
                if session is not None and request.scan_uuid is not None:
                    stored = FindingWriter(session).store_groups(request.scan_uuid, analysis.groups)
                    if self._evidence_store is not None and analysis.evidence:
                        evidence_stored = ingest_evidence(
                            session, self._evidence_store, scan_id=request.scan_uuid,
                            items=[EvidenceItem(fingerprint=item.fingerprint, content=item.content,
                                                evidence_type=item.evidence_type, locator=item.locator)
                                   for item in analysis.evidence]).stored
                    if self._approvals is not None:
                        # Queue one pending approval per group that needs validation;
                        # nothing is executed and re-running must not duplicate a request.
                        pending = {(row.action, row.target)
                                   for row in self._approvals.list_pending(request.scan_uuid)}
                        for group, decision in zip(analysis.groups, decisions):
                            if not decision.requires_validation:
                                continue
                            action = f"validation:{group.candidates[0].vulnerability_type}"[:255]
                            key = (action, group.fingerprint)
                            if key in pending:
                                continue
                            self._approvals.request(scan_id=request.scan_uuid, action=action,
                                                    target=group.fingerprint,
                                                    valid_for=timedelta(hours=72))
                            pending.add(key)
                            validation_requests += 1
                    if analysis.endpoints:
                        WebEndpointRepository(session).replace_for_scan(
                            request.scan_uuid, UUID(request.project_id), analysis.endpoints)
                    rows = session.execute(select(Finding.fingerprint, Evidence.id)
                                           .join(Evidence, Evidence.finding_id == Finding.id)
                                           .where(Finding.scan_id == request.scan_uuid)
                                           .order_by(Finding.fingerprint, Evidence.id)
                                           .limit(MAX_SNAPSHOT_IDS + 1)).all()
                    evidence_snapshot = "available"
                    evidence_snapshot_truncated = len(rows) > MAX_SNAPSHOT_IDS
                    reported = {group.fingerprint for group in analysis.groups}
                    for fingerprint, evidence_id in rows[:MAX_SNAPSHOT_IDS]:
                        if fingerprint in reported:
                            evidence_record_ids.setdefault(fingerprint, []).append(evidence_id)
                report_input = analysis.to_report_input(
                    limitations=limitations,
                    decisions=[DecisionSummary(fingerprint=item.fingerprint, severity=item.severity,
                                               confidence=item.confidence,
                                               requires_validation=item.requires_validation,
                                               rationale=item.rationale) for item in decisions],
                    agent_review=_review_summary(review) if review is not None else None)
                report_input = report_input.model_copy(update={
                    "evidence_record_ids": evidence_record_ids,
                    "evidence_snapshot": evidence_snapshot,
                    "evidence_snapshot_truncated": evidence_snapshot_truncated})
                report = generate(report_input, format=report_format)
                result = WebScanResult(analysis=analysis, decisions=decisions, report=report,
                                       stored=stored, evidence_stored=evidence_stored,
                                       validation_requests=validation_requests,
                                       agent_review=review)
                self._audit.record({**event, "status": "pending_commit" if session is not None
                                    else "succeeded"})
        except ScopeDenied:
            self._audit.record({**event, "status": "denied"})
            raise
        except Exception:
            self._audit.record({**event, "status": "failed"})
            raise
        return result

    def _analyse(self, request: WebScanRequest) -> WebAnalysis:
        findings: list[FindingCandidate] = []
        evidence: list[EvidenceAttachment] = []
        endpoints: list[dict] = []
        seen_endpoints: dict[tuple[str, str], int] = {}
        metadata: dict[str, bytes] = {}
        pages_analyzed = pages_skipped = out_of_scope = 0
        truncated = False
        for page in request.snapshot.pages:
            try:
                check_target(Target(type="web", locator=page.url), request.scope)
            except ScopeDenied:
                out_of_scope += 1
                pages_skipped += 1
                continue
            metadata[page.url] = _metadata_bytes(page)
            checked = check_page(PageMetadata(url=page.url, status_code=page.status_code,
                                              headers=dict(page.headers),
                                              content_type=page.content_type))
            if checked.skipped:
                pages_skipped += 1
                continue
            pages_analyzed += 1
            findings.extend(checked.findings)
            if page.html:
                inventory: EndpointInventory = extract_endpoints(
                    base=Target(type="web", locator=page.url), scope=request.scope,
                    html=page.html, max_endpoints=500)
                out_of_scope += inventory.out_of_scope
                truncated = truncated or inventory.truncated
                for endpoint in inventory.endpoints:
                    key = (endpoint.method, endpoint.url)
                    if key in seen_endpoints:
                        existing = endpoints[seen_endpoints[key]]
                        parameters = list(dict.fromkeys([*existing["parameters"], *endpoint.parameters]))
                        if len(parameters) > MAX_FORM_PARAMETERS:
                            truncated = True
                        existing["parameters"] = parameters[:MAX_FORM_PARAMETERS]
                        continue
                    seen_endpoints[key] = len(endpoints)
                    endpoints.append({**endpoint.model_dump(), "source_url": page.url})
        groups = group_findings(findings)
        for group in groups:
            location = group.candidates[0].target_id
            content = metadata.get(location)
            if content is None:
                continue
            evidence.append(EvidenceAttachment(fingerprint=group.fingerprint, content=content,
                                               evidence_type="http_metadata",
                                               locator=_evidence_url(location)[:1000]))
        limitations: list[str] = ["HTTP 元数据证据及其定位符不保存 URL 查询参数，证据仅保存已知响应头名称、不保存响应头值；无法独立证明属性值；发现和端点仍可能包含查询参数"]
        if any(endpoint["parameters"] for endpoint in endpoints):
            limitations.append("表单参数名可能敏感，持久化时会写入端点记录；验证计划仅生成空值占位候选且受上限限制")
        if out_of_scope:
            limitations.append(f"快照中有 {out_of_scope} 个页面或链接超出授权范围，未分析")
        if pages_skipped:
            limitations.append(f"有 {pages_skipped} 个页面因状态码或内容类型被跳过")
        if truncated:
            limitations.append("端点提取达到上限，清单不完整")
        return WebAnalysis(scan_id=request.scan_id, project_id=request.project_id,
                           target_id=request.target_id or request.target.locator,
                           pages_analyzed=pages_analyzed, pages_skipped=pages_skipped,
                           out_of_scope=out_of_scope, truncated=truncated,
                           findings=findings, groups=groups, evidence=evidence,
                           endpoints=endpoints, coverage_limitations=limitations)


def _evidence_url(url: str) -> str:
    return urlsplit(url)._replace(query="", fragment="").geturl()


def _metadata_bytes(page: WebPageSnapshot) -> bytes:
    # Response headers can carry cookies, credentials, personal data, or
    # attacker-controlled text. Keep only known names and never their values.
    known_headers = {"content-security-policy", "x-content-type-options", "x-frame-options",
                     "referrer-policy", "permissions-policy", "strict-transport-security",
                     "server", "x-powered-by", "x-aspnet-version", "set-cookie"}
    content_type = page.content_type.split(";", 1)[0].strip().lower()
    payload = {"url": _evidence_url(page.url),
               "status_code": page.status_code,
               "content_type": content_type if content_type in _HTML_TYPES else "other",
               "header_names": sorted({name.lower() for name in page.headers
                                       if name.lower() in known_headers}),
               "header_values": "withheld", "query": "withheld"}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
