"""Offline web analysis service: snapshot → findings → evidence → report."""
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session

from vulnmind.analysis.web_service import (WebPageSnapshot, WebScanRequest, WebScanService,
                                           WebSnapshot)
from vulnmind.evidence.store import EvidenceStore
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Evidence, Finding, Project, Scan, WebEndpoint
from vulnmind.schemas import Authorization, Target


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(dict(event))


@pytest.fixture
def session(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'web.db').as_posix()}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    with Session(engine) as opened:
        yield opened
    engine.dispose()


def scope():
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test authorization", approved_by="tester",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         web_origins=["http://example.test", "https://example.test"])


def snapshot():
    return WebSnapshot(target=Target(type="web", locator="http://example.test/"), pages=[
        WebPageSnapshot(url="http://example.test/", status_code=200, content_type="text/html",
                        headers={"server": "test"},
                        html='<html><a href="/admin">a</a><form action="/login" method="post">'
                             '<input name="user"><input name="pass"></form>'
                             '<a href="https://external.test/x">x</a></html>'),
        WebPageSnapshot(url="https://example.test/api", status_code=200,
                        content_type="application/json", headers={}, html="{}"),
        WebPageSnapshot(url="https://evil.test/", status_code=200, content_type="text/html",
                        headers={}, html="<html></html>"),
    ])


def seed(session):
    project = Project(id=uuid4(), name="web")
    session.add(project)
    session.flush()
    scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="web")
    session.add(scan)
    session.flush()
    return project, scan


def test_offline_analysis_persists_findings_endpoints_and_report(session, tmp_path):
    audit = Recorder()
    service = WebScanService(audit, evidence_store=EvidenceStore(tmp_path / "evidence"))
    with session.begin():
        project, scan = seed(session)
        result = service.run(WebScanRequest(scan_id=str(scan.id), project_id=str(project.id),
                                            actor="tester", target=Target(type="web", locator="http://example.test/"),
                                            scope=scope(), snapshot=snapshot(), scan_uuid=scan.id),
                             session=session, report_format="json")
        assert result.analysis.pages_analyzed == 1
        assert result.analysis.pages_skipped == 2
        assert result.analysis.out_of_scope == 2
        assert len(result.analysis.groups) == 6
        assert len(result.analysis.endpoints) == 2
        assert result.stored is not None and len(result.stored.stored) == 6
        assert result.evidence_stored == 6
        payload = json.loads(result.report.content)
        assert payload["schema_version"] == 7
        assert payload["evidence_snapshot"] == "available"
        assert len(payload["groups"]) == 6
        assert any("未发送任何 HTTP 请求" in item for item in payload["limitations"])
    assert session.scalar(select(func.count()).select_from(Finding)) == 6
    assert session.scalar(select(func.count()).select_from(Evidence)) == 6
    assert session.scalar(select(func.count()).select_from(WebEndpoint)) == 2
    assert {row.source_url for row in session.scalars(select(WebEndpoint))} == {"http://example.test/"}
    statuses = [item["status"] for item in audit.events if item["tool_name"] == "web.scan"]
    assert statuses == ["requested", "started", "pending_commit"]


def test_scope_denied_page_is_not_analyzed(session, tmp_path):
    service = WebScanService(Recorder(), evidence_store=EvidenceStore(tmp_path / "evidence"))
    limited = WebSnapshot(target=Target(type="web", locator="http://example.test/"), pages=[
        WebPageSnapshot(url="https://evil.test/", status_code=200, content_type="text/html",
                        headers={}, html="<html></html>")])
    with session.begin():
        project, scan = seed(session)
        result = service.run(WebScanRequest(scan_id=str(scan.id), project_id=str(project.id),
                                            actor="tester", target=Target(type="web", locator="http://example.test/"),
                                            scope=scope(), snapshot=limited, scan_uuid=scan.id),
                             session=session)
    assert result.analysis.pages_analyzed == 0
    assert result.analysis.out_of_scope == 1
    assert result.analysis.groups == []
    assert any("超出授权范围" in item for item in result.analysis.coverage_limitations)


def test_metadata_evidence_withholds_secrets_from_headers_and_query():
    from vulnmind.analysis.web_service import _metadata_bytes
    page = WebPageSnapshot(url="https://example.test/?token=secret-query", status_code=200,
                           content_type="text/html", headers={"Set-Cookie": "sid=secret-cookie",
                           "X-Other": "secret-header"})
    metadata = _metadata_bytes(page).decode("utf-8")
    assert all(secret not in metadata for secret in ("secret-query", "secret-cookie", "secret-header"))
    assert "set-cookie" in metadata and "withheld" in metadata


def test_evidence_locators_withhold_query_but_preserve_finding_identity(session, tmp_path):
    service = WebScanService(Recorder(), evidence_store=EvidenceStore(tmp_path / "evidence"))
    url = "http://example.test/?token=synthetic-secret"
    snapshot = WebSnapshot(target=Target(type="web", locator="http://example.test/"), pages=[
        WebPageSnapshot(url=url, status_code=200, content_type="text/html")])
    with session.begin():
        project, scan = seed(session)
        result = service.run(WebScanRequest(scan_id=str(scan.id), project_id=str(project.id),
                             actor="tester", target=snapshot.target, scope=scope(), snapshot=snapshot,
                             scan_uuid=scan.id), session=session)
        assert result.analysis.evidence
        assert all(item.locator == "http://example.test/" for item in result.analysis.evidence)
        assert all(item.target_id == url for item in result.analysis.findings)
        assert all(row.locator == "http://example.test/" for row in session.scalars(select(Evidence)))


def test_duplicate_endpoints_preserve_distinct_form_parameters(session):
    from vulnmind.agents.form_candidates import form_candidate_urls
    from vulnmind.analysis.validation import plan_probes
    from vulnmind.persistence.repositories import WebEndpointRepository
    service = WebScanService(Recorder())
    snapshot = WebSnapshot(target=Target(type="web", locator="http://example.test/"), pages=[
        WebPageSnapshot(url="http://example.test/", status_code=200, content_type="text/html",
                        html='<a href="/search">a</a><form action="/search"><input name="q"></form>'
                             '<form action="/search"><input name="page"></form>')])
    with session.begin():
        project, scan = seed(session)
        result = service.run(WebScanRequest(scan_id=str(scan.id), project_id=str(project.id),
                             actor="tester", target=snapshot.target, scope=scope(), snapshot=snapshot,
                             scan_uuid=scan.id), session=session)
        assert len(result.analysis.endpoints) == 1
        assert result.analysis.endpoints[0]["parameters"] == ["q", "page"]
        assert any("验证计划仅生成空值占位候选" in item for item in result.analysis.coverage_limitations)
        assert session.scalar(select(WebEndpoint)).parameters == ["q", "page"]
        urls, omitted = form_candidate_urls(WebEndpointRepository(session).list_for_scan(scan.id))
        assert omitted == 0
        assert {probe.parameter for probe in plan_probes(urls)} == {"q", "page"}


def test_combined_form_parameter_limit_is_reported(session):
    service = WebScanService(Recorder())
    fields = lambda start: "".join(f'<input name="p{i}">' for i in range(start, start + 200))
    snapshot = WebSnapshot(target=Target(type="web", locator="http://example.test/"), pages=[
        WebPageSnapshot(url="http://example.test/", status_code=200, content_type="text/html",
                        html='<form action="/search">' + fields(0) + '</form>'),
        WebPageSnapshot(url="http://example.test/other", status_code=200, content_type="text/html",
                        html='<form action="/search">' + fields(200) + '</form>')])
    with session.begin():
        project, scan = seed(session)
        result = service.run(WebScanRequest(scan_id=str(scan.id), project_id=str(project.id),
                             actor="tester", target=snapshot.target, scope=scope(), snapshot=snapshot,
                             scan_uuid=scan.id), session=session)
        assert len(result.analysis.endpoints[0]["parameters"]) == 256
        assert result.analysis.truncated
        assert any("清单不完整" in item for item in result.analysis.coverage_limitations)


def test_validation_requests_are_queued_once(session, tmp_path):
    from vulnmind.security.approvals import ApprovalService

    approvals = ApprovalService(session)
    service = WebScanService(Recorder(), approvals=approvals)
    request = WebScanRequest(scan_id="pending", project_id="pending", actor="tester",
                             target=Target(type="web", locator="http://example.test/"),
                             scope=scope(), snapshot=snapshot())
    with session.begin():
        project, scan = seed(session)
        bound = request.model_copy(update={"scan_id": str(scan.id), "project_id": str(project.id),
                                           "scan_uuid": scan.id})
        first = service.run(bound, session=session)
        assert first.validation_requests == 6
        second = service.run(bound, session=session)
        assert second.validation_requests == 0
        assert len(approvals.list_pending(scan.id)) == 6


def test_wrong_scan_identity_is_rejected(session, tmp_path):
    service = WebScanService(Recorder())
    with pytest.raises(ValueError):
        with session.begin():
            project, scan = seed(session)
            service.run(WebScanRequest(scan_id=str(uuid4()), project_id=str(project.id),
                                       actor="tester", target=Target(type="web", locator="http://example.test/"),
                                       scope=scope(), snapshot=snapshot(), scan_uuid=scan.id),
                        session=session)


def test_agent_review_is_advisory(session, tmp_path):
    from vulnmind.agents.model import ModelResponse, ModelUsage
    from vulnmind.agents.runtime import AgentRuntime
    from vulnmind.findings import FindingCandidate

    fingerprint = FindingCandidate(
        title="缺少 Content-Security-Policy", vulnerability_type="missing_content_security_policy",
        target_id="http://example.test/", location="http://example.test/",
        source_tool="builtin.passive_checks", status="unverified").fingerprint()

    class FakeModel:
        def complete(self, request):
            return ModelResponse(text=json.dumps({"summary": "reviewed", "items": [
                {"fingerprint": fingerprint, "verdict": "confirmed",
                 "rationale": "header is absent"}]}), usage=ModelUsage(input_tokens=10, output_tokens=5))

    service = WebScanService(Recorder(), agent_runtime=AgentRuntime(FakeModel(), Recorder()))
    with session.begin():
        project, scan = seed(session)
        result = service.run(WebScanRequest(scan_id=str(scan.id), project_id=str(project.id),
                                            actor="tester", target=Target(type="web", locator="http://example.test/"),
                                            scope=scope(), snapshot=snapshot(), scan_uuid=scan.id),
                             session=session, report_format="json")
    assert result.agent_review is not None and result.agent_review.status == "completed"
    assert result.agent_review.items[0].verdict == "likely"
    payload = json.loads(result.report.content)
    assert payload["agent_review"]["interpretation"] == "advisory_model_review_not_verification"
    assert payload["groups"][0]["statuses"] == ["unverified"]
