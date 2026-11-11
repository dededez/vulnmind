"""Repository scan service tests: end-to-end analysis, triage, persistence, report."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from vulnmind.analysis.service import RepositoryScanRequest, RepositoryScanService
from vulnmind.findings import FindingCandidate
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import AuditEvent, Finding, Project, Scan
from vulnmind.persistence.audit import DatabaseAuditSink
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import ScopeDenied


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


def authorization(root, *, denied=()):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)], denied_repository_roots=list(denied))


def analyzer(content):
    if "password =" in content.content:
        return [FindingCandidate(title="Hardcoded password", vulnerability_type="secret",
                                 target_id="x", location=f"{content.path}:1", source_tool="stub",
                                 severity="high")]
    return []


def build_repo(tmp_path):
    (tmp_path / "settings.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    return tmp_path


def request_for(tmp_path, **overrides):
    payload = {"scan_id": "scan-1", "project_id": "project-1", "actor": "tester",
               "target": Target(type="repository", locator=str(tmp_path)),
               "scope": authorization(tmp_path)}
    payload.update(overrides)
    return RepositoryScanRequest(**payload)


@pytest.fixture
def factory():
    engine = create_engine("sqlite://")
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def seed_scan(factory):
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="service")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
        session.add(scan)
        session.flush()
        return scan.id, project.id


def test_service_analyzes_and_reports(tmp_path):
    build_repo(tmp_path)
    recorder = Recorder()
    result = RepositoryScanService(recorder, [analyzer]).run(request_for(tmp_path))
    assert result.analysis.files_examined == 2
    assert len(result.analysis.findings) == 1
    assert result.decisions[0].severity == "high"
    assert "Hardcoded password" in result.report.content
    assert "未执行真实扫描" not in result.report.content
    assert recorder.events[0]["status"] == "requested"
    assert recorder.events[1]["status"] == "started"
    assert recorder.events[-1]["status"] == "succeeded"
    assert any(event["tool_name"] == "repo.read_file" for event in recorder.events)
    assert result.stored is None


def test_service_persists_when_given_a_session(tmp_path, factory):
    build_repo(tmp_path)
    scan_id, project_id = seed_scan(factory)
    recorder = Recorder()
    with transaction(factory) as session:
        result = RepositoryScanService(recorder, [analyzer]).run(
            request_for(tmp_path, scan_uuid=scan_id, scan_id=str(scan_id), project_id=str(project_id)), session=session)
        assert result.stored is not None and len(result.stored.stored) == 1
        assert recorder.events[-1]["status"] == "pending_commit"
    with transaction(factory) as session:
        row = session.scalar(select(Finding))
        assert row.scan_id == scan_id and row.severity == "high"


def test_report_links_only_persisted_evidence_for_its_scan(tmp_path, factory):
    import json
    from vulnmind.analysis.repository import AnnotatedFinding, EvidencePayload
    from vulnmind.evidence.store import EvidenceStore
    from vulnmind.persistence.models import Evidence

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("sample", encoding="utf-8")
    scan_id, project_id = seed_scan(factory)
    other_scan, other_project = seed_scan(factory)

    def with_evidence(content):
        finding = FindingCandidate(title="lead", vulnerability_type="secret", target_id="x",
                                   location="app.py:1", source_tool="fixture",
                                   evidence_refs=["source-claim"])
        return [AnnotatedFinding(finding=finding, evidence=[EvidencePayload(content=b"example")])]

    store = EvidenceStore(tmp_path / "evidence")
    service = RepositoryScanService(Recorder(), [with_evidence], evidence_store=store)
    with transaction(factory) as session:
        first = service.run(request_for(repo, scan_uuid=scan_id, scan_id=str(scan_id), project_id=str(project_id)),
                            session=session, report_format="json")
        second = service.run(request_for(repo, scan_uuid=other_scan, scan_id=str(other_scan),
                                         project_id=str(other_project)), session=session, report_format="json")
        evidence_ids = {str(row.id) for row in session.scalars(select(Evidence))}
        first_group = json.loads(first.report.content)["groups"][0]
        second_group = json.loads(second.report.content)["groups"][0]
        first_ids, second_ids = set(first_group["stored_evidence_ids"]), set(second_group["stored_evidence_ids"])
        assert len(first_ids) == len(second_ids) == 1
        assert first_ids.isdisjoint(second_ids) and first_ids | second_ids == evidence_ids
        assert first_group["evidence_refs"] == ["source-claim"]
        assert b"example" not in first.report.content.encode()


def test_report_marks_evidence_snapshot_unavailable_without_session(tmp_path):
    import json
    build_repo(tmp_path)
    result = RepositoryScanService(Recorder(), [analyzer]).run(request_for(tmp_path), report_format="json")
    payload = json.loads(result.report.content)
    assert payload["evidence_snapshot"] == "unavailable"
    assert payload["groups"][0]["stored_evidence_ids"] == []


def test_report_flags_truncated_database_evidence_snapshot(tmp_path, factory, monkeypatch):
    import json
    from vulnmind.analysis.repository import AnnotatedFinding, EvidencePayload
    from vulnmind.evidence.store import EvidenceStore
    import vulnmind.analysis.service as service_module

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("sample", encoding="utf-8")
    scan_id, project_id = seed_scan(factory)
    monkeypatch.setattr(service_module, "MAX_REPORT_EVIDENCE_RECORDS", 1)

    def with_evidence(content):
        return [AnnotatedFinding(finding=FindingCandidate(title="lead", vulnerability_type="secret",
                    target_id="x", location="app.py:1", source_tool="fixture"),
                evidence=[EvidencePayload(content=b"first"), EvidencePayload(content=b"second")])]

    with transaction(factory) as session:
        result = RepositoryScanService(Recorder(), [with_evidence], evidence_store=EvidenceStore(tmp_path / "evidence")).run(
            request_for(repo, scan_uuid=scan_id, scan_id=str(scan_id), project_id=str(project_id)),
            session=session, report_format="json")
        payload = json.loads(result.report.content)
        assert result.evidence_stored == 2
        assert payload["evidence_snapshot"] == "available" and payload["evidence_snapshot_truncated"] is True
        assert len(payload["groups"][0]["stored_evidence_ids"]) == 1


def test_service_requires_scan_uuid_for_persistence(tmp_path, factory):
    build_repo(tmp_path)
    with transaction(factory) as session, pytest.raises(ValueError, match="scan UUID"):
        RepositoryScanService(Recorder(), [analyzer]).run(request_for(tmp_path), session=session)


def test_service_rejects_approval_service_using_a_different_transaction(tmp_path, factory):
    from vulnmind.security.approvals import ApprovalService

    build_repo(tmp_path)
    scan_id, project_id = seed_scan(factory)
    recorder = Recorder()
    with factory() as scan_session, factory() as approval_session:
        service = RepositoryScanService(recorder, [analyzer], approvals=ApprovalService(approval_session))
        with pytest.raises(ValueError, match="approval service must use the scan session"):
            service.run(request_for(tmp_path, scan_uuid=scan_id, scan_id=str(scan_id), project_id=str(project_id)), session=scan_session)
    assert recorder.events == []


@pytest.mark.parametrize("identity", ["scan", "project", "missing"])
def test_service_rejects_inconsistent_persisted_scan_identity(tmp_path, factory, identity):
    build_repo(tmp_path)
    scan_id, project_id = seed_scan(factory)
    request = request_for(tmp_path, scan_uuid=uuid4() if identity == "missing" else scan_id,
                          scan_id=str(uuid4() if identity == "scan" else scan_id),
                          project_id=str(uuid4() if identity == "project" else project_id))
    recorder = Recorder()
    with transaction(factory) as session:
        with pytest.raises(ValueError, match="identities"):
            RepositoryScanService(recorder, [analyzer]).run(request, session=session)
    with transaction(factory) as session:
        assert session.scalar(select(Finding)) is None
    assert not any(event["tool_name"] == "repo.read_file" for event in recorder.events)


def test_service_does_not_report_commit_success_when_caller_rolls_back(tmp_path, factory):
    build_repo(tmp_path)
    scan_id, project_id = seed_scan(factory)
    recorder = Recorder()
    with pytest.raises(RuntimeError, match="rollback"):
        with transaction(factory) as session:
            RepositoryScanService(recorder, [analyzer]).run(request_for(tmp_path, scan_uuid=scan_id, scan_id=str(scan_id), project_id=str(project_id)), session=session)
            raise RuntimeError("rollback")
    with transaction(factory) as session:
        assert session.scalar(select(Finding)) is None
    assert recorder.events[-1]["status"] == "pending_commit"
    assert not any(event["tool_name"] == "repository.scan" and event["status"] == "succeeded" for event in recorder.events)


def test_failed_report_generation_rolls_back_scan_output_even_if_caller_commits(tmp_path, factory):
    build_repo(tmp_path)
    scan_id, project_id = seed_scan(factory)
    recorder = Recorder()
    with transaction(factory) as session:
        with pytest.raises(ValueError):
            RepositoryScanService(recorder, [analyzer]).run(
                request_for(tmp_path, scan_uuid=scan_id, scan_id=str(scan_id), project_id=str(project_id)), session=session, report_format="invalid")
    with transaction(factory) as session:
        assert session.scalar(select(Finding)) is None
    assert recorder.events[-1]["status"] == "failed"


def test_clean_outer_transaction_rolls_back_successful_direct_service(tmp_path, factory):
    build_repo(tmp_path)
    scan_id, project_id = seed_scan(factory)
    with pytest.raises(RuntimeError, match="rollback"):
        with transaction(factory) as session:
            RepositoryScanService(Recorder(), [analyzer]).run(
                request_for(tmp_path, scan_uuid=scan_id, scan_id=str(scan_id), project_id=str(project_id)), session=session)
            raise RuntimeError("rollback")
    with transaction(factory) as session:
        assert session.scalar(select(Finding)) is None


def test_final_audit_failure_rolls_back_outputs_if_caller_commits(tmp_path, factory):
    class FailingAudit(Recorder):
        def record(self, event):
            if event["tool_name"] == "repository.scan" and event["status"] == "pending_commit":
                raise RuntimeError("audit unavailable")
            super().record(event)

    build_repo(tmp_path)
    scan_id, project_id = seed_scan(factory)
    with transaction(factory) as session:
        with pytest.raises(RuntimeError, match="audit unavailable"):
            RepositoryScanService(FailingAudit(), [analyzer]).run(
                request_for(tmp_path, scan_uuid=scan_id, scan_id=str(scan_id), project_id=str(project_id)), session=session)
    with transaction(factory) as session:
        assert session.scalar(select(Finding)) is None


def test_service_refuses_out_of_scope_target(tmp_path):
    build_repo(tmp_path)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    with pytest.raises(ScopeDenied):
        RepositoryScanService(Recorder(), [analyzer]).run(
            request_for(tmp_path, scope=authorization(allowed)))


def test_service_requires_an_analyzer():
    with pytest.raises(ValueError, match="analyser"):
        RepositoryScanService(Recorder(), [])


def test_service_reports_json(tmp_path):
    build_repo(tmp_path)
    result = RepositoryScanService(Recorder(), [analyzer]).run(request_for(tmp_path), report_format="json")
    import json
    payload = json.loads(result.report.content)
    assert payload["mode"] == "analysis" and payload["not_scanned"] is False
    assert payload["groups"][0]["severities"] == ["high"]


def test_service_audit_uses_valid_ids_and_records_results(tmp_path):
    build_repo(tmp_path)
    engine = create_engine("sqlite://")
    AuditEvent.__table__.create(engine)
    result = RepositoryScanService(DatabaseAuditSink(engine), [analyzer]).run(request_for(tmp_path))
    assert result.analysis.files_examined == 2
    with engine.connect() as connection:
        rows = connection.execute(select(AuditEvent.__table__)).mappings().all()
    scan_events = [row for row in rows if row["tool_name"] == "repository.scan"]
    assert [row["status"] for row in scan_events] == ["requested", "started", "succeeded"]
    assert len({row["call_id"] for row in scan_events}) == 1


def test_service_audits_failure_without_exception_details(tmp_path):
    build_repo(tmp_path)
    def failing(content):
        raise RuntimeError("private error details")
    recorder = Recorder()
    with pytest.raises(RuntimeError):
        RepositoryScanService(recorder, [failing]).run(request_for(tmp_path))
    assert recorder.events[-1]["tool_name"] == "repository.scan"
    assert recorder.events[-1]["status"] == "failed"
    assert "private error details" not in str(recorder.events)


def test_service_scope_denial_is_recorded_before_reading(tmp_path):
    build_repo(tmp_path)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    engine = create_engine("sqlite://")
    AuditEvent.__table__.create(engine)
    with pytest.raises(ScopeDenied):
        RepositoryScanService(DatabaseAuditSink(engine), [analyzer]).run(request_for(tmp_path, scope=authorization(allowed)))
    with engine.connect() as connection:
        rows = connection.execute(select(AuditEvent.__table__)).mappings().all()
    assert [row["status"] for row in rows] == ["requested", "denied"]
    assert all(row["tool_name"] == "repository.scan" for row in rows)
