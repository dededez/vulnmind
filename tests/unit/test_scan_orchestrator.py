"""Orchestrator and report-store tests (SQLite, no external services)."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from vulnmind.analysis.orchestrator import ScanOrchestrator, ScanRunRequest
from vulnmind.findings import FindingCandidate
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Finding, Project, Report, Scan
from vulnmind.persistence.repositories import ProjectRepository
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.reports.store import ReportStore, ReportStoreError
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
    (tmp_path / "config.py").write_text("password = 'x'\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def factory():
    engine = create_engine("sqlite://")
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def seeded(factory):
    with transaction(factory) as session:
        return ProjectRepository(session).create("orchestrator").id


def request_for(project_id, root, **overrides):
    payload = {"project_id": project_id, "actor": "tester",
               "target": Target(type="repository", locator=str(root)),
               "scope": authorization(root)}
    payload.update(overrides)
    return ScanRunRequest(**payload)


def test_successful_scan_finishes_with_a_stored_report(factory, seeded, tmp_path):
    build_repo(tmp_path)
    store = ReportStore(tmp_path / "reports")
    with transaction(factory) as session:
        outcome = ScanOrchestrator(session, Recorder(), [analyzer], store).run(request_for(seeded, tmp_path))
        scan_id = outcome.scan_id
        assert outcome.status == "finished" and outcome.files_examined == 2
        assert outcome.stored.stored and len(outcome.stored.stored) == 1
    with transaction(factory) as session:
        scan = session.get(Scan, scan_id)
        assert scan.status == "finished" and scan.started_at is not None and scan.finished_at is not None
        report = session.scalar(select(Report).where(Report.scan_id == scan_id))
        content = store.read(report.storage_uri)
        assert "Hardcoded password" in content
        assert outcome.report.sha256 in report.storage_uri
        assert session.scalar(select(Finding)) is not None


def test_stored_report_references_actual_evidence_record(factory, seeded, tmp_path):
    import json
    from vulnmind.analysis.repository import AnnotatedFinding, EvidencePayload
    from vulnmind.evidence.store import EvidenceStore
    from vulnmind.persistence.models import Evidence
    from vulnmind.reports.loader import load_report

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("sample", encoding="utf-8")
    report_store = ReportStore(tmp_path / "reports")
    evidence_store = EvidenceStore(tmp_path / "evidence")

    def with_evidence(content):
        return [AnnotatedFinding(finding=FindingCandidate(title="lead", vulnerability_type="secret",
                    target_id="x", location="app.py:1", source_tool="fixture"),
                evidence=[EvidencePayload(content=b"example")])]

    with transaction(factory) as session:
        outcome = ScanOrchestrator(session, Recorder(), [with_evidence], report_store, evidence_store).run(
            request_for(seeded, repo, report_format="json"))
    with transaction(factory) as session:
        loaded = load_report(session, report_store, outcome.scan_id)
        payload = json.loads(loaded.content)
        evidence = session.scalar(select(Evidence))
        assert payload["evidence_snapshot"] == "available"
        assert payload["groups"][0]["stored_evidence_ids"] == [str(evidence.id)]
        assert session.get(Finding, evidence.finding_id).scan_id == outcome.scan_id
        assert evidence_store.read(evidence.content_ref) == b"example"


def test_failed_scope_marks_the_scan_failed_without_a_report(factory, seeded, tmp_path):
    build_repo(tmp_path)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    store = ReportStore(tmp_path / "reports")
    with factory() as session:
        with pytest.raises(ScopeDenied):
            ScanOrchestrator(session, Recorder(), [analyzer], store).run(
                request_for(seeded, tmp_path, scope=authorization(allowed)))
        scan = session.scalar(select(Scan))
        assert scan.status == "failed" and scan.finished_at is not None
        assert session.scalar(select(Report)) is None
        session.rollback()


def test_store_round_trip_and_verification(tmp_path):
    store = ReportStore(tmp_path / "reports")
    reference = store.put("# report\nbody\n", format="markdown")
    assert store.read(reference.uri) == "# report\nbody\n"
    assert reference.uri.endswith(".md") and reference.sha256 in reference.uri
    second = store.put("# report\nbody\n", format="markdown")
    assert second.uri == reference.uri


def test_store_rejects_bad_input_and_tampering(tmp_path):
    store = ReportStore(tmp_path / "reports", max_bytes=10)
    with pytest.raises(ReportStoreError, match="size limit"):
        store.put("x" * 11, format="markdown")
    with pytest.raises(ReportStoreError, match="format"):
        store.put("x", format="pdf")
    with pytest.raises(ReportStoreError, match="empty"):
        store.put("", format="json")
    with pytest.raises(ReportStoreError, match="relative"):
        store.read("../escape.md")
    reference = store.put("ok", format="json")
    (store.root / reference.uri).write_text("tampered", encoding="utf-8")
    with pytest.raises(ReportStoreError, match="hash does not match"):
        store.read(reference.uri)
    with pytest.raises(ReportStoreError, match="hash does not match"):
        store.put("ok", format="json")


def test_failed_late_stage_does_not_commit_partial_scan_outputs(factory, seeded, tmp_path):
    from vulnmind.persistence.models import AgentRun, FindingObservation, ScanTask

    build_repo(tmp_path)
    store = ReportStore(tmp_path / "reports")

    def broken_manifest(_analysis):
        raise RuntimeError("manifest unavailable")

    with transaction(factory) as session:
        with pytest.raises(RuntimeError, match="manifest unavailable"):
            ScanOrchestrator(session, Recorder(), [analyzer], store,
                             manifest_provider=broken_manifest).run(request_for(seeded, tmp_path))
        scan_id = session.scalar(select(Scan.id))
    with transaction(factory) as session:
        assert session.get(Scan, scan_id).status == "failed"
        assert session.scalar(select(ScanTask.status)) == "failed"
        assert session.scalar(select(AgentRun.status)) == "failed"
        assert session.scalar(select(Finding)) is None
        assert session.scalar(select(FindingObservation)) is None
        assert session.scalar(select(Report)) is None
    assert not list(store.root.rglob("*.md"))


def test_database_error_in_savepoint_preserves_outer_failure_record(factory, seeded, tmp_path):
    from sqlalchemy.exc import StatementError
    from vulnmind.persistence.models import ContextManifestRecord

    build_repo(tmp_path)
    store = ReportStore(tmp_path / "reports")
    provider = lambda _analysis: {"selected_refs": [object()], "token_estimate": 1}
    with transaction(factory) as session:
        with pytest.raises(StatementError):
            ScanOrchestrator(session, Recorder(), [analyzer], store,
                             manifest_provider=provider).run(request_for(seeded, tmp_path))
        scan_id = session.scalar(select(Scan.id))
    with transaction(factory) as session:
        assert session.get(Scan, scan_id).status == "failed"
        assert session.scalar(select(Finding)) is None
        assert session.scalar(select(Report)) is None
        assert session.scalar(select(ContextManifestRecord)) is None


def test_outer_rollback_still_removes_successful_scan_database_records(factory, seeded, tmp_path):
    build_repo(tmp_path)
    store = ReportStore(tmp_path / "reports")
    with pytest.raises(RuntimeError, match="outer rollback"):
        with transaction(factory) as session:
            ScanOrchestrator(session, Recorder(), [analyzer], store).run(request_for(seeded, tmp_path))
            raise RuntimeError("outer rollback")
    with transaction(factory) as session:
        assert session.scalar(select(Scan)) is None
        assert session.scalar(select(Finding)) is None
        assert session.scalar(select(Report)) is None


def test_store_read_is_bounded(tmp_path):
    store = ReportStore(tmp_path / "reports")
    reference = store.put("0123456789", format="markdown")
    with pytest.raises(ReportStoreError, match="size limit"):
        store.read(reference.uri, max_bytes=5)
    for invalid in (-2, 0, True):
        with pytest.raises(ReportStoreError, match="positive integer"):
            store.read(reference.uri, max_bytes=invalid)


def test_report_reference_hash_is_checked_before_following_link(tmp_path):
    store = ReportStore(tmp_path / "reports")
    expected = store.put("expected", format="markdown")
    other = store.put("different", format="markdown")
    alias = store.root / ("f" * 64 + ".md")
    try:
        alias.symlink_to(store.root / other.uri)
    except OSError:
        pytest.skip("creating symbolic links is unavailable")
    with pytest.raises(ReportStoreError, match="hash does not match"):
        store.read(alias.name)
    assert store.read(expected.uri) == "expected"


def test_orchestrator_requires_analyzers_and_store(factory, seeded, tmp_path):
    with pytest.raises(ValueError, match="analyser"):
        ScanOrchestrator(factory(), Recorder(), [], ReportStore(tmp_path / "r"))
    with transaction(factory) as session:
        with pytest.raises(ValueError, match="report store"):
            ScanOrchestrator(session, Recorder(), [analyzer], object())
        with pytest.raises(ValueError, match="agent runtime"):
            ScanOrchestrator(session, Recorder(), [analyzer], ReportStore(tmp_path / "r"),
                             agent_runtime=object())


def test_orchestrator_attaches_advisory_agent_review(factory, seeded, tmp_path):
    import json

    from vulnmind.agents.model import ModelResponse, ModelUsage
    from vulnmind.agents.runtime import AgentRuntime

    class Model:
        def complete(self, request):
            return ModelResponse(text=json.dumps({"summary": "metadata reviewed", "items": []}),
                                 usage=ModelUsage(output_tokens=3))

    build_repo(tmp_path)
    store = ReportStore(tmp_path / "reports")
    with transaction(factory) as session:
        outcome = ScanOrchestrator(session, Recorder(), [analyzer], store,
                                   agent_runtime=AgentRuntime(Model(), Recorder())).run(
            request_for(seeded, tmp_path))
        assert outcome.agent_review_status == "completed"
        assert outcome.agent_verdicts == 0
        content = store.read(outcome.report.uri)
    assert "模型复核（建议，未验证）" in content
    assert "metadata reviewed" in content


def test_orchestrator_records_task_run_and_manifest(factory, seeded, tmp_path):
    from vulnmind.persistence.models import AgentRun, ContextManifestRecord, ScanTask

    build_repo(tmp_path)
    store = ReportStore(tmp_path / "reports")
    provider = lambda analysis: {"selected_refs": ["target:" + analysis.target_id, "skill:sqli@1"],
                                 "token_estimate": 128}
    with transaction(factory) as session:
        outcome = ScanOrchestrator(session, Recorder(), [analyzer], store,
                                   manifest_provider=provider).run(request_for(seeded, tmp_path))
        assert outcome.task_id is not None and outcome.run_id is not None
        assert outcome.context_manifest_id is not None
        scan_id = outcome.scan_id
    with transaction(factory) as session:
        task = session.scalar(select(ScanTask).where(ScanTask.scan_id == scan_id))
        assert task.status == "finished" and task.phase == "analysis"
        run = session.scalar(select(AgentRun).where(AgentRun.task_id == task.id))
        assert run.status == "succeeded" and run.agent_name == "repository-analysis"
        manifest = session.scalar(select(ContextManifestRecord).where(ContextManifestRecord.run_id == run.id))
        assert manifest.token_estimate == 128 and manifest.selected_refs[1] == "skill:sqli@1"


def test_failed_scan_marks_task_and_run_failed(factory, seeded, tmp_path):
    from vulnmind.persistence.models import AgentRun, ScanTask

    build_repo(tmp_path)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    store = ReportStore(tmp_path / "reports")
    with factory() as session:
        with pytest.raises(ScopeDenied):
            ScanOrchestrator(session, Recorder(), [analyzer], store).run(
                request_for(seeded, tmp_path, scope=authorization(allowed)))
        task = session.scalar(select(ScanTask))
        run = session.scalar(select(AgentRun))
        assert task.status == "failed" and run.status == "failed"
        session.rollback()
