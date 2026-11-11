"""Analyzer evidence contract: pipeline attachments, service and orchestrator ingest."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from vulnmind.analysis.orchestrator import ScanOrchestrator, ScanRunRequest
from vulnmind.analysis.repository import AnnotatedFinding, EvidencePayload, RepositoryPipeline
from vulnmind.analysis.service import RepositoryScanRequest, RepositoryScanService
from vulnmind.evidence.store import EvidenceStore
from vulnmind.findings import FindingCandidate
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Evidence, Project
from vulnmind.persistence.repositories import ProjectRepository
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.reports.store import ReportStore
from vulnmind.schemas import Authorization, Target
from vulnmind.tools.repo_files import RepositoryReader


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


def authorization(root):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)])


def annotated_analyzer(content):
    if "password =" not in content.content:
        return []
    candidate = FindingCandidate(title="Hardcoded password", vulnerability_type="secret",
                                 target_id="ignored", location=f"{content.path}:1", source_tool="stub",
                                 severity="high")
    return [AnnotatedFinding(finding=candidate, evidence=[
        EvidencePayload(content=content.content.encode("utf-8"), evidence_type="code")])]


def invalid_analyzer(content):
    return ["not a finding"]


def build_repo(tmp_path):
    (tmp_path / "config.py").write_bytes(b"password = 'x'\n")
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


def test_pipeline_records_evidence_with_the_grouped_fingerprint(tmp_path):
    build_repo(tmp_path)
    analysis = RepositoryPipeline(RepositoryReader(Recorder()), [annotated_analyzer]).run(
        scan_id="s", project_id="p", target=Target(type="repository", locator=str(tmp_path)),
        scope=authorization(tmp_path), actor="tester")
    assert len(analysis.evidence) == 1
    attachment = analysis.evidence[0]
    assert attachment.fingerprint == analysis.groups[0].fingerprint
    assert attachment.locator == "config.py:1"
    assert attachment.content == b"password = 'x'\n"
    assert analysis.findings[0].status == "unverified"


def test_pipeline_rejects_unsupported_analyzer_results(tmp_path):
    build_repo(tmp_path)
    with pytest.raises(ValueError, match="unsupported result type"):
        RepositoryPipeline(RepositoryReader(Recorder()), [invalid_analyzer]).run(
            scan_id="s", project_id="p", target=Target(type="repository", locator=str(tmp_path)),
            scope=authorization(tmp_path), actor="tester")


def test_service_stores_evidence_when_a_store_is_configured(factory, tmp_path):
    build_repo(tmp_path)
    store = EvidenceStore(tmp_path / "evidence")
    with transaction(factory) as session:
        project = ProjectRepository(session).create("evidence")
        session.flush()
        scan_id = uuid4()
        # The service needs the scan row because evidence links to findings.
        from vulnmind.persistence.models import Scan
        session.add(Scan(id=scan_id, project_id=project.id, status="running", mode="analysis"))
        session.flush()
        result = RepositoryScanService(Recorder(), [annotated_analyzer], evidence_store=store).run(
            RepositoryScanRequest(scan_id=str(scan_id), project_id=str(project.id), actor="tester",
                                 target=Target(type="repository", locator=str(tmp_path)),
                                 scope=authorization(tmp_path), scan_uuid=scan_id),
            session=session)
        assert result.evidence_stored == 1
    with transaction(factory) as session:
        row = session.scalar(select(Evidence))
        assert store.read(row.content_ref) == b"password = 'x'\n"


def test_service_without_evidence_store_writes_no_rows(factory, tmp_path):
    build_repo(tmp_path)
    with transaction(factory) as session:
        project = ProjectRepository(session).create("no evidence")
        session.flush()
        from vulnmind.persistence.models import Scan
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
        session.add(scan)
        session.flush()
        result = RepositoryScanService(Recorder(), [annotated_analyzer]).run(
            RepositoryScanRequest(scan_id=str(scan.id), project_id=str(project.id), actor="tester",
                                  target=Target(type="repository", locator=str(tmp_path)),
                                  scope=authorization(tmp_path), scan_uuid=scan.id),
            session=session)
        assert result.evidence_stored == 0
    with transaction(factory) as session:
        assert session.scalar(select(Evidence)) is None


def test_orchestrator_wires_evidence_end_to_end(factory, tmp_path):
    build_repo(tmp_path)
    evidence_store = EvidenceStore(tmp_path / "evidence")
    report_store = ReportStore(tmp_path / "reports")
    with transaction(factory) as session:
        project = ProjectRepository(session).create("orchestrated")
        session.flush()
        outcome = ScanOrchestrator(session, Recorder(), [annotated_analyzer], report_store,
                                   evidence_store=evidence_store).run(
            ScanRunRequest(project_id=project.id, actor="tester",
                           target=Target(type="repository", locator=str(tmp_path)),
                           scope=authorization(tmp_path)))
        assert outcome.status == "finished" and outcome.evidence_stored == 1
    with transaction(factory) as session:
        assert len(list(session.scalars(select(Evidence)))) == 1
