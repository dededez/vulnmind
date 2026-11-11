"""Report regeneration from stored findings, observations and operator feedback."""
import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session

from vulnmind.findings import FindingCandidate
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Evidence, Finding, FindingObservation, Project, Report, Scan
from vulnmind.persistence.repositories import FeedbackRepository
from vulnmind.reports.regenerate import ReportRebuildError, ReportRegenerator, rebuild_groups
from vulnmind.reports.store import ReportStore


@pytest.fixture
def session(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'regen.db').as_posix()}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    with Session(engine) as opened:
        yield opened
    engine.dispose()


def seed(session, *, complete=True, with_evidence=False):
    project = Project(id=uuid4(), name="regen")
    session.add(project)
    session.flush()
    scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="analysis")
    session.add(scan)
    session.flush()
    candidate = FindingCandidate(title="Reflected input", vulnerability_type="reflected_input",
                                 target_id="https://example.test", location="/search?q=marker",
                                 source_tool="builtin.reflection", status="unverified",
                                 severity="medium")
    finding = Finding(id=uuid4(), scan_id=scan.id, fingerprint=candidate.fingerprint(),
                      title=candidate.title, vuln_type=candidate.vulnerability_type,
                      severity="medium", confidence="0.30", status="unverified",
                      location={"target_id": candidate.target_id, "location": candidate.location},
                      needs_retriage=False, observation_history_complete=complete,
                      observation_revision=0)
    session.add(finding)
    session.flush()
    claim = {"source_tool": candidate.source_tool, "title": candidate.title,
             "source_status_claim": "unverified", "severity": "medium", "evidence_refs": []}
    serialized = json.dumps(claim, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    session.add(FindingObservation(id=uuid4(), finding_id=finding.id,
                                   observation_hash=hashlib.sha256(serialized.encode()).hexdigest(),
                                   **claim))
    evidence_id = None
    if with_evidence:
        evidence_id = uuid4()
        session.add(Evidence(id=evidence_id, finding_id=finding.id, evidence_type="http_metadata",
                             locator="/search?q=marker", content_ref="ab/" + "a" * 64 + ".json",
                             hash="a" * 64))
    session.flush()
    return scan, finding, candidate, evidence_id


def test_rebuild_returns_the_stored_group(session):
    scan, finding, candidate, _ = seed(session)
    groups = rebuild_groups(session, scan.id)
    assert [group.fingerprint for group in groups] == [candidate.fingerprint()]
    assert groups[0].source_tools == ["builtin.reflection"]


def test_incomplete_history_fails_closed(session):
    scan, finding, candidate, _ = seed(session, complete=False)
    with pytest.raises(ReportRebuildError):
        rebuild_groups(session, scan.id)


def test_regenerate_writes_a_new_report_with_feedback(session, tmp_path):
    scan, finding, candidate, evidence_id = seed(session, with_evidence=True)
    FeedbackRepository(session).record(scan.id, candidate.fingerprint(), "false_positive",
                                       actor="alice", note="test endpoint")
    store = ReportStore(tmp_path / "reports")
    result = ReportRegenerator(session, store).regenerate(scan.id, report_format="json",
                                                          now=datetime(2026, 11, 4, tzinfo=timezone.utc))
    assert result.groups == 1 and result.feedback_applied == 1 and result.evidence_ids == 1
    payload = json.loads(result.report.content)
    assert payload["schema_version"] == 7
    assert payload["feedback"][0]["verdict"] == "false_positive"
    assert payload["open_validation_required"] == 0
    assert payload["groups"][0]["stored_evidence_ids"] == [str(evidence_id)]
    rows = list(session.scalars(select(Report).where(Report.scan_id == scan.id)))
    assert [row.storage_uri for row in rows] == [result.reference.uri]
    assert store.read(result.reference.uri) == result.report.content


def test_regenerate_without_feedback_and_unknown_scan(session, tmp_path):
    scan, finding, candidate, _ = seed(session)
    result = ReportRegenerator(session, ReportStore(tmp_path / "reports")).regenerate(scan.id)
    assert result.feedback_applied == 0
    assert "## 人工复核记录" not in result.report.content
    with pytest.raises(ValueError):
        ReportRegenerator(session, ReportStore(tmp_path / "reports")).regenerate(uuid4())
