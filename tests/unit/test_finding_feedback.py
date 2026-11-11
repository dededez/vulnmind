"""Operator feedback persistence: append-only revisions, fail-closed validation."""
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from vulnmind.findings import FindingCandidate
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Finding, Project, Scan
from vulnmind.persistence.repositories import FeedbackRepository


@pytest.fixture
def session(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'feedback.db').as_posix()}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    with Session(engine) as opened:
        yield opened
    engine.dispose()


def seed(session: Session):
    project = Project(id=uuid4(), name="feedback")
    session.add(project)
    session.flush()
    scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="analysis")
    session.add(scan)
    session.flush()
    candidate = FindingCandidate(title="Reflected input", vulnerability_type="xss",
                                 target_id="https://example.test", location="/search?q=1",
                                 source_tool="builtin.reflection")
    finding = Finding(id=uuid4(), scan_id=scan.id, fingerprint=candidate.fingerprint(),
                      title=candidate.title, vuln_type="xss", severity="medium", confidence="0.30",
                      status="unverified",
                      location={"target_id": candidate.target_id, "location": candidate.location})
    session.add(finding)
    session.flush()
    return scan, finding, candidate


def test_records_revisions_and_returns_newest(session):
    scan, finding, candidate = seed(session)
    repository = FeedbackRepository(session)
    first = repository.record(scan.id, candidate.fingerprint(), "false_positive", actor="alice",
                              note=" test endpoint ")
    assert first.revision == 1 and first.verdict == "false_positive" and first.note == "test endpoint"
    second = repository.record(scan.id, candidate.fingerprint(), "needs_more_info", actor="bob")
    assert second.revision == 2 and second.note is None
    latest = repository.latest_for_scan(scan.id)
    assert set(latest) == {candidate.fingerprint()}
    assert latest[candidate.fingerprint()].revision == 2
    assert latest[candidate.fingerprint()].verdict == "needs_more_info"


def test_unknown_verdict_scan_or_finding_is_rejected(session):
    scan, finding, candidate = seed(session)
    repository = FeedbackRepository(session)
    with pytest.raises(ValueError):
        repository.record(scan.id, candidate.fingerprint(), "looks_bad", actor="alice")
    with pytest.raises(ValueError):
        repository.record(uuid4(), candidate.fingerprint(), "confirmed", actor="alice")
    with pytest.raises(ValueError):
        repository.record(scan.id, "0" * 64, "confirmed", actor="alice")


@pytest.mark.parametrize("note", ["x" * 2001, "bad\x00note", "\x1b[31mred"])
def test_note_is_bounded_and_control_characters_rejected(session, note):
    scan, finding, candidate = seed(session)
    with pytest.raises(ValueError):
        FeedbackRepository(session).record(scan.id, candidate.fingerprint(), "confirmed",
                                           actor="alice", note=note)


def test_actor_is_required_and_bounded(session):
    scan, finding, candidate = seed(session)
    with pytest.raises(ValueError):
        FeedbackRepository(session).record(scan.id, candidate.fingerprint(), "confirmed", actor=" ")
    with pytest.raises(ValueError):
        FeedbackRepository(session).record(scan.id, candidate.fingerprint(), "confirmed",
                                           actor="a" * 256)


def test_latest_limit_is_validated(session):
    scan, finding, candidate = seed(session)
    repository = FeedbackRepository(session)
    repository.record(scan.id, candidate.fingerprint(), "accepted_risk", actor="alice")
    with pytest.raises(ValueError):
        repository.latest_for_scan(scan.id, limit=0)
    with pytest.raises(ValueError):
        repository.latest_for_scan(scan.id, limit=1_000_000)
