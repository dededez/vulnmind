"""Evidence ingestion tests: linking snippets to existing findings."""
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from vulnmind.evidence.ingest import EvidenceItem, ingest_evidence
from vulnmind.evidence.store import EvidenceStore
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Evidence, Finding, Project, Scan
from vulnmind.persistence.unit_of_work import transaction


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
    fingerprint = "a" * 64
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="evidence ingest")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
        session.add(scan)
        session.flush()
        finding = Finding(id=uuid4(), scan_id=scan.id, fingerprint=fingerprint, title="Hardcoded password",
                          vuln_type="secret", status="unverified")
        session.add(finding)
        session.flush()
        return scan.id, fingerprint


def test_evidence_is_stored_and_linked(factory, seeded, tmp_path):
    scan_id, fingerprint = seeded
    store = EvidenceStore(tmp_path / "evidence")
    with transaction(factory) as session:
        result = ingest_evidence(session, store, scan_id=scan_id, items=[
            EvidenceItem(fingerprint=fingerprint, content=b"password = 'x'\n", evidence_type="code",
                         locator="config.py:1")])
        assert result.stored == 1 and result.missing_findings == []
    with transaction(factory) as session:
        row = session.scalar(select(Evidence))
        assert row.evidence_type == "code" and row.locator == "config.py:1"
        assert store.read(row.content_ref) == b"password = 'x'\n"
        assert row.hash == (tmp_path / "evidence" / row.content_ref).stem


def test_unknown_fingerprints_are_reported_not_invented(factory, seeded, tmp_path):
    scan_id, fingerprint = seeded
    store = EvidenceStore(tmp_path / "evidence")
    with transaction(factory) as session:
        result = ingest_evidence(session, store, scan_id=scan_id, items=[
            EvidenceItem(fingerprint=fingerprint, content=b"real", locator="a.py:1"),
            EvidenceItem(fingerprint="b" * 64, content=b"orphan", locator="b.py:2")])
        assert result.stored == 1 and result.missing_findings == ["b" * 64]
        assert session.scalar(select(Evidence)).content_ref in result.references


def test_duplicate_content_is_deduplicated_but_rows_remain(factory, seeded, tmp_path):
    scan_id, fingerprint = seeded
    store = EvidenceStore(tmp_path / "evidence")
    with transaction(factory) as session:
        result = ingest_evidence(session, store, scan_id=scan_id, items=[
            EvidenceItem(fingerprint=fingerprint, content=b"same", locator="a.py:1"),
            EvidenceItem(fingerprint=fingerprint, content=b"same", locator="a.py:1")])
        assert result.stored == 2 and len(set(result.references)) == 1
    with transaction(factory) as session:
        assert len(list(session.scalars(select(Evidence)))) == 2


def test_item_validation_and_empty_batches(factory, seeded, tmp_path):
    scan_id, fingerprint = seeded
    store = EvidenceStore(tmp_path / "evidence")
    with transaction(factory) as session:
        assert ingest_evidence(session, store, scan_id=scan_id, items=[]).stored == 0
    with pytest.raises(ValueError):
        EvidenceItem(fingerprint="A" * 64, content=b"x", locator="a.py:1")
    with pytest.raises(ValueError):
        EvidenceItem(fingerprint=fingerprint, content=b"x", locator="a\nb")
    with pytest.raises(ValueError):
        EvidenceItem(fingerprint=fingerprint, content=b"", locator="a.py:1")
    with transaction(factory) as session:
        with pytest.raises(ValueError, match="evidence store"):
            ingest_evidence(session, None, scan_id=scan_id, items=[])
