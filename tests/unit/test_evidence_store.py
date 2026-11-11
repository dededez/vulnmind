"""Evidence store and evidence repository tests."""
from uuid import uuid4
import hashlib
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from vulnmind.evidence.store import EvidenceError, EvidenceStore
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Evidence, Finding, Project, Scan
from vulnmind.persistence.repositories import EvidenceRepository
from vulnmind.persistence.unit_of_work import transaction


@pytest.fixture
def store(tmp_path):
    return EvidenceStore(tmp_path / "evidence", max_bytes=1000)


def test_content_is_deduplicated_by_hash(store):
    first = store.put(b"GET /api?id=1 HTTP/1.1\n", evidence_type="http")
    second = store.put(b"GET /api?id=1 HTTP/1.1\n", evidence_type="http")
    assert first == second
    assert first.uri.endswith(".http")
    assert store.read(first.uri) == b"GET /api?id=1 HTTP/1.1\n"
    assert len(list(store.root.rglob("*.http"))) == 1


def test_different_content_uses_different_entries(store):
    first = store.put(b"one")
    second = store.put(b"two")
    assert first.uri != second.uri
    assert store.verify(first) and store.verify(second)


def test_size_and_type_validation(store):
    with pytest.raises(EvidenceError, match="size limit"):
        store.put(b"x" * 1001)
    with pytest.raises(EvidenceError, match="non-empty"):
        store.put(b"")


def test_reads_are_confined_and_hash_verified(store):
    reference = store.put(b"payload")
    with pytest.raises(EvidenceError, match="relative"):
        store.read("C:\\Windows\\win.ini")
    with pytest.raises(EvidenceError, match="relative"):
        store.read("../outside.bin")
    with pytest.raises(EvidenceError, match="relative"):
        store.read("a/../../outside.bin")
    (store.root / "deadbeef.bin").write_bytes(b"tampered")
    with pytest.raises(EvidenceError, match="hash does not match"):
        store.read("deadbeef.bin")
    assert store.verify(reference) is True


def test_missing_evidence_is_reported(store):
    with pytest.raises(EvidenceError, match="missing"):
        store.read("ab/abcdef.bin")


def test_verify_compares_reference_hash_not_only_filename(store):
    reference = store.put(b"payload")
    forged = reference.model_copy(update={"sha256": "0" * 64})
    assert store.verify(reference) is True
    assert store.verify(forged) is False


def test_read_is_bounded_and_existing_corruption_is_not_overwritten(store):
    payload = b"x" * 1001
    digest = hashlib.sha256(payload).hexdigest()
    oversized = store.root / f"{digest}.bin"
    oversized.write_bytes(payload)
    with pytest.raises(EvidenceError, match="size limit"):
        store.read(oversized.name)
    original = store.put(b"valid")
    path = store.root / original.uri
    path.write_bytes(b"tampered")
    with pytest.raises(EvidenceError, match="hash does not match"):
        store.put(b"valid")
    assert path.read_bytes() == b"tampered"


def test_put_rejects_existing_directory_link(store, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    digest = hashlib.sha256(b"payload").hexdigest()
    link = store.root / digest[:2]
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")
    with pytest.raises(EvidenceError, match="link"):
        store.put(b"payload")
    assert not list(outside.iterdir())


def test_put_denies_a_detected_junction(store, monkeypatch):
    prefix = hashlib.sha256(b"payload").hexdigest()[:2]
    original = getattr(Path, "is_junction", lambda path: False)
    monkeypatch.setattr(Path, "is_junction", lambda path: path.name == prefix or original(path), raising=False)
    with pytest.raises(EvidenceError, match="link"):
        store.put(b"payload")
    assert not list((store.root / prefix).iterdir())


@pytest.fixture
def factory():
    engine = create_engine("sqlite://")
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def test_repository_links_evidence_to_a_finding(factory, store):
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="evidence")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
        session.add(scan)
        session.flush()
        finding = Finding(id=uuid4(), scan_id=scan.id, fingerprint="f" * 64, title="t", vuln_type="x",
                          status="unverified")
        session.add(finding)
        session.flush()
        reference = store.put(b"proof", evidence_type="text")
        row = EvidenceRepository(session).create(finding.id, evidence_type="text", locator="a.py:1",
                                                 content_ref=reference.uri, hash=reference.sha256)
        finding_id = finding.id
        assert row.hash == reference.sha256
    with transaction(factory) as session:
        rows = EvidenceRepository(session).list_for_finding(finding_id)
        assert [item.content_ref for item in rows] == [reference.uri]
        assert session.scalar(select(Evidence)).evidence_type == "text"
        with pytest.raises(ValueError, match="lowercase SHA-256"):
            EvidenceRepository(session).create(finding_id, evidence_type="text", locator="a.py:1",
                                               content_ref="x", hash="XYZ")
        with pytest.raises(ValueError, match="locator"):
            EvidenceRepository(session).create(finding_id, evidence_type="text", locator=" ",
                                               content_ref="x")


def test_evidence_reference_hash_is_checked_before_following_link(tmp_path):
    store = EvidenceStore(tmp_path / "evidence")
    other = store.put(b"different")
    alias = store.root / ("f" * 64 + ".text")
    try:
        alias.symlink_to(store.root / other.uri)
    except OSError:
        pytest.skip("creating symbolic links is unavailable")
    with pytest.raises(EvidenceError, match="hash does not match"):
        store.read(alias.name)
