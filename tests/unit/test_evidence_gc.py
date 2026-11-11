"""Evidence GC tests: only old, hash-valid, unreferenced files are removed."""
import os
import time
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from vulnmind.evidence.gc import EvidenceGcError, referenced_uris, scan_store
from vulnmind.evidence.store import EvidenceStore
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Evidence, Finding, Project, Scan
from vulnmind.persistence.unit_of_work import transaction


@pytest.fixture
def factory(tmp_path):
    engine = create_engine("sqlite://")
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, _):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def make_evidence(factory, uri: str, sha: str) -> None:
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="gc")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="analysis")
        session.add(scan)
        session.flush()
        finding = Finding(id=uuid4(), scan_id=scan.id, fingerprint="f" * 64, title="x",
                          vuln_type="secret", status="unverified")
        session.add(finding)
        session.flush()
        session.add(Evidence(id=uuid4(), finding_id=finding.id, evidence_type="text",
                             locator="x", content_ref=uri, hash=sha))


def test_gc_reports_and_removes_only_old_orphans(factory, tmp_path):
    store = EvidenceStore(tmp_path / "store")
    kept = store.put(b"referenced evidence")
    make_evidence(factory, kept.uri, kept.sha256)
    old = store.put(b"orphaned evidence")
    young = store.put(b"young orphan")
    old_path = tmp_path / "store" / old.uri
    os.utime(old_path, (time.time() - 2 * 86400, time.time() - 2 * 86400))

    with transaction(factory) as session:
        referenced = referenced_uris(session)
    assert referenced == {kept.uri}

    dry = scan_store(store.root, referenced, grace_seconds=86400, dry_run=True)
    assert (dry.orphans, dry.deleted, dry.kept_young, dry.referenced) == (1, 0, 1, 1)
    assert old_path.exists() and (tmp_path / "store" / young.uri).exists()

    with pytest.raises(EvidenceGcError, match="deletion is disabled"):
        scan_store(store.root, referenced, grace_seconds=86400, dry_run=False)
    assert old_path.exists()
    assert (tmp_path / "store" / kept.uri).exists()
    assert (tmp_path / "store" / young.uri).exists()


def test_gc_never_deletes_hash_mismatches_or_links(factory, tmp_path):
    store = EvidenceStore(tmp_path / "store")
    ref = store.put(b"orphan")
    path = tmp_path / "store" / ref.uri
    path.write_bytes(b"tampered")
    os.utime(path, (time.time() - 3 * 86400, time.time() - 3 * 86400))

    report = scan_store(store.root, set(), grace_seconds=0, dry_run=True)
    assert report.unverified == 1 and report.deleted == 0
    assert path.exists()


def test_gc_validates_the_root_and_grace(factory, tmp_path):
    with pytest.raises(EvidenceGcError, match="not a directory"):
        scan_store(tmp_path / "missing", set(), grace_seconds=0, dry_run=True)
    store = EvidenceStore(tmp_path / "store")
    with pytest.raises(ValueError, match="non-negative"):
        scan_store(store.root, set(), grace_seconds=-1, dry_run=True)
