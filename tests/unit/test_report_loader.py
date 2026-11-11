"""Report loading tests: database index, stored body, missing-report behaviour."""
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Finding, Project, Report, Scan
from vulnmind.persistence.repositories import ReportRepository
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.reports.loader import load_report
from vulnmind.reports.store import ReportStore, ReportStoreError


@pytest.fixture
def factory():
    engine = create_engine("sqlite://")
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def seed(factory, *, with_report=True, with_finding=True):
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="loader")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="analysis")
        session.add(scan)
        session.flush()
        if with_finding:
            session.add(Finding(id=uuid4(), scan_id=scan.id, fingerprint="c" * 64, title="t",
                                vuln_type="secret", status="unverified"))
        scan_id = scan.id
        if with_report:
            ReportRepository(session).create(scan_id, format="markdown", storage_uri="pending")
    return scan_id


def test_loads_the_latest_report_and_counts_findings(factory, tmp_path):
    store = ReportStore(tmp_path / "reports")
    scan_id = seed(factory)
    reference = store.put("# report body\n", format="markdown")
    with transaction(factory) as session:
        session.query(Report).filter(Report.scan_id == scan_id).update({Report.storage_uri: reference.uri})
    with transaction(factory) as session:
        loaded = load_report(session, store, scan_id)
        assert loaded.content == "# report body\n"
        assert loaded.format == "markdown" and loaded.findings == 1
        assert loaded.scan_status == "finished"


def test_scan_without_a_report_returns_no_content(factory, tmp_path):
    store = ReportStore(tmp_path / "reports")
    scan_id = seed(factory, with_report=False)
    with transaction(factory) as session:
        loaded = load_report(session, store, scan_id)
        assert loaded.content is None and loaded.format is None and loaded.findings == 1


def test_missing_scan_and_store_are_rejected(factory, tmp_path):
    store = ReportStore(tmp_path / "reports")
    with transaction(factory) as session:
        with pytest.raises(ValueError, match="scan is not stored"):
            load_report(session, store, uuid4())
        scan_id = seed(factory, with_report=False)
        with pytest.raises(ValueError, match="report store"):
            load_report(session, None, scan_id)


def test_tampered_report_fails_closed(factory, tmp_path):
    store = ReportStore(tmp_path / "reports")
    scan_id = seed(factory)
    reference = store.put("# body\n", format="markdown")
    with transaction(factory) as session:
        session.query(Report).filter(Report.scan_id == scan_id).update({Report.storage_uri: reference.uri})
    (store.root / reference.uri).write_text("tampered", encoding="utf-8")
    with transaction(factory) as session:
        with pytest.raises(ReportStoreError, match="hash does not match"):
            load_report(session, store, scan_id)
