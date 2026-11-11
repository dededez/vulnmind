"""Finding persistence tests: one row per fingerprint, no invented evidence."""
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select, update
from sqlalchemy.sql.dml import Insert, Update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from vulnmind.analysis.persistence import FindingWriter
from vulnmind.analysis.repository import RepositoryAnalysis
from vulnmind.findings import FindingCandidate, group_findings
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Evidence, Finding, FindingObservation, Project, Scan
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
def scan_id(factory):
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="analysis")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
        session.add(scan)
        session.flush()
        return scan.id


def candidate(**overrides):
    payload = {"title": "SQL injection", "vulnerability_type": "sqli", "target_id": "t-1",
               "location": "src/app.py:12", "source_tool": "semgrep", "status": "unverified"}
    payload.update(overrides)
    return FindingCandidate(**payload)


def analysis(*groups, target_id="t-1"):
    return RepositoryAnalysis(scan_id="s", project_id="p", target_id=target_id, files_examined=1,
                              files_skipped=0, findings=[c for g in groups for c in g.candidates],
                              groups=list(groups))


def test_one_row_per_fingerprint_and_no_evidence_rows(factory, scan_id):
    group = group_findings([candidate(severity="high", evidence_refs=["evidence:1"])])[0]
    with transaction(factory) as session:
        result = FindingWriter(session).store(scan_id, analysis(group))
        assert len(result.stored) == 1 and result.duplicated == 0
        assert result.evidence_pending == 1
    with transaction(factory) as session:
        row = session.scalar(select(Finding))
        assert row.fingerprint == group.fingerprint and row.vuln_type == "sqli"
        assert row.severity == "high" and row.status == "unverified"
        assert row.location["target_id"] == "t-1" and row.location["source_tools"] == ["semgrep"]
        assert session.scalar(select(Evidence)) is None  # references alone are not evidence


def test_second_store_is_idempotent(factory, scan_id):
    group = group_findings([candidate()])[0]
    with transaction(factory) as session:
        FindingWriter(session).store(scan_id, analysis(group))
    with transaction(factory) as session:
        result = FindingWriter(session).store(scan_id, analysis(group))
        assert result.stored == [] and result.duplicated == 1
        assert result.observations_stored == 0
        assert session.scalar(select(Finding)).needs_retriage is False


def test_new_sources_are_preserved_across_batches_without_inventing_evidence(factory, scan_id):
    first = group_findings([candidate(source_tool="tool-a", severity="low", evidence_refs=["ref:a"])])[0]
    second = group_findings([candidate(source_tool="tool-b", severity="critical", evidence_refs=["ref:b"])])[0]
    with transaction(factory) as session:
        assert FindingWriter(session).store(scan_id, analysis(first)).observations_stored == 1
    with transaction(factory) as session:
        result = FindingWriter(session).store(scan_id, analysis(second))
        assert result.duplicated == 1 and result.observations_stored == 1
    with transaction(factory) as session:
        assert len(list(session.scalars(select(Finding)))) == 1
        finding = session.scalar(select(Finding))
        assert finding.needs_retriage is True
        assert finding.severity == "low"  # stale summary must not be treated as current
        observations = list(session.scalars(select(FindingObservation)))
        assert {row.source_tool for row in observations} == {"tool-a", "tool-b"}
        assert {row.severity for row in observations} == {"low", "critical"}
        assert {ref for row in observations for ref in row.evidence_refs} == {"ref:a", "ref:b"}
        assert session.scalar(select(Evidence)) is None


def test_retriage_rebuilds_summary_without_claiming_validation(factory, scan_id):
    first = group_findings([candidate(source_tool="tool-a", severity="low", evidence_refs=["ref:a"])])[0]
    second = group_findings([candidate(source_tool="tool-b", severity="critical", status="confirmed", evidence_refs=["ref:b"])])[0]
    with transaction(factory) as session:
        finding_id = FindingWriter(session).store(scan_id, analysis(first)).stored[0]
    with transaction(factory) as session:
        FindingWriter(session).store(scan_id, analysis(second))
    with transaction(factory) as session:
        decision = FindingWriter(session).retriage(finding_id)
        assert decision.severity == "critical" and decision.status == "unverified"
        assert decision.requires_validation is True
    with transaction(factory) as session:
        finding = session.get(Finding, finding_id)
        assert finding.needs_retriage is False
        assert finding.severity == "critical"
        assert set(finding.location["source_tools"]) == {"tool-a", "tool-b"}
        assert finding.location["source_tools_revision"] == finding.observation_revision
        assert session.scalar(select(Evidence)) is None
        with pytest.raises(ValueError, match="not marked"):
            FindingWriter(session).retriage(finding_id)


def test_retriage_does_not_clear_legacy_finding_without_observations(factory, scan_id):
    group = group_findings([candidate()])[0]
    with transaction(factory) as session:
        row = Finding(id=uuid4(), scan_id=scan_id, fingerprint=group.fingerprint,
                      title="legacy", vuln_type="sqli", status="unverified",
                      location={"target_id": "t-1", "location": "src/app.py:12"})
        session.add(row)
        session.flush()
        finding_id = row.id
    with transaction(factory) as session:
        with pytest.raises(ValueError, match="history is incomplete"):
            FindingWriter(session).retriage(finding_id)
        assert session.get(Finding, finding_id).needs_retriage is True


def test_new_observation_does_not_make_legacy_history_complete(factory, scan_id):
    group = group_findings([candidate(source_tool="new-tool", severity="critical")])[0]
    with transaction(factory) as session:
        row = Finding(id=uuid4(), scan_id=scan_id, fingerprint=group.fingerprint,
                      title="legacy", vuln_type="sqli", status="unverified", severity="low",
                      location={"target_id": "t-1", "location": "src/app.py:12"})
        session.add(row)
        session.flush()
        finding_id = row.id
    with transaction(factory) as session:
        assert FindingWriter(session).store(scan_id, analysis(group)).observations_stored == 1
    with transaction(factory) as session:
        with pytest.raises(ValueError, match="history is incomplete"):
            FindingWriter(session).retriage(finding_id)
        row = session.get(Finding, finding_id)
        assert row.needs_retriage is True and row.observation_history_complete is False


def test_retriage_detects_revision_change_before_summary_update(factory, scan_id, monkeypatch):
    first = group_findings([candidate(source_tool="a")])[0]
    second = group_findings([candidate(source_tool="b")])[0]
    with transaction(factory) as session:
        finding_id = FindingWriter(session).store(scan_id, analysis(first)).stored[0]
    with transaction(factory) as session:
        FindingWriter(session).store(scan_id, analysis(second))
    with factory() as session:
        original = session.execute
        changed = False
        def race(statement, *args, **kwargs):
            nonlocal changed
            if isinstance(statement, Update) and statement.table.name == "findings" and not changed:
                changed = True
                original(update(Finding).where(Finding.id == finding_id).values(observation_revision=Finding.observation_revision + 1))
            return original(statement, *args, **kwargs)
        monkeypatch.setattr(session, "execute", race)
        with pytest.raises(RuntimeError, match="changed"):
            FindingWriter(session).retriage(finding_id)
        session.rollback()
    with transaction(factory) as session:
        assert session.get(Finding, finding_id).needs_retriage is True


def test_partial_initial_write_cannot_be_committed_as_complete(factory, scan_id, monkeypatch):
    group = group_findings([candidate(source_tool="a"), candidate(source_tool="b")])[0]
    with transaction(factory) as session:
        original = session.execute
        writes = 0
        def fail_second_observation(statement, *args, **kwargs):
            nonlocal writes
            if isinstance(statement, Insert) and statement.table.name == "finding_observations":
                writes += 1
                if writes == 2:
                    raise RuntimeError("simulated storage error")
            return original(statement, *args, **kwargs)
        monkeypatch.setattr(session, "execute", fail_second_observation)
        with pytest.raises(RuntimeError, match="storage error"):
            FindingWriter(session).store(scan_id, analysis(group))
        # Deliberately allow the outer transaction to commit the partial work.
    with transaction(factory) as session:
        row = session.scalar(select(Finding))
        assert row.needs_retriage is True and row.observation_history_complete is False
        assert len(list(session.scalars(select(FindingObservation)))) == 1
        with pytest.raises(ValueError, match="history is incomplete"):
            FindingWriter(session).retriage(row.id)


def test_partial_duplicate_write_invalidates_history_before_new_observations(factory, scan_id, monkeypatch):
    first = group_findings([candidate(source_tool="a")])[0]
    next_batch = group_findings([candidate(source_tool="b"), candidate(source_tool="c")])[0]
    with transaction(factory) as session:
        finding_id = FindingWriter(session).store(scan_id, analysis(first)).stored[0]
    with transaction(factory) as session:
        original = session.execute
        writes = 0
        def fail_second_observation(statement, *args, **kwargs):
            nonlocal writes
            if isinstance(statement, Insert) and statement.table.name == "finding_observations":
                writes += 1
                if writes == 2:
                    raise RuntimeError("simulated storage error")
            return original(statement, *args, **kwargs)
        monkeypatch.setattr(session, "execute", fail_second_observation)
        with pytest.raises(RuntimeError, match="storage error"):
            FindingWriter(session).store(scan_id, analysis(next_batch))
        # Deliberately commit the caught partial failure.
    with transaction(factory) as session:
        row = session.get(Finding, finding_id)
        assert row.needs_retriage is True and row.observation_history_complete is False
        assert len(list(session.scalars(select(FindingObservation)))) == 2
        with pytest.raises(ValueError, match="history is incomplete"):
            FindingWriter(session).retriage(finding_id)


def test_database_rejects_duplicate_fingerprint_for_same_scan(factory, scan_id):
    group = group_findings([candidate()])[0]
    with transaction(factory) as session:
        FindingWriter(session).store(scan_id, analysis(group))
    with factory() as session:
        session.add(Finding(id=uuid4(), scan_id=scan_id, fingerprint=group.fingerprint,
                            title="duplicate", vuln_type="sqli", status="unverified"))
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()
    with transaction(factory) as session:
        assert len(list(session.scalars(select(Finding)))) == 1


def test_disagreement_stays_unverified_and_severity_is_the_most_severe(factory, scan_id):
    group = group_findings([
        candidate(severity="low", status="unverified"),
        candidate(severity="critical", status="confirmed", evidence_refs=["e:1"]),
    ])[0]
    with transaction(factory) as session:
        FindingWriter(session).store(scan_id, analysis(group))
    with transaction(factory) as session:
        row = session.scalar(select(Finding))
        assert row.status == "unverified" and row.severity == "critical"
        # findings.confidence is a text column in migration 0002; numeric review is pending.
        assert 0 < float(row.confidence) <= 0.5
        assert row.location["requires_validation"] is True


def test_agreement_keeps_the_status(factory, scan_id):
    group = group_findings([candidate(status="insufficient_evidence")])[0]
    with transaction(factory) as session:
        FindingWriter(session).store(scan_id, analysis(group))
    with transaction(factory) as session:
        assert session.scalar(select(Finding)).status == "insufficient_evidence"


def test_unknown_severity_is_kept_as_unknown(factory, scan_id):
    group = group_findings([candidate(severity=None), candidate(severity="unknown")])[0]
    with transaction(factory) as session:
        FindingWriter(session).store(scan_id, analysis(group))
    with transaction(factory) as session:
        assert session.scalar(select(Finding)).severity == "unknown"
