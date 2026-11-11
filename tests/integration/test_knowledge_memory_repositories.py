"""SQLite checks for the knowledge, skill, memory and context-manifest repositories.

SQLite proves transaction and JSON handling only; PostgreSQL-specific behaviour
(full-text search, timezone round-trips) is covered by the live test.
"""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from vulnmind.memory.manager import MemoryRecord
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import AgentRun, KnowledgeChunk, MemoryRecordRow, Project, ScanTask
from vulnmind.persistence.repositories import (
    ContextManifestRepository, KnowledgeRepository, MemoryRepository, ProjectRepository, ReportRepository,
    ScanRepository, SkillRepository,
)
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
def project_id(factory):
    with transaction(factory) as session:
        return ProjectRepository(session).create("knowledge test").id


@pytest.fixture
def scan_context(factory):
    """Project, scan and scan task rows that memory and manifests can reference."""
    with transaction(factory) as session:
        project = ProjectRepository(session).create("knowledge test")
        session.flush()
        scan = ScanRepository(session).create(project.id, "simulation")
        session.flush()
        task = ScanTask(id=uuid4(), scan_id=scan.id, phase="analysis", status="running")
        session.add(task)
        session.flush()
        return project.id, scan.id, task.id


def test_document_and_chunk_round_trip(factory):
    with transaction(factory) as session:
        document = KnowledgeRepository(session).create_document(
            title="CWE-89 SQL Injection", source_type="CWE", source_url="https://cwe.mitre.org/data/definitions/89.html",
            version="4.14", trust_level="high", metadata={"lang": "generic"})
        session.flush()
        document_id = document.id
        KnowledgeRepository(session).add_chunks(document_id, [(0, "SQL 注入原理"), (1, "参数化查询修复")])
    with transaction(factory) as session:
        repository = KnowledgeRepository(session)
        stored = repository.get_document(document_id)
        assert stored.title == "CWE-89 SQL Injection"
        assert stored.metadata_ == {"lang": "generic"}
        chunks = repository.list_chunks(document_id)
        assert [chunk.chunk_index for chunk in chunks] == [0, 1]
        assert [chunk.content for chunk in chunks] == ["SQL 注入原理", "参数化查询修复"]


def test_chunks_require_stored_document_and_valid_indices(factory):
    with transaction(factory) as session:
        repository = KnowledgeRepository(session)
        with pytest.raises(ValueError, match="document is not stored"):
            repository.add_chunks(uuid4(), [(0, "内容")])
        document = repository.create_document(title="doc", source_type="rule")
        session.flush()
        with pytest.raises(ValueError, match="unique and non-negative"):
            repository.add_chunks(document.id, [(0, "a"), (0, "b")])
        with pytest.raises(ValueError, match="unique and non-negative"):
            repository.add_chunks(document.id, [(-1, "a")])
        with pytest.raises(ValueError, match="cannot be blank"):
            repository.add_chunks(document.id, [(0, "   ")])
        with pytest.raises(ValueError, match="title"):
            repository.create_document(title=" ", source_type="rule")


def test_chunk_indices_are_unique_per_document(factory):
    with transaction(factory) as session:
        repository = KnowledgeRepository(session)
        document = repository.create_document(title="doc", source_type="rule")
        session.flush()
        repository.add_chunks(document.id, [(0, "a")])
        session.flush()
        session.add(KnowledgeChunk(id=uuid4(), document_id=document.id, chunk_index=0, content="duplicate"))
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()


def test_skill_filters_and_uniqueness(factory):
    with transaction(factory) as session:
        repository = SkillRepository(session)
        repository.create(name="sqli_workflow", version="1", content_uri="skills/sqli/workflow.md",
                          target_type="web", vuln_type="sqli", stage="analysis")
        repository.create(name="repo_audit", version="1", content_uri="skills/target/repository_audit.md",
                          target_type="repository", stage="analysis")
        session.flush()
        assert [skill.name for skill in repository.list_skills(target_type="web")] == ["sqli_workflow"]
        assert [skill.name for skill in repository.list_skills(stage="analysis")] == ["repo_audit", "sqli_workflow"]
        assert repository.list_skills(vuln_type="xss") == []
        with pytest.raises(ValueError, match="content URI"):
            repository.create(name="bad", version="1", content_uri=" ")


def test_memory_save_invalidate_and_fail_closed_reads(factory, scan_context):
    project_id, _, task_id = scan_context
    now = datetime.now(timezone.utc)
    first = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id),
                         content="扫描进度", confidence=0.5, created_at=now)
    second = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id),
                          content="引用第一条", confidence=0.5, source_refs=(f"memory:{first.id}",), created_at=now)
    with transaction(factory) as session:
        repository = MemoryRepository(session)
        repository.save(first)
        repository.save(second)
    with transaction(factory) as session:
        repository = MemoryRepository(session)
        with pytest.raises(ValueError, match="already stored"):
            repository.save(first)
        # SQLite drops timezone information, so reading fails closed instead of guessing.
        with pytest.raises(ValidationError):
            repository.get(first.id)
    with transaction(factory) as session:
        repository = MemoryRepository(session)
        repository.invalidate(first.id)
        rows = {row.id: row for row in session.scalars(select(MemoryRecordRow))}
        assert rows[first.id].invalidated is True
        assert rows[second.id].invalidated is True
        with pytest.raises(KeyError):
            repository.invalidate(uuid4())
        with pytest.raises(ValueError, match="UUID"):
            repository.save(MemoryRecord(level="working", project_id="not-a-uuid", task_id=str(task_id),
                                         content="x", confidence=0.5, created_at=now))


def test_memory_invalidation_ignores_other_projects(factory, scan_context):
    project_id, _, task_id = scan_context
    now = datetime.now(timezone.utc)
    with transaction(factory) as session:
        other_project = ProjectRepository(session).create("other")
        session.flush()
        other_scan = ScanRepository(session).create(other_project.id, "simulation")
        session.flush()
        other_task = ScanTask(id=uuid4(), scan_id=other_scan.id, phase="analysis", status="running")
        session.add(other_task)
        session.flush()
        first = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id), content="a",
                             confidence=0.5, created_at=now)
        foreign = MemoryRecord(level="working", project_id=str(other_project.id), task_id=str(other_task.id),
                               content="b", confidence=0.5, source_refs=("evidence:other",), created_at=now)
        cross_project = MemoryRecord(level="working", project_id=str(other_project.id), task_id=str(other_task.id),
                                     content="bad source", confidence=0.5,
                                     source_refs=(f"memory:{first.id}",), created_at=now)
        repository = MemoryRepository(session)
        repository.save(first)
        with pytest.raises(ValueError, match="provenance is unavailable"):
            repository.save(cross_project)
        repository.save(foreign)
        first_id, foreign_id = first.id, foreign.id
    with transaction(factory) as session:
        MemoryRepository(session).invalidate(first_id)
        assert session.get(MemoryRecordRow, first_id).invalidated is True
        assert session.get(MemoryRecordRow, foreign_id).invalidated is False


def test_memory_revalidates_snapshots_and_rejects_cross_project_task(factory, scan_context):
    project_id, _, task_id = scan_context
    now = datetime.now(timezone.utc)
    with transaction(factory) as session:
        other = ProjectRepository(session).create("different project")
        session.flush()
        other_scan = ScanRepository(session).create(other.id, "simulation")
        session.flush()
        foreign_task = ScanTask(id=uuid4(), scan_id=other_scan.id, phase="analysis", status="running")
        session.add(foreign_task)
        session.flush()
        valid = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id),
                             content="fact", confidence=0.5, created_at=now)
        forged = valid.model_copy(update={"level": "long_term", "task_id": None})
        repository = MemoryRepository(session)
        with pytest.raises(ValidationError):
            repository.save(forged)
        cross_project = valid.model_copy(update={"task_id": str(foreign_task.id)})
        with pytest.raises(ValueError, match="does not belong"):
            repository.save(cross_project)
        with pytest.raises(ValueError, match="does not belong"):
            repository.query_active(project_id=str(project_id), task_id=str(foreign_task.id), now=now)
        with pytest.raises(ValueError, match="does not belong"):
            repository.query_active(project_id=str(project_id), task_id=str(uuid4()), now=now)
        assert session.scalar(select(MemoryRecordRow)) is None


def test_memory_query_does_not_overwrite_unflushed_session_changes(factory, scan_context):
    project_id, _, task_id = scan_context
    with factory() as session:
        session.autoflush = False
        pending = Project(id=uuid4(), name="pending")
        session.add(pending)
        with pytest.raises(ValueError, match="unflushed changes"):
            MemoryRepository(session).query_active(project_id=str(project_id), task_id=str(task_id))
        assert pending in session.new
        session.rollback()


def test_memory_save_rejects_missing_self_and_malformed_sources(factory, scan_context):
    project_id, _, task_id = scan_context
    record_id = uuid4()
    with transaction(factory) as session:
        repository = MemoryRepository(session)
        for reference in (f"memory:{record_id}", f"memory:{uuid4()}", "memory:not-a-uuid"):
            candidate = MemoryRecord(id=record_id, level="working", project_id=str(project_id),
                                     task_id=str(task_id), content="derived", confidence=0.5,
                                     source_refs=(reference,))
            with pytest.raises(ValueError, match="provenance is unavailable"):
                repository.save(candidate)
        assert session.scalar(select(MemoryRecordRow)) is None


def test_memory_save_does_not_validate_unflushed_changes(factory, scan_context):
    project_id, _, task_id = scan_context
    with factory() as session:
        session.autoflush = False
        pending = Project(id=uuid4(), name="pending")
        session.add(pending)
        candidate = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id),
                                 content="derived", confidence=0.5, source_refs=(f"memory:{uuid4()}",))
        with pytest.raises(ValueError, match="unflushed"):
            MemoryRepository(session).save(candidate)
        assert pending in session.new
        session.rollback()


@pytest.mark.parametrize("budget", ["MAX_MEMORY_LINEAGE_REFS", "MAX_MEMORY_LINEAGE_RECORDS"])
def test_memory_invalidation_budget_fails_before_mutating_any_row(factory, scan_context, monkeypatch, budget):
    import vulnmind.persistence.repositories as repositories

    project_id, _, task_id = scan_context
    with transaction(factory) as session:
        repository = MemoryRepository(session)
        first = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id),
                             content="first", confidence=0.5, source_refs=("evidence:a",))
        second = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id),
                              content="second", confidence=0.5, source_refs=("evidence:b",))
        repository.save(first)
        repository.save(second)
        session.flush()
    with transaction(factory) as session:
        monkeypatch.setattr(repositories, budget, 1)
        with pytest.raises(ValueError, match="invalidation exceeds"):
            MemoryRepository(session).invalidate(first.id)
    with transaction(factory) as session:
        assert session.get(MemoryRecordRow, first.id).invalidated is False
        assert session.get(MemoryRecordRow, second.id).invalidated is False


def test_ambiguous_legacy_memory_reference_blocks_invalidation_before_changes(factory, scan_context):
    project_id, _, task_id = scan_context
    now = datetime.now(timezone.utc)
    first_id, legacy_id = uuid4(), uuid4()
    with transaction(factory) as session:
        MemoryRepository(session).save(MemoryRecord(id=first_id, level="working", project_id=str(project_id),
                                                  task_id=str(task_id), content="source", confidence=0.5))
        session.add(MemoryRecordRow(id=legacy_id, level="working", project_id=project_id, task_id=task_id,
                                    content="legacy", confidence=0.5, source_refs=[f"MEMORY:{first_id}"],
                                    invalidated=False, created_at=now))
    with transaction(factory) as session:
        with pytest.raises(ValueError, match="provenance is unavailable"):
            MemoryRepository(session).invalidate(first_id)
    with transaction(factory) as session:
        assert session.get(MemoryRecordRow, first_id).invalidated is False
        assert session.get(MemoryRecordRow, legacy_id).invalidated is False


def test_report_repository_tracks_generated_reports(factory, project_id):
    with transaction(factory) as session:
        scan = ScanRepository(session).create(project_id, "analysis")
        session.flush()
        report = ReportRepository(session).create(scan.id, format="markdown", storage_uri="reports/scan-1.md")
        report_id, scan_id = report.id, scan.id
    with transaction(factory) as session:
        repository = ReportRepository(session)
        assert repository.get(report_id).storage_uri == "reports/scan-1.md"
        assert [row.id for row in repository.list_for_scan(scan_id)] == [report_id]
        with pytest.raises(ValueError, match="storage URI"):
            repository.create(scan_id, format="json", storage_uri=" ")
        with pytest.raises(ValueError, match="format"):
            repository.create(scan_id, format=" ", storage_uri="reports/x.json")


def test_context_manifest_records_selection(factory, scan_context):
    _, scan_id, task_id = scan_context
    run_id = uuid4()
    with transaction(factory) as session:
        session.add(AgentRun(id=run_id, task_id=task_id, agent_name="planner", status="succeeded"))
        session.flush()
        manifest = ContextManifestRepository(session).create(
            run_id=run_id, agent_name="planner", selected_refs=["skill:sqli@1", "memory:x"], token_estimate=120)
        manifest_id = manifest.id
    with transaction(factory) as session:
        repository = ContextManifestRepository(session)
        stored = repository.get(manifest_id)
        assert stored.selected_refs == ["skill:sqli@1", "memory:x"]
        assert stored.token_estimate == 120
        assert [item.id for item in repository.list_for_run(run_id)] == [manifest_id]
        with pytest.raises(ValueError, match="agent name"):
            repository.create(run_id=run_id, agent_name=" ", selected_refs=[], token_estimate=1)
        with pytest.raises(ValueError, match="token estimate"):
            repository.create(run_id=run_id, agent_name="planner", selected_refs=[], token_estimate=-1)
        with pytest.raises(ValueError, match="list or mapping"):
            repository.create(run_id=run_id, agent_name="planner", selected_refs="text", token_estimate=1)
