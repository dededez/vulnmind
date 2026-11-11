"""Opt-in integration test. VULNMIND_TEST_DATABASE_URL must point to a test DB."""
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, func, inspect, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from vulnmind.persistence.base import Base
import vulnmind.persistence.models  # noqa: F401
from vulnmind.knowledge.ingestion import ingest_document
from vulnmind.memory.manager import MemoryRecord
from vulnmind.persistence.audit import AuditError, DatabaseAuditSink, SessionAuditSink, verify_audit_chain
from vulnmind.persistence.models import (
    AgentRun, AuditEvent, ContextManifestRecord, KnowledgeChunk, MemoryRecordRow, Project, Scan, ScanTask,
)
from vulnmind.persistence.repositories import (
    ContextManifestRepository, KnowledgeRepository, MemoryRepository, ScopeRepository, TargetRepository,
    WebEndpointRepository,
)
from vulnmind.schemas import Authorization, Target


@pytest.mark.skipif(not os.getenv("VULNMIND_TEST_DATABASE_URL"), reason="dedicated PostgreSQL test database not configured")
def test_upgrade_and_downgrade_in_isolated_schema(monkeypatch, tmp_path, capsys):
    url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
    if url.get_backend_name() != "postgresql":
        pytest.fail("VULNMIND_TEST_DATABASE_URL must be PostgreSQL")
    schema = "vulnmind_test_" + uuid4().hex
    engine = create_engine(url, isolation_level="AUTOCOMMIT")
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    project = Path(__file__).resolve().parents[2]
    config.set_main_option("script_location", str(project / "migrations"))
    scoped = url.update_query_dict({"options": f"-csearch_path={schema},public"})
    monkeypatch.setenv("VULNMIND_DATABASE_URL", scoped.render_as_string(hide_password=False))
    with engine.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    try:
        command.upgrade(config, "head")
        tables = set(inspect(engine).get_table_names(schema=schema))
        assert set(Base.metadata.tables) | {"alembic_version"} == tables
        scoped_engine = create_engine(scoped)
        try:
            project_id, scan_id = uuid4(), uuid4()
            with Session(scoped_engine) as session, session.begin():
                session.add(Project(id=project_id, name="integration test"))
                session.flush()
                session.add(Scan(id=scan_id, project_id=project_id, status="created", mode="test"))
                target = TargetRepository(session).create(project_id, Target(type="web", locator="https://example.test/api"))
                session.flush()
                now = datetime.now(timezone.utc)
                authorization = Authorization(authorization_source="test", approved_by="owner", starts_at=now-timedelta(hours=1), expires_at=now+timedelta(hours=1), web_origins=["https://example.test"], allowed_web_paths={"https://example.test": ["/api"]})
                scope = ScopeRepository(session).create(target.id, authorization)
                target_id, scope_id = target.id, scope.id
            DatabaseAuditSink(scoped_engine).record({"call_id": str(uuid4()), "tool_name": "mock", "actor": "test", "target_type": "web", "status": "requested"})
            with Session(scoped_engine) as session:
                assert session.get(Scan, scan_id).project_id == project_id
                assert session.scalar(select(func.count()).select_from(AuditEvent)) == 1
                restored = ScopeRepository(session).load_authorization(scope_id, target_id=target_id)
                assert restored == authorization
            with Session(scoped_engine) as session, session.begin():
                WebEndpointRepository(session).replace_for_scan(scan_id, project_id, [{
                    "url": "https://example.test/api/login", "method": "GET", "source": "link",
                    "source_url": "https://example.test/api/index", "parameters": ["q"]}, {
                    "url": "https://example.test/api/login", "method": "GET",
                    "source_url": "https://example.test/api/other", "parameters": ["q", "page"]}])
            with Session(scoped_engine) as session:
                row = WebEndpointRepository(session).list_for_scan(scan_id)[0]
                assert row.source_url == "https://example.test/api/index"
                assert row.parameters == ["q", "page"]
                from vulnmind.agents.form_candidates import form_candidate_urls
                from vulnmind.analysis.validation import plan_probes
                urls, omitted = form_candidate_urls([row])
                assert omitted == 0
                assert {probe.parameter for probe in plan_probes(urls)} == {"q", "page"}
            command.downgrade(config, "0012_finding_feedback")
            command.upgrade(config, "head")
            with Session(scoped_engine) as session:
                row = WebEndpointRepository(session).list_for_scan(scan_id)[0]
                assert row.source_url == "https://example.test/api/index"
                assert row.parameters is None
            # Exercise the database-wide transaction lock using real concurrent
            # PostgreSQL connections, not a mocked advisory lock.
            from vulnmind.evidence.coordination import lock_evidence_transaction
            from sqlalchemy.exc import OperationalError
            with Session(scoped_engine) as owner, owner.begin():
                lock_evidence_transaction(owner)
                with pytest.raises(OperationalError):
                    with Session(scoped_engine) as other, other.begin():
                        other.execute(text("SET LOCAL lock_timeout = '200ms'"))
                        lock_evidence_transaction(other)
            from concurrent.futures import ThreadPoolExecutor
            sink = DatabaseAuditSink(scoped_engine)
            def write_audit(_):
                sink.record({"call_id": str(uuid4()), "tool_name": "parallel", "actor": "test",
                             "target_type": "repository", "status": "requested"})
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(write_audit, range(40)))
            with scoped_engine.connect() as connection:
                audit_report = verify_audit_chain(connection)
            assert audit_report.valid and audit_report.complete and audit_report.checked == 41
            # A transaction snapshot older than the advisory-lock acquisition
            # cannot safely observe the current chain tail. Reject that mode.
            for isolation in ("REPEATABLE READ", "SERIALIZABLE"):
                strict_engine = create_engine(scoped, isolation_level=isolation)
                try:
                    with pytest.raises(AuditError, match="read committed"):
                        DatabaseAuditSink(strict_engine).record({
                            "call_id": str(uuid4()), "tool_name": "snapshot", "actor": "test",
                            "target_type": "repository", "status": "requested"})
                    with Session(strict_engine) as session, pytest.raises(AuditError, match="read committed"):
                        SessionAuditSink(session).record({
                            "call_id": str(uuid4()), "tool_name": "snapshot", "actor": "test",
                            "target_type": "repository", "status": "requested"})
                    with Session(strict_engine) as session, pytest.raises(ValueError, match="read committed"):
                        MemoryRepository(session).save(MemoryRecord(level="working", project_id=str(project_id),
                            task_id=str(uuid4()), content="not saved", confidence=0.5))
                finally:
                    strict_engine.dispose()
            with scoped_engine.connect() as connection:
                assert verify_audit_chain(connection).checked == 41
            # Fake model; audit rows and their transaction are real PostgreSQL.
            from pydantic import BaseModel
            from vulnmind.agents.audit import AgentAuditBridge
            from vulnmind.agents.model import ModelResponse
            from vulnmind.agents.runtime import AgentRuntime, AgentSpec

            class AuditReply(BaseModel):
                verdict: str

            class FakeModel:
                def __init__(self):
                    self.responses = iter(["invalid", '{"verdict":"unverified"}'])

                def complete(self, request):
                    return ModelResponse(text=next(self.responses))

            with Session(scoped_engine) as session, session.begin():
                runtime = AgentRuntime(FakeModel(), AgentAuditBridge(SessionAuditSink(session)))
                assert runtime.run(AgentSpec(name="audit", role="test", system_prompt="Review."),
                                   task="Review.", context=[], schema=AuditReply, actor="test").attempts == 2
            with Session(scoped_engine) as session:
                rows = session.execute(select(AuditEvent.call_id, AuditEvent.status)
                                       .where(AuditEvent.tool_name == "agent.test/audit")
                                       .order_by(AuditEvent.created_at)).all()
                assert [row.status for row in rows] == ["requested", "retrying", "succeeded"]
                assert len({row.call_id for row in rows}) == 1
                assert verify_audit_chain(session.connection()).valid
            # Knowledge, memory and manifest rows are written through the repositories.
            with Session(scoped_engine) as session, session.begin():
                task = ScanTask(id=uuid4(), scan_id=scan_id, phase="analysis", status="running")
                session.add(task)
                session.flush()
                run = AgentRun(id=uuid4(), task_id=task.id, agent_name="planner", status="succeeded")
                session.add(run)
                session.flush()
                run_id_for_context = run.id
                knowledge = KnowledgeRepository(session)
                document = knowledge.create_document(title="CWE-89 SQL Injection", source_type="CWE",
                                                     source_url="https://cwe.mitre.org/data/definitions/89.html",
                                                     version="4.14", trust_level="high", metadata={"lang": "generic"})
                session.flush()
                chunks = knowledge.add_chunks(document.id, [
                    (0, "SQL injection happens when untrusted input reaches a query string"),
                    (1, "Parameterized queries separate code from data")])
                session.flush()
                for chunk in chunks:
                    chunk.tsvector = func.to_tsvector(text("'simple'::regconfig"), chunk.content)
                session.flush()
                ContextManifestRepository(session).create(
                    run_id=run.id, agent_name="planner", selected_refs=["knowledge:chunk:1"], token_estimate=64)
                MemoryRepository(session).save(MemoryRecord(
                    level="working", project_id=str(project_id), task_id=str(task.id),
                    content="checked /api", confidence=0.6))
                task_id_for_memory = task.id
                document_id = document.id
            with Session(scoped_engine) as session:
                hits = KnowledgeRepository(session).search_chunks("parameterized queries")
                assert [hit.chunk_index for hit in hits] == [1]
                assert session.scalar(select(func.count()).select_from(KnowledgeChunk).where(
                    KnowledgeChunk.tsvector.is_not(None))) == 2
                active = MemoryRepository(session).query_active(project_id=str(project_id), task_id=str(task_id_for_memory))
                assert [record.content for record in active] == ["checked /api"]
                assert active[0].created_at.utcoffset() is not None
                MemoryRepository(session).invalidate(active[0].id)
                assert MemoryRepository(session).query_active(project_id=str(project_id), task_id=str(task_id_for_memory)) == []
                invalidated_source_id = active[0].id
                indexes = {index["name"] for index in inspect(scoped_engine).get_indexes("knowledge_chunks", schema=schema)}
                assert "ix_knowledge_chunks_tsvector" in indexes
                assert session.scalar(select(func.count()).select_from(ContextManifestRecord)) == 1
            # A stale or fabricated source must not silently enter context, even
            # if inserted after the original invalidation already completed.
            # The earlier read session rolls back on exit, so commit a distinct
            # invalidation before testing a subsequent transaction.
            def insert_legacy_memory(session, record):
                session.add(MemoryRecordRow(id=record.id, level=record.level, project_id=UUID(record.project_id),
                    task_id=UUID(record.task_id) if record.task_id else None, content=record.content,
                    source_refs=list(record.source_refs), confidence=record.confidence,
                    validated_by=record.validated_by, invalidated=record.invalidated,
                    created_at=record.created_at, expires_at=record.expires_at))
            with Session(scoped_engine) as session, session.begin():
                MemoryRepository(session).invalidate(invalidated_source_id)
            for reference in (f"memory:{invalidated_source_id}", f"memory:{uuid4()}"):
                with Session(scoped_engine) as session, session.begin():
                    child = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id_for_memory),
                                         content="derived", confidence=0.5, source_refs=(reference,))
                    with pytest.raises(ValueError, match="provenance is unavailable"):
                        MemoryRepository(session).save(child)
                    insert_legacy_memory(session, child)
                with Session(scoped_engine) as session, session.begin():
                    repository = MemoryRepository(session)
                    with pytest.raises(ValueError, match="provenance is unavailable"):
                        repository.query_active(project_id=str(project_id), task_id=str(task_id_for_memory))
                    repository.invalidate(child.id)
            with Session(scoped_engine) as session, session.begin():
                source = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id_for_memory),
                                      content="source", confidence=0.5)
                child = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id_for_memory),
                                    content="derived", confidence=0.5, source_refs=(f"memory:{source.id}",))
                repository = MemoryRepository(session)
                repository.save(source)
                repository.save(child)
                active = repository.query_active(project_id=str(project_id), task_id=str(task_id_for_memory))
                assert {item.id for item in active} == {source.id, child.id}
                repository.invalidate(source.id)
                assert repository.query_active(project_id=str(project_id), task_id=str(task_id_for_memory)) == []
            # A source invalidation racing a new dependent must serialize: the
            # dependent commits first, then the invalidator sees and revokes it.
            from threading import Event
            source = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id_for_memory),
                                  content="race source", confidence=0.5)
            child = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id_for_memory),
                                 content="race child", confidence=0.5, source_refs=(f"memory:{source.id}",))
            with Session(scoped_engine) as session, session.begin():
                MemoryRepository(session).save(source)
            saved, release, invalidation_started, invalidation_done = Event(), Event(), Event(), Event()
            original_lock = MemoryRepository._lock_project_writes
            def observed_lock(repository, requested_project):
                if repository.session.info.get("observe_invalidation"):
                    invalidation_started.set()
                return original_lock(repository, requested_project)
            def save_child():
                with Session(scoped_engine) as session, session.begin():
                    MemoryRepository(session).save(child)
                    session.flush()
                    saved.set()
                    if not release.wait(10):
                        raise RuntimeError("test writer release timed out")
            def invalidate_source():
                if not saved.wait(10):
                    raise RuntimeError("test writer did not start")
                with Session(scoped_engine) as session, session.begin():
                    session.info["observe_invalidation"] = True
                    MemoryRepository(session).invalidate(source.id)
                invalidation_done.set()
            with monkeypatch.context() as patcher:
                patcher.setattr(MemoryRepository, "_lock_project_writes", observed_lock)
                with ThreadPoolExecutor(max_workers=2) as pool:
                    write_future = pool.submit(save_child)
                    invalidate_future = pool.submit(invalidate_source)
                    try:
                        assert invalidation_started.wait(10)
                        assert not invalidation_done.wait(0.3)
                    finally:
                        release.set()
                    write_future.result(timeout=10)
                    invalidate_future.result(timeout=10)
            with Session(scoped_engine) as session:
                assert session.get(MemoryRecordRow, source.id).invalidated is True
                assert session.get(MemoryRecordRow, child.id).invalidated is True
            # A long-lived ORM session must not reuse a cached source whose
            # invalidation was committed by another transaction.
            with Session(scoped_engine) as writer, writer.begin():
                source = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id_for_memory),
                                      content="cached source", confidence=0.5)
                child = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id_for_memory),
                                    content="derived", confidence=0.5, source_refs=(f"memory:{source.id}",))
                MemoryRepository(writer).save(source)
                MemoryRepository(writer).save(child)
            with Session(scoped_engine) as reader:
                cached = reader.get(MemoryRecordRow, source.id)
                assert cached.invalidated is False
                with Session(scoped_engine) as writer, writer.begin():
                    writer.get(MemoryRecordRow, source.id).invalidated = True
                with pytest.raises(ValueError, match="provenance is unavailable"):
                    MemoryRepository(reader).query_active(project_id=str(project_id), task_id=str(task_id_for_memory))
            with Session(scoped_engine) as session, session.begin():
                MemoryRepository(session).invalidate(source.id)
            with Session(scoped_engine) as session, session.begin():
                other_task = ScanTask(id=uuid4(), scan_id=scan_id, phase="other", status="running")
                session.add(other_task)
                session.flush()
                source = MemoryRecord(level="working", project_id=str(project_id), task_id=str(other_task.id),
                                      content="other task", confidence=0.5)
                child = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id_for_memory),
                                    content="derived", confidence=0.5, source_refs=(f"memory:{source.id}",))
                repository = MemoryRepository(session)
                repository.save(source)
                with pytest.raises(ValueError, match="provenance is unavailable"):
                    repository.save(child)
                insert_legacy_memory(session, child)
                with pytest.raises(ValueError, match="provenance is unavailable"):
                    repository.query_active(project_id=str(project_id), task_id=str(task_id_for_memory))
                repository.invalidate(source.id)
            with Session(scoped_engine) as session, session.begin():
                foreign_project, foreign_scan, foreign_task = uuid4(), uuid4(), uuid4()
                session.add(Project(id=foreign_project, name="other project"))
                session.flush()
                session.add(Scan(id=foreign_scan, project_id=foreign_project, status="created", mode="test"))
                session.flush()
                session.add(ScanTask(id=foreign_task, scan_id=foreign_scan, phase="analysis", status="running"))
                session.flush()
                source = MemoryRecord(level="working", project_id=str(foreign_project), task_id=str(foreign_task),
                                      content="other project", confidence=0.5)
                child = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id_for_memory),
                                    content="derived", confidence=0.5, source_refs=(f"memory:{source.id}",))
                repository = MemoryRepository(session)
                repository.save(source)
                with pytest.raises(ValueError, match="provenance is unavailable"):
                    repository.save(child)
                insert_legacy_memory(session, child)
                with pytest.raises(ValueError, match="provenance is unavailable"):
                    repository.query_active(project_id=str(project_id), task_id=str(task_id_for_memory))
                repository.invalidate(child.id)
            with Session(scoped_engine) as session, session.begin():
                source = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id_for_memory),
                                      content="expired ancestor", confidence=0.5,
                                      created_at=now - timedelta(hours=2), expires_at=now - timedelta(hours=1))
                parent = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id_for_memory),
                                      content="legacy parent", confidence=0.5, source_refs=(f"memory:{source.id}",))
                child = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id_for_memory),
                                     content="new child", confidence=0.5, source_refs=(f"memory:{parent.id}",))
                repository = MemoryRepository(session)
                repository.save(source)
                insert_legacy_memory(session, parent)
                with pytest.raises(ValueError, match="provenance is unavailable"):
                    repository.save(child)
                repository.invalidate(parent.id)
            with Session(scoped_engine) as session, session.begin():
                source = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id_for_memory),
                                      content="expired", confidence=0.5,
                                      created_at=now - timedelta(hours=2), expires_at=now - timedelta(hours=1))
                child = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id_for_memory),
                                    content="derived", confidence=0.5, source_refs=(f"memory:{source.id}",))
                repository = MemoryRepository(session)
                repository.save(source)
                with pytest.raises(ValueError, match="provenance is unavailable"):
                    repository.save(child)
                insert_legacy_memory(session, child)
                with pytest.raises(ValueError, match="provenance is unavailable"):
                    repository.query_active(project_id=str(project_id), task_id=str(task_id_for_memory))
                repository.invalidate(child.id)
            with Session(scoped_engine) as session, session.begin():
                first_id, second_id = uuid4(), uuid4()
                repository = MemoryRepository(session)
                for identifier, other in ((first_id, second_id), (second_id, first_id)):
                    record = MemoryRecord(id=identifier, level="working", project_id=str(project_id),
                                          task_id=str(task_id_for_memory), content="cycle", confidence=0.5,
                                          source_refs=(f"memory:{other}",))
                    insert_legacy_memory(session, record)
                with pytest.raises(ValueError, match="cyclic"):
                    repository.query_active(project_id=str(project_id), task_id=str(task_id_for_memory))
                repository.invalidate(first_id)
            with Session(scoped_engine) as session, session.begin():
                ingested = ingest_document(
                    session, title="SSRF note", source_type="OWASP", trust_level="medium",
                    content="Server side request forgery bypasses allowlists. " * 60,
                    metadata={"language": "python", "vulnerability_type": "ssrf"})
            assert ingested.chunk_count >= 2
            with Session(scoped_engine) as session:
                hits = KnowledgeRepository(session).search_chunks("forgery allowlists")
                assert hits, "ingested chunks must be findable through full-text search"
                assert all(hit.tsvector is not None for hit in hits)
                filtered = KnowledgeRepository(session).search_chunks("forgery", filters={"source_type": "OWASP", "language": "python"})
                assert filtered and all(hit.document_id == ingested.document_id for hit in filtered)
                assert not KnowledgeRepository(session).search_chunks("forgery", filters={"source_type": "CWE"})
            # The stored FTS result is selected by the same provider used by scan;
            # the manifest records references only, with no claim of model use.
            from vulnmind.analysis.repository import RepositoryAnalysis
            from vulnmind.context.scan_manifest import knowledge_manifest_provider
            from vulnmind.findings import FindingCandidate, group_findings
            from vulnmind.knowledge.postgres_adapters import DatabaseChunkStore, PostgresSparseRetriever
            finding = FindingCandidate(title="SSRF lead", vulnerability_type="ssrf", target_id="test",
                                       location="app.py:1", source_tool="test")
            analysis = RepositoryAnalysis(scan_id=str(scan_id), project_id=str(project_id), target_id="test",
                                          files_examined=1, files_skipped=0, findings=[finding],
                                          groups=group_findings([finding]))
            with Session(scoped_engine) as session, session.begin():
                payload = knowledge_manifest_provider(PostgresSparseRetriever(session), DatabaseChunkStore(session))(analysis)
                refs = payload["selected_refs"]
                assert refs["retrieval_status"] == "matched" and refs["model_context_used"] is False
                assert any(item["document_id"] == str(ingested.document_id) and item["selected"]
                           for item in refs["knowledge"])
                ContextManifestRepository(session).create(run_id=run_id_for_context, **payload)
            with Session(scoped_engine) as session, session.begin():
                bandit_document = ingest_document(session, title="pickle guidance", source_type="reference",
                    content="python pickle unsafe deserialization guidance for untrusted data", size=500, overlap=0)
                bandit_finding = FindingCandidate(title="Bandit security finding B301", vulnerability_type="B301",
                    target_id="test", location="app.py:1", source_tool="bandit")
                bandit_analysis = RepositoryAnalysis(scan_id=str(scan_id), project_id=str(project_id),
                    target_id="test", files_examined=1, files_skipped=0, findings=[bandit_finding],
                    groups=group_findings([bandit_finding]))
                bandit_payload = knowledge_manifest_provider(PostgresSparseRetriever(session),
                    DatabaseChunkStore(session))(bandit_analysis)["selected_refs"]
                assert bandit_payload["retrieval_status"] == "matched"
                assert any(item["document_id"] == str(bandit_document.document_id) and item["selected"]
                           for item in bandit_payload["knowledge"])
                assert bandit_payload["model_context_used"] is False
            with Session(scoped_engine) as session, session.begin():
                row = session.scalar(select(KnowledgeChunk).where(KnowledgeChunk.document_id == ingested.document_id))
                changed_chunk_id = row.id
                original_content = row.content
                row.content = "uniqueupdatedterm"
            with Session(scoped_engine) as session:
                assert KnowledgeRepository(session).search_chunks("uniqueupdatedterm")
            with Session(scoped_engine) as session, session.begin():
                # Restore the chunk so its stored offsets match its content again;
                # the trigger keeps tsvector in sync either way.
                row = session.get(KnowledgeChunk, changed_chunk_id)
                row.content = original_content
            # pgvector: store embeddings and confirm cosine-distance ordering.
            from vulnmind.knowledge.vector import EMBEDDING_DIMENSIONS

            first = [1.0] + [0.0] * (EMBEDDING_DIMENSIONS - 1)
            second = [0.0, 1.0] + [0.0] * (EMBEDDING_DIMENSIONS - 2)
            with Session(scoped_engine) as session, session.begin():
                repository = KnowledgeRepository(session)
                # Start with only the original document's embeddings.
                original_chunks = repository.list_chunks(document_id)
                repository.set_embedding(original_chunks[0].id, first)
                repository.set_embedding(original_chunks[1].id, second)
                with pytest.raises(ValueError, match="nonzero direction"):
                    repository.set_embedding(original_chunks[0].id, [0.0] * EMBEDDING_DIMENSIONS)
                with pytest.raises(ValueError, match="nonzero direction"):
                    repository.dense_search([0.0] * EMBEDDING_DIMENSIONS)
            with Session(scoped_engine) as session:
                hits = KnowledgeRepository(session).dense_search(first, limit=2)
                assert [hit.document_id for hit in hits] == [document_id, document_id]
                assert [hit.chunk_index for hit in hits] == [0, 1]
                assert KnowledgeRepository(session).dense_search(second, limit=1)[0].chunk_index == 1
            # Real two-way retrieval: pgvector dense + FTS sparse fused by RRF.
            from vulnmind.knowledge.postgres_adapters import (
                DatabaseChunkStore, PostgresDenseRetriever, PostgresSparseRetriever,
            )
            from vulnmind.knowledge.retrieval import HybridRetriever, hybrid_search

            class KeepOrder:
                def rank(self, query, candidates):
                    return [candidate.chunk_id for candidate in candidates]

            with Session(scoped_engine) as session:
                fused = hybrid_search("parameterized queries",
                                      dense=PostgresDenseRetriever(session, encode=lambda query: second),
                                      sparse=PostgresSparseRetriever(session),
                                      store=DatabaseChunkStore(session), reranker=KeepOrder(),
                                      per_retriever=10, candidates=10, final=5)
                assert fused, "hybrid search must return candidates"
                assert any("dense" in item.ranks and "sparse" in item.ranks for item in fused)
                from vulnmind.knowledge.hybrid import PostgresHybridRetriever
                class SyntheticEncoder:
                    model_info = None  # The test corpus deliberately has legacy synthetic vectors.
                    def __call__(self, query):
                        return second
                shared = PostgresHybridRetriever(session, encoder=SyntheticEncoder())
                assert shared.search("parameterized queries", limit=5) == [item.chunk.chunk_id for item in fused]
            # A closer CWE vector must not crowd out an OWASP result before the
            # metadata filter is applied. Vectors are synthetic test inputs.
            with Session(scoped_engine) as session, session.begin():
                filtered_chunk = KnowledgeRepository(session).list_chunks(ingested.document_id)[0]
                KnowledgeRepository(session).set_embedding(filtered_chunk.id, first)
                filtered_chunk_id = filtered_chunk.id
            with Session(scoped_engine) as session:
                repository = KnowledgeRepository(session)
                assert repository.dense_search(second, limit=1)[0].document_id == document_id
                filtered = repository.dense_search(second, limit=1, filters={"source_type": "OWASP"})
                assert [row.id for row in filtered] == [filtered_chunk_id]
                fused = hybrid_search("server side request forgery",
                                      dense=PostgresDenseRetriever(session, encode=lambda query: second),
                                      sparse=PostgresSparseRetriever(session), store=DatabaseChunkStore(session),
                                      reranker=KeepOrder(), per_retriever=1, candidates=2, final=1,
                                      filters={"source_type": "OWASP"})
                assert len(fused) == 1 and fused[0].chunk.document_id == str(ingested.document_id)
                assert set(fused[0].ranks) == {"dense", "sparse"}
                store = DatabaseChunkStore(session)
                adapter = HybridRetriever(dense=PostgresDenseRetriever(session, encode=lambda query: second),
                                          sparse=PostgresSparseRetriever(session), store=store, reranker=KeepOrder(),
                                          filters={"source_type": "OWASP"})
                payload = knowledge_manifest_provider(adapter, store, retrieval_method="hybrid")(analysis)["selected_refs"]
                assert payload["retrieval_method"] == "hybrid" and payload["model_context_used"] is False
                assert payload["retrieval_method_provenance"] == "caller_declared"
                assert any(item["chunk_id"] == str(filtered_chunk_id) and item["selected"]
                           for item in payload["knowledge"])
            # Simulate rows created before validation or by another writer.
            # Invalid stored vectors must never appear as cosine candidates.
            for unsafe_value in (0.0, 1e-25, 1e20):
                with Session(scoped_engine) as session, session.begin():
                    row = session.get(KnowledgeChunk, filtered_chunk_id)
                    row.embedding = [unsafe_value] + [0.0] * (EMBEDDING_DIMENSIONS - 1)
                with Session(scoped_engine) as session:
                    assert KnowledgeRepository(session).dense_search(
                        second, limit=1, filters={"source_type": "OWASP"}) == []
            with Session(scoped_engine) as session, session.begin():
                KnowledgeRepository(session).set_embedding(filtered_chunk_id, first)
            # Real PostgreSQL FTS -> context selection -> persisted scan manifest.
            # The analyzer is a deterministic test double, not a real scanner.
            from vulnmind.analysis.orchestrator import ScanOrchestrator, ScanRunRequest
            from vulnmind.reports.store import ReportStore

            repo = tmp_path / "repo"
            repo.mkdir()
            (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
            local_scope = Authorization(authorization_source="test", approved_by="owner",
                                        starts_at=now-timedelta(hours=1), expires_at=now+timedelta(hours=1),
                                        repository_roots=[str(repo)])
            def test_analyzer(file_content):
                return [FindingCandidate(title="SQL lead", vulnerability_type="sqli", target_id="test",
                                         location=f"{file_content.path}:1", source_tool="fixture")]
            with Session(scoped_engine) as session, session.begin():
                provider = knowledge_manifest_provider(PostgresSparseRetriever(session), DatabaseChunkStore(session))
                outcome = ScanOrchestrator(session, SessionAuditSink(session), [test_analyzer],
                                           ReportStore(tmp_path / "reports"), manifest_provider=provider).run(
                    ScanRunRequest(project_id=project_id, actor="test",
                                   target=Target(type="repository", locator=str(repo)), scope=local_scope))
                persisted = session.get(ContextManifestRecord, outcome.context_manifest_id)
                assert persisted.selected_refs["model_context_used"] is False
                assert persisted.selected_refs["retrieval_status"] == "matched"
                assert any(item["document_id"] == str(document_id) for item in persisted.selected_refs["knowledge"])
            # The deterministic finding above has no evidence store; verify
            # must report it as incomplete against PostgreSQL, not as OK.
            import json
            from types import SimpleNamespace
            from vulnmind.__main__ import _verify

            monkeypatch.setenv("VULNMIND_REPORT_ROOT", str(tmp_path / "reports"))
            monkeypatch.setenv("VULNMIND_EVIDENCE_ROOT", "")
            assert _verify(SimpleNamespace(scan_id=str(outcome.scan_id))) == 1
            verification = json.loads(capsys.readouterr().out)
            assert verification["status"] == "incomplete"
            assert verification["findings_without_evidence"] == 1
            assert verification["report_integrity"] == "valid"
            # Shared production adapter -> scan orchestration -> persisted manifest.
            # This uses synthetic embeddings, not a real model or quality evaluation.
            with Session(scoped_engine) as session, session.begin():
                provider = knowledge_manifest_provider(
                    PostgresHybridRetriever(session, encoder=SyntheticEncoder()), DatabaseChunkStore(session),
                    retrieval_method="hybrid")
                hybrid_scan = ScanOrchestrator(session, SessionAuditSink(session), [test_analyzer],
                    ReportStore(tmp_path / "reports"), manifest_provider=provider).run(
                        ScanRunRequest(project_id=project_id, actor="test",
                            target=Target(type="repository", locator=str(repo)), scope=local_scope))
                hybrid_manifest = session.get(ContextManifestRecord, hybrid_scan.context_manifest_id).selected_refs
                assert hybrid_manifest["retrieval_method"] == "hybrid"
                assert hybrid_manifest["retrieval_status"] == "matched"
                assert hybrid_manifest["model_context_used"] is False
            # A second run persists evidence, then reads the saved report and
            # verifies the exact linked row through the real database.
            from vulnmind.analysis.repository import AnnotatedFinding, EvidencePayload
            from vulnmind.evidence.store import EvidenceStore
            from vulnmind.persistence.models import Evidence, Finding
            from vulnmind.reports.loader import load_report

            def analyzer_with_evidence(file_content):
                return [AnnotatedFinding(finding=test_analyzer(file_content)[0],
                                         evidence=[EvidencePayload(content=b"local fixture evidence")])]
            evidence_store = EvidenceStore(tmp_path / "evidence")
            with Session(scoped_engine) as session, session.begin():
                store = DatabaseChunkStore(session)
                hybrid_provider = knowledge_manifest_provider(
                    HybridRetriever(dense=PostgresDenseRetriever(session, encode=lambda query: second),
                                    sparse=PostgresSparseRetriever(session), store=store, reranker=KeepOrder()),
                    store, retrieval_method="hybrid")
                evidence_outcome = ScanOrchestrator(session, SessionAuditSink(session), [analyzer_with_evidence],
                                                   ReportStore(tmp_path / "reports"), evidence_store,
                                                   manifest_provider=hybrid_provider).run(
                    ScanRunRequest(project_id=project_id, actor="test", report_format="json",
                                   target=Target(type="repository", locator=str(repo)), scope=local_scope))
                hybrid_manifest = session.get(ContextManifestRecord, evidence_outcome.context_manifest_id)
                assert hybrid_manifest.selected_refs["retrieval_method"] == "hybrid"
                assert hybrid_manifest.selected_refs["model_context_used"] is False
                assert any(item["document_id"] == str(document_id) for item in hybrid_manifest.selected_refs["knowledge"])
            with Session(scoped_engine) as session:
                loaded = load_report(session, ReportStore(tmp_path / "reports"), evidence_outcome.scan_id)
                report_payload = json.loads(loaded.content)
                evidence = session.scalar(select(Evidence).join(Finding).where(Finding.scan_id == evidence_outcome.scan_id))
                assert report_payload["groups"][0]["stored_evidence_ids"] == [str(evidence.id)]
                assert evidence_store.read(evidence.content_ref) == b"local fixture evidence"
            monkeypatch.setenv("VULNMIND_EVIDENCE_ROOT", str(tmp_path / "evidence"))
            assert _verify(SimpleNamespace(scan_id=str(evidence_outcome.scan_id))) == 0
            verified = json.loads(capsys.readouterr().out)
            assert verified["status"] == "ok" and verified["evidence_snapshot_integrity"] == "valid"
            assert verified["finding_snapshot_integrity"] == "valid"
            from sqlalchemy import delete
            import vulnmind.__main__ as cli_module
            extra_evidence_id = uuid4()
            with Session(scoped_engine) as session, session.begin():
                session.add(Evidence(id=extra_evidence_id, finding_id=evidence.finding_id,
                                     evidence_type=evidence.evidence_type, locator=evidence.locator,
                                     content_ref=evidence.content_ref, hash=evidence.hash))
            with monkeypatch.context() as patcher:
                patcher.setattr(cli_module, "_MAX_VERIFY_EVIDENCE", 1)
                assert _verify(SimpleNamespace(scan_id=str(evidence_outcome.scan_id))) == 1
            limited = json.loads(capsys.readouterr().out)
            assert limited["status"] == "incomplete" and limited["evidence_limit_reached"] is True
            assert limited["evidence_checked"] == limited["evidence_unchecked"] == 1
            assert limited["evidence_snapshot_integrity"] == "not_checked_limit"
            with Session(scoped_engine) as session, session.begin():
                session.execute(delete(Evidence).where(Evidence.id == extra_evidence_id))
            # Commit a new row after the verifier's first read. All remaining
            # reads must still see its original PostgreSQL transaction snapshot.
            import vulnmind.reports.loader as loader_module
            original_load = loader_module.load_report
            concurrent_id = uuid4()
            def load_then_write(verify_session, store, requested_id):
                result = original_load(verify_session, store, requested_id)
                with Session(scoped_engine) as writer, writer.begin():
                    writer.add(Finding(id=concurrent_id, scan_id=evidence_outcome.scan_id,
                                       fingerprint="d" * 64, title="concurrent lead",
                                       vuln_type="secret", status="unverified"))
                return result
            with monkeypatch.context() as patcher:
                patcher.setattr(loader_module, "load_report", load_then_write)
                assert _verify(SimpleNamespace(scan_id=str(evidence_outcome.scan_id))) == 0
            concurrent_result = json.loads(capsys.readouterr().out)
            assert concurrent_result["status"] == "ok" and concurrent_result["findings_without_evidence"] == 0
            with Session(scoped_engine) as session, session.begin():
                assert session.get(Finding, concurrent_id) is not None
                session.execute(delete(Finding).where(Finding.id == concurrent_id))
            extra_id = uuid4()
            with Session(scoped_engine) as session, session.begin():
                session.add(Finding(id=extra_id, scan_id=evidence_outcome.scan_id, fingerprint="f" * 64,
                                    title="later lead", vuln_type="secret", status="unverified"))
            assert _verify(SimpleNamespace(scan_id=str(evidence_outcome.scan_id))) == 1
            drift = json.loads(capsys.readouterr().out)
            assert drift["status"] == "incomplete" and drift["finding_snapshot_integrity"] == "incomplete"
            assert drift["findings_only_in_database"] == 1 and drift["findings_only_in_report"] == 0
            with Session(scoped_engine) as session, session.begin():
                session.execute(delete(Finding).where(Finding.id == extra_id))
            with Session(scoped_engine) as session, session.begin():
                session.execute(delete(Evidence).where(Evidence.id == evidence.id))
            assert _verify(SimpleNamespace(scan_id=str(evidence_outcome.scan_id))) == 1
            broken = json.loads(capsys.readouterr().out)
            assert broken["status"] == "broken" and broken["evidence_snapshot_missing"] == [str(evidence.id)]
            # Exercise actual PostgreSQL backfill with synthetic vectors.
            import importlib.util
            spec = importlib.util.spec_from_file_location("backfill_integration", project / "scripts/backfill_embeddings.py")
            backfill_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(backfill_module)
            class SyntheticModel:
                def __init__(self, first, second):
                    self.vector = [first, second] + [0.0] * (EMBEDDING_DIMENSIONS - 2)
                def encode(self, contents, **kwargs):
                    return [self.vector[:] for _ in contents]
            original_model = SyntheticModel(1.0, 0.0)
            other_model = SyntheticModel(0.0, 1.0)
            monkeypatch.setattr(backfill_module, "MAX_TOTAL_CHARACTERS", 1)
            with pytest.raises(ValueError, match="exceeds backfill limits"):
                with Session(scoped_engine) as session, session.begin():
                    backfill_module.backfill(session, original_model, batch_size=8)
            monkeypatch.setattr(backfill_module, "MAX_TOTAL_CHARACTERS", 10_000_000)
            with Session(scoped_engine) as session, session.begin():
                replaced, checked = backfill_module.backfill(session, original_model, batch_size=8, replace_all=True)
                assert replaced > 0 and checked == 0
            with Session(scoped_engine) as session, session.begin():
                new_document = ingest_document(session, title="new backfill test", content="safe test text",
                                               source_type="test")
            with pytest.raises(ValueError, match="do not match"):
                with Session(scoped_engine) as session, session.begin():
                    backfill_module.backfill(session, other_model, batch_size=8)
            with Session(scoped_engine) as session:
                assert KnowledgeRepository(session).list_chunks(new_document.document_id)[0].embedding is None
            with Session(scoped_engine) as session, session.begin():
                inserted, checked = backfill_module.backfill(session, original_model, batch_size=8)
                assert inserted == 1 and checked == replaced
                # The lock stays held until commit and blocks ordinary writers.
                from sqlalchemy.exc import OperationalError
                with pytest.raises(OperationalError):
                    with scoped_engine.begin() as competitor:
                        competitor.execute(text("SET LOCAL lock_timeout = '200ms'"))
                        competitor.execute(text("UPDATE knowledge_chunks SET content = content WHERE 1 = 0"))
            class FailingModel:
                def __init__(self):
                    self.calls = 0
                def encode(self, contents, **kwargs):
                    self.calls += 1
                    if self.calls > 1:
                        raise RuntimeError("synthetic encoding failure")
                    return other_model.encode(contents, **kwargs)
            with pytest.raises(RuntimeError, match="synthetic encoding failure"):
                with Session(scoped_engine) as session, session.begin():
                    backfill_module.backfill(session, FailingModel(), batch_size=1, replace_all=True)
            with Session(scoped_engine) as session:
                unchanged = KnowledgeRepository(session).list_chunks(new_document.document_id)[0]
                assert list(unchanged.embedding) == original_model.vector
            with Session(scoped_engine) as session, session.begin():
                replaced_again, checked = backfill_module.backfill(session, other_model, batch_size=8, replace_all=True)
                assert replaced_again == replaced + 1 and checked == 0
        finally:
            scoped_engine.dispose()
        # A downgrade must not silently erase existing embeddings. This is an
        # isolated disposable test schema; remove only its synthetic vectors
        # after verifying the guard, then continue the original downgrade test.
        with pytest.raises(RuntimeError, match="vectors are stored"):
            command.downgrade(config, "0013_endpoint_parameters")
        with scoped_engine.begin() as connection:
            assert connection.execute(text("SELECT count(*) FROM knowledge_chunks WHERE embedding IS NOT NULL")).scalar_one() > 0
            connection.execute(text("UPDATE knowledge_chunks SET embedding = NULL"))
        command.downgrade(config, "base")
        assert not (set(Base.metadata.tables) & set(inspect(engine).get_table_names(schema=schema)))
    finally:
        with engine.connect() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()

