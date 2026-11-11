"""Staged knowledge workflow on an explicitly configured disposable PG."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session


@pytest.mark.skipif(not os.getenv("VULNMIND_TEST_DATABASE_URL"), reason="dedicated PostgreSQL not configured")
def test_staged_knowledge_persists_and_replays_without_retrieval(monkeypatch, tmp_path, capsys):
    from vulnmind import __main__
    from vulnmind.knowledge import hybrid as hybrid_module
    from vulnmind.knowledge.ingestion import ingest_document
    from vulnmind.persistence.audit import trace_scan_audit
    from vulnmind.persistence.base import Base
    from vulnmind.persistence.models import ContextManifestRecord, KnowledgeChunk, Project, Scan, WorkflowOperation

    url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
    if url.get_backend_name() != "postgresql":
        pytest.fail("dedicated PostgreSQL is required")
    schema = "vulnmind_staged_knowledge_" + uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = url.update_query_dict({"options": f"-csearch_path={schema},public"})
    engine = create_engine(scoped)
    try:
        Base.metadata.create_all(engine)
        project_id, workflow_id = uuid4(), uuid4()
        with Session(engine) as session, session.begin():
            session.add(Project(id=project_id, name="staged context"))
            document = ingest_document(session, title="synthetic TLS", source_type="reference",
                content="tls certificate verification prevents interception", size=500, overlap=0)
            session.flush()
            chunk_id = str(session.scalar(select(KnowledgeChunk.id).where(
                KnowledgeChunk.document_id == document.document_id)))
        class FakeEncoder:
            pass
        class FakeHybrid:
            def __init__(self, session, *, encoder): pass
            def search(self, query, *, limit): return [chunk_id]
        monkeypatch.setattr(hybrid_module, "LocalQueryEncoder", FakeEncoder)
        monkeypatch.setattr(hybrid_module, "PostgresHybridRetriever", FakeHybrid)
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("import requests\nrequests.get('https://example.test', verify=False)\n", encoding="utf-8")
        now = datetime.now(timezone.utc)
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(json.dumps({"authorization_source": "test", "approved_by": "owner",
            "starts_at": (now - timedelta(hours=1)).isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(),
            "repository_roots": [str(repo)]}), encoding="utf-8")
        monkeypatch.setenv("VULNMIND_DATABASE_URL", scoped.render_as_string(hide_password=False))
        monkeypatch.setenv("VULNMIND_REPORT_ROOT", str(tmp_path / "reports"))
        monkeypatch.setenv("VULNMIND_EVIDENCE_ROOT", "")
        initial_args = ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id),
            "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
            "--knowledge-context", "--staged-knowledge"]
        monkeypatch.setattr(sys, "argv", initial_args)
        assert __main__.main() == 0
        scan_id = UUID(json.loads(capsys.readouterr().out)["scan_id"])
        monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-context", "--workflow-id", str(workflow_id)])
        assert __main__.main() == 0
        context = json.loads(capsys.readouterr().out)
        assert context["status"] == "loaded" and context["scan_id"] == str(scan_id)
        assert chunk_id in {item["chunk_id"] for item in context["selected_refs"]["knowledge"]}
        assert "prevents interception" not in json.dumps(context)
        monkeypatch.setattr(sys, "argv", initial_args)
        with Session(engine) as session:
            rows = session.scalars(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow_id)).all()
            stages = {item.stage: item for item in rows}
            assert set(stages) == {"repository_scan", "knowledge_context"}
            assert all(item.status == "completed" for item in stages.values())
            manifest = session.get(ContextManifestRecord, UUID(stages["knowledge_context"].result_ref))
            assert manifest.selected_refs["retrieval_status"] == "matched"
            assert chunk_id in {item["chunk_id"] for item in manifest.selected_refs["knowledge"]}
            assert trace_scan_audit(session.connection(), stages["knowledge_context"].id)["outcome"] == "committed"
        # A separate process exits after scan commit but before claiming the
        # knowledge stage. Resume must use the existing scan, not repeat it.
        interrupted_id = uuid4()
        child_args = ["workflow-scan", "--workflow-id", str(interrupted_id), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file), "--knowledge-context", "--staged-knowledge"]
        child_script = """import os,sys
from vulnmind import __main__
from vulnmind.knowledge import hybrid
import vulnmind.graph.guarded_repository_workflow as graph
class Encoder: pass
hybrid.LocalQueryEncoder = Encoder
original = graph.claim_stage
def interrupt(*args, **kwargs):
 if kwargs['stage'] == 'knowledge_context': os._exit(94)
 return original(*args, **kwargs)
graph.claim_stage = interrupt
sys.argv = ['vulnmind'] + sys.argv[1:]
__main__.main()
"""
        child_env = os.environ.copy()
        child_env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
        child = subprocess.run([sys.executable, "-c", child_script, *child_args], capture_output=True,
                               encoding="utf-8", env=child_env, timeout=90)
        assert child.returncode == 94, child.stderr + child.stdout
        monkeypatch.setattr(sys, "argv", ["vulnmind", *child_args])
        assert __main__.main() == 0
        resumed_scan = UUID(json.loads(capsys.readouterr().out)["scan_id"])
        assert resumed_scan != scan_id
        with Session(engine) as session:
            assert len(session.scalars(select(Scan)).all()) == 2
            assert len(session.scalars(select(ContextManifestRecord)).all()) == 2
        # Scan commit acknowledgement is lost; reconcile must not start the
        # missing knowledge stage, and a later normal run may continue it.
        reconcile_id = uuid4()
        reconcile_args = ["workflow-scan", "--workflow-id", str(reconcile_id), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file), "--knowledge-context", "--staged-knowledge"]
        scan_exit_script = """import os,sys
from vulnmind import __main__
import vulnmind.graph.guarded_repository_workflow as graph
graph.complete_stage = lambda *args, **kwargs: os._exit(95)
sys.argv = ['vulnmind'] + sys.argv[1:]
__main__.main()
"""
        child = subprocess.run([sys.executable, "-c", scan_exit_script, *reconcile_args], capture_output=True,
                               encoding="utf-8", env=child_env, timeout=90)
        assert child.returncode == 95, child.stderr + child.stdout
        monkeypatch.setattr(sys, "argv", ["vulnmind", *reconcile_args, "--reconcile"])
        assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
        with Session(engine) as session:
            stages = session.scalars(select(WorkflowOperation).where(WorkflowOperation.workflow_id == reconcile_id)).all()
            assert len(stages) == 1 and stages[0].stage == "repository_scan" and stages[0].status == "completed"
        monkeypatch.setattr(sys, "argv", ["vulnmind", *reconcile_args])
        assert __main__.main() == 0 and json.loads(capsys.readouterr().out)["status"] == "finished"
        lost_id = uuid4()
        lost_args = ["vulnmind", "workflow-scan", "--workflow-id", str(lost_id), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file), "--knowledge-context", "--staged-knowledge"]
        original_commit = Session.commit
        def lost_ack(session):
            original_commit(session)
            raise RuntimeError("synthetic lost knowledge commit acknowledgement")
        monkeypatch.setattr(Session, "commit", lost_ack)
        monkeypatch.setattr(sys, "argv", lost_args)
        assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
        monkeypatch.setattr(Session, "commit", original_commit)
        monkeypatch.setattr(hybrid_module, "LocalQueryEncoder", lambda: pytest.fail("committed knowledge must not rerun"))
        assert __main__.main() == 0 and json.loads(capsys.readouterr().out)["status"] == "finished"
        monkeypatch.setattr(hybrid_module, "LocalQueryEncoder", FakeEncoder)
        failed_id = uuid4()
        class BrokenHybrid:
            def __init__(self, session, *, encoder): pass
            def search(self, query, *, limit): raise ValueError("synthetic retrieval failure")
        monkeypatch.setattr(hybrid_module, "PostgresHybridRetriever", BrokenHybrid)
        failed_args = ["vulnmind", "workflow-scan", "--workflow-id", str(failed_id), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file), "--knowledge-context", "--staged-knowledge"]
        monkeypatch.setattr(sys, "argv", failed_args)
        assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
        with Session(engine) as session:
            failed = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == failed_id,
                                                                    WorkflowOperation.stage == "knowledge_context"))
            scan_stage = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == failed_id,
                                                                        WorkflowOperation.stage == "repository_scan"))
            assert failed.status == "started" and scan_stage.status == "completed"
            assert session.get(Scan, UUID(scan_stage.result_ref)) is not None
            assert trace_scan_audit(session.connection(), failed.id)["outcome"] == "failed"
        monkeypatch.setattr(hybrid_module, "LocalQueryEncoder", lambda: pytest.fail("must reuse saved manifest"))
        monkeypatch.setattr(hybrid_module, "PostgresHybridRetriever", lambda *a, **k: pytest.fail("must not retrieve twice"))
        assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
        # An audit failure must roll back the manifest and completed receipt.
        from vulnmind.persistence.audit import AuditError, SessionAuditSink
        monkeypatch.setattr(hybrid_module, "LocalQueryEncoder", FakeEncoder)
        monkeypatch.setattr(hybrid_module, "PostgresHybridRetriever", FakeHybrid)
        original_record = SessionAuditSink.record
        def fail_knowledge_audit(self, event):
            if event["tool_name"] == "repository.knowledge.transaction" and event["status"] == "succeeded":
                raise AuditError("synthetic knowledge audit failure")
            return original_record(self, event)
        monkeypatch.setattr(SessionAuditSink, "record", fail_knowledge_audit)
        audit_fail_id = uuid4()
        monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(audit_fail_id),
            "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
            "--knowledge-context", "--staged-knowledge"])
        assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
        monkeypatch.setattr(SessionAuditSink, "record", original_record)
        with Session(engine) as session:
            operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == audit_fail_id,
                                                                       WorkflowOperation.stage == "knowledge_context"))
            assert operation.status == "started" and operation.result_ref is None
            assert len(session.scalars(select(ContextManifestRecord)).all()) == 4
        monkeypatch.setattr(hybrid_module, "LocalQueryEncoder", lambda: pytest.fail("must reuse saved manifest"))
        monkeypatch.setattr(hybrid_module, "PostgresHybridRetriever", lambda *a, **k: pytest.fail("must not retrieve twice"))
        monkeypatch.setattr(sys, "argv", initial_args)
        assert __main__.main() == 0
        assert UUID(json.loads(capsys.readouterr().out)["scan_id"]) == scan_id
        with Session(engine) as session:
            assert len(session.scalars(select(Scan)).all()) == 6
            assert len(session.scalars(select(ContextManifestRecord)).all()) == 4
        # A manifest changed after commit cannot be treated as a verified receipt.
        with Session(engine) as session, session.begin():
            manifest = session.get(ContextManifestRecord, manifest.id)
            manifest.selected_refs = {**manifest.selected_refs, "retrieval_status": "empty"}
        assert __main__.main() == 2
        assert json.loads(capsys.readouterr().out)["status"] == "unknown"
        monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-context", "--workflow-id", str(workflow_id)])
        assert __main__.main() == 2
        assert json.loads(capsys.readouterr().out)["status"] == "blocked"
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()
