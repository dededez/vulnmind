import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from vulnmind.persistence.models import WorkflowOperation
from vulnmind.persistence.workflow_operations import claim_stage, complete_stage


@pytest.mark.skipif(not os.getenv("VULNMIND_TEST_DATABASE_URL"), reason="dedicated PostgreSQL not configured")
def test_postgres_concurrent_claim_and_recovery():
    url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
    if url.get_backend_name() != "postgresql":
        pytest.fail("dedicated PostgreSQL is required")
    schema = "vulnmind_workflow_" + uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(url.update_query_dict({"options": f"-csearch_path={schema},public"}))
    try:
        WorkflowOperation.__table__.create(engine)
        workflow_id = uuid4()
        with ThreadPoolExecutor(max_workers=8) as pool:
            claims = list(pool.map(lambda _: claim_stage(engine, workflow_id=workflow_id,
                                                        stage="scan", input_digest="f" * 64), range(8)))
        owners = [item for item in claims if item.status == "claimed"]
        assert len(owners) == 1 and sum(item.status == "unknown" for item in claims) == 7
        result_id = uuid4()
        complete_stage(engine, operation_id=owners[0].operation_id,
                       owner_token=owners[0].owner_token, result_id=result_id)
        assert claim_stage(engine, workflow_id=workflow_id, stage="scan", input_digest="f" * 64).result_id == result_id
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.mark.skipif(not os.getenv("VULNMIND_TEST_DATABASE_URL"), reason="dedicated PostgreSQL not configured")
def test_migration_refuses_to_discard_claim_history(monkeypatch):
    from pathlib import Path
    from alembic import command
    from alembic.config import Config

    url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
    if url.get_backend_name() != "postgresql":
        pytest.fail("dedicated PostgreSQL is required")
    schema = "vulnmind_workflow_migration_" + uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = url.update_query_dict({"options": f"-csearch_path={schema},public"})
    monkeypatch.setenv("VULNMIND_DATABASE_URL", scoped.render_as_string(hide_password=False))
    project = Path(__file__).resolve().parents[2]
    config = Config(str(project / "alembic.ini"))
    config.set_main_option("script_location", str(project / "migrations"))
    engine = create_engine(scoped)
    try:
        command.upgrade(config, "head")
        workflow_id = uuid4()
        claim_stage(engine, workflow_id=workflow_id, stage="scan", input_digest="e" * 64)
        with pytest.raises(RuntimeError, match="refusing to discard workflow operation history"):
            command.downgrade(config, "0014_embedding_dimension")
        from vulnmind.agents.model import ModelResponse
        from vulnmind.persistence.workflow_plans import execute_tool_plan
        planning = claim_stage(engine, workflow_id=uuid4(), stage="repository_plan", input_digest="a" * 64)
        with pytest.raises(RuntimeError, match="refusing to discard workflow tool plans or planning claims"):
            command.downgrade(config, "0015_workflow_operations")
        class FakeClient:
            def complete(self, request):
                return ModelResponse(text='{"selected_tools": []}')
        execute_tool_plan(engine, operation_id=planning.operation_id, owner_token=planning.owner_token,
                          input_digest="a" * 64, enabled={"gitleaks_sandbox"}, actor="test", client=FakeClient())
        with pytest.raises(RuntimeError, match="refusing to discard workflow tool plans or planning claims"):
            command.downgrade(config, "0015_workflow_operations")
        assert claim_stage(engine, workflow_id=workflow_id, stage="scan", input_digest="e" * 64).status == "unknown"
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.mark.skipif(not os.getenv("VULNMIND_TEST_DATABASE_URL"), reason="dedicated PostgreSQL not configured")
def test_project_create_commits_project_and_audit_in_postgres(monkeypatch, capsys):
    import json
    import sys
    from uuid import UUID
    from sqlalchemy import select
    from sqlalchemy.orm import Session
    from vulnmind import __main__
    from vulnmind.persistence.models import AuditEvent, Project

    url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
    if url.get_backend_name() != "postgresql":
        pytest.fail("dedicated PostgreSQL is required")
    schema = "vulnmind_project_" + uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = url.update_query_dict({"options": f"-csearch_path={schema},public"})
    engine = create_engine(scoped)
    try:
        Project.__table__.create(engine)
        AuditEvent.__table__.create(engine)
        monkeypatch.setenv("VULNMIND_DATABASE_URL", scoped.render_as_string(hide_password=False))
        monkeypatch.setattr(sys, "argv", ["vulnmind", "project-create", "--name", "PG integration"])
        assert __main__.main() == 0
        project_id = UUID(json.loads(capsys.readouterr().out)["project_id"])
        with Session(engine) as session:
            assert session.get(Project, project_id).name == "PG integration"
            assert session.scalar(select(AuditEvent).where(AuditEvent.call_id == project_id)) is not None
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.mark.skipif(not os.getenv("VULNMIND_TEST_DATABASE_URL"), reason="dedicated PostgreSQL not configured")
def test_workflow_scan_cli_real_postgres_is_idempotent(monkeypatch, capsys, tmp_path):
    import json
    import subprocess
    import sys
    from datetime import datetime, timedelta, timezone
    from uuid import UUID
    from sqlalchemy import select
    from sqlalchemy.orm import Session
    from vulnmind import __main__
    from vulnmind.persistence.base import Base
    from vulnmind.persistence.models import AuditEvent, Finding, Project, Scan

    url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
    if url.get_backend_name() != "postgresql":
        pytest.fail("dedicated PostgreSQL is required")
    schema = "vulnmind_workflow_cli_" + uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = url.update_query_dict({"options": f"-csearch_path={schema},public"})
    engine = create_engine(scoped)
    try:
        Base.metadata.create_all(engine)
        project_id, workflow_id = uuid4(), uuid4()
        with Session(engine) as session, session.begin():
            session.add(Project(id=project_id, name="workflow PG test"))
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("import requests\nrequests.get('https://example.test', verify=False)\n", encoding="utf-8")
        now = datetime.now(timezone.utc)
        scope = {"authorization_source": "test", "approved_by": "owner",
                 "starts_at": (now - timedelta(hours=1)).isoformat(),
                 "expires_at": (now + timedelta(hours=1)).isoformat(), "repository_roots": [str(repo)]}
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(json.dumps(scope), encoding="utf-8")
        monkeypatch.setenv("VULNMIND_DATABASE_URL", scoped.render_as_string(hide_password=False))
        monkeypatch.setenv("VULNMIND_REPORT_ROOT", str(tmp_path / "reports"))
        monkeypatch.setenv("VULNMIND_EVIDENCE_ROOT", "")
        monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id),
            "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file)])
        assert __main__.main() == 0
        first = json.loads(capsys.readouterr().out)
        assert __main__.main() == 0
        second = json.loads(capsys.readouterr().out)
        assert first["scan_id"] == second["scan_id"]
        scan_id = UUID(first["scan_id"])
        with Session(engine) as session:
            assert len(session.scalars(select(Scan)).all()) == 1
            assert len(session.scalars(select(Finding)).all()) == 1
            assert session.scalar(select(AuditEvent).where(
                AuditEvent.tool_name == "repository.scan.transaction", AuditEvent.call_id == scan_id)) is not None
        # Two independent CLI processes race for a new workflow. Only one
        # may execute; the other may observe either unknown or completion.
        concurrent_id = uuid4()
        args = [sys.executable, "-m", "vulnmind", "workflow-scan", "--workflow-id", str(concurrent_id),
                "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file)]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(__import__("pathlib").Path(__file__).resolve().parents[2] / "src")
        with ThreadPoolExecutor(max_workers=2) as pool:
            processes = list(pool.map(lambda _: subprocess.run(args, capture_output=True, text=True,
                                                               env=env, timeout=60), range(2)))
        responses = [json.loads(process.stdout) for process in processes]
        assert all(item["status"] in {"finished", "unknown"} for item in responses)
        assert any(item["status"] == "finished" for item in responses)
        with Session(engine) as session:
            assert len(session.scalars(select(Scan)).all()) == 2
        # Planner is confined to explicitly enabled tools; rejected output is
        # audited outside the rolled-back scan business transaction.
        from vulnmind.agents import deepseek
        from vulnmind.agents.model import ModelResponse
        class FakePlanner:
            def __init__(self, **kwargs):
                pass
            def complete(self, request):
                return ModelResponse(text=json.dumps({"selected_tools": ["trivy_sandbox"]}))
        monkeypatch.setattr(deepseek, "DeepSeekClient", FakePlanner)
        rejected_id = uuid4()
        monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(rejected_id),
            "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
            "--gitleaks-sandbox", "--agent-plan"])
        assert __main__.main() == 2
        assert json.loads(capsys.readouterr().out)["status"] == "unknown"
        with Session(engine) as session:
            from vulnmind.persistence.models import WorkflowOperation
            operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == rejected_id))
            assert operation.status == "started" and session.get(Scan, operation.id) is None
            statuses = session.scalars(select(AuditEvent.status).where(
                AuditEvent.tool_name == "repository.plan.selection").order_by(AuditEvent.created_at)).all()
            assert statuses == ["requested", "failed"]
        # A terminal planning audit error must roll back the plan receipt and
        # completion together, while retaining the initial started claim.
        from vulnmind.persistence.audit import AuditError, SessionAuditSink
        from vulnmind.persistence.models import WorkflowToolPlan
        class GoodPlanner:
            def __init__(self, **kwargs): pass
            def complete(self, request): return ModelResponse(text='{"selected_tools": []}')
        monkeypatch.setattr(deepseek, "DeepSeekClient", GoodPlanner)
        original_audit_record = SessionAuditSink.record
        def fail_plan_terminal(self, event):
            if event["tool_name"] == "repository.plan.transaction" and event["status"] == "succeeded":
                raise AuditError("synthetic plan audit failure")
            return original_audit_record(self, event)
        monkeypatch.setattr(SessionAuditSink, "record", fail_plan_terminal)
        failure_id = uuid4()
        monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(failure_id),
            "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
            "--gitleaks-sandbox", "--agent-plan"])
        assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
        monkeypatch.setattr(SessionAuditSink, "record", original_audit_record)
        with Session(engine) as session:
            operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == failure_id))
            assert operation.status == "started" and operation.stage == "repository_plan"
            assert session.scalar(select(WorkflowToolPlan).where(WorkflowToolPlan.operation_id == operation.id)) is None
        # Exercise persisted context plus model guidance without a network or
        # real embedding model. Retrieval and model responses are test doubles.
        from vulnmind.knowledge.ingestion import ingest_document
        from vulnmind.knowledge import hybrid as hybrid_module
        from vulnmind.persistence.models import ContextManifestRecord, KnowledgeChunk, Report
        with Session(engine) as session, session.begin():
            document = ingest_document(session, title="synthetic TLS guidance", source_type="reference",
                content="tls certificate verification prevents interception", size=500, overlap=0)
            session.flush()
            chunk_id = str(session.scalar(select(KnowledgeChunk.id).where(
                KnowledgeChunk.document_id == document.document_id)))
        class FakeEncoder:
            pass
        class FakeHybrid:
            def __init__(self, session, *, encoder):
                pass
            def search(self, query, *, limit):
                return [chunk_id]
        class FakeKnowledgeClient:
            def __init__(self, **kwargs):
                pass
            def complete(self, request):
                prompt = " ".join(message.content for message in request.messages)
                assert str(repo) not in prompt
                result = ({"relevant": True, "supported": True, "conflicting": False}
                    if "Independently assess" in prompt else
                    {"answer": "tls certificate verification", "cited_refs": ["knowledge:0"],
                     "supporting_quotes": [{"ref": "knowledge:0", "quote": "tls certificate verification"}]}
                    if "cited_refs" in prompt else {"summary": "review", "items": []})
                return ModelResponse(text=json.dumps(result))
        monkeypatch.setattr(hybrid_module, "LocalQueryEncoder", FakeEncoder)
        monkeypatch.setattr(hybrid_module, "PostgresHybridRetriever", FakeHybrid)
        monkeypatch.setattr(deepseek, "DeepSeekClient", FakeKnowledgeClient)
        knowledge_id = uuid4()
        monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(knowledge_id),
            "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
            "--knowledge-context", "--agent-knowledge", "--agent-review", "--report-format", "json"])
        assert __main__.main() == 0
        knowledge_scan_id = UUID(json.loads(capsys.readouterr().out)["scan_id"])
        with Session(engine) as session:
            manifest = session.scalar(select(ContextManifestRecord).where(
                ContextManifestRecord.selected_refs.is_not(None)))
            assert manifest is not None and manifest.selected_refs["retrieval_status"] == "matched"
            report = session.scalar(select(Report).where(Report.scan_id == knowledge_scan_id))
            content = json.loads((tmp_path / "reports" / report.storage_uri).read_text(encoding="utf-8"))
            assert content["knowledge_review"]["status"] == "answered"
            assert content["knowledge_review"]["review_status"] == "accepted"
        # Recovery of a committed scan with an independently verified audit.
        import vulnmind.graph.guarded_repository_workflow as guarded
        monkeypatch.setattr(guarded, "complete_stage", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError()))
        recovery_id = uuid4()
        recovery_args = ["vulnmind", "workflow-scan", "--workflow-id", str(recovery_id),
            "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file)]
        monkeypatch.setattr(sys, "argv", recovery_args)
        assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
        monkeypatch.setattr(sys, "argv", [*recovery_args, "--reconcile"])
        assert __main__.main() == 0
        recovered_scan_id = UUID(json.loads(capsys.readouterr().out)["scan_id"])
        with Session(engine) as session:
            from vulnmind.persistence.models import WorkflowOperation
            operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == recovery_id))
            assert operation.status == "completed" and operation.id == recovered_scan_id
            assert session.scalar(select(AuditEvent).where(AuditEvent.call_id == recovered_scan_id,
                AuditEvent.tool_name == "workflow.reconcile", AuditEvent.status == "succeeded")) is not None
        # A late writer racing with reconciliation must accept the same
        # receipt, while never accepting a different result.
        from vulnmind.persistence.workflow_operations import complete_stage
        complete_stage(engine, operation_id=operation.id, owner_token=operation.owner_token,
                       result_id=recovered_scan_id)
        with pytest.raises(ValueError):
            complete_stage(engine, operation_id=operation.id, owner_token=operation.owner_token, result_id=uuid4())
        # Concurrent recovery attempts may race, but cannot duplicate the scan
        # or record more than one reconciliation transition.
        race_id = uuid4()
        race_args = ["vulnmind", "workflow-scan", "--workflow-id", str(race_id),
            "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file)]
        monkeypatch.setattr(sys, "argv", race_args)
        assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
        with Session(engine) as session:
            row = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == race_id))
            operation_id, digest = row.id, row.input_digest
        from vulnmind.persistence.workflow_reconcile import reconcile_repository_scan
        from vulnmind.persistence.audit import AuditError, SessionAuditSink
        original_record = SessionAuditSink.record
        def fail_recovery_audit(self, event):
            if event["tool_name"] == "workflow.reconcile":
                raise AuditError("synthetic recovery audit failure")
            return original_record(self, event)
        monkeypatch.setattr(SessionAuditSink, "record", fail_recovery_audit)
        monkeypatch.setattr(sys, "argv", [*race_args, "--reconcile"])
        assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
        with Session(engine) as session:
            assert session.get(WorkflowOperation, operation_id).status == "started"
        monkeypatch.setattr(SessionAuditSink, "record", original_record)
        def reconcile(_):
            return reconcile_repository_scan(engine, workflow_id=race_id, operation_id=operation_id,
                input_digest=digest, project_id=project_id, report_root=tmp_path / "reports", actor="cli")
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(reconcile, range(2)))
        assert any(outcomes)
        with Session(engine) as session:
            row = session.get(WorkflowOperation, operation_id)
            assert row.status == "completed" and row.result_ref == str(operation_id)
            events = session.scalars(select(AuditEvent).where(AuditEvent.call_id == operation_id,
                AuditEvent.tool_name == "workflow.reconcile")).all()
            assert len(events) == 1
        # Two independent workers race for a planner. A committed plan is
        # shared, and an in-flight plan is never repeated by the loser.
        marker = tmp_path / "model-calls.txt"
        model_env = os.environ.copy()
        model_env["PYTHONPATH"] = str(__import__("pathlib").Path(__file__).resolve().parents[2] / "src")
        model_env["VULNMIND_TEST_MARKER"] = str(marker)
        plan_id = uuid4()
        args = ["workflow-scan", "--workflow-id", str(plan_id), "--project-id", str(project_id),
                "--repository", str(repo), "--scope-file", str(scope_file), "--gitleaks-sandbox", "--agent-plan"]
        script = """import json, os, sys, time
from pathlib import Path
from vulnmind import __main__
from vulnmind.agents import deepseek
from vulnmind.agents.model import ModelResponse
class FakeClient:
 def __init__(self, **kwargs): pass
 def complete(self, request):
  with Path(os.environ['VULNMIND_TEST_MARKER']).open('a', encoding='utf-8') as f: f.write('call\\n')
  time.sleep(1)
  return ModelResponse(text=json.dumps({'selected_tools': []}))
deepseek.DeepSeekClient = FakeClient
sys.argv = ['vulnmind'] + sys.argv[1:]
raise SystemExit(__main__.main())
"""
        with ThreadPoolExecutor(max_workers=2) as pool:
            processes = list(pool.map(lambda _: subprocess.run([sys.executable, "-c", script, *args],
                capture_output=True, text=True, env=model_env, timeout=90), range(2)))
        results = [json.loads(item.stdout) for item in processes]
        assert all(item["status"] in {"finished", "unknown"} for item in results)
        assert any(item["status"] == "finished" for item in results)
        assert marker.read_text(encoding="utf-8").splitlines() == ["call"]
        with Session(engine) as session:
            stages = session.scalars(select(WorkflowOperation).where(WorkflowOperation.workflow_id == plan_id)).all()
            assert {item.stage for item in stages} == {"repository_plan", "repository_scan"}
            assert all(item.status == "completed" for item in stages)
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()
