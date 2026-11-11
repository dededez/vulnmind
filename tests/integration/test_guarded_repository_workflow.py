from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from sqlalchemy import create_engine

from vulnmind.graph.guarded_repository_workflow import build_guarded_repository_graph
from vulnmind.persistence.models import WorkflowOperation
from vulnmind.schemas import Authorization, Target


@pytest.fixture
def setup_workflow(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'workflow.db').as_posix()}")
    WorkflowOperation.__table__.create(engine)
    repo = tmp_path / "repo"
    repo.mkdir()
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner",
                          starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                          repository_roots=[str(repo)])
    state = {"task_id": str(uuid4()), "project_id": str(uuid4()),
             "targets": [Target(type="repository", locator=str(repo)).model_dump(mode="json")],
             "authorized_scope": scope.model_dump(mode="json"), "workflow_options": {"tools": ["tls"]}}
    yield engine, state
    engine.dispose()


def test_replay_recovers_committed_scan_without_reexecution(setup_workflow):
    engine, state = setup_workflow
    calls = []
    result_id = uuid4()
    def execute(request):
        calls.append(request)
        return result_id
    graph = build_guarded_repository_graph(engine, execute, InMemorySaver())
    config = {"configurable": {"thread_id": "test"}}
    assert graph.invoke(state, config)["report"] == {"scan_id": str(result_id)}
    assert graph.invoke(state, config)["report"] == {"scan_id": str(result_id)}
    assert len(calls) == 1
    changed = {**state, "workflow_options": {"tools": ["other"]}}
    assert graph.invoke(changed, config)["status"] == "blocked"
    assert len(calls) == 1


def test_failed_or_uncertain_execution_is_not_automatically_repeated(setup_workflow):
    engine, state = setup_workflow
    calls = []
    def execute(request):
        calls.append(request)
        raise RuntimeError("private detail")
    graph = build_guarded_repository_graph(engine, execute)
    first = graph.invoke(state)
    second = graph.invoke(state)
    assert first["status"] == second["status"] == "unknown"
    assert "private detail" not in str(first) and len(calls) == 1


def test_expired_authorization_never_invokes_executor(setup_workflow):
    engine, state = setup_workflow
    state["authorized_scope"]["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    def execute(_):
        pytest.fail("executor must not be called")
    assert build_guarded_repository_graph(engine, execute).invoke(state)["status"] == "blocked"


def test_report_verification_retries_without_repeating_scan(setup_workflow):
    engine, state = setup_workflow
    calls, checks = [], []
    scan_id = uuid4()
    def execute(_):
        calls.append(True)
        return scan_id
    def verify(_, identifier):
        checks.append(identifier)
        return len(checks) > 1
    workflow = build_guarded_repository_graph(engine, execute, report_verifier=verify)
    first = workflow.invoke(state)
    second = workflow.invoke(state)
    assert first["status"] == "unknown" and not first["report"]
    assert second["status"] == "finished" and second["report"]["scan_id"] == str(scan_id)
    assert len(calls) == 1 and checks == [scan_id, scan_id]


def test_report_verification_rechecks_scope_after_scan(setup_workflow):
    engine, state = setup_workflow
    checks = []
    def execute(request):
        # Simulate authorization expiry while the scan is running.
        state["authorized_scope"]["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        request["authorized_scope"]["expires_at"] = state["authorized_scope"]["expires_at"]
        return uuid4()
    def verify(*args):
        checks.append(True)
        return True
    result = build_guarded_repository_graph(engine, execute, report_verifier=verify).invoke(state)
    assert result["status"] == "unknown" and not checks


def test_knowledge_stage_recovers_committed_receipt_without_repeating_work(setup_workflow):
    from vulnmind.persistence.workflow_operations import complete_stage
    engine, state = setup_workflow
    calls = []
    scan_id, manifest_id = uuid4(), uuid4()
    def scan(_):
        calls.append("scan")
        return scan_id
    def prepare(_):
        calls.append("prepare")
    def execute(_, operation_id, token, digest, actual_scan):
        calls.append("knowledge")
        assert actual_scan == scan_id
        complete_stage(engine, operation_id=operation_id, owner_token=token, result_id=manifest_id)
        raise RuntimeError("synthetic lost acknowledgement")
    def verify(_, operation_id, actual_manifest, digest, actual_scan):
        calls.append("verify")
        return actual_manifest == manifest_id and actual_scan == scan_id
    graph = build_guarded_repository_graph(engine, scan, report_verifier=lambda *_: True,
        knowledge_executor=execute, knowledge_prepare=prepare, knowledge_verifier=verify)
    assert graph.invoke(state)["status"] == "unknown"
    assert graph.invoke(state)["status"] == "finished"
    assert calls == ["scan", "prepare", "knowledge", "verify"]


def test_reconcile_never_starts_missing_knowledge_stage(setup_workflow):
    engine, state = setup_workflow
    scan_id = uuid4()
    initial = build_guarded_repository_graph(engine, lambda _: scan_id)
    assert initial.invoke(state)["status"] == "finished"
    def forbidden(*args):
        pytest.fail("reconciliation must not start knowledge work")
    graph = build_guarded_repository_graph(engine, forbidden, reconcile_only=True, reconciler=forbidden,
        report_verifier=lambda *_: True, knowledge_executor=forbidden, knowledge_prepare=forbidden,
        knowledge_verifier=forbidden)
    assert graph.invoke(state)["status"] == "unknown"


def test_final_report_check_repeats_without_repeating_knowledge_or_scan(setup_workflow):
    from vulnmind.persistence.workflow_operations import complete_stage
    engine, state = setup_workflow
    calls = []
    scan_id, manifest_id = uuid4(), uuid4()
    def scan(_):
        calls.append("scan")
        return scan_id
    def execute(_, operation_id, token, digest, actual_scan):
        calls.append("knowledge")
        complete_stage(engine, operation_id=operation_id, owner_token=token, result_id=manifest_id)
        return manifest_id
    checks = []
    def report(*_):
        checks.append(True)
        return len(checks) != 2  # Report changes while knowledge stage is running.
    graph = build_guarded_repository_graph(engine, scan, report_verifier=report,
        knowledge_executor=execute, knowledge_verifier=lambda *_: True)
    assert graph.invoke(state)["status"] == "unknown"
    assert graph.invoke(state)["status"] == "finished"
    assert calls == ["scan", "knowledge"] and len(checks) == 4


def test_guarded_graph_runs_real_repository_service_once(tmp_path):
    from uuid import UUID
    from sqlalchemy import select
    from sqlalchemy.orm import Session
    from vulnmind.analysis.orchestrator import ScanOrchestrator, ScanRunRequest
    from vulnmind.analysis.python_tls import find_python_tls_candidates
    from vulnmind.persistence.audit import SessionAuditSink
    from vulnmind.persistence.base import Base
    from vulnmind.persistence.models import Finding, Project, Scan
    from vulnmind.reports.store import ReportStore

    engine = create_engine(f"sqlite:///{(tmp_path / 'real.db').as_posix()}")
    Base.metadata.create_all(engine)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import requests\nrequests.get('https://example.test', verify=False)\n", encoding="utf-8")
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner",
                          starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                          repository_roots=[str(repo)])
    project_id, workflow_id = uuid4(), uuid4()
    with Session(engine) as session, session.begin():
        session.add(Project(id=project_id, name="guarded graph test"))
    state = {"task_id": str(workflow_id), "project_id": str(project_id),
             "targets": [Target(type="repository", locator=str(repo)).model_dump(mode="json")],
             "authorized_scope": scope.model_dump(mode="json"), "workflow_options": {"tools": ["tls"]}}
    def execute(current):
        with Session(engine) as session, session.begin():
            service = ScanOrchestrator(session, SessionAuditSink(session), [find_python_tls_candidates],
                                       ReportStore(tmp_path / "reports"))
            outcome = service.run(ScanRunRequest(project_id=UUID(current["project_id"]), actor="test",
                target=Target.model_validate(current["targets"][0]),
                scope=Authorization.model_validate(current["authorized_scope"])))
            scan_id = outcome.scan_id
        return scan_id  # only after the scan transaction commits
    try:
        graph = build_guarded_repository_graph(engine, execute)
        first = graph.invoke(state)
        second = graph.invoke(state)
        assert first["status"] == second["status"] == "finished"
        assert first["report"] == second["report"]
        with Session(engine) as session:
            assert len(session.scalars(select(Scan)).all()) == 1
            assert len(session.scalars(select(Finding)).all()) == 1
    finally:
        engine.dispose()
