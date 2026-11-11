"""CLI scan tests: built-in repository analysis end-to-end against SQLite."""
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Finding, Project, Scan
from vulnmind.persistence.unit_of_work import transaction


@pytest.fixture
def workspace(tmp_path):
    database = tmp_path / "scan.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "client.py").write_bytes(
        b"import requests\n\n\ndef fetch(url):\n    return requests.get(url, verify=False)\n")
    (repo / "pkg" / "safe.py").write_bytes(b"import httpx\n\n\ndef ok(url):\n    return httpx.get(url)\n")
    (repo / "README.md").write_bytes(b"# demo\n")
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="cli scan")
        session.add(project)
        session.flush()
        project_id = project.id
    engine.dispose()
    now = datetime.now(timezone.utc)
    scope = {"authorization_source": "local test authorization", "approved_by": "owner",
             "starts_at": (now - timedelta(hours=1)).isoformat(),
             "expires_at": (now + timedelta(hours=1)).isoformat(),
             "repository_roots": [str(repo)]}
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(scope), encoding="utf-8")
    return database, repo, project_id, scope_file


def run_scan(*arguments, env_overrides):
    env = os.environ.copy()
    env.update(env_overrides)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-m", "vulnmind", "scan", *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=60)


def env_for(workspace, tmp_path):
    database, _, _, _ = workspace
    return {"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
            "VULNMIND_REPORT_ROOT": str(tmp_path / "reports")}


def test_project_create_to_scan_and_feedback(workspace, tmp_path):
    database, repo, _, scope_file = workspace
    env = os.environ.copy()
    env.update(env_for(workspace, tmp_path))
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"

    def cli(*args):
        return subprocess.run([sys.executable, "-m", "vulnmind", *map(str, args)],
                              capture_output=True, encoding="utf-8", env=env, timeout=60)

    created = cli("project-create", "--name", "MVP test")
    assert created.returncode == 0, created.stdout + created.stderr
    project_id = json.loads(created.stdout)["project_id"]
    result = cli("scan", "--repository", repo, "--project-id", project_id, "--scope-file", scope_file)
    assert result.returncode == 0, result.stdout + result.stderr
    scan_id = json.loads(result.stdout)["scan_id"]
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        from vulnmind.persistence.models import AuditEvent
        finding = session.scalar(select(Finding).where(Finding.scan_id == __import__("uuid").UUID(scan_id)))
        fingerprint = finding.fingerprint
        assert session.scalar(select(AuditEvent).where(AuditEvent.tool_name == "project.create")) is not None
    engine.dispose()
    feedback = cli("finding-feedback", "--scan-id", scan_id, "--fingerprint", fingerprint,
                   "--verdict", "needs_more_info")
    assert feedback.returncode == 0, feedback.stdout + feedback.stderr
    regenerated = cli("report-regenerate", "--scan-id", scan_id)
    assert regenerated.returncode == 0, regenerated.stdout + regenerated.stderr
    report = cli("report", "--scan-id", scan_id)
    assert report.returncode == 0 and "人工复核" in report.stdout


def test_project_create_rejects_invalid_name_without_creating_rows(workspace, tmp_path):
    database, _, _, _ = workspace
    env = os.environ.copy()
    env.update(env_for(workspace, tmp_path))
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    result = subprocess.run([sys.executable, "-m", "vulnmind", "project-create", "--name", "bad\nname"],
                            capture_output=True, encoding="utf-8", env=env, timeout=30)
    assert result.returncode == 2 and json.loads(result.stdout)["status"] == "blocked"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert len(session.scalars(select(Project)).all()) == 1
    engine.dispose()


def test_project_create_rolls_back_if_audit_is_unavailable(tmp_path):
    database = tmp_path / "missing-audit.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Project.__table__.create(engine)
    env = os.environ.copy()
    env["VULNMIND_DATABASE_URL"] = f"sqlite:///{database.as_posix()}"
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    result = subprocess.run([sys.executable, "-m", "vulnmind", "project-create", "--name", "test"],
                            capture_output=True, encoding="utf-8", env=env, timeout=30)
    assert result.returncode == 2 and json.loads(result.stdout)["status"] == "blocked"
    with sessionmaker(engine)() as session:
        assert session.scalar(select(Project)) is None
    engine.dispose()


def test_workflow_scan_replay_across_processes_and_input_binding(workspace, tmp_path):
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    env = os.environ.copy()
    env.update(env_for(workspace, tmp_path))
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    def cli(*args):
        return subprocess.run([sys.executable, "-m", "vulnmind", *map(str, args)],
                              capture_output=True, encoding="utf-8", env=env, timeout=60)
    args = ("workflow-scan", "--workflow-id", workflow_id, "--project-id", project_id,
            "--repository", repo, "--scope-file", scope_file)
    first, second = cli(*args), cli(*args)
    assert first.returncode == second.returncode == 0, first.stdout + second.stdout + first.stderr + second.stderr
    first_result, second_result = json.loads(first.stdout), json.loads(second.stdout)
    assert first_result["status"] == "finished" and first_result["scan_id"] == second_result["scan_id"]
    changed = cli(*args, "--report-format", "json")
    assert changed.returncode == 2 and json.loads(changed.stdout)["status"] == "blocked"
    status = json.loads(cli("workflow-status", "--workflow-id", workflow_id).stdout)
    operation = status["operations"][0]
    assert operation["status"] == "completed" and operation["result_id"] == first_result["scan_id"]
    assert operation["operation_id"] == operation["result_id"]
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        from vulnmind.persistence.models import AuditEvent
        assert len(session.scalars(select(Scan)).all()) == 1
        assert session.scalar(select(AuditEvent).where(
            AuditEvent.tool_name == "repository.scan.transaction",
            AuditEvent.call_id == __import__("uuid").UUID(operation["operation_id"]))) is not None
    engine.dispose()


def test_workflow_commit_receipt_failure_stays_unknown_and_does_not_repeat(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    import vulnmind.graph.guarded_repository_workflow as guarded
    from vulnmind.persistence.models import WorkflowOperation
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file)])
    def fail_receipt(*args, **kwargs):
        raise RuntimeError("synthetic receipt failure")
    monkeypatch.setattr(guarded, "complete_stage", fail_receipt)
    assert __main__.main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "unknown"
    assert __main__.main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "unknown"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow_id))
        scans = session.scalars(select(Scan)).all()
        assert len(scans) == 1 and scans[0].id == operation.id and operation.status == "started"
    engine.dispose()


def test_workflow_reconciles_verified_committed_scan_without_reexecution(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    import vulnmind.graph.guarded_repository_workflow as guarded
    from vulnmind.persistence.models import AuditEvent, WorkflowOperation
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    args = ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file)]
    monkeypatch.setattr(sys, "argv", args)
    monkeypatch.setattr(guarded, "complete_stage", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError()))
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    monkeypatch.setattr(sys, "argv", [*args, "--reconcile"])
    assert __main__.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "finished"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow_id))
        assert operation.status == "completed" and operation.result_ref == result["scan_id"]
        assert len(session.scalars(select(Scan)).all()) == 1
        assert session.scalar(select(AuditEvent).where(AuditEvent.call_id == operation.id,
            AuditEvent.tool_name == "workflow.reconcile", AuditEvent.status == "succeeded")) is not None
    engine.dispose()


def test_reconcile_unknown_cannot_create_or_execute_a_new_operation(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.persistence.models import WorkflowOperation
    database, repo, project_id, scope_file = workspace
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file), "--reconcile"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "blocked"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert session.scalar(select(WorkflowOperation)) is None and session.scalar(select(Scan)) is None
    engine.dispose()


@pytest.mark.parametrize("damage", ["report", "audit", "unterminated_child"])
def test_workflow_reconcile_rejects_unreliable_evidence(workspace, tmp_path, monkeypatch, capsys, damage):
    from vulnmind import __main__
    import vulnmind.graph.guarded_repository_workflow as guarded
    from vulnmind.persistence.audit import DatabaseAuditSink
    from vulnmind.persistence.models import AuditEvent, Report, WorkflowOperation
    from vulnmind.persistence.scan_audit import CorrelatedAuditSink
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    args = ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file)]
    monkeypatch.setattr(sys, "argv", args)
    monkeypatch.setattr(guarded, "complete_stage", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError()))
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow_id))
        operation_id = operation.id
        report_uri = session.scalar(select(Report).where(Report.scan_id == operation_id)).storage_uri
    if damage == "report":
        (tmp_path / "reports" / report_uri).write_text("tampered", encoding="utf-8")
    elif damage == "audit":
        with sessionmaker(engine).begin() as session:
            event = session.scalar(select(AuditEvent).where(AuditEvent.call_id == operation_id))
            event.actor = "tampered"
    else:
        sink = CorrelatedAuditSink(DatabaseAuditSink(engine), operation_id)
        sink.record({"call_id": str(uuid4()), "tool_name": "synthetic.pending", "actor": "tester",
                     "target_type": "repository", "status": "requested"})
    monkeypatch.setattr(sys, "argv", [*args, "--reconcile"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    with sessionmaker(engine)() as session:
        operation = session.get(WorkflowOperation, operation_id)
        assert operation.status == "started" and len(session.scalars(select(Scan)).all()) == 1
    engine.dispose()


def test_workflow_reconcile_rejects_missing_commit_audit(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.persistence.audit import AuditError, DatabaseAuditSink
    database, repo, project_id, scope_file = workspace
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    original = DatabaseAuditSink.record
    def fail_final(self, event):
        if event["tool_name"] == "repository.scan.transaction" and event["status"] == "succeeded":
            raise AuditError("synthetic audit outage")
        return original(self, event)
    monkeypatch.setattr(DatabaseAuditSink, "record", fail_final)
    args = ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file)]
    monkeypatch.setattr(sys, "argv", args)
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    monkeypatch.setattr(sys, "argv", [*args, "--reconcile"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert len(session.scalars(select(Scan)).all()) == 1
    engine.dispose()


def test_reconcile_rejects_valid_report_from_another_scan(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.persistence.models import Report, WorkflowOperation
    import vulnmind.graph.guarded_repository_workflow as guarded
    database, repo, project_id, scope_file = workspace
    for name, value in env_for(workspace, tmp_path).items(): monkeypatch.setenv(name, value)
    first_workflow = uuid4()
    def args(workflow_id):
        return ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id), "--project-id", str(project_id),
                "--repository", str(repo), "--scope-file", str(scope_file), "--report-format", "json"]
    original_complete = guarded.complete_stage
    monkeypatch.setattr(guarded, "complete_stage", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError()))
    monkeypatch.setattr(sys, "argv", args(first_workflow))
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    monkeypatch.setattr(guarded, "complete_stage", original_complete)
    monkeypatch.setattr(sys, "argv", args(uuid4()))
    assert __main__.main() == 0
    second_scan = __import__("uuid").UUID(json.loads(capsys.readouterr().out)["scan_id"])
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine).begin() as session:
        operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == first_workflow))
        first_report = session.scalar(select(Report).where(Report.scan_id == operation.id))
        second_report = session.scalar(select(Report).where(Report.scan_id == second_scan))
        first_report.storage_uri = second_report.storage_uri
    monkeypatch.setattr(sys, "argv", [*args(first_workflow), "--reconcile"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    with sessionmaker(engine)() as session:
        operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == first_workflow))
        assert operation.status == "started" and len(session.scalars(select(Scan)).all()) == 2
    engine.dispose()


def test_workflow_reconcile_checks_current_authorization(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    import vulnmind.graph.guarded_repository_workflow as guarded
    from vulnmind.persistence.models import WorkflowOperation
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(guarded, "complete_stage", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError()))
    args = ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file)]
    monkeypatch.setattr(sys, "argv", args)
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    scope = json.loads(scope_file.read_text(encoding="utf-8"))
    scope["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    scope_file.write_text(json.dumps(scope), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [*args, "--reconcile"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "blocked"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow_id))
        assert operation.status == "started"
    engine.dispose()


def test_workflow_reconcile_rolls_back_if_audit_write_fails(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    import vulnmind.graph.guarded_repository_workflow as guarded
    from vulnmind.persistence.audit import AuditError, SessionAuditSink
    from vulnmind.persistence.models import WorkflowOperation
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(guarded, "complete_stage", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError()))
    args = ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file)]
    monkeypatch.setattr(sys, "argv", args)
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    original = SessionAuditSink.record
    def fail_reconcile(self, event):
        if event["tool_name"] == "workflow.reconcile":
            raise AuditError("synthetic audit failure")
        return original(self, event)
    monkeypatch.setattr(SessionAuditSink, "record", fail_reconcile)
    monkeypatch.setattr(sys, "argv", [*args, "--reconcile"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow_id))
        assert operation.status == "started" and operation.result_ref is None
    monkeypatch.setattr(SessionAuditSink, "record", original)
    assert __main__.main() == 0 and json.loads(capsys.readouterr().out)["status"] == "finished"
    engine.dispose()


def test_reconcile_rolls_back_if_audit_trace_changes_during_recovery(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    import vulnmind.graph.guarded_repository_workflow as guarded
    import vulnmind.persistence.workflow_reconcile as recovery
    from vulnmind.persistence.models import AuditEvent, WorkflowOperation
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(guarded, "complete_stage", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError()))
    args = ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file)]
    monkeypatch.setattr(sys, "argv", args)
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    original = recovery.trace_scan_audit
    count = []
    def changing_trace(*args, **kwargs):
        trace = original(*args, **kwargs)
        count.append(True)
        if len(count) == 2:
            trace["operations"].append({"call_id": str(uuid4()), "tool_name": "test", "outcome": "unknown"})
        return trace
    monkeypatch.setattr(recovery, "trace_scan_audit", changing_trace)
    monkeypatch.setattr(sys, "argv", [*args, "--reconcile"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow_id))
        assert operation.status == "started"
        assert session.scalar(select(AuditEvent).where(AuditEvent.tool_name == "workflow.reconcile")) is None
    engine.dispose()


def test_reconcile_does_not_initialize_or_call_model(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    import vulnmind.graph.guarded_repository_workflow as guarded
    _, repo, project_id, scope_file = workspace
    calls = []
    class FakeClient:
        def __init__(self, **kwargs):
            calls.append("initialized")
        def complete(self, request):
            calls.append("called")
            return ModelResponse(text=json.dumps({"summary": "review", "items": []}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    monkeypatch.setattr(guarded, "complete_stage", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError()))
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    args = ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file), "--agent-review"]
    monkeypatch.setattr(sys, "argv", args)
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    assert calls == ["initialized", "called"]
    monkeypatch.setattr(sys, "argv", [*args, "--reconcile"])
    assert __main__.main() == 0 and json.loads(capsys.readouterr().out)["status"] == "finished"
    assert calls == ["initialized", "called"]


def test_reconcile_planned_scan_does_not_repeat_model_or_scanner(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    import vulnmind.graph.guarded_repository_workflow as guarded
    _, repo, project_id, scope_file = workspace
    calls = []
    class FakeClient:
        def __init__(self, **kwargs):
            calls.append("initialized")
        def complete(self, request):
            calls.append("called")
            return ModelResponse(text=json.dumps({"selected_tools": []}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    monkeypatch.setattr(guarded, "complete_stage", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError()))
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    args = ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file), "--gitleaks-sandbox", "--agent-plan"]
    monkeypatch.setattr(sys, "argv", args)
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    monkeypatch.setattr(sys, "argv", [*args, "--reconcile"])
    assert __main__.main() == 0 and json.loads(capsys.readouterr().out)["status"] == "finished"
    assert calls == ["initialized", "called"]


def test_reconcile_planned_scan_rejects_tampered_plan(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    from vulnmind.persistence.models import WorkflowToolPlan
    import vulnmind.graph.guarded_repository_workflow as guarded
    database, repo, project_id, scope_file = workspace
    class FakeClient:
        def __init__(self, **kwargs): pass
        def complete(self, request): return ModelResponse(text=json.dumps({"selected_tools": []}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    monkeypatch.setattr(guarded, "complete_stage", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError()))
    for name, value in env_for(workspace, tmp_path).items(): monkeypatch.setenv(name, value)
    args = ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file), "--gitleaks-sandbox", "--agent-plan"]
    monkeypatch.setattr(sys, "argv", args)
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine).begin() as session:
        session.scalar(select(WorkflowToolPlan)).selected_tools = ["gitleaks_sandbox"]
    monkeypatch.setattr(sys, "argv", [*args, "--reconcile"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    engine.dispose()


def test_completed_planned_workflow_rejects_tampered_plan(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    from vulnmind.persistence.models import WorkflowToolPlan
    database, repo, project_id, scope_file = workspace
    class FakeClient:
        def __init__(self, **kwargs): pass
        def complete(self, request): return ModelResponse(text=json.dumps({"selected_tools": []}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    for name, value in env_for(workspace, tmp_path).items(): monkeypatch.setenv(name, value)
    args = ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file), "--gitleaks-sandbox", "--agent-plan"]
    monkeypatch.setattr(sys, "argv", args)
    assert __main__.main() == 0 and json.loads(capsys.readouterr().out)["status"] == "finished"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine).begin() as session:
        session.scalar(select(WorkflowToolPlan)).selected_tools = ["gitleaks_sandbox"]
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    with sessionmaker(engine)() as session:
        assert len(session.scalars(select(Scan)).all()) == 1
    engine.dispose()


def test_workflow_process_death_after_scan_commit_is_recoverable_as_unknown(workspace, tmp_path):
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    env = os.environ.copy()
    env.update(env_for(workspace, tmp_path))
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    args = ["workflow-scan", "--workflow-id", str(workflow_id), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file)]
    script = ("import os,sys; import vulnmind.graph.guarded_repository_workflow as g; "
              "from vulnmind import __main__; "
              "g.complete_stage=lambda *a,**k: os._exit(91); "
              "sys.argv=['vulnmind']+sys.argv[1:]; __main__.main()")
    killed = subprocess.run([sys.executable, "-c", script, *args], capture_output=True, encoding="utf-8", env=env, timeout=60)
    assert killed.returncode == 91, killed.stderr
    replay = subprocess.run([sys.executable, "-m", "vulnmind", *args], capture_output=True, encoding="utf-8", env=env, timeout=60)
    assert replay.returncode == 2 and json.loads(replay.stdout)["status"] == "unknown"
    status = subprocess.run([sys.executable, "-m", "vulnmind", "workflow-status", "--workflow-id", str(workflow_id)],
                            capture_output=True, encoding="utf-8", env=env, timeout=60)
    operation = json.loads(status.stdout)["operations"][0]
    assert operation["status"] == "unknown" and operation["result_id"] is None
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        scans = session.scalars(select(Scan)).all()
        assert len(scans) == 1 and str(scans[0].id) == operation["operation_id"]
    engine.dispose()
    recovered = subprocess.run([sys.executable, "-m", "vulnmind", *args, "--reconcile"],
                               capture_output=True, encoding="utf-8", env=env, timeout=60)
    assert recovered.returncode == 0, recovered.stdout + recovered.stderr
    assert json.loads(recovered.stdout)["scan_id"] == operation["operation_id"]


def test_workflow_replay_rejects_damaged_report_without_new_scan(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.persistence.models import Report
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file)])
    assert __main__.main() == 0
    capsys.readouterr()
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        report = session.scalar(select(Report))
        report_uri = report.storage_uri
    report_path = tmp_path / "reports" / report_uri
    original = report_path.read_bytes()
    report_path.write_text("damaged", encoding="utf-8")
    assert __main__.main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "unknown"
    report_path.write_bytes(original)
    assert __main__.main() == 0
    assert json.loads(capsys.readouterr().out)["status"] == "finished"
    with sessionmaker(engine)() as session:
        assert len(session.scalars(select(Scan)).all()) == 1
    engine.dispose()


@pytest.mark.parametrize("report_format", ["markdown", "json"])
def test_workflow_rejects_valid_report_from_another_scan(workspace, tmp_path, monkeypatch, capsys, report_format):
    from vulnmind import __main__
    from vulnmind.persistence.models import Report
    database, repo, project_id, scope_file = workspace
    for name, value in env_for(workspace, tmp_path).items(): monkeypatch.setenv(name, value)
    def args(workflow_id):
        return ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id), "--project-id", str(project_id),
                "--repository", str(repo), "--scope-file", str(scope_file), "--report-format", report_format]
    workflow1, workflow2 = uuid4(), uuid4()
    monkeypatch.setattr(sys, "argv", args(workflow1))
    assert __main__.main() == 0
    scan1 = __import__("uuid").UUID(json.loads(capsys.readouterr().out)["scan_id"])
    monkeypatch.setattr(sys, "argv", args(workflow2))
    assert __main__.main() == 0
    scan2 = __import__("uuid").UUID(json.loads(capsys.readouterr().out)["scan_id"])
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine).begin() as session:
        first = session.scalar(select(Report).where(Report.scan_id == scan1))
        second = session.scalar(select(Report).where(Report.scan_id == scan2))
        first.storage_uri = second.storage_uri  # Both files have valid content hashes.
    monkeypatch.setattr(sys, "argv", args(workflow1))
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    with sessionmaker(engine)() as session:
        assert len(session.scalars(select(Scan)).all()) == 2
    engine.dispose()


def test_workflow_rejects_receipt_redirected_to_another_scan(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.persistence.models import WorkflowOperation
    database, repo, project_id, scope_file = workspace
    for name, value in env_for(workspace, tmp_path).items(): monkeypatch.setenv(name, value)
    def args(workflow_id):
        return ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id), "--project-id", str(project_id),
                "--repository", str(repo), "--scope-file", str(scope_file)]
    workflow1, workflow2 = uuid4(), uuid4()
    monkeypatch.setattr(sys, "argv", args(workflow1))
    assert __main__.main() == 0
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", args(workflow2))
    assert __main__.main() == 0
    other_scan_id = json.loads(capsys.readouterr().out)["scan_id"]
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine).begin() as session:
        operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow1))
        operation.result_ref = other_scan_id
    monkeypatch.setattr(sys, "argv", args(workflow1))
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    with sessionmaker(engine)() as session:
        assert len(session.scalars(select(Scan)).all()) == 2
    engine.dispose()


def test_workflow_advisory_review_runs_once_and_is_reported(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    from vulnmind.persistence.models import Report
    database, repo, project_id, scope_file = workspace
    requests = []
    class FakeClient:
        def __init__(self, **kwargs):
            pass
        def complete(self, request):
            requests.append(request)
            return ModelResponse(text=json.dumps({"summary": "advisory review", "items": []}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file), "--agent-review"])
    assert __main__.main() == 0
    capsys.readouterr()
    assert __main__.main() == 0
    capsys.readouterr()
    assert len(requests) == 1
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        report = session.scalar(select(Report))
        rendered = (tmp_path / "reports" / report.storage_uri).read_text(encoding="utf-8")
        assert "模型复核" in rendered and "未验证" in rendered
        assert len(session.scalars(select(Scan)).all()) == 1
    engine.dispose()


def test_workflow_planner_omission_is_reported_and_not_reexecuted(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    from vulnmind.persistence.models import Report
    database, repo, project_id, scope_file = workspace
    requests = []
    class FakeClient:
        def __init__(self, **kwargs):
            pass
        def complete(self, request):
            requests.append(request)
            prompt = " ".join(item.content for item in request.messages)
            assert "gitleaks_sandbox" in prompt and str(repo) not in prompt
            return ModelResponse(text=json.dumps({"selected_tools": []}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--gitleaks-sandbox", "--agent-plan"])
    assert __main__.main() == 0
    capsys.readouterr()
    assert __main__.main() == 0
    capsys.readouterr()
    assert len(requests) == 1
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        report = session.scalar(select(Report))
        rendered = (tmp_path / "reports" / report.storage_uri).read_text(encoding="utf-8")
        assert "模型规划未选择用户启用的分析器" in rendered and "gitleaks_sandbox" in rendered.replace("\\", "")
        assert len(session.scalars(select(Scan)).all()) == 1
    engine.dispose()


def test_workflow_planner_cannot_enable_unrequested_scanners(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    database, repo, project_id, scope_file = workspace
    class FakeClient:
        def __init__(self, **kwargs):
            pass
        def complete(self, request):
            return ModelResponse(text=json.dumps({"selected_tools": ["trivy_sandbox"]}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--gitleaks-sandbox", "--agent-plan"])
    assert __main__.main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "unknown"
    assert __main__.main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "unknown"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        from vulnmind.persistence.models import AuditEvent
        assert session.scalar(select(Scan)) is None
        statuses = session.scalars(select(AuditEvent.status).where(
            AuditEvent.tool_name == "repository.plan.selection").order_by(AuditEvent.created_at)).all()
        assert statuses == ["requested", "failed"]
    engine.dispose()


def test_workflow_planner_selected_scanner_runs_once(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    import vulnmind.analysis.repo_analyzers as analyzers
    _, repo, project_id, scope_file = workspace
    calls = []
    class FakeClient:
        def __init__(self, **kwargs):
            pass
        def complete(self, request):
            return ModelResponse(text=json.dumps({"selected_tools": ["gitleaks_sandbox"]}))
    class FakeScanner:
        def __init__(self, *args, **kwargs):
            pass
        def analyze(self, **kwargs):
            calls.append(kwargs)
            return []
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    monkeypatch.setattr(analyzers, "SandboxedGitleaksAnalyzer", FakeScanner)
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--gitleaks-sandbox", "--agent-plan"])
    assert __main__.main() == 0
    capsys.readouterr()
    assert __main__.main() == 0
    capsys.readouterr()
    assert len(calls) == 1 and calls[0]["root"] == repo


def test_workflow_resumes_committed_plan_without_model_access(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    import vulnmind.graph.guarded_repository_workflow as guarded
    from vulnmind.persistence.models import WorkflowOperation, WorkflowToolPlan
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    calls = []
    class FakeClient:
        def __init__(self, **kwargs):
            calls.append("initialized")
        def complete(self, request):
            calls.append("called")
            return ModelResponse(text=json.dumps({"selected_tools": []}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    original_claim = guarded.claim_stage
    def interrupt_scan(*args, **kwargs):
        if kwargs["stage"] == "repository_scan":
            raise RuntimeError("simulated interruption before scan claim")
        return original_claim(*args, **kwargs)
    monkeypatch.setattr(guarded, "claim_stage", interrupt_scan)
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--gitleaks-sandbox", "--agent-plan"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        stages = session.scalars(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow_id)).all()
        assert len(stages) == 1 and stages[0].stage == "repository_plan" and stages[0].status == "completed"
        assert session.scalar(select(WorkflowToolPlan)).selected_tools == []
        assert session.scalar(select(Scan)) is None
        from vulnmind.persistence.audit import trace_scan_audit
        trace = trace_scan_audit(session.connection(), stages[0].id)
        assert trace["outcome"] == "committed" and trace["complete"]
        assert any(item["tool_name"] == "repository.plan.selection" and item["outcome"] == "succeeded"
                   for item in trace["operations"])
    monkeypatch.setattr(guarded, "claim_stage", original_claim)
    monkeypatch.setattr(deepseek, "DeepSeekClient", lambda **kwargs: pytest.fail("model must not be initialized"))
    assert __main__.main() == 0 and json.loads(capsys.readouterr().out)["status"] == "finished"
    assert calls == ["initialized", "called"]
    with sessionmaker(engine)() as session:
        assert len(session.scalars(select(Scan)).all()) == 1
    engine.dispose()


def test_workflow_refuses_tampered_committed_plan(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    import vulnmind.graph.guarded_repository_workflow as guarded
    from vulnmind.persistence.models import WorkflowToolPlan
    database, repo, project_id, scope_file = workspace
    class FakeClient:
        def __init__(self, **kwargs): pass
        def complete(self, request): return ModelResponse(text=json.dumps({"selected_tools": []}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    original_claim = guarded.claim_stage
    def interrupt_scan(*args, **kwargs):
        if kwargs["stage"] == "repository_scan": raise RuntimeError("simulated interruption")
        return original_claim(*args, **kwargs)
    monkeypatch.setattr(guarded, "claim_stage", interrupt_scan)
    for name, value in env_for(workspace, tmp_path).items(): monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--gitleaks-sandbox", "--agent-plan"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine).begin() as session:
        # Even another user-enabled name must not be accepted if it differs
        # from the choice committed to the audit chain.
        session.scalar(select(WorkflowToolPlan)).selected_tools = ["gitleaks_sandbox"]
    monkeypatch.setattr(guarded, "claim_stage", original_claim)
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    with sessionmaker(engine)() as session:
        assert session.scalar(select(Scan)) is None
    engine.dispose()


def test_workflow_rechecks_scope_after_completed_plan(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    import vulnmind.graph.guarded_repository_workflow as guarded
    database, repo, project_id, scope_file = workspace
    class FakeClient:
        def __init__(self, **kwargs): pass
        def complete(self, request): return ModelResponse(text=json.dumps({"selected_tools": []}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    original_claim = guarded.claim_stage
    def interrupt_scan(*args, **kwargs):
        if kwargs["stage"] == "repository_scan": raise RuntimeError("simulated interruption")
        return original_claim(*args, **kwargs)
    monkeypatch.setattr(guarded, "claim_stage", interrupt_scan)
    for name, value in env_for(workspace, tmp_path).items(): monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--gitleaks-sandbox", "--agent-plan"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    scope = json.loads(scope_file.read_text(encoding="utf-8"))
    scope["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    scope_file.write_text(json.dumps(scope), encoding="utf-8")
    monkeypatch.setattr(guarded, "claim_stage", original_claim)
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "blocked"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert session.scalar(select(Scan)) is None
    engine.dispose()


def test_workflow_resumes_plan_after_process_death_without_model_key(workspace, tmp_path):
    from vulnmind.persistence.models import WorkflowOperation
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    env = os.environ.copy()
    env.pop("DEEPSEEK_API_KEY", None)
    env.pop("VULNMIND_DEEPSEEK_API_KEY", None)
    env.update(env_for(workspace, tmp_path))
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    args = ["workflow-scan", "--workflow-id", str(workflow_id), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file), "--gitleaks-sandbox", "--agent-plan"]
    script = """import json, os, sys
from vulnmind import __main__
from vulnmind.agents import deepseek
from vulnmind.agents.model import ModelResponse
import vulnmind.graph.guarded_repository_workflow as graph
class FakeClient:
 def __init__(self, **kwargs): pass
 def complete(self, request): return ModelResponse(text=json.dumps({'selected_tools': []}))
deepseek.DeepSeekClient = FakeClient
original = graph.claim_stage
def die_before_scan(*args, **kwargs):
 if kwargs['stage'] == 'repository_scan': os._exit(92)
 return original(*args, **kwargs)
graph.claim_stage = die_before_scan
sys.argv = ['vulnmind'] + sys.argv[1:]
__main__.main()
"""
    child = subprocess.run([sys.executable, "-c", script, *args], capture_output=True, encoding="utf-8", env=env, timeout=60)
    assert child.returncode == 92, child.stderr
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        operations = session.scalars(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow_id)).all()
        assert len(operations) == 1 and operations[0].stage == "repository_plan" and operations[0].status == "completed"
    resumed = subprocess.run([sys.executable, "-m", "vulnmind", *args], capture_output=True,
                             encoding="utf-8", env=env, timeout=60)
    assert resumed.returncode == 0 and json.loads(resumed.stdout)["status"] == "finished", resumed.stdout + resumed.stderr
    with sessionmaker(engine)() as session:
        assert len(session.scalars(select(Scan)).all()) == 1
    engine.dispose()


def test_workflow_never_repeats_model_call_after_process_death_during_planning(workspace, tmp_path):
    from vulnmind.persistence.models import WorkflowOperation
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    env = os.environ.copy()
    env.pop("DEEPSEEK_API_KEY", None)
    env.pop("VULNMIND_DEEPSEEK_API_KEY", None)
    env.update(env_for(workspace, tmp_path))
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    args = ["workflow-scan", "--workflow-id", str(workflow_id), "--project-id", str(project_id),
            "--repository", str(repo), "--scope-file", str(scope_file), "--gitleaks-sandbox", "--agent-plan"]
    script = """import os, sys
from vulnmind import __main__
from vulnmind.agents import deepseek
class FakeClient:
 def __init__(self, **kwargs): pass
 def complete(self, request): os._exit(93)
deepseek.DeepSeekClient = FakeClient
sys.argv = ['vulnmind'] + sys.argv[1:]
__main__.main()
"""
    child = subprocess.run([sys.executable, "-c", script, *args], capture_output=True, env=env, timeout=60)
    assert child.returncode == 93
    resumed = subprocess.run([sys.executable, "-m", "vulnmind", *args], capture_output=True,
                             encoding="utf-8", env=env, timeout=60)
    assert resumed.returncode == 2 and json.loads(resumed.stdout)["status"] == "unknown"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        operations = session.scalars(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow_id)).all()
        assert len(operations) == 1 and operations[0].stage == "repository_plan" and operations[0].status == "started"
        assert session.scalar(select(Scan)) is None
    engine.dispose()


def test_workflow_planner_configuration_failure_does_not_create_claim(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.persistence.models import WorkflowOperation
    database, repo, project_id, scope_file = workspace
    def unavailable(**kwargs):
        raise ValueError("synthetic missing credential")
    monkeypatch.setattr(deepseek, "DeepSeekClient", unavailable)
    for name, value in env_for(workspace, tmp_path).items(): monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--gitleaks-sandbox", "--agent-plan"])
    assert __main__.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "blocked" and "synthetic" not in str(result)
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert session.scalar(select(WorkflowOperation)) is None
    engine.dispose()


def test_legacy_completed_scan_does_not_create_new_plan(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    from vulnmind.persistence.models import WorkflowOperation, WorkflowToolPlan
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    class FakeClient:
        def __init__(self, **kwargs): pass
        def complete(self, request): return ModelResponse(text=json.dumps({"selected_tools": []}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    for name, value in env_for(workspace, tmp_path).items(): monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--gitleaks-sandbox", "--agent-plan"])
    assert __main__.main() == 0
    first = json.loads(capsys.readouterr().out)
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    # Simulate a pre-0016 completed scan in a disposable test database.
    with sessionmaker(engine).begin() as session:
        plan = session.scalar(select(WorkflowToolPlan))
        operation = session.get(WorkflowOperation, plan.operation_id)
        session.delete(plan)
        session.flush()
        session.delete(operation)
    monkeypatch.setattr(deepseek, "DeepSeekClient", lambda **kwargs: pytest.fail("legacy replay must not call model"))
    assert __main__.main() == 0
    assert json.loads(capsys.readouterr().out)["scan_id"] == first["scan_id"]
    with sessionmaker(engine)() as session:
        assert session.scalar(select(WorkflowToolPlan)) is None
        assert len(session.scalars(select(Scan)).all()) == 1
    engine.dispose()


def test_missing_plan_migration_fails_before_claim_or_model(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.persistence.models import WorkflowOperation, WorkflowToolPlan
    database, repo, project_id, scope_file = workspace
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    WorkflowToolPlan.__table__.drop(engine)  # Disposable test DB only.
    monkeypatch.setattr(deepseek, "DeepSeekClient", lambda **kwargs: pytest.fail("no model initialization"))
    for name, value in env_for(workspace, tmp_path).items(): monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--gitleaks-sandbox", "--agent-plan"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "blocked"
    with sessionmaker(engine)() as session:
        assert session.scalar(select(WorkflowOperation)) is None and session.scalar(select(Scan)) is None
    engine.dispose()


def test_workflow_plan_and_terminal_audit_commit_atomically(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    from vulnmind.persistence.audit import AuditError, SessionAuditSink
    from vulnmind.persistence.models import AuditEvent, WorkflowOperation, WorkflowToolPlan
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    calls = []
    class FakeClient:
        def __init__(self, **kwargs): pass
        def complete(self, request):
            calls.append(True)
            return ModelResponse(text=json.dumps({"selected_tools": []}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    original = SessionAuditSink.record
    def fail_plan_commit(self, event):
        if event["tool_name"] == "repository.plan.transaction" and event["status"] == "succeeded":
            raise AuditError("synthetic plan audit failure")
        return original(self, event)
    monkeypatch.setattr(SessionAuditSink, "record", fail_plan_commit)
    for name, value in env_for(workspace, tmp_path).items(): monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--gitleaks-sandbox", "--agent-plan"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    assert len(calls) == 1
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow_id))
        assert operation.stage == "repository_plan" and operation.status == "started"
        assert session.scalar(select(WorkflowToolPlan)) is None and session.scalar(select(Scan)) is None
        statuses = session.scalars(select(AuditEvent.status).where(
            AuditEvent.call_id == operation.id, AuditEvent.tool_name == "repository.plan.transaction"
        ).order_by(AuditEvent.created_at)).all()
        assert statuses == ["requested", "failed"]
    engine.dispose()


def test_planner_rejects_request_digest_changed_during_model_call(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    from vulnmind.persistence.models import WorkflowOperation, WorkflowToolPlan
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    class TamperingClient:
        def __init__(self, **kwargs): pass
        def complete(self, request):
            with sessionmaker(engine).begin() as session:
                row = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow_id))
                row.input_digest = "f" * 64
            return ModelResponse(text='{"selected_tools": []}')
    monkeypatch.setattr(deepseek, "DeepSeekClient", TamperingClient)
    for name, value in env_for(workspace, tmp_path).items(): monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--gitleaks-sandbox", "--agent-plan"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    with sessionmaker(engine)() as session:
        assert session.scalar(select(WorkflowToolPlan)) is None and session.scalar(select(Scan)) is None
        assert session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow_id)).status == "started"
    engine.dispose()


def test_lost_plan_commit_ack_recovers_without_second_model_call(workspace, tmp_path, monkeypatch, capsys):
    from sqlalchemy.orm import Session
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.agents.model import ModelResponse
    from vulnmind.persistence.models import AuditEvent, WorkflowOperation, WorkflowToolPlan
    database, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    calls = []
    class FakeClient:
        def __init__(self, **kwargs): pass
        def complete(self, request):
            calls.append(True)
            return ModelResponse(text=json.dumps({"selected_tools": []}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    for name, value in env_for(workspace, tmp_path).items(): monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--gitleaks-sandbox", "--agent-plan"])
    original_commit = Session.commit
    def lost_ack(session):
        original_commit(session)
        raise RuntimeError("synthetic lost commit acknowledgement")
    monkeypatch.setattr(Session, "commit", lost_ack)
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "unknown"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        operation = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == workflow_id))
        assert operation.stage == "repository_plan" and operation.status == "completed"
        assert session.scalar(select(WorkflowToolPlan)).selected_tools == []
        statuses = session.scalars(select(AuditEvent.status).where(AuditEvent.call_id == operation.id,
            AuditEvent.tool_name == "repository.plan.transaction").order_by(AuditEvent.created_at)).all()
        assert statuses == ["requested", "succeeded"]
    monkeypatch.setattr(Session, "commit", original_commit)
    monkeypatch.setattr(deepseek, "DeepSeekClient", lambda **kwargs: pytest.fail("model must not be initialized"))
    assert __main__.main() == 0 and json.loads(capsys.readouterr().out)["status"] == "finished"
    assert len(calls) == 1
    engine.dispose()


def test_workflow_planner_not_called_for_unauthorized_repository(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.agents import deepseek
    from vulnmind.persistence.models import WorkflowOperation
    database, _, project_id, scope_file = workspace
    outside = tmp_path / "outside"
    outside.mkdir()
    class FakeClient:
        def __init__(self, **kwargs):
            pass
        def complete(self, request):
            pytest.fail("scope denial must happen before the model call")
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
        "--project-id", str(project_id), "--repository", str(outside), "--scope-file", str(scope_file),
        "--gitleaks-sandbox", "--agent-plan"])
    assert __main__.main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert session.scalar(select(WorkflowOperation)) is None
        assert session.scalar(select(Scan)) is None
    engine.dispose()


def test_workflow_knowledge_context_requires_postgres_before_claim(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.persistence.models import WorkflowOperation
    database, repo, project_id, scope_file = workspace
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--knowledge-context"])
    assert __main__.main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert session.scalar(select(WorkflowOperation)) is None
        assert session.scalar(select(Scan)) is None
    engine.dispose()


def test_staged_knowledge_requires_explicit_knowledge_context(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.persistence.models import WorkflowOperation
    database, repo, project_id, scope_file = workspace
    for name, value in env_for(workspace, tmp_path).items(): monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--staged-knowledge"])
    assert __main__.main() == 2 and json.loads(capsys.readouterr().out)["status"] == "blocked"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert session.scalar(select(WorkflowOperation)) is None and session.scalar(select(Scan)) is None
    engine.dispose()


def test_workflow_imported_reports_are_bound_to_content(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    database, repo, project_id, scope_file = workspace
    bandit = tmp_path / "bandit.json"
    bandit.write_text(json.dumps({"results": [{"filename": "pkg/safe.py", "line_number": 1,
        "test_id": "B301", "issue_severity": "MEDIUM"}]}), encoding="utf-8")
    sarif = tmp_path / "semgrep.sarif"
    sarif.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep"}},
        "results": [{"ruleId": "rule", "message": {"text": "candidate"}, "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "pkg/safe.py"}, "region": {"startLine": 1}}}]}]}]}), encoding="utf-8")
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--bandit-json", str(bandit), "--semgrep-sarif", str(sarif)])
    assert __main__.main() == 0
    capsys.readouterr()
    assert __main__.main() == 0
    capsys.readouterr()
    bandit.write_text('{"results": []}', encoding="utf-8")
    assert __main__.main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert len(session.scalars(select(Scan)).all()) == 1
        assert "B301" in {item.vuln_type for item in session.scalars(select(Finding))}
    engine.dispose()


def test_workflow_refuses_report_changed_between_binding_and_use(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    from vulnmind.analysis.bandit import BanditReportAnalyzer
    database, repo, project_id, scope_file = workspace
    bandit = tmp_path / "bandit.json"
    bandit.write_text('{"results": []}', encoding="utf-8")
    original = BanditReportAnalyzer.analyze
    def change_before_analyze(self, **kwargs):
        bandit.write_text('{"results": [], "changed": true}', encoding="utf-8")
        return original(self, **kwargs)
    monkeypatch.setattr(BanditReportAnalyzer, "analyze", change_before_analyze)
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
        "--bandit-json", str(bandit)])
    assert __main__.main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "unknown"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert session.scalar(select(Scan)) is None
    engine.dispose()


def test_unexpected_graph_exception_does_not_claim_no_work_occurred(workspace, tmp_path, monkeypatch, capsys):
    from vulnmind import __main__
    import vulnmind.graph.guarded_repository_workflow as guarded
    _, repo, project_id, scope_file = workspace
    workflow_id = uuid4()
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    class BrokenGraph:
        def invoke(self, state):
            raise RuntimeError("sensitive exception")
    monkeypatch.setattr(guarded, "build_guarded_repository_graph", lambda *args, **kwargs: BrokenGraph())
    monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(workflow_id),
        "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file)])
    assert __main__.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "unknown" and result["workflow_id"] == str(workflow_id)
    assert "sensitive" not in str(result)


def test_knowledge_requires_explicit_agent_review_before_scan(workspace, tmp_path):
    database, repo, project_id, scope_file = workspace
    result = run_scan("--repository", repo, "--project-id", project_id, "--scope-file", scope_file,
                      "--agent-knowledge", env_overrides=env_for(workspace, tmp_path))
    assert result.returncode == 2 and json.loads(result.stdout)["status"] == "blocked"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert session.scalar(select(Scan)) is None
    engine.dispose()


def test_scan_runs_and_stores_findings(workspace, tmp_path):
    database, repo, project_id, scope_file = workspace
    result = run_scan("--repository", repo, "--project-id", project_id, "--scope-file", scope_file,
                      env_overrides=env_for(workspace, tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "finished"
    assert payload["files_examined"] == 3 and payload["groups"] == 1
    assert payload["findings_stored"] == 1
    report = (tmp_path / "reports").joinpath(*Path(payload["report_uri"]).parts)
    assert report.is_file() and "TLS" in report.read_text(encoding="utf-8")

    engine = create_engine(f"sqlite:///{database.as_posix()}")
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as session:
        scan = session.get(Scan, __import__("uuid").UUID(payload["scan_id"]))
        assert scan.status == "finished"
        finding = session.scalar(select(Finding))
        assert finding.vuln_type == "tls_certificate_verification_disabled"
        assert finding.location["location"].endswith("client.py:5")
    engine.dispose()


def test_scan_imports_external_bandit_json_without_executing_scanner(workspace, tmp_path):
    database, repo, project_id, scope_file = workspace
    report = tmp_path / "bandit.json"
    report.write_text(json.dumps({"results": [{"filename": "pkg/safe.py", "line_number": 3,
        "test_id": "B301", "issue_severity": "MEDIUM", "code": "secret-snippet",
        "issue_text": "secret-message"}], "errors": [{"filename": "secret-error"}]}), encoding="utf-8")
    environment = {**env_for(workspace, tmp_path), "VULNMIND_EVIDENCE_ROOT": str(tmp_path / "evidence")}
    result = run_scan("--repository", repo, "--project-id", project_id, "--scope-file", scope_file,
                      "--bandit-json", report, env_overrides=environment)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "finished" and payload["findings_stored"] == 2
    assert payload["evidence_stored"] == 1
    rendered = (tmp_path / "reports").joinpath(*Path(payload["report_uri"]).parts).read_text(encoding="utf-8")
    assert "1 条扫描错误" in rendered and "secret-error" not in rendered
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        from vulnmind.evidence.store import EvidenceStore
        from vulnmind.persistence.models import Evidence
        finding = session.scalar(select(Finding).where(Finding.vuln_type == "B301"))
        assert finding is not None and finding.location["location"] == "pkg/safe.py:3"
        assert "secret" not in finding.title
        evidence = session.scalar(select(Evidence).where(Evidence.finding_id == finding.id))
        assert evidence is not None
        metadata = EvidenceStore(tmp_path / "evidence").read(evidence.content_ref).decode("utf-8")
        assert "untrusted_external_bandit_report" in metadata and "secret" not in metadata
    engine.dispose()
    env = os.environ.copy()
    env.update(environment)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    verified = subprocess.run([sys.executable, "-m", "vulnmind", "verify", "--scan-id", payload["scan_id"]],
                              capture_output=True, encoding="utf-8", env=env, timeout=60)
    assert verified.returncode == 1, verified.stdout + verified.stderr
    verification = json.loads(verified.stdout)
    assert verification["status"] == "incomplete" and verification["evidence_checked"] == 1
    assert verification["findings_without_evidence"] == 1 and not verification["evidence_broken"]


@pytest.mark.parametrize("selection,expected_count", [(["bandit_json"], 2), ([], 1)])
def test_model_planner_selects_only_user_enabled_tools(workspace, tmp_path, monkeypatch, capsys, selection, expected_count):
    import vulnmind.agents.deepseek as deepseek
    from vulnmind.agents.model import ModelResponse
    from vulnmind import __main__
    database, repo, project_id, scope_file = workspace
    report = tmp_path / "bandit.json"
    report.write_text(json.dumps({"results": [{"filename": "pkg/safe.py", "line_number": 1,
        "test_id": "B301", "issue_severity": "MEDIUM"}]}), encoding="utf-8")
    class FakeClient:
        def complete(self, request):
            prompt = "\n".join(item.content for item in request.messages)
            assert str(repo) not in prompt and str(report) not in prompt
            return ModelResponse(text=json.dumps({"selected_tools": selection}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "scan", "--repository", str(repo), "--project-id",
        str(project_id), "--scope-file", str(scope_file), "--bandit-json", str(report), "--agent-plan"])
    assert __main__.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings_stored"] == expected_count
    assert payload["planned_tools"] == selection
    rendered = (tmp_path / "reports").joinpath(*Path(payload["report_uri"]).parts).read_text(encoding="utf-8")
    assert "模型规划仅从用户启用的分析器中选择" in rendered
    assert ("模型规划未选择用户启用的分析器" in rendered) is (not selection)


def test_model_planner_cannot_add_unenabled_tool(workspace, tmp_path, monkeypatch, capsys):
    import vulnmind.agents.deepseek as deepseek
    from vulnmind.agents.model import ModelResponse
    from vulnmind import __main__
    database, repo, project_id, scope_file = workspace
    report = tmp_path / "bandit.json"
    report.write_text('{"results":[]}', encoding="utf-8")
    class FakeClient:
        def complete(self, request):
            return ModelResponse(text=json.dumps({"selected_tools": ["trivy_sandbox"]}))
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "scan", "--repository", str(repo), "--project-id",
        str(project_id), "--scope-file", str(scope_file), "--bandit-json", str(report), "--agent-plan"])
    assert __main__.main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert session.scalar(select(Scan)) is None
        from vulnmind.persistence.models import AuditEvent
        statuses = session.scalars(select(AuditEvent.status).where(
            AuditEvent.tool_name == "repository.plan.selection").order_by(AuditEvent.created_at)).all()
        assert statuses == ["requested", "failed"]
    engine.dispose()


def test_model_planner_is_not_called_for_out_of_scope_repository(workspace, tmp_path, monkeypatch, capsys):
    import vulnmind.agents.deepseek as deepseek
    from vulnmind import __main__
    _, _, project_id, scope_file = workspace
    outside = tmp_path / "outside"
    outside.mkdir()
    report = tmp_path / "bandit.json"
    report.write_text('{"results":[]}', encoding="utf-8")
    class FakeClient:
        def complete(self, request):
            pytest.fail("out-of-scope targets must be blocked before model calls")
    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    for name, value in env_for(workspace, tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["vulnmind", "scan", "--repository", str(outside), "--project-id",
        str(project_id), "--scope-file", str(scope_file), "--bandit-json", str(report), "--agent-plan"])
    assert __main__.main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"


@pytest.mark.skipif(os.getenv("VULNMIND_TEST_REAL_MODEL") != "1", reason="explicit real-model test not requested")
def test_real_model_planner_on_synthetic_local_repository(workspace, tmp_path):
    database, repo, project_id, scope_file = workspace
    report = tmp_path / "bandit.json"
    report.write_text(json.dumps({"results": [{"filename": "pkg/safe.py", "line_number": 1,
        "test_id": "B301", "issue_severity": "MEDIUM"}]}), encoding="utf-8")
    result = run_scan("--repository", repo, "--project-id", project_id, "--scope-file", scope_file,
                      "--bandit-json", report, "--agent-plan", env_overrides=env_for(workspace, tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    output = json.loads(result.stdout)
    assert output["status"] == "finished"
    assert set(output["planned_tools"]) <= {"bandit_json"}
    assert output["findings_stored"] == (2 if "bandit_json" in output["planned_tools"] else 1)


def test_scan_can_record_a_skill_context_manifest(workspace, tmp_path):
    database, repo, project_id, scope_file = workspace
    skills = tmp_path / "skills"
    (skills / "target").mkdir(parents=True)
    (skills / "target" / "repository_audit.md").write_text(
        "---\nskill_id: repository_audit\nname: Repository audit\nversion: '1'\n"
        "target_type: repository\nstage: analysis\n---\nValidate scope before reading.\n",
        encoding="utf-8")
    result = run_scan("--repository", repo, "--project-id", project_id, "--scope-file", scope_file,
                      "--skills", skills, env_overrides=env_for(workspace, tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["context_manifest"]

    from vulnmind.persistence.models import ContextManifestRecord
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as session:
        manifest = session.scalar(select(ContextManifestRecord))
        assert manifest is not None
        assert any(ref.startswith("skill:repository_audit@1#sha256=") for ref in manifest.selected_refs)
    engine.dispose()


def test_knowledge_context_refuses_non_postgresql_before_scanning(workspace, tmp_path):
    database, repo, project_id, scope_file = workspace
    result = run_scan("--repository", repo, "--project-id", project_id, "--scope-file", scope_file,
                      "--knowledge-context", env_overrides=env_for(workspace, tmp_path))
    assert result.returncode == 2 and json.loads(result.stdout)["status"] == "blocked"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert session.scalar(select(Scan)) is None
    engine.dispose()


def test_scan_rejects_out_of_scope_and_bad_input(workspace, tmp_path):
    database, repo, project_id, scope_file = workspace
    outside = tmp_path / "outside"
    outside.mkdir()
    denied = run_scan("--repository", outside, "--project-id", project_id, "--scope-file", scope_file,
                      env_overrides=env_for(workspace, tmp_path))
    assert denied.returncode == 2
    missing_project = run_scan("--repository", repo, "--project-id", uuid4(), "--scope-file", scope_file,
                               env_overrides=env_for(workspace, tmp_path))
    assert missing_project.returncode == 2
    broken = tmp_path / "broken.json"
    broken.write_text('{"credential": "do-not-echo"}', encoding="utf-8")
    bad_scope = run_scan("--repository", repo, "--project-id", project_id, "--scope-file", broken,
                         env_overrides=env_for(workspace, tmp_path))
    assert bad_scope.returncode == 2
    assert "do-not-echo" not in bad_scope.stdout + bad_scope.stderr
    no_db = run_scan("--repository", repo, "--project-id", project_id, "--scope-file", scope_file,
                     env_overrides={"VULNMIND_DATABASE_URL": "", "VULNMIND_REPORT_ROOT": ""})
    assert no_db.returncode == 2


def test_agent_review_without_api_key_is_blocked_before_scanning(workspace, tmp_path):
    database, repo, project_id, scope_file = workspace
    env = {**env_for(workspace, tmp_path), "DEEPSEEK_API_KEY": "", "VULNMIND_DEEPSEEK_API_KEY": ""}
    result = run_scan("--repository", repo, "--project-id", project_id, "--scope-file", scope_file,
                      "--agent-review", env_overrides=env)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert session.scalar(select(Scan)) is None
    engine.dispose()


def test_scan_ingests_an_external_semgrep_sarif(workspace, tmp_path):
    database, repo, project_id, scope_file = workspace
    document = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Semgrep"}},
        "results": [{
            "ruleId": "python.lang.security.audit.sqli",
            "level": "error",
            "message": {"text": "User input reaches a SQL query"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "pkg/client.py"},
                "region": {"startLine": 5}}}]}]}]}
    document["runs"][0]["results"].extend([
        {"ruleId": "malformed", "locations": 7},
        {"ruleId": "outside", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "../../secret"}}}]},
    ])
    report = tmp_path / "semgrep.sarif"
    report.write_text(json.dumps(document), encoding="utf-8")
    result = run_scan("--repository", repo, "--project-id", project_id, "--scope-file", scope_file,
                      "--semgrep-sarif", report, env_overrides=env_for(workspace, tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "finished" and payload["groups"] == 2
    report_file = (tmp_path / "reports").joinpath(*Path(payload["report_uri"]).parts)
    content = report_file.read_text(encoding="utf-8")
    assert "User input reaches a SQL query" in content and "semgrep" in content
    assert "pkg/client.py:5" in content
    assert "SARIF 有 2 条结果无法导入" in content
    assert "../../secret" not in content


def test_scan_rejects_a_malformed_sarif_report(workspace, tmp_path):
    database, repo, project_id, scope_file = workspace
    report = tmp_path / "broken.sarif"
    report.write_text("{not json", encoding="utf-8")
    result = run_scan("--repository", repo, "--project-id", project_id, "--scope-file", scope_file,
                      "--semgrep-sarif", report, env_overrides=env_for(workspace, tmp_path))
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with sessionmaker(engine)() as session:
        assert session.scalar(select(Scan)) is None
    engine.dispose()
