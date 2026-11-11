from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Project, Scan, DurableStep, Report
from vulnmind.persistence.durable import Journal, StepUnknown, recover_step, workflow_lock
from vulnmind.graph.durable_repository import RepositoryFlow, STAGES
from vulnmind.schemas import Target, Authorization


@pytest.fixture(params=["sqlite", "postgresql"])
def flow(tmp_path, request):
    import os
    from sqlalchemy import text
    from sqlalchemy.engine import make_url
    admin = None
    if request.param == "postgresql":
        if not os.getenv("VULNMIND_TEST_DATABASE_URL"):
            pytest.skip("dedicated PostgreSQL not configured")
        url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
        schema = "durable_flow_" + uuid4().hex
        admin = create_engine(url, isolation_level="AUTOCOMMIT")
        with admin.connect() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_engine(url.update_query_dict({"options": f"-csearch_path={schema},public"}))
    else:
        engine = create_engine(f"sqlite:///{(tmp_path / 'db.sqlite').as_posix()}")
    Base.metadata.create_all(engine)
    project = uuid4()
    with Session(engine) as session, session.begin():
        session.add(Project(id=project, name="durable test"))
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("import requests\nrequests.get('https://example.test', verify=False)\n")
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="local test", approved_by="test", starts_at=now-timedelta(minutes=1),
                          expires_at=now+timedelta(hours=1), repository_roots=[str(root)])
    opts = dict(actor="test", tools=[], reports={}, report_format="json", report_root=str(tmp_path / "reports"),
                evidence_root=str(tmp_path / "evidence"), agent_model="fake", agent_plan=False,
                agent_analysis=False, agent_review=False, agent_report=False, knowledge_context=False, agent_knowledge=False)
    yield RepositoryFlow(engine, uuid4(), project, Target(type="repository", locator=str(root)), scope, opts)
    engine.dispose()
    if admin:
        with admin.connect() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def test_every_stage_resumes_without_reexecution(flow, monkeypatch):
    called = []
    original = flow.compute
    def compute(stage, prior, audit):
        called.append(stage)
        return original(stage, prior, audit)
    monkeypatch.setattr(flow, "compute", compute)
    for stage in STAGES[:-1]:
        assert flow.run(pause_after=stage)["status"] == "paused"
    assert flow.run()["status"] == "finished"
    assert flow.run()["status"] == "finished"
    assert called == list(STAGES)
    with Session(flow.engine) as session:
        assert session.scalar(select(func.count()).select_from(Scan)) == 1
        assert session.scalar(select(func.count()).select_from(Report)) == 1
        assert session.scalar(select(func.count()).select_from(DurableStep)) == len(STAGES)


def test_unknown_requires_decision_and_active_lock_blocks_recovery(flow):
    journal = Journal(flow.engine, flow.workflow_id, {"x": 1}, "test")
    def fail(_):
        raise RuntimeError("interrupted after effect")
    with workflow_lock(flow.engine, flow.workflow_id):
        with pytest.raises(RuntimeError):
            journal.run("model", {}, fail)
        with pytest.raises(StepUnknown):
            recover_step(flow.engine, flow.workflow_id, "model", "retry", "test", "inspected", True)
    with pytest.raises(StepUnknown):
        journal.run("model", {}, lambda _: {"ok": True})
    with pytest.raises(ValueError):
        recover_step(flow.engine, flow.workflow_id, "model", "retry", "test", "inspected")
    recover_step(flow.engine, flow.workflow_id, "model", "retry", "test", "inspected", True)
    assert journal.run("model", {}, lambda _: {"ok": True}) == {"ok": True}


def test_payload_tampering_and_changed_input_rejected(flow):
    flow.run(pause_after="plan")
    with Session(flow.engine) as session, session.begin():
        row = session.scalar(select(DurableStep).where(DurableStep.stage == "plan"))
        row.payload = {"selected_tools": ["not_enabled"]}
    with pytest.raises(StepUnknown):
        flow.run()


def test_all_model_roles_pass_results_forward_and_replay_without_model(flow, monkeypatch):
    import json
    from vulnmind.agents.model import ModelResponse
    prompts = []
    class FakeClient:
        def complete(self, request):
            prompts.append(request)
            text = request.messages[-1].content
            if 'selected_tools' in text:
                return ModelResponse(text='{"selected_tools": []}')
            if '"items"' in text:
                return ModelResponse(text='{"summary":"reviewed", "items":[]}')
            return ModelResponse(text='{"summary":"metadata only advisory"}')
    opts = {**flow.options, "tools": ["bandit_json"], "agent_plan": True, "agent_analysis": True,
            "agent_review": True, "agent_report": True, "agent_knowledge": True}
    active = RepositoryFlow(flow.engine, flow.workflow_id, flow.project_id, flow.target, flow.scope, opts,
                            client_factory=FakeClient)
    compute = active.compute
    def with_knowledge(stage, prior, audit):
        if stage == "knowledge":
            return {"status": "selected", "chunks": [{"chunk_id": "test-ref", "content": "saved knowledge snapshot"}]}
        return compute(stage, prior, audit)
    monkeypatch.setattr(active, "compute", with_knowledge)
    assert active.run()["status"] == "finished"
    assert len(prompts) == 4
    assert "saved knowledge snapshot" in prompts[1].messages[-1].content
    assert "metadata only advisory" in prompts[2].messages[-1].content
    assert "agent:triage" in prompts[3].messages[-1].content
    active.client_factory = lambda: pytest.fail("completed models must not be initialized")
    assert active.run()["status"] == "finished"


def test_transaction_failure_rolls_back_business_output_and_receipt(flow, monkeypatch):
    from vulnmind.persistence.audit import SessionAuditSink
    original = SessionAuditSink.record
    def failed(self, event):
        if event["tool_name"] == "workflow.initialize" and event["status"] == "succeeded":
            raise RuntimeError("lost transaction")
        original(self, event)
    monkeypatch.setattr(SessionAuditSink, "record", failed)
    with pytest.raises(RuntimeError):
        flow.run()
    with Session(flow.engine) as session:
        assert session.scalar(select(func.count()).select_from(Scan)) == 0
        assert session.scalar(select(DurableStep)).status == "running"
    monkeypatch.setattr(SessionAuditSink, "record", original)
    assert flow.run()["status"] == "finished"


def test_cli_cross_process_crash_after_committed_analysis_and_resume(flow, tmp_path):
    import json
    import os
    import subprocess
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(flow.scope.model_dump_json(), encoding="utf-8")
    args = ["vulnmind", "workflow-run", "--workflow-id", str(flow.workflow_id), "--project-id", str(flow.project_id),
            "--repository", flow.target.locator, "--scope-file", str(scope_path), "--report-format", "json"]
    env = {**os.environ, "VULNMIND_DATABASE_URL": flow.engine.url.render_as_string(hide_password=False),
           "VULNMIND_REPORT_ROOT": flow.options["report_root"], "VULNMIND_EVIDENCE_ROOT": flow.options["evidence_root"],
           "PYTHONPATH": str(root / "src"), "PYTHONIOENCODING": "utf-8", "DEEPSEEK_API_KEY": "", "VULNMIND_DEEPSEEK_API_KEY": ""}
    driver = '''import os,sys
from vulnmind.persistence.durable import Journal
original = Journal.run
def run(self, stage, *args, **kwargs):
    result = original(self, stage, *args, **kwargs)
    if stage == "analyze": os._exit(73)
    return result
Journal.run = run
from vulnmind.__main__ import main
sys.argv = ARGS
raise SystemExit(main())
'''.replace("ARGS", repr(args))
    killed = subprocess.run([sys.executable, "-c", driver], cwd=root, env=env, capture_output=True, timeout=30)
    assert killed.returncode == 73, killed.stdout + killed.stderr
    (Path(flow.target.locator) / "app.py").write_text("raise RuntimeError('must not rescan')\n")
    result = subprocess.run([sys.executable, "-m", *args], cwd=root, env=env, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["status"] == "finished"
    with Session(flow.engine) as session:
        analysis = session.scalar(select(DurableStep).where(DurableStep.stage == "analyze"))
        assert analysis.attempt == 1 and len(analysis.payload["groups"]) == 1


def test_two_cli_processes_share_one_durable_workflow(flow, tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    scope = tmp_path / "concurrent-scope.json"
    scope.write_text(flow.scope.model_dump_json(), encoding="utf-8")
    command = [sys.executable, "-m", "vulnmind", "workflow-run", "--workflow-id", str(flow.workflow_id),
               "--project-id", str(flow.project_id), "--repository", flow.target.locator, "--scope-file", str(scope)]
    env = {**os.environ, "VULNMIND_DATABASE_URL": flow.engine.url.render_as_string(hide_password=False),
           "VULNMIND_REPORT_ROOT": flow.options["report_root"], "VULNMIND_EVIDENCE_ROOT": flow.options["evidence_root"],
           "PYTHONPATH": str(root / "src"), "PYTHONIOENCODING": "utf-8"}
    processes = [subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
    outputs = [process.communicate(timeout=40) for process in processes]
    assert any(p.returncode == 0 for p in processes), outputs
    assert all(p.returncode in {0, 2} for p in processes), outputs
    with Session(flow.engine) as session:
        assert session.scalar(select(func.count()).select_from(Scan)) == 1
        assert session.scalar(select(func.count()).select_from(Report)) == 1
        assert all(row.attempt == 1 for row in session.scalars(select(DurableStep)))


def test_abort_closes_the_scan_without_executing_remaining_stages(flow, monkeypatch):
    assert flow.run(pause_after="initialize")["status"] == "paused"
    monkeypatch.setattr(flow, "compute", lambda *args: (_ for _ in ()).throw(RuntimeError("interrupted")))
    with pytest.raises(RuntimeError):
        flow.run()
    recover_step(flow.engine, flow.workflow_id, "plan", "abort", "test", "operator stopped this task")
    with Session(flow.engine) as session:
        scan = session.get(Scan, flow.scan_id)
        assert scan.status == "aborted" and scan.finished_at is not None
    with pytest.raises(StepUnknown):
        flow.run()


def test_context_query_verifies_receipt_and_excludes_reference_bodies(flow, monkeypatch):
    from vulnmind.persistence.workflow_knowledge import read_workflow_context
    from vulnmind.persistence.models import ContextManifestRecord
    import json
    compute = flow.compute
    def supplied(stage, prior, audit):
        if stage == "knowledge":
            return {"manifest": {"selected_refs": {"references": ["knowledge:ref-1"]}, "token_estimate": 12},
                    "chunks": [{"chunk_id": "ref-1", "content": "private-body"}]}
        return compute(stage, prior, audit)
    monkeypatch.setattr(flow, "compute", supplied)
    flow.run()
    payload = read_workflow_context(flow.engine, flow.workflow_id)
    assert payload["selected_refs"]["references"] == ["knowledge:ref-1"]
    assert "private-body" not in json.dumps(payload)
    with Session(flow.engine) as session, session.begin():
        session.scalar(select(ContextManifestRecord)).selected_refs = {"references": ["knowledge:changed"]}
    with pytest.raises(ValueError):
        read_workflow_context(flow.engine, flow.workflow_id)
