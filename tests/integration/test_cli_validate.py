"""CLI validate-request / validate-run validation paths (SQLite, no network)."""
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from vulnmind.analysis.validation import plan_digest, plan_probes
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Approval, Project, Scan
from vulnmind.persistence.unit_of_work import transaction

PROJECT_ROOT = Path(__file__).resolve().parents[2]
URL = "https://app.test/search?q=x"


@pytest.fixture
def workspace(tmp_path):
    database = tmp_path / "validate.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="validate cli")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="crawl")
        session.add(scan)
        session.flush()
        scan_id = scan.id
    engine.dispose()
    now = datetime.now(timezone.utc)
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({
        "authorization_source": "local test", "approved_by": "owner",
        "starts_at": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "web_origins": ["https://app.test"],
        "allowed_ip_networks": ["127.0.0.0/8"]}), encoding="utf-8")
    env = os.environ.copy()
    env.update({"PYTHONPATH": str(PROJECT_ROOT / "src"), "PYTHONIOENCODING": "utf-8",
                "VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"})
    return {"database": database, "scan_id": scan_id, "scope_file": scope_file, "env": env}


def run_cli(kind, *arguments, env):
    return subprocess.run([sys.executable, "-m", "vulnmind", kind, *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=120)


def test_validate_request_records_a_bound_approval(workspace):
    result = run_cli("validate-request", "--scan-id", workspace["scan_id"], "--url", URL,
                     env=workspace["env"])
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    probes = plan_probes([URL])
    assert payload["status"] == "requested" and payload["probe_count"] == len(probes) == 4
    assert payload["operation_digest"] == plan_digest(probes)
    engine = create_engine(f"sqlite:///{workspace['database'].as_posix()}")
    with sessionmaker(engine)() as session:
        row = session.scalar(select(Approval))
        assert row.status == "pending" and row.action == "validation.probes"
        assert row.operation_hash == payload["operation_digest"]
    engine.dispose()


def test_validate_request_with_unknown_scan_is_blocked(workspace):
    result = run_cli("validate-request", "--scan-id", uuid4(), "--url", URL, env=workspace["env"])
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"


def test_validate_run_without_a_valid_approval_is_blocked(workspace):
    result = run_cli("validate-run", "--scan-id", workspace["scan_id"], "--url", URL,
                     "--scope-file", workspace["scope_file"], "--approval-token", uuid4(),
                     env=workspace["env"])
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"


def test_paused_validation_does_not_consume_pending_approval(workspace):
    created = run_cli("validate-request", "--scan-id", workspace["scan_id"], "--url", URL,
                      env=workspace["env"])
    assert created.returncode == 0, created.stdout + created.stderr
    engine = create_engine(workspace["env"]["VULNMIND_DATABASE_URL"])
    with sessionmaker(engine)() as session:
        approval = session.scalar(select(Approval))
        approval_id = str(approval.id)
    result = run_cli("validate-run", "--scan-id", workspace["scan_id"], "--url", URL,
                     "--scope-file", workspace["scope_file"], "--approval-token", approval_id,
                     env=workspace["env"])
    assert result.returncode == 2
    with sessionmaker(engine)() as session:
        assert session.scalar(select(Approval)).status == "pending"
    engine.dispose()


def test_validate_run_requires_a_scope_file(workspace):
    result = run_cli("validate-run", "--scan-id", workspace["scan_id"], "--url", URL,
                     "--approval-token", uuid4(), env=workspace["env"])
    assert result.returncode == 2
    assert "scope-file" in result.stderr


def test_validate_run_without_database_is_blocked(workspace):
    env = dict(workspace["env"])
    env["VULNMIND_DATABASE_URL"] = ""
    result = run_cli("validate-run", "--scan-id", workspace["scan_id"], "--url", URL,
                     "--scope-file", workspace["scope_file"], "--approval-token", uuid4(), env=env)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"


def test_validate_request_accepts_a_plan_file(workspace, tmp_path):
    probes = plan_probes([URL])
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"version": 1, "digest": plan_digest(probes),
                                "probes": [probe.model_dump(mode="json") for probe in probes]}),
                    encoding="utf-8")
    result = run_cli("validate-request", "--scan-id", workspace["scan_id"],
                     "--plan-file", plan, env=workspace["env"])
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["probe_count"] == len(probes)
    assert payload["operation_digest"] == plan_digest(probes)


def test_validate_request_rejects_tampered_or_ambiguous_plans(workspace, tmp_path):
    probes = plan_probes([URL])
    tampered = {"probes": [probe.model_dump(mode="json") for probe in probes]}
    tampered["probes"][0]["url"] = tampered["probes"][0]["url"].replace("vmxreflect1a2b", "evil")
    plan = tmp_path / "tampered.json"
    plan.write_text(json.dumps(tampered), encoding="utf-8")
    assert run_cli("validate-request", "--scan-id", workspace["scan_id"], "--plan-file", plan,
                   env=workspace["env"]).returncode == 2

    valid = tmp_path / "valid.json"
    valid.write_text(json.dumps({"probes": [probe.model_dump(mode="json") for probe in probes]}),
                     encoding="utf-8")
    assert run_cli("validate-request", "--scan-id", workspace["scan_id"], "--url", URL,
                   "--plan-file", valid, env=workspace["env"]).returncode == 2
    assert run_cli("validate-request", "--scan-id", workspace["scan_id"],
                   env=workspace["env"]).returncode == 2


def test_validation_plan_requires_a_model_key(workspace):
    env = dict(workspace["env"])
    env["DEEPSEEK_API_KEY"] = ""
    env["VULNMIND_DEEPSEEK_API_KEY"] = ""
    result = run_cli("validation-plan", "--scan-id", workspace["scan_id"], env=env)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"


def test_validation_plan_with_unknown_scan_is_blocked(workspace):
    env = dict(workspace["env"])
    env["DEEPSEEK_API_KEY"] = "test-key-not-used"
    env.pop("VULNMIND_DEEPSEEK_API_KEY", None)
    result = run_cli("validation-plan", "--scan-id", uuid4(), env=env)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"


def test_validation_plan_from_stored_form_uses_fake_model_without_sending_target(workspace, monkeypatch, capsys, tmp_path):
    from types import SimpleNamespace
    from vulnmind.__main__ import _validation_plan
    from vulnmind.agents.model import ModelResponse, ModelUsage
    from vulnmind.persistence.repositories import WebEndpointRepository
    import vulnmind.agents.deepseek as deepseek

    requests = []
    class FakeClient:
        def complete(self, request):
            requests.append(request)
            return ModelResponse(text=json.dumps({"summary": "review", "selections": [
                {"index": 0, "reason": "review"}]}),
                usage=ModelUsage(input_tokens=1, output_tokens=1))

    monkeypatch.setattr(deepseek, "DeepSeekClient", FakeClient)
    monkeypatch.setenv("VULNMIND_DATABASE_URL", workspace["env"]["VULNMIND_DATABASE_URL"])
    engine = create_engine(workspace["env"]["VULNMIND_DATABASE_URL"])
    with sessionmaker(engine)() as session, session.begin():
        scan = session.get(Scan, workspace["scan_id"])
        WebEndpointRepository(session).replace_for_scan(scan.id, scan.project_id, [{
            "url": "https://private.test/search", "parameters": ["private_name"]}, {
            "url": "https://private.test/unknown"}])
    engine.dispose()
    output = tmp_path / "plan.json"
    args = SimpleNamespace(scan_id=str(workspace["scan_id"]), limit=500, max_selections=1,
                           agent_model=None, actor="tester", output=output)
    assert _validation_plan(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "completed" and result["selected_count"] == 1
    assert result["candidates_truncated"] is False
    assert result["parameters_unknown_endpoints"] == 1
    assert result["endpoint_list_may_be_truncated"] is False
    from vulnmind.analysis.validation import load_plan
    assert load_plan(output.read_text(encoding="utf-8"))[0].parameter == "private_name"
    prompt = "\n".join(message.content for message in requests[0].messages)
    assert "private.test" not in prompt and "private_name" not in prompt
    args.limit = 1
    assert _validation_plan(args) == 0
    assert json.loads(capsys.readouterr().out)["endpoint_list_may_be_truncated"] is True
