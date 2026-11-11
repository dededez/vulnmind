from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import create_engine

from vulnmind.persistence.models import WorkflowOperation
from vulnmind.persistence.workflow_operations import claim_stage, complete_stage


@pytest.fixture
def engine(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'claims.db').as_posix()}")
    WorkflowOperation.__table__.create(engine)
    yield engine
    engine.dispose()


def test_crash_after_claim_is_unknown_and_cannot_replay(engine):
    workflow_id = uuid4()
    initial = claim_stage(engine, workflow_id=workflow_id, stage="scan", input_digest="a" * 64)
    assert initial.status == "claimed" and initial.owner_token
    resumed = claim_stage(engine, workflow_id=workflow_id, stage="scan", input_digest="a" * 64)
    assert resumed.status == "unknown" and resumed.owner_token is None
    with pytest.raises(ValueError, match="identity"):
        claim_stage(engine, workflow_id=workflow_id, stage="scan", input_digest="b" * 64)


def test_only_owner_can_complete_and_result_is_recovered(engine):
    workflow_id, result = uuid4(), uuid4()
    claim = claim_stage(engine, workflow_id=workflow_id, stage="scan", input_digest="a" * 64)
    with pytest.raises(ValueError, match="not owned"):
        complete_stage(engine, operation_id=claim.operation_id, owner_token=uuid4(), result_id=result)
    complete_stage(engine, operation_id=claim.operation_id, owner_token=claim.owner_token, result_id=result)
    recovered = claim_stage(engine, workflow_id=workflow_id, stage="scan", input_digest="a" * 64)
    assert recovered.status == "completed" and recovered.result_id == result
    complete_stage(engine, operation_id=claim.operation_id, owner_token=claim.owner_token, result_id=result)
    with pytest.raises(ValueError, match="already completed"):
        complete_stage(engine, operation_id=claim.operation_id, owner_token=claim.owner_token, result_id=uuid4())


def test_concurrent_claims_have_exactly_one_owner(engine):
    workflow_id = uuid4()
    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(pool.map(lambda _: claim_stage(engine, workflow_id=workflow_id,
                                                    stage="scan", input_digest="c" * 64), range(8)))
    assert sum(item.status == "claimed" for item in claims) == 1
    assert sum(item.status == "unknown" for item in claims) == 7
    assert len({item.operation_id for item in claims}) == 1


def test_started_claim_survives_process_exit(engine):
    workflow_id = uuid4()
    script = """from uuid import UUID
from sqlalchemy import create_engine
from vulnmind.persistence.workflow_operations import claim_stage
import sys
claim = claim_stage(create_engine(sys.argv[1]), workflow_id=UUID(sys.argv[2]), stage='scan', input_digest='d' * 64)
assert claim.status == 'claimed'
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    child = subprocess.run([sys.executable, "-c", script, str(engine.url), str(workflow_id)],
                           capture_output=True, text=True, env=env, timeout=20)
    assert child.returncode == 0, child.stderr
    assert claim_stage(engine, workflow_id=workflow_id, stage="scan", input_digest="d" * 64).status == "unknown"


def test_plan_audit_binds_selection_and_request_digest(engine):
    from sqlalchemy.orm import Session
    from vulnmind.agents.model import ModelResponse
    from vulnmind.persistence.models import AuditEvent, WorkflowToolPlan
    from vulnmind.persistence.workflow_plans import execute_tool_plan, load_tool_plan
    AuditEvent.__table__.create(engine)
    WorkflowToolPlan.__table__.create(engine)
    claim = claim_stage(engine, workflow_id=uuid4(), stage="repository_plan", input_digest="a" * 64)
    class FakeClient:
        def complete(self, request): return ModelResponse(text='{"selected_tools": []}')
    class NeverCall:
        def complete(self, request): pytest.fail("invalid ownership must not call a model")
    with pytest.raises(ValueError, match="not owned"):
        execute_tool_plan(engine, operation_id=claim.operation_id, owner_token=uuid4(),
                          input_digest="a" * 64, enabled={"gitleaks_sandbox"}, actor="test", client=NeverCall())
    plan_id = execute_tool_plan(engine, operation_id=claim.operation_id, owner_token=claim.owner_token,
                                input_digest="a" * 64, enabled={"gitleaks_sandbox"}, actor="test", client=FakeClient())
    assert load_tool_plan(engine, plan_id=plan_id, operation_id=claim.operation_id,
                          enabled={"gitleaks_sandbox"}) == ()
    with Session(engine) as session, session.begin():
        session.get(WorkflowOperation, claim.operation_id).input_digest = "b" * 64
    with pytest.raises(ValueError, match="audit does not verify"):
        load_tool_plan(engine, plan_id=plan_id, operation_id=claim.operation_id, enabled={"gitleaks_sandbox"})
