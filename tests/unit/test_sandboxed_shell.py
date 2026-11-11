"""Sandboxed shell executor: approval binding, single use, read-only sandbox."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from vulnmind.analysis.sandbox import SandboxError
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Approval, Project, Scan
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.schemas import Authorization, Target
from vulnmind.security.approvals import ApprovalService
from vulnmind.security.scope import ScopeDenied
from vulnmind.tools.shell import (SHELL_ACTION, SandboxedShellExecutor, ShellDenied,
                                  ShellExecutor, ShellToolInput, shell_operation_digest)


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


class Runner:
    def __init__(self, result=(0, b"ok")):
        self.result = result
        self.calls = []

    def __call__(self, argv, root, relative, timeout, max_bytes):
        self.calls.append({"argv": argv, "root": root, "relative": relative,
                           "timeout": timeout, "max_bytes": max_bytes})
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


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
def seeded(factory, tmp_path):
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "app.py").write_text("print('ok')\n", encoding="utf-8")
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="shell")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="analysis")
        session.add(scan)
        session.flush()
        return {"repo": repo, "project_id": project.id, "scan_id": scan.id}


def authorization(root):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)])


def scope(seeded):
    return authorization(seeded["repo"])


def target(seeded):
    return Target(type="repository", locator=str(seeded["repo"]))


def request_for(seeded, **overrides):
    payload = {"argv": ["ls", "-la"], "cwd": str(seeded["repo"] / "pkg"),
               "purpose": "list files", "scan_id": seeded["scan_id"]}
    payload.update(overrides)
    return ShellToolInput(**payload)


def approved_token(factory, seeded, request, *, approved=True, purpose_delta=None):
    """Create, approve and commit an approval bound to this exact request."""
    digest = shell_operation_digest(request)
    with transaction(factory) as session:
        approval = ApprovalService(session).request(
            scan_id=seeded["scan_id"], action=SHELL_ACTION, target=digest,
            valid_for=timedelta(hours=1), operation_hash=digest)
        session.flush()
        ApprovalService(session).decide(approval.id, approver="owner", approved=approved)
        session.flush()
        return str(approval.id), digest


def executor(factory, runner, events=None):
    session = factory()
    return (SandboxedShellExecutor(events or Recorder(), approvals=ApprovalService(session),
                                   session=session, runner=runner), session)


def test_command_runs_after_single_use_approval(factory, seeded):
    base = request_for(seeded)
    token, digest = approved_token(factory, seeded, base)
    runner = Runner((0, b"total 0\n"))
    recorder = Recorder()
    instance, session = executor(factory, runner, recorder)
    try:
        result = instance.run(base.model_copy(update={"approval_token": token}),
                              actor="tester", target=target(seeded), scope=scope(seeded))
        session.commit()
    finally:
        session.close()
    assert runner.calls == [{"argv": ["ls", "-la"], "root": seeded["repo"].resolve(),
                             "relative": "pkg", "timeout": 120, "max_bytes": 200_000}]
    assert result.exit_code == 0 and result.output == "total 0\n" and not result.truncated
    assert [event["status"] for event in recorder.events] == ["requested", "started", "succeeded"]
    with transaction(factory) as check:
        row = check.scalar(select(Approval))
        assert row.status == "consumed" and row.consumed_at is not None and row.operation_hash == digest


def test_replayed_approval_is_denied_without_running(factory, seeded):
    base = request_for(seeded)
    token, _ = approved_token(factory, seeded, base)
    runner = Runner()
    first, session = executor(factory, runner)
    first.run(base.model_copy(update={"approval_token": token}), actor="tester",
              target=target(seeded), scope=scope(seeded))
    session.commit()
    assert len(runner.calls) == 1
    second, second_session = executor(factory, runner)
    try:
        with pytest.raises(ShellDenied, match="exact operation"):
            second.run(base.model_copy(update={"approval_token": token}), actor="tester",
                       target=target(seeded), scope=scope(seeded))
    finally:
        second_session.close()
        session.close()
    assert len(runner.calls) == 1


def test_wrong_operation_for_the_approval_is_denied(factory, seeded):
    base = request_for(seeded)
    token, _ = approved_token(factory, seeded, base)
    runner = Runner()
    instance, session = executor(factory, runner)
    try:
        with pytest.raises(ShellDenied, match="exact operation"):
            instance.run(base.model_copy(update={"approval_token": token, "purpose": "different"}),
                         actor="tester", target=target(seeded), scope=scope(seeded))
    finally:
        session.close()
    assert runner.calls == []


def test_denied_decision_cannot_be_used(factory, seeded):
    base = request_for(seeded)
    token, _ = approved_token(factory, seeded, base, approved=False)
    runner = Runner()
    instance, session = executor(factory, runner)
    try:
        with pytest.raises(ShellDenied, match="exact operation"):
            instance.run(base.model_copy(update={"approval_token": token}), actor="tester",
                         target=target(seeded), scope=scope(seeded))
    finally:
        session.close()
    assert runner.calls == []


def test_missing_approval_and_scan_are_denied(factory, seeded):
    runner = Runner()
    instance, session = executor(factory, runner)
    try:
        with pytest.raises(ShellDenied, match="approval"):
            instance.run(request_for(seeded), actor="tester", target=target(seeded), scope=scope(seeded))
        with pytest.raises(ShellDenied, match="scan id"):
            instance.run(request_for(seeded, scan_id=None, approval_token=str(uuid4())),
                         actor="tester", target=target(seeded), scope=scope(seeded))
    finally:
        session.close()
    assert runner.calls == []


def test_disallowed_program_and_network_are_denied(factory, seeded):
    runner = Runner()
    instance, session = executor(factory, runner)
    try:
        with pytest.raises(ShellDenied, match="program"):
            instance.run(request_for(seeded, argv=["sh", "-c", "id"]), actor="tester",
                         target=target(seeded), scope=scope(seeded))
        with pytest.raises(ShellDenied, match="network"):
            instance.run(request_for(seeded, network_access=True, approval_token=str(uuid4())),
                         actor="tester", target=target(seeded), scope=scope(seeded))
    finally:
        session.close()
    assert runner.calls == []


def test_cwd_outside_the_target_is_denied(factory, seeded, tmp_path):
    base = request_for(seeded, cwd=str(tmp_path))
    token, _ = approved_token(factory, seeded, base)
    runner = Runner()
    instance, session = executor(factory, runner)
    try:
        with pytest.raises(ShellDenied, match="outside"):
            instance.run(base.model_copy(update={"approval_token": token}), actor="tester",
                         target=target(seeded), scope=scope(seeded))
    finally:
        session.close()
    assert runner.calls == []


def test_out_of_scope_target_is_denied(factory, seeded, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    runner = Runner()
    instance, session = executor(factory, runner)
    try:
        with pytest.raises(ScopeDenied):
            instance.run(request_for(seeded), actor="tester",
                         target=Target(type="repository", locator=str(outside)), scope=scope(seeded))
    finally:
        session.close()
    assert runner.calls == []


def test_output_is_truncated(factory, seeded):
    base = request_for(seeded, max_output_bytes=10)
    token, _ = approved_token(factory, seeded, base)
    runner = Runner((0, b"x" * 100))
    instance, session = executor(factory, runner)
    try:
        result = instance.run(base.model_copy(update={"approval_token": token}), actor="tester",
                              target=target(seeded), scope=scope(seeded))
        session.commit()
    finally:
        session.close()
    assert result.truncated and result.output == "x" * 10 and result.output_bytes == 10


def test_sandbox_error_marks_the_audit_failed(factory, seeded):
    base = request_for(seeded)
    token, _ = approved_token(factory, seeded, base)
    recorder = Recorder()
    instance, session = executor(factory, Runner(SandboxError("sandbox is missing")), recorder)
    try:
        with pytest.raises(SandboxError):
            instance.run(base.model_copy(update={"approval_token": token}), actor="tester",
                         target=target(seeded), scope=scope(seeded))
    finally:
        session.close()
    assert recorder.events[-1]["status"] == "failed"


def test_invalid_runner_result_is_rejected(factory, seeded):
    base = request_for(seeded)
    token, _ = approved_token(factory, seeded, base)
    instance, session = executor(factory, Runner("not a tuple"))
    try:
        with pytest.raises(SandboxError, match="invalid result"):
            instance.run(base.model_copy(update={"approval_token": token}), actor="tester",
                         target=target(seeded), scope=scope(seeded))
    finally:
        session.close()


def test_constructor_requires_approvals_session_and_sandbox(factory, seeded):
    session = factory()
    try:
        with pytest.raises(ValueError, match="approval service"):
            SandboxedShellExecutor(Recorder(), approvals=object(), session=session, runner=Runner())
        with pytest.raises(ValueError, match="session"):
            SandboxedShellExecutor(Recorder(), approvals=ApprovalService(session), session=object(),
                                   runner=Runner())
        with pytest.raises(ValueError, match="WslSandbox"):
            SandboxedShellExecutor(Recorder(), approvals=ApprovalService(session), session=session)
        with pytest.raises(ValueError, match="audit"):
            SandboxedShellExecutor(object(), approvals=ApprovalService(session), session=session,
                                   runner=Runner())
    finally:
        session.close()


def test_host_shell_executor_stays_disabled(tmp_path):
    with pytest.raises(ShellDenied):
        ShellExecutor(Recorder()).run(request_for({"repo": tmp_path, "scan_id": uuid4()}),
                                      actor="tester", target=Target(type="repository", locator=str(tmp_path)),
                                      scope=authorization(tmp_path))
