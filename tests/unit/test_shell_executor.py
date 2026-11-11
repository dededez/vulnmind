"""Policy tests for the shell executor: boundaries, timeout, cap, environment."""
import os
import sys
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import ScopeDenied
from vulnmind.tools.shell import ShellDenied, ShellExecutor, ShellToolInput, shell_operation_digest


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


def authorization(tmp_path, *, denied=()):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(tmp_path)], denied_repository_roots=list(denied))


def request(**overrides):
    payload = {"argv": [sys.executable, "-c", "print('ok')"], "cwd": "", "purpose": "test run"}
    payload.update(overrides)
    return payload


def run(executor, payload, tmp_path, *, denied=(), target=None, scope=None):
    return executor.run(ShellToolInput(**payload), actor="tester",
                        target=target or Target(type="repository", locator=str(tmp_path)),
                        scope=scope or authorization(tmp_path, denied=denied))


def test_runs_argv_without_shell(tmp_path):
    recorder = Recorder()
    with pytest.raises(ShellDenied, match="disabled"):
        run(ShellExecutor(recorder), request(cwd=str(tmp_path)), tmp_path)
    assert [event["status"] for event in recorder.events] == ["requested", "denied"]
    assert all("output" not in event and "argv" not in event for event in recorder.events)


def test_shell_metacharacters_are_literal_arguments(tmp_path):
    payload = ShellToolInput(**request(argv=[sys.executable, "-c", "import sys; print(sys.argv[1])", "; echo injected"], cwd=str(tmp_path)))
    result = ShellExecutor(Recorder())._execute(payload, tmp_path, str(uuid4()))
    assert result.output.strip() == "; echo injected"


def test_working_directory_must_stay_inside_target(tmp_path):
    with pytest.raises(ShellDenied, match="outside the authorized target"):
        ShellExecutor._authorized_cwd(str(tmp_path.parent), Target(type="repository", locator=str(tmp_path)), authorization(tmp_path))


def test_working_directory_must_be_absolute_and_existing(tmp_path):
    target, scope = Target(type="repository", locator=str(tmp_path)), authorization(tmp_path)
    with pytest.raises(ShellDenied, match="absolute"): ShellExecutor._authorized_cwd(".", target, scope)
    with pytest.raises(ShellDenied, match="does not exist"): ShellExecutor._authorized_cwd(str(tmp_path / "missing"), target, scope)


def test_denied_root_overlap_is_refused(tmp_path):
    denied = tmp_path / "vendor"
    denied.mkdir()
    with pytest.raises(ShellDenied, match="overlaps"):
        ShellExecutor._authorized_cwd(str(denied), Target(type="repository", locator=str(tmp_path)), authorization(tmp_path, denied=[str(denied)]))


def test_network_and_risk_are_refused(tmp_path):
    for level in ("low", "medium", "high"):
        for network in (False, True):
            with pytest.raises(ShellDenied, match="disabled"):
                run(ShellExecutor(Recorder()), request(cwd=str(tmp_path), risk_level=level, network_access=network), tmp_path)


class Gate:
    def __init__(self, approved: bool):
        self.approved = approved
        self.calls = []

    def is_approved(self, approval_id, *, action, target):
        self.calls.append((approval_id, action, target))
        return self.approved


def test_medium_risk_runs_only_with_a_matching_approval(tmp_path):
    payload = request(cwd=str(tmp_path), risk_level="medium", approval_token=str(uuid4()))
    gate = Gate(approved=True)
    with pytest.raises(ShellDenied, match="disabled"):
        run(ShellExecutor(Recorder(), gate), payload, tmp_path)
    assert gate.calls == []


def test_legacy_internal_gate_cannot_authorize_a_command(tmp_path):
    gate = Gate(approved=True)
    executor = ShellExecutor(Recorder(), gate)
    for level in ("low", "medium", "high"):
        payload = ShellToolInput(**request(cwd=str(tmp_path), risk_level=level, approval_token=str(uuid4())))
        with pytest.raises(ShellDenied, match="binding and isolation"):
            executor._require_approval(payload, Target(type="repository", locator=str(tmp_path)))
    assert gate.calls == []


def test_web_target_is_refused(tmp_path):
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner", starts_at=now-timedelta(hours=1), expires_at=now+timedelta(hours=1), web_origins=["https://example.test"])
    with pytest.raises(ShellDenied, match="disabled"):
        run(ShellExecutor(Recorder()), request(cwd=str(tmp_path)), tmp_path, target=Target(type="web", locator="https://example.test"), scope=scope)


def test_timeout_terminates_the_process(tmp_path):
    payload = ShellToolInput(**request(argv=[sys.executable, "-c", "import time; time.sleep(30)"], cwd=str(tmp_path), timeout_seconds=1))
    result = ShellExecutor(Recorder())._execute(payload, tmp_path, str(uuid4()))
    assert result.timed_out and result.duration_ms < 15000


def test_output_is_capped(tmp_path):
    payload = ShellToolInput(**request(argv=[sys.executable, "-c", "print('x' * 5000)"], cwd=str(tmp_path), max_output_bytes=50))
    result = ShellExecutor(Recorder())._execute(payload, tmp_path, str(uuid4()))
    assert result.truncated and result.output_bytes == 50 and len(result.output) == 50


def test_environment_is_limited_to_the_allowlist(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNMIND_TEST_VISIBLE", "shown")
    assert "VULNMIND_TEST_VISIBLE" not in ShellExecutor._environment([])
    assert ShellExecutor._environment(["VULNMIND_TEST_VISIBLE"])["VULNMIND_TEST_VISIBLE"] == "shown"


def test_denied_requests_are_audited(tmp_path):
    recorder = Recorder()
    with pytest.raises(ShellDenied):
        run(ShellExecutor(recorder), request(cwd=str(tmp_path), network_access=True), tmp_path)
    assert [event["status"] for event in recorder.events] == ["requested", "denied"]


@pytest.mark.parametrize("argv", [
    [],
    ["./scanner"],
    ["../scanner"],
    [sys.executable, ""],
    [sys.executable, "bad\x00argument"],
])
def test_argument_vector_is_validated(argv):
    with pytest.raises(ValidationError):
        ShellToolInput(argv=argv, cwd="C:\\", purpose="test")


def test_absolute_programs_must_exist(tmp_path):
    with pytest.raises(ShellDenied, match="does not exist"):
        ShellExecutor._authorized_program(str(tmp_path / "missing-scanner.exe"), authorization(tmp_path))


def test_program_inside_denied_root_is_refused(tmp_path):
    denied = tmp_path / "vendor"
    denied.mkdir()
    program = denied / "scanner.exe"
    program.write_bytes(b"")
    with pytest.raises(ShellDenied, match="denied path"):
        ShellExecutor._authorized_program(str(program), authorization(tmp_path, denied=[str(denied)]))


def test_secret_like_environment_names_are_rejected():
    with pytest.raises(ValidationError, match="secret-like"):
        ShellToolInput(argv=[sys.executable], cwd="C:\\", purpose="test",
                       env_allowlist=["VULNMIND_API_TOKEN"])


def test_shell_approval_digest_binds_operation_not_token(tmp_path):
    scan_id = uuid4()
    first = ShellToolInput(**request(cwd=str(tmp_path), scan_id=scan_id, approval_token="one"))
    different_token = ShellToolInput(**request(cwd=str(tmp_path), scan_id=scan_id, approval_token="two"))
    changed_arguments = ShellToolInput(**request(cwd=str(tmp_path), scan_id=scan_id, argv=[sys.executable, "-V"]))
    changed_timeout = ShellToolInput(**request(cwd=str(tmp_path), scan_id=scan_id, timeout_seconds=5))
    assert shell_operation_digest(first) == shell_operation_digest(different_token)
    assert shell_operation_digest(first) != shell_operation_digest(changed_arguments)
    assert shell_operation_digest(first) != shell_operation_digest(changed_timeout)
    with pytest.raises(ValueError):
        shell_operation_digest(ShellToolInput(**request(cwd=str(tmp_path))))
