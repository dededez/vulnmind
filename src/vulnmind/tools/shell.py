"""Policy-gated shell executor prototype.

The public executor fails closed: this prototype cannot isolate child processes
or enforce its caller-supplied network and risk declarations. The private
execution helpers are retained for future work and are not a security sandbox.

Do not register this as a pure Tool Registry tool: the registry rejects
non-pure permissions on purpose. A privileged caller must supply the policy
decision (approval) that is still missing.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vulnmind.analysis.sandbox import SHELL_APPLETS, SandboxError
from vulnmind.schemas import Authorization, Target, TargetType
from vulnmind.security.approvals import ApprovalGate, operation_digest
from vulnmind.security.scope import ScopeDenied, check_target
from vulnmind.tools.registry import AuditSink

_PROGRAM = re.compile(r"[A-Za-z0-9._-]{1,255}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_SECRET_HINT = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", re.IGNORECASE)
_OS_ENV = ("SYSTEMROOT", "SYSTEMDRIVE", "PATH", "PATHEXT", "TEMP", "TMP")
_MAX_ARGV = 64
_MAX_ARGUMENT = 4096


class ShellDenied(Exception):
    """The request is outside policy; nothing was executed."""


class ShellToolInput(BaseModel):
    """Input schema mirrors section 7.1 of the design document."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    argv: list[str] = Field(min_length=1, max_length=_MAX_ARGV)
    cwd: str
    timeout_seconds: int = Field(default=120, ge=1, le=600)
    env_allowlist: list[str] = Field(default_factory=list, max_length=32)
    network_access: bool = False
    risk_level: Literal["low", "medium", "high"] = "low"
    purpose: str = Field(min_length=1, max_length=500)
    approval_token: str | None = Field(default=None, max_length=256)
    scan_id: UUID | None = None
    max_output_bytes: int = Field(default=200_000, ge=1, le=1_000_000)

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("argv cannot be empty")
        for argument in value:
            if not isinstance(argument, str) or not argument or len(argument) > _MAX_ARGUMENT:
                raise ValueError("every argument must contain 1 to 4096 characters")
            if any(ord(char) < 32 or ord(char) == 127 for char in argument):
                raise ValueError("arguments cannot contain control characters")
        program = value[0]
        if program in {".", ".."}:
            raise ValueError("invalid program name")
        if _PROGRAM.fullmatch(program):
            return value
        # Absolute paths are allowed (virtualenv interpreters, scanner binaries);
        # relative paths and parent references are not.
        candidate = Path(program)
        if not candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError("program must be a plain executable name or an absolute path")
        return value

    @field_validator("cwd", "purpose")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("working directory and purpose cannot be blank")
        return value

    @field_validator("env_allowlist")
    @classmethod
    def validate_env_names(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("environment allowlist cannot repeat a name")
        for name in value:
            if not _ENV_NAME.fullmatch(name):
                raise ValueError("environment names must be plain identifiers")
            if _SECRET_HINT.search(name):
                raise ValueError("secret-like environment names are never forwarded")
        return value


class ShellResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    call_id: str
    exit_code: int | None
    timed_out: bool
    truncated: bool
    duration_ms: float
    output_bytes: int
    output: str


def shell_operation_digest(request: ShellToolInput) -> str:
    """Fingerprint the complete server-side request except its approval token.

    This helper does not enable execution, verify an approver, or commit an
    approval consumption. Request fields must never contain credentials.
    """
    if request.scan_id is None:
        raise ValueError("a scan ID is required for operation binding")
    snapshot = ShellToolInput.model_validate(request.model_dump())
    return operation_digest({"tool": "shell.exec", "request": snapshot.model_dump(mode="json", exclude={"approval_token"})})


class ShellExecutor:
    """Runs commands inside an authorized repository under the tool contract."""

    def __init__(self, audit: AuditSink, approvals: ApprovalGate | None = None):
        self._audit = audit
        self._approvals = approvals

    def run(self, request: ShellToolInput, *, actor: str, target: Target,
            scope: Authorization) -> ShellResult:
        call_id = str(uuid4())
        # Never record argv, output, cwd or credentials in audit events.
        event = {"call_id": call_id, "tool_name": "shell.exec", "actor": actor,
                 "target_type": target.type.value}
        self._audit.record({**event, "status": "requested"})
        # The current backend cannot enforce filesystem or network isolation.
        # Do not trust caller-supplied risk and network flags as a security boundary.
        self._audit.record({**event, "status": "denied"})
        raise ShellDenied("shell execution is disabled until isolation is available")

    def _require_approval(self, request: ShellToolInput, target: Target) -> None:
        # A legacy status lookup does not bind the complete command or consume
        # a decision. Never let this helper turn that lookup into authorization.
        raise ShellDenied("shell approval is disabled until binding and isolation are integrated")

    @staticmethod
    def _authorized_cwd(raw: str, target: Target, scope: Authorization) -> Path:
        if not Path(raw).is_absolute():
            raise ShellDenied("working directory must be absolute")
        try:
            cwd = Path(raw).resolve(strict=True)
        except (OSError, RuntimeError):
            raise ShellDenied("working directory does not exist") from None
        if not cwd.is_dir():
            raise ShellDenied("working directory is not a directory")
        root = Path(target.locator).resolve(strict=True)
        if not cwd.is_relative_to(root):
            raise ShellDenied("working directory is outside the authorized target")
        for denied in scope.denied_repository_roots:
            try:
                denied_path = Path(denied).resolve(strict=True)
            except (OSError, RuntimeError):
                raise ShellDenied("invalid denied repository root") from None
            if cwd.is_relative_to(denied_path) or denied_path.is_relative_to(cwd):
                raise ShellDenied("working directory overlaps a denied path")
        return cwd

    @staticmethod
    def _authorized_program(program: str, scope: Authorization) -> None:
        """Absolute programs must exist and must not hide inside a denied root."""
        if _PROGRAM.fullmatch(program):
            return
        try:
            resolved = Path(program).resolve(strict=True)
        except (OSError, RuntimeError):
            raise ShellDenied("program does not exist") from None
        if not resolved.is_file():
            raise ShellDenied("program is not a file")
        for denied in scope.denied_repository_roots:
            try:
                denied_path = Path(denied).resolve(strict=True)
            except (OSError, RuntimeError):
                raise ShellDenied("invalid denied repository root") from None
            if resolved.is_relative_to(denied_path):
                raise ShellDenied("program is inside a denied path")

    def _execute(self, request: ShellToolInput, cwd: Path, call_id: str) -> ShellResult:
        environment = self._environment(request.env_allowlist)
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        started = time.monotonic()
        process = subprocess.Popen(  # noqa: S603 - argv only, shell disabled
            request.argv, cwd=str(cwd), env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=creationflags, start_new_session=os.name != "nt")
        collected: list[bytes] = []
        state = {"total": 0, "truncated": False}

        def pump() -> None:
            assert process.stdout is not None
            while True:
                chunk = process.stdout.read(65536)
                if not chunk:
                    break
                room = request.max_output_bytes - state["total"]
                if room <= 0:
                    state["truncated"] = True
                    continue
                keep = chunk[:room]
                collected.append(keep)
                state["total"] += len(keep)
                if len(keep) < len(chunk):
                    state["truncated"] = True

        reader = threading.Thread(target=pump, daemon=True)
        reader.start()
        timed_out = False
        try:
            process.wait(timeout=request.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._terminate(process)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        reader.join(timeout=10)
        if process.stdout is not None:
            process.stdout.close()
        duration = (time.monotonic() - started) * 1000
        return ShellResult(call_id=call_id, exit_code=process.returncode, timed_out=timed_out,
                           truncated=state["truncated"], duration_ms=round(duration, 1),
                           output_bytes=state["total"],
                           output=b"".join(collected).decode("utf-8", "replace"))

    @staticmethod
    def _terminate(process: subprocess.Popen) -> None:
        if os.name == "nt":
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False)
                return
            except OSError:
                pass
            process.kill()
            return
        try:
            os.killpg(os.getpgid(process.pid), 9)
        except (ProcessLookupError, PermissionError, OSError):
            process.kill()

    @staticmethod
    def _environment(allowlist: list[str]) -> dict[str, str]:
        environment = {name: os.environ[name] for name in allowlist if name in os.environ}
        for name in _OS_ENV:
            if name in os.environ:
                environment.setdefault(name, os.environ[name])
        return environment


SHELL_ACTION = "shell.exec"


class SandboxedShellExecutor:
    """Runs one allowlisted read-only command after a bound, single-use approval.

    The approval is consumed with a compare-and-set and the consumption is
    committed *before* the command starts, so a crash cannot replay it. This
    requires a session dedicated to the executor: committing approval
    consumption commits the caller's other pending work in the same session.

    The command itself runs through ``WslSandbox.run_shell_isolated``: private
    mount/network/PID namespaces, a read-only repository bind mount, no network
    and a non-root user. The host kernel and WSL distribution remain trusted; this
    is not equivalent to a hardware-isolated container.
    """

    def __init__(self, audit, *, approvals, session, sandbox=None, runner=None):
        if not callable(getattr(audit, "record", None)):
            raise ValueError("an audit sink is required")
        if not callable(getattr(approvals, "consume_bound", None)):
            raise ValueError("an approval service with consume_bound is required")
        if not callable(getattr(session, "commit", None)):
            raise ValueError("a dedicated session is required for approval consumption")
        if runner is None and not callable(getattr(sandbox, "run_shell_isolated", None)):
            raise ValueError("a WslSandbox or runner is required")
        if runner is not None and not callable(runner):
            raise ValueError("runner must be callable")
        self._audit = audit
        self._approvals = approvals
        self._session = session
        self._sandbox = sandbox
        self._runner = runner

    def run(self, request: ShellToolInput, *, actor: str, target: Target,
            scope: Authorization) -> ShellResult:
        call_id = str(uuid4())
        event = {"call_id": call_id, "tool_name": SHELL_ACTION, "actor": actor,
                 "target_type": target.type.value}
        self._audit.record({**event, "status": "requested"})
        try:
            check_target(target, scope)
            if target.type.value != TargetType.REPOSITORY.value:
                raise ShellDenied("shell commands only run against a repository target")
            if request.network_access:
                raise ShellDenied("network access is not available in the shell sandbox")
            if request.argv[0] not in SHELL_APPLETS:
                raise ShellDenied("program is not allowed in the shell sandbox")
            cwd = ShellExecutor._authorized_cwd(request.cwd, target, scope)
            if request.scan_id is None:
                raise ShellDenied("a scan id is required for approval binding")
            if not request.approval_token:
                raise ShellDenied("an operator approval is required")
            digest = shell_operation_digest(request)
            if not self._approvals.consume_bound(request.approval_token, scan_id=request.scan_id,
                                                 action=SHELL_ACTION, target=digest,
                                                 operation_hash=digest):
                raise ShellDenied("approval is not valid for this exact operation")
            try:
                self._session.commit()
            except Exception as exc:  # noqa: BLE001 - any commit failure must stop execution
                raise ShellDenied("approval consumption could not be committed") from exc
            self._audit.record({**event, "status": "started"})
            root = Path(target.locator).resolve(strict=True)
            relative = cwd.relative_to(root).as_posix()
            if relative == ".":
                relative = ""
            started = time.monotonic()
            exit_code, raw = self._execute(request, root, relative)
            duration = (time.monotonic() - started) * 1000
            truncated = len(raw) > request.max_output_bytes
            output = raw[:request.max_output_bytes].decode("utf-8", "replace")
            self._audit.record({**event, "status": "succeeded"})
            return ShellResult(call_id=call_id, exit_code=exit_code,
                               timed_out=exit_code in (124, 137), truncated=truncated,
                               duration_ms=round(duration, 1),
                               output_bytes=min(len(raw), request.max_output_bytes),
                               output=output)
        except ScopeDenied:
            self._audit.record({**event, "status": "denied"})
            raise
        except ShellDenied:
            self._audit.record({**event, "status": "denied"})
            raise
        except SandboxError:
            self._audit.record({**event, "status": "failed"})
            raise

    def _execute(self, request: ShellToolInput, root: Path, relative: str) -> tuple[int, bytes]:
        if self._runner is not None:
            result = self._runner(list(request.argv), root, relative,
                                  request.timeout_seconds, request.max_output_bytes)
        else:
            result = self._sandbox.run_shell_isolated(
                root, argv=list(request.argv), cwd_relative=relative,
                timeout_seconds=request.timeout_seconds,
                max_output_bytes=request.max_output_bytes)
        if (not isinstance(result, tuple) or len(result) != 2
                or isinstance(result[0], bool) or not isinstance(result[0], int)
                or not isinstance(result[1], (bytes, bytearray))):
            raise SandboxError("sandbox returned an invalid result")
        return result[0], bytes(result[1])
