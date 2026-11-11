"""Repository-level analyzers: tools that scan a whole tree once.

Semgrep, Gitleaks and Trivy work on a repository, not on a single file, so they
cannot use the per-file ``Analyzer`` interface. They are still policy-bound:

* the executable must live under an explicitly trusted root;
* the argument vector is built here, never taken from the caller;
* the process runs with a minimal environment, a timeout and a bounded report;
* findings are normalised to ``unverified`` and the configured target ID.

This is a trusted-tool allowlist, not an operating-system sandbox.
"""
from __future__ import annotations

import subprocess
import tempfile
import os
import hashlib
import re
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol

from vulnmind.findings import FindingCandidate
from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import check_target
from vulnmind.tools.adapters import AdapterError, parse_gitleaks, parse_sarif, parse_trivy, resolve_path

MAX_REPORT_BYTES = 32 * 1024 * 1024


class ScannerError(RuntimeError):
    """The scanner could not be executed or produced no usable report."""


class RepoScanFindings(list[FindingCandidate]):
    """List-compatible results carrying bounded, non-sensitive coverage notes."""
    def __init__(self, findings: Sequence[FindingCandidate], *, skipped: int, source: str):
        super().__init__(findings)
        self.coverage_limitations = ((f"{source} 有 {skipped} 条结果无法导入，分析可能不完整",)
                                     if skipped else ())


class RepoScanner(Protocol):
    def analyze(self, *, root: Path, actor: str, target: Target,
                scope: Authorization) -> list[FindingCandidate]: ...


Runner = Callable[[Sequence[str], Path, float], int]


def _subprocess_runner(argv: Sequence[str], cwd: Path, timeout: float) -> int:
    # Never forward credentials or tool configuration from the parent process.
    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP")
                   if key in os.environ}
    completed = subprocess.run(list(argv), cwd=str(cwd), timeout=timeout,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               env=environment,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return completed.returncode


class GitleaksAnalyzer:
    """Host execution is disabled; injected runners are for trusted tests."""

    def __init__(self, executable: Path, *, trusted_root: Path, target_id: str,
                 timeout_seconds: float = 120.0, runner: Runner | None = None):
        self._executable = Path(executable).resolve(strict=True)
        trusted = Path(trusted_root).resolve(strict=True)
        if not self._executable.is_relative_to(trusted):
            raise ScannerError("scanner executable is outside the trusted root")
        if not self._executable.is_file():
            raise ScannerError("scanner executable is not a file")
        if not target_id.strip():
            raise ValueError("target_id is required")
        if not 1 <= timeout_seconds <= 600:
            raise ValueError("timeout must be between 1 and 600 seconds")
        self._target_id = target_id
        self._timeout = float(timeout_seconds)
        self._runner = runner or _subprocess_runner

    def analyze(self, *, root: Path, actor: str, target: Target,
                scope: Authorization) -> list[FindingCandidate]:
        if self._runner is _subprocess_runner:
            raise ScannerError("host scanner execution is disabled; use the isolated WSL scanner")
        if not actor.strip():
            raise ScannerError("actor is required")
        if target.type.value != "repository":
            raise ScannerError("repository scanning requires a repository target")
        root = Path(root).resolve(strict=True)
        if not root.is_dir():
            raise ScannerError("repository root must be a directory")
        check_target(target, scope)
        if root != Path(target.locator).resolve(strict=True):
            raise ScannerError("scanner root does not match authorized target")
        with tempfile.TemporaryDirectory(prefix="vulnmind-gitleaks-") as workspace:
            report = Path(workspace) / "report.json"
            argv = [str(self._executable), "detect", "--no-git", "--redact",
                    "--exit-code", "0", "--report-format", "json",
                    "--report-path", str(report), "--source", str(root)]
            try:
                code = self._runner(argv, root, self._timeout)
            except (OSError, subprocess.SubprocessError) as exc:
                raise ScannerError("scanner could not be executed") from exc
            if code != 0:
                raise ScannerError("scanner exited with a failure status")
            if not report.is_file():
                raise ScannerError("scanner produced no report")
            if report.stat().st_size > MAX_REPORT_BYTES:
                raise ScannerError("scanner report exceeds the size limit")
            with report.open("rb") as stream:
                data = stream.read(MAX_REPORT_BYTES + 1)
            if len(data) > MAX_REPORT_BYTES:
                raise ScannerError("scanner report exceeds the size limit")
        try:
            parsed = parse_gitleaks(data, target_id=self._target_id)
        except AdapterError as exc:
            raise ScannerError("scanner report is not usable") from exc
        if parsed.truncated:
            raise ScannerError("scanner report exceeds the result limit")
        return RepoScanFindings([FindingCandidate.model_validate({**finding.model_dump(), "status": "unverified"})
                                 for finding in parsed.findings], skipped=parsed.skipped, source="Gitleaks")


def default_gitleaks_analyzer(project_root: Path, *, target_id: str) -> GitleaksAnalyzer | None:
    executable = project_root / ".devtools" / "scanners" / "gitleaks.exe"
    if not executable.is_file():
        return None
    return GitleaksAnalyzer(executable, trusted_root=project_root / ".devtools" / "scanners",
                            target_id=target_id)


class SandboxedGitleaksAnalyzer:
    """Run Gitleaks inside the WSL sandbox (no network namespace) instead of the host."""

    def __init__(self, sandbox, *, target_id: str, binary: str = "/usr/local/bin/gitleaks",
                 timeout_seconds: float = 180.0):
        for method in ("run_isolated_gitleaks",):
            if not callable(getattr(sandbox, method, None)):
                raise ValueError("a sandbox with run_isolated_gitleaks is required")
        if not target_id.strip():
            raise ValueError("target_id is required")
        if not binary.startswith("/"):
            raise ValueError("sandbox binary must be an absolute POSIX path")
        if not 1 <= timeout_seconds <= 600:
            raise ValueError("scanner timeout must be between 1 and 600 seconds")
        self._sandbox = sandbox
        self._target_id = target_id
        self._binary = binary
        self._timeout = timeout_seconds

    def analyze(self, *, root: Path, actor: str, target: Target,
                scope: Authorization) -> list[FindingCandidate]:
        from vulnmind.analysis.sandbox import sandbox_gitleaks_report

        if not actor.strip():
            raise ScannerError("actor is required")
        if target.type.value != "repository":
            raise ScannerError("repository scanning requires a repository target")
        root = Path(root).resolve(strict=True)
        if not root.is_dir():
            raise ScannerError("repository root must be a directory")
        check_target(target, scope)
        if root != Path(target.locator).resolve(strict=True):
            raise ScannerError("scanner root does not match authorized target")
        from vulnmind.analysis.sandbox import SandboxError

        try:
            data = sandbox_gitleaks_report(self._sandbox, root, binary=self._binary,
                                            timeout_seconds=self._timeout)
        except SandboxError as exc:
            raise ScannerError("sandboxed scanner could not run") from exc
        try:
            parsed = parse_gitleaks(data, target_id=self._target_id)
        except AdapterError as exc:
            raise ScannerError("scanner report is not usable") from exc
        if parsed.truncated:
            raise ScannerError("scanner report exceeds the result limit")
        return RepoScanFindings([FindingCandidate.model_validate({**finding.model_dump(), "status": "unverified"})
                                 for finding in parsed.findings], skipped=parsed.skipped, source="Gitleaks")

class SandboxedTrivyAnalyzer:
    """Require a filesystem-isolated Trivy runner; generic WSL run is unsafe."""

    def __init__(self, sandbox, *, target_id: str, binary: str = "/usr/local/bin/trivy",
                 cache_dir: str = "/var/cache/trivy", timeout_seconds: float = 300.0):
        if not callable(getattr(sandbox, "run_isolated_trivy", None)):
            raise ScannerError("filesystem-isolated Trivy execution is unavailable")
        if not target_id.strip():
            raise ValueError("target_id is required")
        if not binary.startswith("/") or not cache_dir.startswith("/"):
            raise ValueError("sandbox paths must be absolute POSIX paths")
        if not 1 <= timeout_seconds <= 900:
            raise ValueError("timeout must be between 1 and 900 seconds")
        self._sandbox = sandbox
        self._target_id = target_id
        self._binary = binary
        self._cache = cache_dir
        self._timeout = timeout_seconds

    def analyze(self, *, root: Path, actor: str, target: Target,
                scope: Authorization) -> list[FindingCandidate]:
        from vulnmind.analysis.sandbox import SandboxError

        if not actor.strip():
            raise ScannerError("actor is required")
        if target.type.value != "repository":
            raise ScannerError("repository scanning requires a repository target")
        root = Path(root).resolve(strict=True)
        if not root.is_dir():
            raise ScannerError("repository root must be a directory")
        check_target(target, scope)
        if root != Path(target.locator).resolve(strict=True):
            raise ScannerError("scanner root does not match authorized target")
        try:
            data = self._sandbox.run_isolated_trivy(root, binary=self._binary, cache_dir=self._cache,
                                                     timeout_seconds=self._timeout)
        except SandboxError as exc:
            raise ScannerError("sandboxed scanner could not run") from exc
        if not isinstance(data, bytes) or len(data) > MAX_REPORT_BYTES:
            raise ScannerError("sandboxed scanner report is invalid or too large")
        try:
            parsed = parse_trivy(data, target_id=self._target_id)
        except AdapterError as exc:
            raise ScannerError("scanner report is not usable") from exc
        if parsed.truncated:
            raise ScannerError("scanner report exceeds the result limit")
        return RepoScanFindings([FindingCandidate.model_validate({**finding.model_dump(), "status": "unverified"})
                                 for finding in parsed.findings], skipped=parsed.skipped, source="Trivy")


def _split_location(location: str) -> tuple[str, str | None]:
    head, separator, tail = location.rpartition(":")
    if separator and tail.isdigit() and 0 < int(tail) <= 10_000_000:
        return head, tail
    return location, None


class SarifReportAnalyzer:
    """Ingest an externally produced SARIF report (for example Semgrep).

    No scanner runs here: Semgrep's published wheels target glibc, which the
    Alpine sandbox does not provide, so an operator runs Semgrep separately and
    supplies its SARIF output. The document is untrusted input; only relative
    locations that resolve inside the authorized root are kept.
    """

    def __init__(self, report: Path, *, target_id: str, source_tool: str = "semgrep",
                 max_results: int = 1000, max_bytes: int = MAX_REPORT_BYTES,
                 expected_sha256: str | None = None):
        try:
            self._report = Path(report).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ScannerError("SARIF report does not exist") from exc
        if not self._report.is_file():
            raise ScannerError("SARIF report is not a file")
        if not target_id.strip():
            raise ValueError("target_id is required")
        if not source_tool.strip() or len(source_tool) > 128:
            raise ValueError("source_tool must contain 1 to 128 characters")
        if not 1 <= max_results <= 5000:
            raise ValueError("max_results must be between 1 and 5000")
        if not 1 <= max_bytes <= MAX_REPORT_BYTES:
            raise ValueError("max_bytes is out of range")
        if expected_sha256 is not None and (not isinstance(expected_sha256, str)
                                             or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)):
            raise ValueError("invalid expected report digest")
        self._target_id = target_id
        self._source_tool = source_tool
        self._max_results = max_results
        self._max_bytes = max_bytes
        self._expected_sha256 = expected_sha256

    def analyze(self, *, root: Path, actor: str, target: Target,
                scope: Authorization) -> list[FindingCandidate]:
        if not actor.strip():
            raise ScannerError("actor is required")
        if target.type.value != "repository":
            raise ScannerError("repository scanning requires a repository target")
        root = Path(root).resolve(strict=True)
        if not root.is_dir():
            raise ScannerError("repository root must be a directory")
        check_target(target, scope)
        if root != Path(target.locator).resolve(strict=True):
            raise ScannerError("scanner root does not match authorized target")
        if self._report.stat().st_size > self._max_bytes:
            raise ScannerError("SARIF report exceeds the size limit")
        with self._report.open("rb") as stream:
            data = stream.read(self._max_bytes + 1)
        if len(data) > self._max_bytes:
            raise ScannerError("SARIF report exceeds the size limit")
        if self._expected_sha256 is not None and hashlib.sha256(data).hexdigest() != self._expected_sha256:
            raise ScannerError("SARIF report changed after workflow binding")
        try:
            parsed = parse_sarif(data, target_id=self._target_id, source_tool=self._source_tool,
                                 max_results=self._max_results)
        except AdapterError as exc:
            raise ScannerError("SARIF report is not usable") from exc
        if parsed.truncated:
            raise ScannerError("SARIF report exceeds the result limit")
        findings: list[FindingCandidate] = []
        skipped = parsed.skipped
        for finding in parsed.findings:
            path, line = _split_location(finding.location)
            resolved = resolve_path(root, path)
            if resolved is None:
                skipped += 1
                continue
            relative = resolved.relative_to(root).as_posix()
            location = f"{relative}:{line}" if line else relative
            findings.append(FindingCandidate(
                title=finding.title, vulnerability_type=finding.vulnerability_type,
                target_id=self._target_id, location=location[:1000],
                source_tool=self._source_tool, status="unverified",
                severity=finding.severity))
        return RepoScanFindings(findings, skipped=skipped, source="SARIF")


class McpCheckovAnalyzer:
    """Run Checkov IaC audit via the controlled HexStrike MCP server over a bounded workspace snapshot."""

    def __init__(self, *, target_id: str, external_root: Path | None = None,
                 distro: str = "VulnMindLab", external_service=None):
        if not target_id.strip():
            raise ValueError("target_id is required")
        self._target_id = target_id
        self._external_root = Path(external_root) if external_root else None
        self._distro = distro
        self._external_service = external_service

    def _collect_iac_files(self, root: Path) -> list[tuple[str, str]]:
        from vulnmind.integrations.hexstrike.workspace_ops import (
            MAX_BYTES, MAX_CONTENT, MAX_FILES, WorkspaceError, normalize_name,
        )
        collected: list[tuple[str, str]] = []
        total_bytes = 0
        import os
        def candidates():
            for directory, dirs, names in os.walk(root, followlinks=False):
                dirs[:] = sorted(d for d in dirs if not d.startswith('.') and d not in
                    {'node_modules','venv','dist','build','coverage','__pycache__'}
                    and not Path(directory,d).is_symlink() and not Path(directory,d).is_junction())
                for name in sorted(names): yield Path(directory,name)
        for path in candidates():
            if len(collected) >= MAX_FILES - 1: break
            if path.is_junction() or not path.resolve().is_relative_to(root): continue
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if any(part.startswith(".") and part not in {".dockerfile"} for part in rel.split("/")[:-1]):
                continue
            lower = path.name.lower()
            is_iac = (
                lower == "dockerfile"
                or lower.startswith("dockerfile.")
                or lower.endswith((".dockerfile", ".tf", ".yaml", ".yml"))
            )
            if not is_iac:
                continue
            try:
                norm = normalize_name(rel)
            except WorkspaceError:
                continue
            size = path.stat().st_size
            if size > MAX_CONTENT or total_bytes + size > MAX_BYTES or len(collected) >= MAX_FILES - 1:
                continue
            try:
                text = path.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                continue
            collected.append((norm, text))
            total_bytes += len(text.encode("utf-8"))
        return collected

    def analyze(self, *, root: Path, actor: str, target: Target,
                scope: Authorization) -> list[FindingCandidate]:
        if not actor.strip():
            raise ScannerError("actor is required")
        if target.type.value != "repository":
            raise ScannerError("repository scanning requires a repository target")
        root = Path(root).resolve(strict=True)
        if not root.is_dir():
            raise ScannerError("repository root must be a directory")
        check_target(target, scope)
        if root != Path(target.locator).resolve(strict=True):
            raise ScannerError("scanner root does not match authorized target")
        iac_files = self._collect_iac_files(root)
        if not iac_files:
            return RepoScanFindings([], skipped=0, source="Checkov-MCP")
        service = self._external_service
        if service is None:
            from vulnmind.workbench.external import ExternalWorkbench
            ext_root = self._external_root or (Path(__file__).resolve().parents[3] / ".vulnmind-workbench" / "external")
            service = ExternalWorkbench(ext_root, distro=self._distro)
        workspace_id = None
        try:
            for rel_name, content in iac_files:
                prep_args = {"tool_id": "hexstrike.create_file", "arguments": {"filename": rel_name, "content": content}}
                if workspace_id:
                    prep_args["workspace_job_id"] = workspace_id
                prepared = service.prepare(prep_args)
                workspace_id = prepared["plan"]["scope"]["workspace"]
                exec_res = service.execute(prepared["plan"]["execution_id"], prepared["digest"])
                if exec_res["execution"]["status"] != "succeeded":
                    raise ScannerError("MCP workspace staging failed")
            scan_prep = service.prepare({
                "tool_id": "hexstrike.checkov_iac_scan",
                "workspace_job_id": workspace_id,
                "arguments": {"directory": ".", "output_format": "json"},
            })
            scan_exec = service.execute(scan_prep["plan"]["execution_id"], scan_prep["digest"])
        except Exception as exc:
            if isinstance(exc, ScannerError):
                raise
            raise ScannerError("MCP Checkov execution failed") from exc
        if scan_exec["execution"]["status"] != "succeeded":
            raise ScannerError("MCP Checkov scanner returned failure status")
        payload = scan_exec["execution"].get("result") or {}
        failed_checks = (payload.get("results") or {}).get("failed_checks") or []
        findings: list[FindingCandidate] = []
        skipped = 0
        for item in failed_checks:
            check_id = str(item.get("check_id") or "CKV_UNKNOWN").strip()
            check_name = str(item.get("check_name") or "IaC policy violation").strip()
            file_path = str(item.get("file_path") or "").strip().lstrip("/")
            resolved = resolve_path(root, file_path)
            if resolved is None:
                skipped += 1
                continue
            relative = resolved.relative_to(root).as_posix()
            findings.append(FindingCandidate(
                title=f"{check_id}: {check_name}"[:250],
                vulnerability_type="iac_misconfiguration",
                target_id=self._target_id,
                location=relative[:1000],
                source_tool="hexstrike.checkov_iac_scan",
                status="unverified",
                severity="medium",
            ))
        return RepoScanFindings(findings, skipped=skipped, source="Checkov-MCP")
