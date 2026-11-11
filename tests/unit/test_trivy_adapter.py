"""Trivy parser and sandboxed analyzer tests (no DB required)."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vulnmind.analysis.repo_analyzers import SandboxedTrivyAnalyzer, ScannerError
from vulnmind.schemas import Authorization, Target
from vulnmind.tools.adapters import AdapterError, parse_trivy


def report():
    return {"SchemaVersion": 2, "Results": [{
        "Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip",
        "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2023-32681", "PkgName": "requests",
             "InstalledVersion": "2.19.0", "FixedVersion": "2.31.0", "Severity": "MEDIUM",
             "Title": "Proxy-Authorization header leak"},
            {"VulnerabilityID": "CVE-2024-0001", "PkgName": "urllib3",
             "InstalledVersion": "1.26.0", "FixedVersion": "1.26.5", "Severity": "CRITICAL"},
            {"VulnerabilityID": "CVE-2024-0002", "PkgName": "flask",
             "InstalledVersion": "1.0", "FixedVersion": None, "Severity": "UNKNOWN"},
        ]}]}


def test_parse_trivy_maps_fields_and_severity():
    parsed = parse_trivy(json.dumps(report()), target_id="repo")
    assert len(parsed.findings) == 3
    first = parsed.findings[0]
    assert first.vulnerability_type == "dependency_vulnerability"
    assert first.source_tool == "trivy" and first.status == "unverified"
    assert first.severity == "medium" and "CVE-2023-32681" in first.title
    assert first.location == "requirements.txt:requests"
    assert [item.severity for item in parsed.findings] == ["medium", "critical", "unknown"]


def test_parse_trivy_limits_and_rejects_bad_shapes():
    parsed = parse_trivy(report(), target_id="repo", max_results=1)
    assert len(parsed.findings) == 1 and parsed.truncated is True
    with pytest.raises(AdapterError):
        parse_trivy([], target_id="repo")
    with pytest.raises(AdapterError):
        parse_trivy({"Results": "nope"}, target_id="repo")
    skipped = parse_trivy({"Results": [{"Vulnerabilities": [{"PkgName": "x"}]}]}, target_id="repo")
    assert skipped.findings == [] and skipped.skipped == 1
    with pytest.raises(AdapterError):
        parse_trivy({}, target_id="repo")
    with pytest.raises(AdapterError, match="Results"):
        parse_trivy({"Results": False}, target_id="repo")
    malformed = parse_trivy({"Results": [{"Vulnerabilities": False}, report()["Results"][0]]}, target_id="repo")
    assert malformed.skipped == 1 and len(malformed.findings) == 3


class FakeSandbox:
    def __init__(self, payload=None, exit_code=0):
        self.payload = json.dumps(report()).encode() if payload is None else payload
        self.exit_code = exit_code
        self.calls = []

    def run_isolated_trivy(self, root, *, binary, cache_dir, timeout_seconds):
        from vulnmind.analysis.sandbox import SandboxError
        self.calls.append((root, binary, cache_dir, timeout_seconds))
        if self.exit_code:
            raise SandboxError("failure status")
        return self.payload


def authorization(root):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)])


def test_analyzer_uses_injected_isolated_runner_contract(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    sandbox = FakeSandbox()
    findings = SandboxedTrivyAnalyzer(sandbox, target_id="repository").analyze(
        root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
        scope=authorization(repo))
    assert len(findings) == 3 and findings[1].severity == "critical"
    assert sandbox.calls == [(repo.resolve(), "/usr/local/bin/trivy", "/var/cache/trivy", 300.0)]


def test_analyzer_failures_are_explicit(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ScannerError, match="could not run"):
        SandboxedTrivyAnalyzer(FakeSandbox(exit_code=2), target_id="repository").analyze(
            root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
            scope=authorization(repo))
    with pytest.raises(ScannerError, match="not usable"):
        SandboxedTrivyAnalyzer(FakeSandbox(payload=b"{}"), target_id="repository").analyze(
            root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
            scope=authorization(repo))
    with pytest.raises(ValueError, match="POSIX"):
        SandboxedTrivyAnalyzer(FakeSandbox(), target_id="repository", binary="trivy")


def test_wsl_trivy_uses_the_isolated_contract_not_generic_run(tmp_path):
    from vulnmind.analysis.sandbox import WslSandbox

    calls = []

    def generic(*_args):
        raise AssertionError("generic WSL execution must not run")

    sandbox = WslSandbox(runner=generic)
    payload = json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        {"PkgName": "requests", "InstalledVersion": "2.19.0",
         "VulnerabilityID": "CVE-2018-18074", "Severity": "HIGH"}]}]}).encode()

    def isolated(root, *, binary, cache_dir, timeout_seconds):
        calls.append((root, binary, cache_dir, timeout_seconds))
        return payload

    sandbox.run_isolated_trivy = isolated
    repo = tmp_path / "repo"
    repo.mkdir()
    findings = SandboxedTrivyAnalyzer(sandbox, target_id="repository").analyze(
        root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
        scope=authorization(repo))
    assert calls == [(repo.resolve(), "/usr/local/bin/trivy", "/var/cache/trivy", 300.0)]
    assert findings and findings[0].source_tool == "trivy" and findings[0].status == "unverified"


def test_trivy_checks_authorization_and_target_before_runner(tmp_path):
    from vulnmind.security.scope import ScopeDenied
    repo = tmp_path / "repo"
    repo.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    sandbox = FakeSandbox()
    analyzer = SandboxedTrivyAnalyzer(sandbox, target_id="repository")
    with pytest.raises(ScopeDenied):
        analyzer.analyze(root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
                         scope=authorization(other))
    with pytest.raises(ScannerError, match="authorized target"):
        analyzer.analyze(root=other, actor="tester", target=Target(type="repository", locator=str(repo)),
                         scope=authorization(repo))
    assert sandbox.calls == []


def test_trivy_truncated_results_fail_closed(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    data = report()
    data["Results"][0]["Vulnerabilities"] = [data["Results"][0]["Vulnerabilities"][0]] * 2001
    sandbox = FakeSandbox(payload=json.dumps(data).encode())
    with pytest.raises(ScannerError, match="result limit"):
        SandboxedTrivyAnalyzer(sandbox, target_id="repository").analyze(
            root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
            scope=authorization(repo))
