"""WSL sandbox tests: path mapping, argv construction, analyzer contract."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vulnmind.analysis.repo_analyzers import SandboxedGitleaksAnalyzer, ScannerError
from vulnmind.analysis.sandbox import SandboxError, WslSandbox, windows_to_wsl
from vulnmind.schemas import Authorization, Target


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "config.py").write_bytes(b"aws_access_key_id = 'AKIAABCDEFGHIJKLMNOP'\n")
    return root


def authorization(root):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)])


def report_bytes():
    return json.dumps([{"RuleID": "aws-access-token", "Description": "AWS Access Token",
                        "File": "config.py", "StartLine": 1, "Secret": "AKIAABCDEFGHIJKLMNOP"}]).encode()


class FakeSandbox:
    def __init__(self, *, exit_code=0, report=None):
        self.calls = []
        self.exit_code = exit_code
        self.report = report if report is not None else report_bytes()

    def run(self, argv, *, cwd_windows=None, network=False):
        self.calls.append((list(argv), cwd_windows, network))
        return self.exit_code, b""

    def read_file(self, path):
        self.calls.append((["cat", path], None, False))
        return self.report

    def remove(self, path):
        self.calls.append((["rm", path], None, False))

    def run_isolated_gitleaks(self, root, *, binary, timeout_seconds):
        from vulnmind.analysis.sandbox import SandboxError
        self.calls.append(([binary, "isolated"], root, False))
        if self.exit_code:
            raise SandboxError("scanner failed")
        return self.report


def test_windows_path_mapping():
    assert windows_to_wsl(Path(r"D:\work\repo")) == "/mnt/d/work/repo"
    assert windows_to_wsl(r"C:\Users\Public") == "/mnt/c/Users/Public"
    with pytest.raises(SandboxError, match="UNC"):
        windows_to_wsl(r"\\server\share")
    with pytest.raises(SandboxError, match="absolute"):
        windows_to_wsl("relative/path")
    with pytest.raises(SandboxError, match="absolute"):
        windows_to_wsl(r"C:relative")
    with pytest.raises(SandboxError, match="absolute"):
        windows_to_wsl(r"1:\bad")
    with pytest.raises(SandboxError, match="absolute"):
        windows_to_wsl(r"C:\safe\..\outside")


def test_sandbox_prepends_unshare_and_passes_argv():
    sandbox = WslSandbox(runner=lambda command, cwd: (0, b""))
    code, _ = sandbox.run(["echo", "hello"], cwd_windows=Path(r"D:\work"))
    assert code == 0
    sandbox._runner = lambda command, cwd: (0, b"")
    # Verify the command construction directly.
    built = []
    sandbox._runner = lambda command, cwd: (built.append((list(command), cwd)) or (0, b""))
    sandbox.run(["gitleaks", "version"], cwd_windows=Path(r"D:\work"))
    assert built[0][0] == ["/usr/bin/unshare", "-n", "gitleaks", "version"]


def test_sandbox_validates_inputs():
    sandbox = WslSandbox(runner=lambda command, cwd: (0, b""))
    with pytest.raises(ValueError):
        sandbox.run([], cwd_windows=None)
    with pytest.raises(ValueError):
        WslSandbox(" ")
    with pytest.raises(ValueError):
        WslSandbox("distro", timeout_seconds=0)
    with pytest.raises(SandboxError):
        sandbox.read_file("relative")


def test_analyzer_runs_inside_the_sandbox(repo):
    sandbox = FakeSandbox()
    analyzer = SandboxedGitleaksAnalyzer(sandbox, target_id="repository")
    findings = analyzer.analyze(root=repo, actor="tester",
                                target=Target(type="repository", locator=str(repo)),
                                scope=authorization(repo))
    assert len(findings) == 1 and findings[0].vulnerability_type == "secret"
    assert findings[0].status == "unverified"
    detect_call = sandbox.calls[0][0]
    assert detect_call[0] == "/usr/local/bin/gitleaks"
    assert detect_call[1] == "isolated"
    assert sandbox.calls[0][1] == repo.resolve()
    assert sandbox.calls[0][2] is False  # network disabled


def test_analyzer_failures_are_explicit(repo):
    with pytest.raises(ScannerError, match="could not run"):
        SandboxedGitleaksAnalyzer(FakeSandbox(exit_code=1), target_id="repository").analyze(
            root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
            scope=authorization(repo))
    with pytest.raises(ScannerError, match="not usable"):
        SandboxedGitleaksAnalyzer(FakeSandbox(report=b"{}"), target_id="repository").analyze(
            root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
            scope=authorization(repo))
    with pytest.raises(ValueError, match="sandbox with run"):
        SandboxedGitleaksAnalyzer(object(), target_id="repository")
    with pytest.raises(ValueError, match="absolute POSIX"):
        SandboxedGitleaksAnalyzer(FakeSandbox(), target_id="repository", binary="gitleaks")





def test_sandbox_analyzer_rejects_mismatched_root_before_execution(repo, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    sandbox = FakeSandbox()
    with pytest.raises(ScannerError, match="does not match"):
        SandboxedGitleaksAnalyzer(sandbox, target_id="repository").analyze(root=other, actor="tester", target=Target(type="repository", locator=str(repo)), scope=authorization(repo))
    assert sandbox.calls == []


def test_sandbox_analyzer_refuses_truncated_report(repo):
    rows = [{"RuleID": "rule", "File": f"file{i}.py", "StartLine": 1} for i in range(1001)]
    sandbox = FakeSandbox(report=json.dumps(rows).encode())
    with pytest.raises(ScannerError, match="result limit"):
        SandboxedGitleaksAnalyzer(sandbox, target_id="repository").analyze(root=repo, actor="tester", target=Target(type="repository", locator=str(repo)), scope=authorization(repo))


def test_isolated_trivy_rejects_untrusted_paths_before_execution(repo):
    sandbox = WslSandbox()
    with pytest.raises(SandboxError, match="binary is not trusted"):
        sandbox.run_isolated_trivy(repo, binary="/usr/bin/trivy", cache_dir="/var/cache/trivy",
                                   timeout_seconds=60)
    with pytest.raises(SandboxError, match="cache path is not trusted"):
        sandbox.run_isolated_trivy(repo, binary="/usr/local/bin/trivy", cache_dir="/tmp/cache",
                                   timeout_seconds=60)
    for bad in (0, -1, 901):
        with pytest.raises(ValueError, match="timeout"):
            sandbox.run_isolated_trivy(repo, binary="/usr/local/bin/trivy",
                                       cache_dir="/var/cache/trivy", timeout_seconds=bad)


def test_isolated_trivy_requires_a_mapped_windows_root(tmp_path):
    sandbox = WslSandbox()
    with pytest.raises(SandboxError):
        sandbox.run_isolated_trivy(tmp_path / "missing", binary="/usr/local/bin/trivy",
                                   cache_dir="/var/cache/trivy", timeout_seconds=60)


def test_isolated_trivy_passes_distinct_timeout_and_output_limits(repo, monkeypatch):
    from types import SimpleNamespace
    from vulnmind.analysis import sandbox as module
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=b"{}")
    monkeypatch.setattr(module.subprocess, "run", run)
    result = WslSandbox().run_isolated_trivy(repo, binary="/usr/local/bin/trivy",
                                            cache_dir="/var/cache/trivy", timeout_seconds=7)
    assert result == b"{}"
    command, kwargs = calls[0]
    assert command[-2:] == ["7", str(module.MAX_OUTPUT_BYTES + 1)]
    assert command[command.index("/usr/bin/unshare") + 1:][:4] == ["-m", "-n", "-p", "--fork"]
    assert b'limit_bytes="$3"' in kwargs["input"]
    assert b'head -c "$limit_bytes"' in kwargs["input"]
