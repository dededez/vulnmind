"""Repository-level analyzer tests: policy binding, parsing, pipeline integration."""
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest

from vulnmind.analysis.repo_analyzers import GitleaksAnalyzer, ScannerError, default_gitleaks_analyzer
from vulnmind.schemas import Authorization, Target


@pytest.fixture
def trusted(tmp_path):
    root = tmp_path / "scanners"
    root.mkdir()
    executable = root / "gitleaks.exe"
    executable.write_bytes(b"fake")
    return root, executable


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "config.py").write_bytes(b"aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'\n")
    return root


def authorization(root):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)])


def gitleaks_report(secret="AKIAIOSFODNN7EXAMPLE"):
    return [{"RuleID": "aws-access-token", "Description": "AWS Access Token", "File": "config.py",
             "StartLine": 1, "Secret": secret, "Match": secret, "Entropy": 3.6}]


def runner_writing(payload, *, exit_code=0, write_report=True):
    calls = []

    def runner(argv, cwd, timeout):
        calls.append((list(argv), cwd, timeout))
        if write_report:
            index = list(argv).index("--report-path")
            Path(argv[index + 1]).write_bytes(json.dumps(payload).encode("utf-8"))
        return exit_code

    runner.calls = calls
    return runner


def analyzer(executable, trusted_root, runner, target_id="repository"):
    return GitleaksAnalyzer(executable, trusted_root=trusted_root, target_id=target_id, runner=runner)


def test_findings_are_parsed_and_marked_unverified(tmp_path, trusted, repo):
    root, executable = trusted
    found = analyzer(executable, root, runner_writing(gitleaks_report())).analyze(
        root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
        scope=authorization(repo))
    assert len(found) == 1
    assert found[0].status == "unverified" and found[0].vulnerability_type == "secret"
    assert found[0].location == "config.py:1" and found[0].target_id == "repository"
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(found[0].model_dump(), ensure_ascii=False)


def test_pipeline_reports_skipped_scanner_rows(tmp_path, trusted, repo):
    from vulnmind.analysis.repository import RepositoryPipeline
    from vulnmind.tools.repo_files import RepositoryReader

    class Recorder:
        def record(self, event):
            pass

    root, executable = trusted
    data = [*gitleaks_report(), {"RuleID": "malformed-secret-marker"}]
    pipeline = RepositoryPipeline(RepositoryReader(Recorder()), [], repo_analyzers=[
        analyzer(executable, root, runner_writing(data))])
    result = pipeline.run(scan_id="s", project_id="p", target=Target(type="repository", locator=str(repo)),
                          scope=authorization(repo), actor="tester")
    assert len(result.groups) == 1
    assert any("Gitleaks 有 1 条结果无法导入" in item for item in result.coverage_limitations)
    assert "malformed-secret-marker" not in json.dumps(result.to_report_input().model_dump(), ensure_ascii=False, default=str)


def test_argument_vector_is_built_by_the_analyzer(tmp_path, trusted, repo):
    root, executable = trusted
    runner = runner_writing(gitleaks_report())
    analyzer(executable, root, runner).analyze(
        root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
        scope=authorization(repo))
    argv, cwd, timeout = runner.calls[0]
    assert argv[0] == str(executable.resolve())
    assert argv[1:3] == ["detect", "--no-git"]
    assert "--redact" in argv and "--exit-code" in argv
    assert argv[argv.index("--source") + 1] == str(repo.resolve())
    assert cwd == repo.resolve() and timeout == 120.0


def test_failures_are_reported_not_swallowed(tmp_path, trusted, repo):
    root, executable = trusted
    with pytest.raises(ScannerError, match="failure status"):
        analyzer(executable, root, runner_writing(gitleaks_report(), exit_code=2)).analyze(
            root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
            scope=authorization(repo))
    with pytest.raises(ScannerError, match="no report"):
        analyzer(executable, root, runner_writing(gitleaks_report(), write_report=False)).analyze(
            root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
            scope=authorization(repo))
    with pytest.raises(ScannerError, match="not usable"):
        analyzer(executable, root, runner_writing({"unexpected": "shape"})).analyze(
            root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
            scope=authorization(repo))


def test_executable_must_live_under_the_trusted_root(tmp_path, trusted):
    root, executable = trusted
    outside = tmp_path / "elsewhere.exe"
    outside.write_bytes(b"x")
    with pytest.raises(ScannerError, match="trusted root"):
        GitleaksAnalyzer(outside, trusted_root=root, target_id="repository")
    with pytest.raises(ValueError, match="target_id"):
        GitleaksAnalyzer(executable, trusted_root=root, target_id=" ")
    with pytest.raises(ValueError, match="timeout"):
        GitleaksAnalyzer(executable, trusted_root=root, target_id="repository", timeout_seconds=0)


def test_default_analyzer_is_optional(tmp_path):
    assert default_gitleaks_analyzer(tmp_path, target_id="repository") is None
    scanners = tmp_path / ".devtools" / "scanners"
    scanners.mkdir(parents=True)
    (scanners / "gitleaks.exe").write_bytes(b"fake")
    assert default_gitleaks_analyzer(tmp_path, target_id="repository") is not None


def test_pipeline_runs_repository_analyzers_once(tmp_path, trusted, repo):
    from vulnmind.analysis.repository import RepositoryPipeline
    from vulnmind.tools.repo_files import RepositoryReader

    root, executable = trusted
    recorder_events = []

    class Recorder:
        def record(self, event):
            recorder_events.append(event)

    pipeline = RepositoryPipeline(RepositoryReader(Recorder()), [], access=None,
                                  repo_analyzers=[analyzer(executable, root, runner_writing(gitleaks_report()))])
    analysis = pipeline.run(scan_id="s", project_id="p", target=Target(type="repository", locator=str(repo)),
                            scope=authorization(repo), actor="tester")
    assert analysis.repo_analyzers == ["GitleaksAnalyzer"]
    assert len(analysis.groups) == 1
    assert analysis.findings[0].target_id == str(repo)


def test_scanner_rechecks_scope_and_root_before_running(trusted, repo, tmp_path):
    from vulnmind.security.scope import ScopeDenied
    scanners, executable = trusted
    other = tmp_path / "other"
    other.mkdir()
    runner = runner_writing([])
    worker = analyzer(executable, scanners, runner)
    with pytest.raises(ScannerError, match="does not match"):
        worker.analyze(root=other, actor="tester", target=Target(type="repository", locator=str(repo)), scope=authorization(repo))
    with pytest.raises(ScopeDenied):
        worker.analyze(root=other, actor="tester", target=Target(type="repository", locator=str(other)), scope=authorization(repo))
    assert runner.calls == []


def test_scanner_process_does_not_inherit_credentials(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from vulnmind.analysis import repo_analyzers
    seen = {}
    monkeypatch.setenv("VULNMIND_TEST_SECRET", "do-not-pass")
    monkeypatch.setenv("GITLEAKS_CONFIG", "untrusted")
    def fake_run(*args, **kwargs):
        seen.update(kwargs)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(repo_analyzers.subprocess, "run", fake_run)
    assert repo_analyzers._subprocess_runner(["scanner"], tmp_path, 10) == 0
    assert "VULNMIND_TEST_SECRET" not in seen["env"]
    assert "GITLEAKS_CONFIG" not in seen["env"]


def test_unisolated_host_scanner_is_disabled(trusted, repo):
    scanners, executable = trusted
    worker = GitleaksAnalyzer(executable, trusted_root=scanners, target_id="repository")
    with pytest.raises(ScannerError, match="host scanner execution is disabled"):
        worker.analyze(root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
                       scope=authorization(repo))
