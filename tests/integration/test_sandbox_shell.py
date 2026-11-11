"""Real sandbox test: a read-only BusyBox command runs inside the WSL distro.

Skipped when the sandbox distro is not installed. Nothing here is a general
shell test: only allowlisted applets are expected to work.
"""
import shutil
import subprocess

import pytest

from vulnmind.analysis.sandbox import SHELL_APPLETS, SandboxError, WslSandbox

DISTRO = "VulnMindSandbox"


def _distro_available() -> bool:
    if shutil.which("wsl.exe") is None:
        return False
    try:
        completed = subprocess.run(["wsl.exe", "-l", "-q"], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    names = completed.stdout.decode("utf-16-le", "ignore").replace("\x00", "")
    return DISTRO in names


pytestmark = pytest.mark.skipif(not _distro_available(), reason="WSL sandbox distro is not installed")


def build_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (repo / "README.md").write_text("# demo\n", encoding="utf-8")
    return repo


def test_allowlisted_command_runs_read_only(tmp_path):
    repo = build_repo(tmp_path)
    code, output = WslSandbox().run_shell_isolated(
        repo, argv=["ls", "-1"], cwd_relative="", timeout_seconds=60, max_output_bytes=10_000)
    assert code == 0
    assert b"README.md" in output and b"pkg" in output


def test_command_runs_in_the_requested_subdirectory(tmp_path):
    repo = build_repo(tmp_path)
    code, output = WslSandbox().run_shell_isolated(
        repo, argv=["cat", "app.py"], cwd_relative="pkg", timeout_seconds=60, max_output_bytes=10_000)
    assert code == 0 and output.strip() == b"print('ok')"


def test_non_allowlisted_program_is_refused_before_execution(tmp_path):
    repo = build_repo(tmp_path)
    assert "sh" not in SHELL_APPLETS
    with pytest.raises(SandboxError, match="not allowed"):
        WslSandbox().run_shell_isolated(
            repo, argv=["sh", "-c", "id"], cwd_relative="", timeout_seconds=60, max_output_bytes=1000)


def test_relative_traversal_in_cwd_is_rejected(tmp_path):
    repo = build_repo(tmp_path)
    with pytest.raises(ValueError, match="cwd"):
        WslSandbox().run_shell_isolated(
            repo, argv=["ls"], cwd_relative="../../etc", timeout_seconds=60, max_output_bytes=1000)
    with pytest.raises(ValueError, match="cwd"):
        WslSandbox().run_shell_isolated(
            repo, argv=["ls"], cwd_relative="/etc", timeout_seconds=60, max_output_bytes=1000)
