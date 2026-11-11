"""Real sandboxed Trivy run; skipped unless the distro, binary and DB exist."""
import shutil
import subprocess

import pytest

from vulnmind.analysis.repo_analyzers import SandboxedTrivyAnalyzer
from vulnmind.analysis.sandbox import WslSandbox
from vulnmind.schemas import Authorization, Target
from datetime import datetime, timedelta, timezone

DISTRO = "VulnMindSandbox"


def _ready() -> bool:
    if shutil.which("wsl.exe") is None:
        return False
    try:
        completed = subprocess.run(
            ["wsl.exe", "-d", DISTRO, "-u", "root", "--", "/bin/sh", "-c",
             "test -x /usr/local/bin/trivy && test -s /var/cache/trivy/db/trivy.db"],
            capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


pytestmark = pytest.mark.skipif(not _ready(), reason="sandbox Trivy DB is not prepared")


def authorization(root):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)])


def test_sandboxed_trivy_finds_dependency_vulnerabilities(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.19.0\nflask==1.0\n", encoding="utf-8")
    findings = SandboxedTrivyAnalyzer(WslSandbox(), target_id="repository").analyze(
        root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
        scope=authorization(repo))
    assert findings
    assert all(item.vulnerability_type == "dependency_vulnerability" for item in findings)
    assert all(item.status == "unverified" and item.source_tool == "trivy" for item in findings)
    assert any("requests" in item.location for item in findings)
