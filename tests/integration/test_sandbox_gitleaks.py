"""Real sandbox test: Gitleaks runs inside the WSL distribution without network.

Skipped when the sandbox distro is not installed. The distro name is fixed by
the setup script (``.devtools/install_sandbox.ps1``).
"""
import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vulnmind.analysis.repo_analyzers import SandboxedGitleaksAnalyzer
from vulnmind.analysis.sandbox import WslSandbox
from vulnmind.schemas import Authorization, Target

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


def authorization(root: Path):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)])


def test_sandboxed_gitleaks_finds_a_secret(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "settings.py").write_text("aws_access_key_id = 'AKIAABCDEFGHIJKLMNOP'\n", encoding="utf-8")
    analyzer = SandboxedGitleaksAnalyzer(WslSandbox(), target_id="repository")
    findings = analyzer.analyze(root=repo, actor="tester",
                                target=Target(type="repository", locator=str(repo)),
                                scope=authorization(repo))
    assert findings, "sandboxed gitleaks should find the synthetic key"
    assert findings[0].vulnerability_type == "secret"
    assert findings[0].status == "unverified"
    assert findings[0].location == "settings.py:1"


def test_sandbox_has_no_network(tmp_path):
    sandbox = WslSandbox()
    code, output = sandbox.run(["/bin/sh", "-c", "cat /proc/net/route 2>/dev/null | wc -l"], network=False)
    assert code == 0
    assert output.strip() in {b"0", b"1"}  # only the header, or nothing, in an empty netns


def test_scanner_mount_namespace_is_read_only_and_hides_host(tmp_path, monkeypatch):
    import vulnmind.analysis.sandbox as module

    repo = tmp_path / "repo with spaces"
    repo.mkdir()
    marker = repo / "marker.txt"
    marker.write_text("original", encoding="utf-8")
    original = "/usr/bin/timeout -s KILL \"$limit\" chroot \"$t\" /bin/busybox su -s /bin/sh nobody -c 'cd /repo && exec /bin/gitleaks detect --no-git --redact --exit-code 0 --report-format json --report-path /tmp/report.json --source .'"
    check = r'''test -z "$(/sbin/ip -o route show)"
chroot "$t" /bin/busybox su -s /bin/sh nobody -c 'test "$(/bin/busybox id -u)" = 65534 && test ! -e /mnt && test ! -e /proc && test -r /repo/marker.txt && ! (echo changed > /repo/marker.txt)'
printf 'isolated' '''
    assert original in module._GITLEAKS_SCRIPT
    script = module._GITLEAKS_SCRIPT.replace(original, check).replace('/bin/busybox head -c 33554433 "$t/tmp/report.json"', '')
    monkeypatch.setattr(module, "_GITLEAKS_SCRIPT", script)
    assert WslSandbox().run_isolated_gitleaks(repo, binary="/usr/local/bin/gitleaks", timeout_seconds=30) == b"isolated"
    assert marker.read_text(encoding="utf-8") == "original"


def test_scanner_cannot_follow_absolute_link_to_host_file(tmp_path, monkeypatch):
    import vulnmind.analysis.sandbox as module

    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside-only", encoding="utf-8")
    linked = subprocess.run(["wsl.exe", "-d", DISTRO, "-u", "root", "--", "/bin/ln", "-s",
                             module.windows_to_wsl(outside), module.windows_to_wsl(repo / "escape")],
                            capture_output=True, timeout=30)
    if linked.returncode:
        pytest.skip("WSL could not create a host filesystem symlink")
    original = "/usr/bin/timeout -s KILL \"$limit\" chroot \"$t\" /bin/busybox su -s /bin/sh nobody -c 'cd /repo && exec /bin/gitleaks detect --no-git --redact --exit-code 0 --report-format json --report-path /tmp/report.json --source .'"
    check = r'''chroot "$t" /bin/busybox su -s /bin/sh nobody -c 'test ! -e /repo/escape && test ! -r /repo/escape'
printf 'confined' '''
    assert original in module._GITLEAKS_SCRIPT
    script = module._GITLEAKS_SCRIPT.replace(original, check).replace('/bin/busybox head -c 33554433 "$t/tmp/report.json"', '')
    monkeypatch.setattr(module, "_GITLEAKS_SCRIPT", script)
    assert WslSandbox().run_isolated_gitleaks(repo, binary="/usr/local/bin/gitleaks", timeout_seconds=30) == b"confined"
    assert outside.read_text(encoding="utf-8") == "outside-only"


def test_timeout_removes_the_isolated_mount_directory(tmp_path):
    import vulnmind.analysis.sandbox as module

    repo = tmp_path / "repo"
    repo.mkdir()
    original = "/usr/bin/timeout -s KILL \"$limit\" chroot \"$t\" /bin/busybox su -s /bin/sh nobody -c 'cd /repo && exec /bin/gitleaks detect --no-git --redact --exit-code 0 --report-format json --report-path /tmp/report.json --source .'"
    assert original in module._GITLEAKS_SCRIPT
    script = module._GITLEAKS_SCRIPT.replace('case "$t" in', 'printf "%s\\n" "$t"\ncase "$t" in')
    script = script.replace(original, '/usr/bin/timeout -s KILL "$limit" /bin/sleep 20')
    result = subprocess.run(["wsl.exe", "-d", DISTRO, "-u", "root", "--", "/usr/bin/unshare", "-m", "-n",
                             "/bin/sh", "-s", "--", module.windows_to_wsl(repo), "1"],
                            input=script.encode(), capture_output=True, timeout=20)
    assert result.returncode != 0
    directory = result.stdout.decode("utf-8").strip()
    assert directory.startswith("/tmp/vulnmind-scan.") and "\n" not in directory
    exists = subprocess.run(["wsl.exe", "-d", DISTRO, "-u", "root", "--", "/bin/busybox", "test", "-e", directory],
                            capture_output=True, timeout=15)
    assert exists.returncode == 1


def test_cli_scan_uses_the_sandbox(tmp_path):
    import os
    import sys
    from uuid import uuid4
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session, sessionmaker
    from vulnmind.persistence.base import Base
    from vulnmind.persistence.models import Finding, Project

    database = tmp_path / "sandbox.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "settings.py").write_text("aws_access_key_id = 'AKIAABCDEFGHIJKLMNOP'\n", encoding="utf-8")
    with factory() as session:
        project = Project(id=uuid4(), name="sandbox cli")
        session.add(project)
        session.commit()
        project_id = project.id
    engine.dispose()
    scope = authorization(repo)
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(scope.model_dump(mode="json")), encoding="utf-8")
    env = os.environ.copy()
    env.update({"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
                "VULNMIND_REPORT_ROOT": str(tmp_path / "reports"),
                "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src"),
                "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"})
    result = subprocess.run([sys.executable, "-m", "vulnmind", "scan", "--repository", str(repo),
                             "--project-id", str(project_id), "--scope-file", str(scope_file),
                             "--gitleaks-sandbox"],
                            capture_output=True, encoding="utf-8", env=env, timeout=240)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "finished" and payload["findings_stored"] >= 1
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with Session(engine) as session:
        types = {row.vuln_type for row in session.scalars(select(Finding))}
    engine.dispose()
    assert "secret" in types
