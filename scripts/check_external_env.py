"""Report which external prerequisites are missing, with the next concrete step.

Read-only: it only looks for executables and extension files. It never installs,
downloads or starts anything, and it makes no network calls.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Finding:
    capability: str
    status: str  # ready | partial | missing
    detail: str
    next_step: str


def _probe_versions(executable: str, arguments: tuple[str, ...]) -> tuple[bool, str]:
    path = shutil.which(executable)
    if path is None:
        return False, "not on PATH"
    try:
        completed = subprocess.run([path, *arguments], capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=15)
    except (OSError, subprocess.SubprocessError):
        return True, f"found at {path}"
    output = (completed.stdout or completed.stderr or "").strip().splitlines()
    return True, f"{path} ({output[0] if output else 'no version output'})"


def collect(project_root: Path | None = None) -> dict[str, tuple[bool, str]]:
    root = project_root or PROJECT_ROOT
    probes: dict[str, tuple[bool, str]] = {}
    for name, arguments in (("docker", ("--version",)), ("psql", ("--version",)),
                            ("semgrep", ("--version",)), ("gitleaks", ("version",)),
                            ("trivy", ("--version",)), ("cl", ()), ("wsl", ("--status",))):
        probes[name] = _probe_versions(name, arguments)
    keygen = shutil.which("ssh-keygen")
    probes["ssh-keygen"] = (keygen is not None, keygen or "not on PATH")
    distros = _wsl_distros()
    probes["wsl_distro"] = (bool(distros), ", ".join(distros) if distros else "no WSL distribution installed")
    pgsql = root / ".devtools" / "pgsql"
    probes["pg_binaries"] = ((pgsql / "bin" / "postgres.exe").is_file(),
                             str(pgsql) if pgsql.is_dir() else "missing .devtools/pgsql")
    probes["pg_config"] = ((pgsql / "bin" / "pg_config.exe").is_file(), str(pgsql / "bin"))
    probes["pgvector_extension"] = ((pgsql / "share" / "extension" / "vector.control").is_file(),
                                    str(pgsql / "share" / "extension" / "vector.control"))
    probes["vs_build_tools"] = (_vs_build_tools() is not None, _vs_build_tools() or "missing")
    scanners = root / ".devtools" / "scanners"
    for name in ("gitleaks", "trivy", "semgrep"):
        local = scanners / f"{name}.exe"
        probes[f"{name}_local"] = (local.is_file(), str(local) if local.is_file() else "not installed locally")
    return probes


def _wsl_distros() -> list[str]:
    """Return installed WSL distributions; empty means no isolation runtime."""
    wsl = shutil.which("wsl")
    if wsl is None:
        return []
    try:
        completed = subprocess.run([wsl, "-l", "-q"], capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=15)
    except (OSError, subprocess.SubprocessError):
        return []
    text = (completed.stdout or "").replace("\x00", "")
    names = [line.strip() for line in text.splitlines() if line.strip()]
    return [name for name in names if "\ufffd" not in name]


def _vs_build_tools() -> str | None:
    for candidate in (
        Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"),
        Path(r"C:\Program Files\Microsoft Visual Studio\2022\BuildTools"),
    ):
        if (candidate / "VC" / "Auxiliary" / "Build" / "vcvars64.bat").is_file():
            return str(candidate)
    return None


def assess(probes: dict[str, tuple[bool, str]]) -> list[Finding]:
    """Map raw probes to capabilities, with the next actionable step."""
    findings = [
        _finding("PostgreSQL 实时测试",
                 ready=probes["pg_binaries"][0],
                 partial=probes["psql"][0],
                 detail=probes["pg_binaries"][1],
                 next_step="运行 scripts/test_local_postgres.py（本机一次性 loopback 集群）；"
                           "若需保留 schema，另建专用库并设置 VULNMIND_RETAINED_TEST_DATABASE_URL。"),
        _finding("pgvector 稠密检索",
                 ready=probes["pgvector_extension"][0],
                 partial=probes["pg_config"][0] and probes["vs_build_tools"][0],
                 detail=probes["pgvector_extension"][1],
                 next_step="用 VS BuildTools + .devtools/pgsql/bin/pg_config 从源码编译 pgvector，"
                           "安装到 .devtools/pgsql 后执行 CREATE EXTENSION vector，再新增 0009 迁移。"),
        _finding("真实扫描器",
                 ready=probes["gitleaks"][0] or probes["gitleaks_local"][0],
                 partial=any(probes[name][0] for name in
                             ("semgrep", "gitleaks", "trivy", "semgrep_local", "trivy_local")),
                 detail=", ".join(f"{name}={probes[name][1]}" for name in
                                  ("gitleaks", "gitleaks_local", "trivy", "trivy_local",
                                   "semgrep", "semgrep_local")),
                 next_step="Gitleaks 已接入（vulnmind scan --gitleaks）。Trivy/Semgrep 按需放入 "
                           ".devtools/scanners 并校验 SHA256；不要写入项目依赖。"),
        _finding("网络/执行隔离",
                 ready=probes["docker"][0] or probes["wsl_distro"][0],
                 partial=probes["wsl"][0] and not probes["wsl_distro"][0],
                 detail=f"docker={probes['docker'][1]}; wsl={probes['wsl_distro'][1]}",
                 next_step="安装 Docker Desktop 或启用 WSL2 发行版，在容器/命名空间内运行 scanners 与 HTTP；"
                           "隔离就绪前保持 Shell/HTTP 默认拒绝。"),
        _finding("审批身份认证",
                 ready=probes["ssh-keygen"][0],
                 partial=probes["ssh-keygen"][0],
                 detail=probes["ssh-keygen"][1],
                 next_step="用 OpenSSH 签名（ssh-keygen -Y sign/verify）为审批人签名，"
                           "服务端用允许列表公钥验证；无 IdP 时先落这一层，仍不替代企业 SSO。"),
    ]
    return findings


def _finding(capability: str, *, ready: bool, partial: bool, detail: str, next_step: str) -> Finding:
    status = "ready" if ready else ("partial" if partial else "missing")
    return Finding(capability=capability, status=status, detail=detail, next_step=next_step)


def render(findings: list[Finding]) -> dict:
    return {"project": str(PROJECT_ROOT),
            "items": [{"capability": item.capability, "status": item.status,
                       "detail": item.detail, "next_step": item.next_step} for item in findings],
            "ready": [item.capability for item in findings if item.status == "ready"],
            "blocked": [item.capability for item in findings if item.status != "ready"]}


def main() -> int:
    payload = render(assess(collect()))
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
