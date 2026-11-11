"""Tests for the external prerequisite checker (pure assessment logic)."""
import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_external_env.py"
_spec = importlib.util.spec_from_file_location("check_external_env", SCRIPT)
module = importlib.util.module_from_spec(_spec)
sys.modules["check_external_env"] = module
_spec.loader.exec_module(module)


def probes(**overrides):
    base = {name: (False, "not on PATH") for name in
            ("docker", "psql", "semgrep", "gitleaks", "trivy", "ssh-keygen", "cl", "wsl", "wsl_distro",
             "gitleaks_local", "trivy_local", "semgrep_local",
             "pg_binaries", "pg_config", "pgvector_extension", "vs_build_tools")}
    base.update(overrides)
    return base


def statuses(findings):
    return {item.capability: item.status for item in findings}


def test_everything_missing_is_reported_with_next_steps():
    findings = module.assess(probes())
    assert set(statuses(findings).values()) == {"missing"}
    assert all(item.next_step for item in findings)
    payload = module.render(findings)
    assert payload["blocked"] and payload["ready"] == []


def test_ready_paths_are_recognised():
    findings = module.assess(probes(**{
        "pg_binaries": (True, ".devtools/pgsql"),
        "pgvector_extension": (True, "vector.control"),
        "semgrep": (True, "C:/tools/semgrep"),
        "gitleaks_local": (True, ".devtools/scanners/gitleaks.exe"),
        "docker": (True, "Docker version 27"),
        "ssh-keygen": (True, "OpenSSH"),
    }))
    assert statuses(findings)["PostgreSQL 实时测试"] == "ready"
    assert statuses(findings)["pgvector 稠密检索"] == "ready"
    assert statuses(findings)["真实扫描器"] == "ready"
    assert statuses(findings)["网络/执行隔离"] == "ready"
    payload = module.render(findings)
    assert len(payload["ready"]) == 5 and payload["blocked"] == []


def test_partial_paths_explain_what_is_still_needed():
    findings = module.assess(probes(**{
        "pg_binaries": (True, ".devtools/pgsql"),
        "psql": (True, "psql"),
        "pg_config": (True, "pg_config"),
        "vs_build_tools": (True, "VS BuildTools"),
        "trivy": (True, "trivy"),
        "wsl_distro": (True, "Ubuntu"),
    }))
    found = statuses(findings)
    assert found["pgvector 稠密检索"] == "partial"
    assert found["真实扫描器"] == "partial"
    assert found["网络/执行隔离"] == "ready"  # an installed WSL distribution counts
    assert found["PostgreSQL 实时测试"] == "ready"


def test_render_output_is_stable_json():
    payload = module.render(module.assess(probes()))
    assert set(payload) == {"project", "items", "ready", "blocked"}
    assert all(set(item) == {"capability", "status", "detail", "next_step"} for item in payload["items"])


