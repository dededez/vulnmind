"""CLI agent-run validation paths (no key, no network)."""
import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def run_cli(tmp_path, *extra, env_extra=None):
    env = os.environ.copy()
    env.pop("DEEPSEEK_API_KEY", None)
    env.pop("VULNMIND_DEEPSEEK_API_KEY", None)
    env.update({"PYTHONPATH": str(PROJECT_ROOT / "src"), "PYTHONIOENCODING": "utf-8",
                "PYTHONDONTWRITEBYTECODE": "1"})
    env.update(env_extra or {})
    return subprocess.run([sys.executable, "-m", "vulnmind", "agent-run", "--task", "Review.",
                           *extra], capture_output=True, encoding="utf-8", env=env, timeout=120)


def test_missing_api_key_is_blocked_without_a_request(tmp_path):
    result = run_cli(tmp_path)
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"


def test_invalid_context_file_is_blocked(tmp_path):
    bad = tmp_path / "context.json"
    bad.write_text('{"not": "a list"}', encoding="utf-8")
    result = run_cli(tmp_path, "--context-file", str(bad), env_extra={"DEEPSEEK_API_KEY": "test"})
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"
