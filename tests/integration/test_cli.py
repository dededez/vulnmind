from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys


def run_cli(path):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-m", "vulnmind", "simulate", "--request", str(path)], capture_output=True, encoding="utf-8", env=env, timeout=10)


def test_cli_simulates_without_echoing_authorization(tmp_path):
    now = datetime.now(timezone.utc)
    request = {"task_id": "t", "project_id": "p", "targets": [{"type": "web", "locator": "https://example.test/api"}], "authorization": {"authorization_source": "private source identifier", "approved_by": "owner", "starts_at": (now-timedelta(hours=1)).isoformat(), "expires_at": (now+timedelta(hours=1)).isoformat(), "web_origins": ["https://example.test"]}}
    path = tmp_path / "request.json"
    path.write_text(json.dumps(request), encoding="utf-8")
    result = run_cli(path)
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["status"] == "simulated"
    assert output["report"]["scanning_performed"] is False
    assert output["audit"] == {"persistent": False, "event_count": 3}
    assert "private source identifier" not in result.stdout
    assert "example.test" not in result.stdout


def test_cli_rejects_invalid_input_without_echoing_it(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text('{"credential":"do-not-echo"}', encoding="utf-8")
    result = run_cli(path)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"
    assert "do-not-echo" not in result.stdout + result.stderr


def run_analyze(*arguments):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-m", "vulnmind", "analyze", *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=20)


def sarif_document():
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "semgrep"}},
            "results": [{
                "ruleId": "python.sqli",
                "level": "error",
                "message": {"text": "SQL injection"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/app.py"},
                        "region": {"startLine": 12},
                    }
                }],
            }],
        }],
    }


def test_cli_analyze_writes_a_report(tmp_path):
    sarif = tmp_path / "out.sarif"
    sarif.write_text(json.dumps(sarif_document()), encoding="utf-8")
    output = tmp_path / "report.md"
    result = run_analyze("--sarif", sarif, "--scan-id", "scan-1", "--project-id", "project-1",
                         "--output", output)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["status"] == "written" and summary["format"] == "markdown"
    assert summary["findings"] == 1 and summary["groups"] == 1 and summary["requires_validation"] == 1
    content = output.read_text(encoding="utf-8")
    assert "SQL injection" in content and "src/app.py:12" in content
    assert "未执行真实扫描" not in content  # analysis mode, not simulation


def test_cli_analyze_can_print_markdown(tmp_path):
    gitleaks = tmp_path / "gitleaks.json"
    gitleaks.write_text(json.dumps([{"RuleID": "aws", "File": "config.py", "StartLine": 3,
                                     "Secret": "AKIAIOSFODNN7EXAMPLE"}]), encoding="utf-8")
    result = run_analyze("--gitleaks", gitleaks, "--scan-id", "s", "--project-id", "p")
    assert result.returncode == 0, result.stderr
    assert "config.py:3" in result.stdout
    assert "AKIAIOSFODNN7EXAMPLE" not in result.stdout


def test_cli_analyze_reports_skipped_results_without_leaking_their_content(tmp_path):
    document = sarif_document()
    document["runs"][0]["results"].append({"ruleId": "secret-marker", "locations": 42})
    report = tmp_path / "out.sarif"
    report.write_text(json.dumps(document), encoding="utf-8")
    result = run_analyze("--sarif", report, "--scan-id", "s", "--project-id", "p")
    assert result.returncode == 0
    assert "扫描器有 1 条结果无法导入" in result.stdout
    assert "secret-marker" not in result.stdout


def test_cli_analyze_rejects_bad_reports_without_echoing_content(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text('{"credential":"do-not-echo"}', encoding="utf-8")
    result = run_analyze("--sarif", broken, "--scan-id", "s", "--project-id", "p")
    assert result.returncode == 2 and "blocked" in result.stdout
    assert "do-not-echo" not in result.stdout + result.stderr
    both = run_analyze("--sarif", broken, "--gitleaks", broken, "--scan-id", "s", "--project-id", "p")
    assert both.returncode == 2
