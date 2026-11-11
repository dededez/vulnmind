"""SARIF ingestion for externally run Semgrep (no scanner execution)."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vulnmind.analysis.repo_analyzers import SarifReportAnalyzer, ScannerError
from vulnmind.schemas import Authorization, Target


def authorization(root):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)])


def sarif(*locations, level="error", rule="python.lang.security.audit.sqli"):
    results = []
    for uri, line in locations:
        results.append({
            "ruleId": rule,
            "level": level,
            "message": {"text": "User input reaches a SQL query"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line}}}]})
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Semgrep"}},
        "results": results,
    }]}


def write_report(tmp_path, document):
    path = tmp_path / "semgrep.sarif"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def build_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("query = input()\n", encoding="utf-8")
    return repo


def test_relative_locations_are_kept_and_escapes_dropped(tmp_path):
    repo = build_repo(tmp_path)
    report = write_report(tmp_path, sarif(
        ("src/app.py", 3), ("/etc/passwd", 1), ("../../outside.py", 2),
        ("..\\..\\outside.py", 2), ("C:\\repo\\src\\app.py", 1)))
    findings = SarifReportAnalyzer(report, target_id="repository").analyze(
        root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
        scope=authorization(repo))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.location == "src/app.py:3"
    assert finding.vulnerability_type == "python.lang.security.audit.sqli"
    assert finding.source_tool == "semgrep" and finding.status == "unverified"
    assert finding.severity == "high" and finding.target_id == "repository"
    assert len(findings.coverage_limitations) == 1
    assert "4 条结果无法导入" in findings.coverage_limitations[0]


def test_warning_level_maps_to_medium(tmp_path):
    repo = build_repo(tmp_path)
    report = write_report(tmp_path, sarif(("src/app.py", 3), level="warning"))
    findings = SarifReportAnalyzer(report, target_id="repository").analyze(
        root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
        scope=authorization(repo))
    assert findings[0].severity == "medium"


def test_bound_digest_verifies_exact_sarif_bytes(tmp_path):
    import hashlib
    repo = build_repo(tmp_path)
    report = write_report(tmp_path, sarif(("src/app.py", 3)))
    digest = hashlib.sha256(report.read_bytes()).hexdigest()
    analyzer = SarifReportAnalyzer(report, target_id="repository", expected_sha256=digest)
    target = Target(type="repository", locator=str(repo))
    assert analyzer.analyze(root=repo, actor="tester", target=target, scope=authorization(repo))
    report.write_bytes(report.read_bytes() + b" ")
    with pytest.raises(ScannerError, match="changed after workflow binding"):
        analyzer.analyze(root=repo, actor="tester", target=target, scope=authorization(repo))


def test_truncated_result_limit_is_rejected(tmp_path):
    repo = build_repo(tmp_path)
    report = write_report(tmp_path, sarif(("src/app.py", 1), ("src/app.py", 2)))
    with pytest.raises(ScannerError, match="result limit"):
        SarifReportAnalyzer(report, target_id="repository", max_results=1).analyze(
            root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
            scope=authorization(repo))


def test_malformed_and_oversized_reports_are_rejected(tmp_path):
    repo = build_repo(tmp_path)
    broken = tmp_path / "broken.sarif"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(ScannerError, match="not usable"):
        SarifReportAnalyzer(broken, target_id="repository").analyze(
            root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
            scope=authorization(repo))
    valid = write_report(tmp_path, sarif(("src/app.py", 1)))
    with pytest.raises(ScannerError, match="size limit"):
        SarifReportAnalyzer(valid, target_id="repository", max_bytes=10).analyze(
            root=repo, actor="tester", target=Target(type="repository", locator=str(repo)),
            scope=authorization(repo))
    with pytest.raises(ScannerError, match="does not exist"):
        SarifReportAnalyzer(tmp_path / "missing.sarif", target_id="repository")


def test_root_must_match_the_authorized_target(tmp_path):
    repo = build_repo(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    report = write_report(tmp_path, sarif(("src/app.py", 1)))
    with pytest.raises(ScannerError, match="authorized target"):
        SarifReportAnalyzer(report, target_id="repository").analyze(
            root=other, actor="tester", target=Target(type="repository", locator=str(repo)),
            scope=authorization(repo))
