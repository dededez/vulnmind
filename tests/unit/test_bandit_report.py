"""Externally generated Bandit JSON is untrusted and never executed."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from vulnmind.analysis.bandit import BanditReportAnalyzer
from vulnmind.analysis.repo_analyzers import ScannerError
from vulnmind.schemas import Authorization, Target


def setup(tmp_path, payload):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("pass\n", encoding="utf-8")
    report = tmp_path / "bandit.json"
    report.write_text(json.dumps(payload), encoding="utf-8")
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner",
                          starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                          repository_roots=[str(root)])
    return root, report, scope


def item(filename="app.py", **kwargs):
    return {"filename": filename, "line_number": 1, "test_id": "B301", "issue_severity": "HIGH",
            "code": "secret-code", "issue_text": "secret-message", **kwargs}


def run(root, report, scope, **kwargs):
    return BanditReportAnalyzer(report, target_id="repository", **kwargs).analyze(
        root=root, actor="tester", target=Target(type="repository", locator=str(root)), scope=scope)


def test_imports_only_confined_valid_findings_without_report_text(tmp_path):
    root, report, scope = setup(tmp_path, {"results": [item(), item("../../escape.py"),
                                             item("C:\\escape.py"), item(test_id="secret"),
                                             item("missing.py"), item(".")],
                                          "errors": [{"filename": "secret-error"}]})
    result = run(root, report, scope)
    assert len(result) == 1 and result[0].finding.location == "app.py:1"
    assert result[0].finding.source_tool == "bandit" and result[0].finding.status == "unverified"
    assert result[0].finding.vulnerability_type == "B301" and result[0].finding.severity == "high"
    assert "5 条结果无法导入" in result.coverage_limitations[0]
    assert any("1 条扫描错误" in note for note in result.coverage_limitations)
    assert "secret" not in result[0].model_dump_json()
    metadata = json.loads(result[0].evidence[0].content)
    assert metadata["source"] == "untrusted_external_bandit_report" and metadata["rule"] == "B301"


def test_limits_and_malformed_reports_fail_closed(tmp_path):
    root, report, scope = setup(tmp_path, {"results": [item(), item(line_number=2)], "errors": []})
    with pytest.raises(ScannerError, match="result limit"):
        run(root, report, scope, max_results=1)
    with pytest.raises(ScannerError, match="size limit"):
        run(root, report, scope, max_bytes=10)
    report.write_text('{"results": "not-an-array"}', encoding="utf-8")
    with pytest.raises(ScannerError, match="not usable"):
        run(root, report, scope)


def test_bound_digest_verifies_exact_bandit_bytes(tmp_path):
    import hashlib
    root, report, scope = setup(tmp_path, {"results": [item()]})
    digest = hashlib.sha256(report.read_bytes()).hexdigest()
    assert run(root, report, scope, expected_sha256=digest)
    report.write_bytes(report.read_bytes() + b" ")
    with pytest.raises(ScannerError, match="changed after workflow binding"):
        run(root, report, scope, expected_sha256=digest)


def test_malformed_results_are_skipped_without_creating_false_findings(tmp_path):
    root, report, scope = setup(tmp_path, {"results": [item(line_number=True), item(issue_severity="bad"),
                                                      item("bad\npath"), None]})
    result = run(root, report, scope)
    assert result == [] and "4 条结果无法导入" in result.coverage_limitations[0]


def test_overlong_normalized_location_is_skipped_instead_of_truncated(tmp_path, monkeypatch):
    from pathlib import PurePosixPath
    import vulnmind.analysis.bandit as module
    root, report, scope = setup(tmp_path, {"results": [item()]})
    class SimulatedResolvedFile:
        def is_file(self):
            return True
        def relative_to(self, base):
            return PurePosixPath("a" * 999)
    monkeypatch.setattr(module, "resolve_path", lambda base, path: SimulatedResolvedFile())
    result = run(root, report, scope)
    assert result == [] and "1 条结果无法导入" in result.coverage_limitations[0]
