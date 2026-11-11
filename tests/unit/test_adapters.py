"""Adapter parsing tests: normalisation, redaction, limits and failure modes."""
import json
from pathlib import Path

import pytest

from vulnmind.tools.adapters import AdapterError, parse_gitleaks, parse_sarif, resolve_path


def sarif_result(**overrides):
    result = {"ruleId": "python.lang.security.audit.sqli", "level": "error",
              "message": {"text": "Possible SQL injection"},
              "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.py"},
                                                  "region": {"startLine": 12}}}]}
    result.update(overrides)
    return result


def sarif_document(*results, tool="semgrep"):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": tool}}, "results": list(results)}]}


def test_sarif_result_becomes_an_unverified_candidate():
    parsed = parse_sarif(sarif_document(sarif_result()), target_id="repo-1")
    assert parsed.skipped == 0 and len(parsed.findings) == 1
    finding = parsed.findings[0]
    assert finding.location == "src/app.py:12"
    assert finding.severity == "high" and finding.status == "unverified"
    assert finding.source_tool == "semgrep"
    assert finding.vulnerability_type == "python.lang.security.audit.sqli"


@pytest.mark.parametrize("level,expected", [("error", "high"), ("warning", "medium"), ("note", "low"),
                                            ("none", "unknown"), (None, "unknown")])
def test_sarif_level_maps_to_severity(level, expected):
    parsed = parse_sarif(sarif_document(sarif_result(level=level)), target_id="repo-1")
    assert parsed.findings[0].severity == expected


def test_sarif_skips_results_without_a_location():
    without = sarif_result(locations=[])
    parsed = parse_sarif(sarif_document(sarif_result(), without), target_id="repo-1")
    assert len(parsed.findings) == 1 and parsed.skipped == 1


@pytest.mark.parametrize("locations", [7, "broken", {}, [{"physicalLocation": {"artifactLocation": "broken"}}]])
def test_sarif_skips_malformed_location_without_losing_valid_results(locations):
    parsed = parse_sarif(sarif_document(sarif_result(locations=locations), sarif_result()), target_id="repo")
    assert parsed.skipped == 1 and len(parsed.findings) == 1
    assert parsed.findings[0].location == "src/app.py:12"


def test_sarif_records_invalid_run_results_and_rejects_boolean_limit():
    data = {"runs": [{"results": False}, {"results": [sarif_result()]}]}
    parsed = parse_sarif(data, target_id="repo")
    assert parsed.skipped == 1 and len(parsed.findings) == 1
    with pytest.raises(AdapterError, match="max_results"):
        parse_sarif(data, target_id="repo", max_results=True)
    with pytest.raises(AdapterError, match="max_results"):
        parse_sarif("not valid json", target_id="repo", max_results=True)


def test_sarif_accepts_rule_object_and_falls_back_to_a_title():
    result = {"rule": {"id": "CWE-79"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.php"}}}]}
    parsed = parse_sarif(sarif_document(result), target_id="repo-1")
    assert parsed.findings[0].vulnerability_type == "CWE-79"
    assert parsed.findings[0].location == "a.php"


def test_sarif_rejects_invalid_documents():
    with pytest.raises(AdapterError):
        parse_sarif({"version": "2.1.0"}, target_id="repo-1")
    with pytest.raises(AdapterError):
        parse_sarif("{not json", target_id="repo-1")
    with pytest.raises(AdapterError):
        parse_sarif(sarif_document(sarif_result()), target_id="repo-1", max_results=0)


def test_gitleaks_secret_values_are_never_kept():
    secret = "AKIAIOSFODNN7EXAMPLE"
    document = [{"RuleID": "aws-access-token", "Description": "AWS Access Token", "File": "config.py",
                 "StartLine": 4, "Secret": secret, "Match": f"key = '{secret}'", "Entropy": 3.5}]
    parsed = parse_gitleaks(document, target_id="repo-1")
    finding = parsed.findings[0]
    assert finding.location == "config.py:4"
    assert finding.vulnerability_type == "secret" and finding.severity == "unknown"
    dumped = json.dumps(finding.model_dump(), ensure_ascii=False)
    assert secret not in dumped and "Entropy" not in dumped


def test_gitleaks_does_not_copy_secrets_from_description_or_rule():
    secret = "example-secret-value"
    result = parse_gitleaks([{"RuleID": secret, "Description": f"match {secret}", "File": "a.py",
                              "Secret": secret, "Match": secret}], target_id="repo")
    assert result.findings[0].title == "Potential secret"
    assert secret not in json.dumps(result.findings[0].model_dump())


def test_gitleaks_skips_items_without_a_file_and_rejects_non_arrays():
    parsed = parse_gitleaks([{"RuleID": "r", "StartLine": 1}, {"RuleID": "ok", "File": "a.py"}], target_id="repo-1")
    assert len(parsed.findings) == 1 and parsed.skipped == 1
    with pytest.raises(AdapterError):
        parse_gitleaks({"findings": []}, target_id="repo-1")


def test_result_limits_are_enforced():
    results = [sarif_result() for _ in range(5)]
    parsed = parse_sarif(sarif_document(*results), target_id="repo-1", max_results=2)
    assert len(parsed.findings) == 2
    assert len(parse_gitleaks([{"RuleID": "r", "File": "a.py"}], target_id="repo-1", max_results=1).findings) == 1


def test_document_size_limit_can_be_reached(monkeypatch):
    import vulnmind.tools.adapters as adapters
    monkeypatch.setattr(adapters, "MAX_DOCUMENT_BYTES", 10)
    with pytest.raises(AdapterError, match="size limit"):
        parse_sarif("x" * 11, target_id="repo-1")
    with pytest.raises(AdapterError, match="size limit"):
        parse_sarif("汉" * 4, target_id="repo-1")


def test_deep_json_is_rejected_as_an_adapter_error():
    depth = 10_000
    with pytest.raises(AdapterError, match="valid JSON"):
        parse_sarif("[" * depth + "]" * depth, target_id="repo")


def test_resolve_path_rejects_escapes(tmp_path):
    assert resolve_path(tmp_path, "src/a.py") == (tmp_path / "src/a.py").resolve()
    assert resolve_path(tmp_path, "../outside.py") is None
    assert resolve_path(tmp_path, str(Path("C:/Windows/win.ini"))) is None
    assert resolve_path(tmp_path, "  ") is None


def test_resolve_path_rejects_windows_traversal_and_link_escape(tmp_path):
    from vulnmind.tools.adapters import resolve_path
    assert resolve_path(tmp_path, r"..\outside.txt") is None
    assert resolve_path(tmp_path, r"C:outside.txt") is None
    root = tmp_path / "root"
    root.mkdir()
    link = root / "link"
    try:
        link.symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("creating symbolic links is unavailable")
    assert resolve_path(root, "link/secret.txt") is None


def test_result_limit_reports_truncation_only_when_results_remain():
    record = {"RuleID": "rule", "File": "a.py"}
    assert not parse_gitleaks([record], target_id="repo", max_results=1).truncated
    assert parse_gitleaks([record, record], target_id="repo", max_results=1).truncated
    assert parse_sarif(sarif_document(sarif_result(), sarif_result()), target_id="repo", max_results=1).truncated
