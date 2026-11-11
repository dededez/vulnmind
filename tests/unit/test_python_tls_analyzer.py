from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

from vulnmind.analysis.python_tls import MAX_PYTHON_CHARACTERS, find_python_tls_candidates
from vulnmind.analysis.service import RepositoryScanRequest, RepositoryScanService
from vulnmind.schemas import Authorization, Target
from vulnmind.tools.repo_files import FileContent


def source(text, language="python"):
    return FileContent(path="example.py", language=language, encoding="utf-8",
                       size_bytes=len(text.encode()), sha256=sha256(text.encode()).hexdigest(), content=text)


def test_detects_literal_disabled_verification_without_echoing_source():
    secret = "sensitive-example-value"
    text = f'import requests\nrequests.get("https://{secret}", verify=False)\nrequests.get("/", verify=True)\n'
    result = find_python_tls_candidates(source(text))
    assert len(result) == 1
    assert result[0].location == "example.py:2" and result[0].status == "unverified"
    assert secret not in result[0].model_dump_json()


def test_limits_detection_to_explicit_patterns_without_evaluating_code():
    text = 'requests.get("/", verify=flag)\nclient.get("/", verify=False)\nhttpx.post("/", verify=False)\n'
    result = find_python_tls_candidates(source(text))
    assert [item.location for item in result] == ["example.py:3"]
    assert find_python_tls_candidates(source(text, "javascript")) == []
    with pytest.raises(ValueError, match="parse"):
        find_python_tls_candidates(source("def broken(:\n"))
    with pytest.raises(ValueError, match="character limit"):
        find_python_tls_candidates(source("x" * (MAX_PYTHON_CHARACTERS + 1)))


def test_excessive_matches_fail_instead_of_silently_truncating():
    with pytest.raises(ValueError, match="finding limit"):
        find_python_tls_candidates(source('requests.get("/", verify=False)\n' * 101))


def test_real_file_flows_through_scope_pipeline_and_report(tmp_path):
    (tmp_path / "app.py").write_text('import requests\nrequests.get("https://example.test", verify=False)\n', encoding="utf-8")
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner", starts_at=now-timedelta(minutes=1),
                          expires_at=now+timedelta(minutes=1), repository_roots=[str(tmp_path)])
    class Audit:
        def record(self, event):
            pass
    request = RepositoryScanRequest(scan_id="s", project_id="p", actor="test",
                                    target=Target(type="repository", locator=str(tmp_path)), scope=scope)
    result = RepositoryScanService(Audit(), [find_python_tls_candidates]).run(request)
    assert result.analysis.files_examined == 1 and len(result.analysis.findings) == 1
    assert result.analysis.findings[0].status == "unverified"
    assert "可能禁用了 TLS 证书验证" in result.report.content
    assert result.report.counts["confirmed"] == 0
