import json
from uuid import uuid4

import pytest

from vulnmind.reports.identity import matches_scan


@pytest.mark.parametrize("format", ["json", "markdown"])
def test_report_identity_requires_matching_scan_and_project(format):
    scan_id, project_id = uuid4(), uuid4()
    if format == "json":
        content = json.dumps({"scan_id": str(scan_id), "project_id": str(project_id)})
    else:
        content = f"# VulnMind 报告\n\n- 扫描：{scan_id}\n- 项目：{project_id}\n"
    assert matches_scan(content, format, scan_id=scan_id, project_id=project_id)
    assert not matches_scan(content, format, scan_id=uuid4(), project_id=project_id)
    assert not matches_scan(content, format, scan_id=scan_id, project_id=uuid4())
    assert not matches_scan(content, "other", scan_id=scan_id, project_id=project_id)
