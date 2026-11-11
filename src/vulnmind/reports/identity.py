"""Check generated report identity, separately from file integrity."""
import json
from uuid import UUID


def matches_scan(content: str, report_format: str, *, scan_id: UUID, project_id: UUID) -> bool:
    """Require the generated report header to name the expected scan/project.

    This is a structural check, not a signature or evidence verification.
    Unknown or legacy report formats fail closed.
    """
    if not isinstance(content, str) or not isinstance(scan_id, UUID) or not isinstance(project_id, UUID):
        return False
    if report_format == "json":
        try:
            value = json.loads(content)
        except (ValueError, TypeError, RecursionError):
            return False
        return (isinstance(value, dict) and value.get("scan_id") == str(scan_id)
                and value.get("project_id") == str(project_id))
    if report_format == "markdown":
        lines = content.splitlines()
        return (len(lines) >= 4 and lines[0] == "# VulnMind 报告" and lines[1] == ""
                and lines[2] == f"- 扫描：{scan_id}" and lines[3] == f"- 项目：{project_id}")
    return False
