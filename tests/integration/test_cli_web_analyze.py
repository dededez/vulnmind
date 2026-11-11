"""CLI tests for offline web snapshot analysis against SQLite."""
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Project
from vulnmind.schemas import Authorization


def authorization():
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test authorization", approved_by="tester",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         web_origins=["http://example.test"])


def snapshot(target="http://example.test/"):
    return {"version": 1, "target": {"type": "web", "locator": target}, "pages": [
        {"url": "http://example.test/", "status_code": 200, "content_type": "text/html",
         "headers": {"server": "test"},
         "html": '<html><a href="/admin">a</a><form action="/login" method="post">'
                 '<input name="user"><input name="pass"></form></html>'}]}


def run(command, *arguments, env_overrides):
    env = os.environ.copy()
    env.update(env_overrides)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-m", "vulnmind", command, *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=60)


@pytest.fixture
def seeded(tmp_path):
    database = tmp_path / "web.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    with Session(engine) as session, session.begin():
        project = Project(id=uuid4(), name="web cli")
        session.add(project)
        project_id = project.id
    engine.dispose()
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(authorization().model_dump_json(), encoding="utf-8")
    snapshot_file = tmp_path / "snapshot.json"
    snapshot_file.write_text(json.dumps(snapshot()), encoding="utf-8")
    env = {"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
           "VULNMIND_REPORT_ROOT": str(tmp_path / "reports"),
           "VULNMIND_EVIDENCE_ROOT": str(tmp_path / "evidence")}
    return project_id, scope_file, snapshot_file, tmp_path, env


def test_web_analyze_stores_findings_endpoints_and_report(seeded):
    project_id, scope_file, snapshot_file, tmp_path, env = seeded
    result = run("web-analyze", "--snapshot", snapshot_file, "--project-id", project_id,
                 "--scope-file", scope_file, "--report-format", "json", env_overrides=env)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "finished"
    assert payload["pages_analyzed"] == 1 and payload["out_of_scope"] == 0
    assert payload["groups"] == 6 and payload["findings_stored"] == 6
    assert payload["endpoints"] == 2 and payload["evidence_stored"] == 6
    scan_id = payload["scan_id"]

    findings = run("findings", "--scan-id", scan_id, env_overrides=env)
    assert findings.returncode == 0
    assert len(json.loads(findings.stdout)["findings"]) == 6
    endpoints = run("endpoints", "--scan-id", scan_id, env_overrides=env)
    assert endpoints.returncode == 0
    assert {item["url"] for item in json.loads(endpoints.stdout)["endpoints"]} == {
        "http://example.test/admin", "http://example.test/login"}
    rows = {item["url"]: item for item in json.loads(endpoints.stdout)["endpoints"]}
    assert rows["http://example.test/login"]["parameters"] == ["user", "pass"]

    report = run("report", "--scan-id", scan_id, "--json", env_overrides=env)
    assert report.returncode == 0
    document = json.loads(json.loads(report.stdout)["content"])
    assert document["schema_version"] == 7
    assert any("离线快照" in item for item in document["limitations"])

    verified = run("verify", "--scan-id", scan_id, env_overrides=env)
    assert verified.returncode == 0, verified.stdout
    assert json.loads(verified.stdout)["status"] == "ok"


def test_invalid_inputs_are_blocked(seeded):
    project_id, scope_file, snapshot_file, tmp_path, env = seeded
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert run("web-analyze", "--snapshot", bad, "--project-id", project_id,
               "--scope-file", scope_file, env_overrides=env).returncode == 2
    out_of_scope = tmp_path / "outside.json"
    out_of_scope.write_text(json.dumps(snapshot(target="http://evil.test/")), encoding="utf-8")
    assert run("web-analyze", "--snapshot", out_of_scope, "--project-id", project_id,
               "--scope-file", scope_file, env_overrides=env).returncode == 2
    assert run("web-analyze", "--snapshot", snapshot_file, "--project-id", uuid4(),
               "--scope-file", scope_file, env_overrides=env).returncode == 2
    assert run("web-analyze", "--snapshot", snapshot_file, "--project-id", project_id,
               "--scope-file", scope_file,
               env_overrides={**env, "VULNMIND_DATABASE_URL": ""}).returncode == 2


def test_validation_requests_are_queued(seeded):
    project_id, scope_file, snapshot_file, tmp_path, env = seeded
    result = run("web-analyze", "--snapshot", snapshot_file, "--project-id", project_id,
                 "--scope-file", scope_file, "--validation-requests", env_overrides=env)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["validation_requests"] == 6
    listed = run("approvals", "list", "--scan-id", payload["scan_id"], env_overrides=env)
    assert listed.returncode == 0
    assert len(json.loads(listed.stdout)["pending"]) == 6
