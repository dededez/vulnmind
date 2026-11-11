"""Explicit real-model smoke on a synthetic authorized repository and existing knowledge.

Invokes the configured model for four advisory roles. Outputs only identities,
counts and usage; writes no credentials. Keeps the sample and resume arguments.
"""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
from uuid import UUID, uuid4

from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session

from vulnmind.config import Settings
from vulnmind.persistence.models import Project, DurableStep, AgentRun, ScanTask, Finding, Evidence
from vulnmind.persistence.audit import verify_complete_audit_chain


def main():
    root = Path(__file__).resolve().parents[1]
    workflow, project = uuid4(), uuid4()
    work = root / ".devtools" / "runtime" / ("agent-smoke-" + workflow.hex)
    repo = work / "repository"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text("import requests\nrequests.get('https://example.invalid', verify=False)\n", encoding="utf-8")
    external = work / "bandit.json"
    external.write_text(json.dumps({"results": [{"filename": "app.py", "test_id": "B501", "line_number": 2,
                                               "issue_severity": "HIGH"}], "errors": []}), encoding="utf-8")
    now = datetime.now(timezone.utc)
    scope = work / "authorization.json"
    scope.write_text(json.dumps({"authorization_source": "user-requested development test on synthetic owned fixture",
        "approved_by": "local-workspace-owner", "starts_at": (now-timedelta(minutes=1)).isoformat(),
        "expires_at": (now+timedelta(hours=24)).isoformat(), "repository_roots": [str(repo)]}), encoding="utf-8")
    engine = create_engine(Settings().database_url)
    with Session(engine) as session, session.begin():
        session.add(Project(id=project, name="durable multi-agent smoke " + workflow.hex[:8]))
    args = [sys.executable, "-m", "vulnmind", "workflow-run", "--workflow-id", str(workflow), "--project-id", str(project),
            "--repository", str(repo), "--scope-file", str(scope), "--bandit-json", str(external), "--report-format", "json",
            "--agent-plan", "--agent-analysis", "--agent-review", "--agent-report", "--knowledge-context", "--agent-knowledge"]
    (work / "command.json").write_text(json.dumps(args, ensure_ascii=False, indent=2), encoding="utf-8")
    first = subprocess.run(args, cwd=root, capture_output=True, encoding="utf-8", timeout=300)
    payload = json.loads(first.stdout)
    with Session(engine) as session:
        rows = session.scalars(select(DurableStep).where(DurableStep.workflow_id == workflow)
                               .order_by(DurableStep.created_at)).all()
        stages = [{"stage": row.stage, "status": row.status, "attempt": row.attempt} for row in rows]
        knowledge = next((row.payload for row in rows if row.stage == "knowledge" and row.payload), {})
    output = {"status": payload["status"], "workflow_id": str(workflow), "project_id": str(project),
              "scan_id": payload.get("scan_id"), "stages": stages, "reference_count": len(knowledge.get("chunks", [])),
              "sample_directory": str(work), "real_model": True, "real_local_encoder": True}
    if first.returncode == 0:
        replay = subprocess.run(args, cwd=root, capture_output=True, encoding="utf-8", timeout=60)
        output["replay_status"] = json.loads(replay.stdout)["status"]
        with Session(engine) as session:
            output["all_attempts_one"] = all(row.attempt == 1 for row in session.scalars(
                select(DurableStep).where(DurableStep.workflow_id == workflow)))
            scan_id = UUID(payload["scan_id"])
            output["findings"] = session.scalar(select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id))
            output["evidence"] = session.scalar(select(func.count()).select_from(Evidence).join(Finding)
                                                 .where(Finding.scan_id == scan_id))
            chain = verify_complete_audit_chain(session.connection())
            output["audit_valid"] = chain.valid and not chain.unhashed
    engine.dispose()
    artifact = root / "evaluation" / "durable_agent_smoke_20261108.json"
    artifact.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output, ensure_ascii=False))
    return 0 if output.get("replay_status") == "finished" and output.get("all_attempts_one") and output.get("audit_valid") else 2


if __name__ == "__main__":
    raise SystemExit(main())
