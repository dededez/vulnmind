"""Disposable PG dump + artifact restore + continuation of a real v2 workflow.

Uses a synthetic repository and fake model responses, never the configured DB.
All copied/moved artifacts remain inside this invocation's verified temp root.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
from uuid import uuid4

from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session

from pg_backup_restore import _binaries, _bootstrap, _remove_created_test_dir, ROOT
from vulnmind.graph.durable_repository import RepositoryFlow
from vulnmind.persistence.audit import verify_complete_audit_chain
from vulnmind.persistence.models import Project, Scan, DurableStep, Evidence, Finding
from vulnmind.schemas import Target, Authorization
from vulnmind.agents.model import ModelResponse


def main():
    temp, data, log, password, flags, binaries = _bootstrap(_binaries())
    engine = restored_engine = None
    try:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = {**os.environ, "PGPASSWORD": password}
        def run(argv):
            result = subprocess.run(argv, cwd=temp, env=env, capture_output=True, creationflags=flags, timeout=120)
            if result.returncode:
                raise RuntimeError("isolated restore drill command failed")
            return result
        # postgres is long-lived: inherited PIPE handles can keep communicate()
        # blocked on Windows even after pg_ctl exits. Server output uses -l.
        subprocess.run([str(binaries / "pg_ctl.exe"), "-D", str(data), "-l", str(log),
                        "-o", f"-h 127.0.0.1 -p {port}", "-w", "start"],
                       cwd=temp, env=env, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, creationflags=flags, timeout=120)
        base = ["-h", "127.0.0.1", "-p", str(port), "-U", "vulnmind_drill"]
        for db in ("durable_source", "durable_restored"):
            run([str(binaries / "createdb.exe"), *base, db])
        source_url = f"postgresql+psycopg://vulnmind_drill:{password}@127.0.0.1:{port}/durable_source"
        result = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT,
            env={**env, "VULNMIND_DATABASE_URL": source_url}, capture_output=True, creationflags=flags, timeout=120)
        if result.returncode:
            raise RuntimeError("drill migration failed")
        engine = create_engine(source_url)
        project, workflow = uuid4(), uuid4()
        with Session(engine) as session, session.begin():
            session.add(Project(id=project, name="durable recovery drill"))
        artifacts = temp / "artifacts"
        repo = artifacts / "repo"
        repo.mkdir(parents=True)
        (repo / "test.py").write_text("import requests\nrequests.get('https://example.invalid', verify=False)\n")
        bandit = artifacts / "bandit.json"
        bandit.write_text(json.dumps({"results": [{"filename": "test.py", "test_id": "B501", "line_number": 2, "issue_severity": "HIGH"}]}))
        now = datetime.now(timezone.utc)
        scope = Authorization(authorization_source="owned restore drill fixture", approved_by="test",
            starts_at=now-timedelta(minutes=1), expires_at=now+timedelta(hours=1), repository_roots=[str(repo)])
        options = dict(actor="restore-drill", tools=["bandit_json"],
            reports={"bandit_json": {"path": str(bandit), "sha256": hashlib.sha256(bandit.read_bytes()).hexdigest()}},
            report_format="json", report_root=str(artifacts / "reports"), evidence_root=str(artifacts / "evidence"),
            agent_model="fake", agent_plan=True, agent_analysis=True, agent_review=True, agent_report=True,
            knowledge_context=False, agent_knowledge=False)
        calls = []
        class Fake:
            def complete(self, request):
                calls.append(1)
                prompt = request.messages[-1].content
                if "selected_tools" in prompt:
                    return ModelResponse(text='{"selected_tools":["bandit_json"]}')
                if '"items"' in prompt:
                    return ModelResponse(text='{"summary":"advisory", "items":[]}')
                return ModelResponse(text='{"summary":"advisory"}')
        target = Target(type="repository", locator=str(repo))
        flow = RepositoryFlow(engine, workflow, project, target, scope, options, client_factory=Fake)
        assert flow.run(pause_after="report")["status"] == "paused"
        assert len(calls) == 4
        dump = temp / "durable.dump"
        run([str(binaries / "pg_dump.exe"), *base, "-Fc", "-f", str(dump), "durable_source"])
        run([str(binaries / "pg_restore.exe"), *base, "-d", "durable_restored", "--no-owner", str(dump)])
        # Restore both content-addressed stores at the paths bound by the task.
        for name in ("reports", "evidence"):
            live = (artifacts / name).resolve(strict=True)
            snapshot, old = artifacts / (name + "-backup"), artifacts / (name + "-original")
            if not live.is_relative_to(temp) or live.is_symlink() or old.exists() or snapshot.exists():
                raise RuntimeError("invalid drill artifact paths")
            if any(path.is_symlink() or path.is_junction() for path in live.rglob("*")):
                raise RuntimeError("linked drill artifact")
            shutil.copytree(live, snapshot)
            live.rename(old)
            shutil.copytree(snapshot, live)
        restored_engine = create_engine(source_url.replace("/durable_source", "/durable_restored"))
        def no_model():
            raise AssertionError("completed model was called after restore")
        restored = RepositoryFlow(restored_engine, workflow, project, target, scope, options, client_factory=no_model)
        outcome = restored.run()
        with Session(restored_engine) as session:
            chain = verify_complete_audit_chain(session.connection())
            receipt_count = session.scalar(select(func.count()).select_from(DurableStep))
            evidence_count = session.scalar(select(func.count()).select_from(Evidence))
            assert session.get(Scan, flow.scan_id).status == "finished"
            assert all(row.attempt == 1 for row in session.scalars(select(DurableStep)))
        assert outcome["status"] == "finished" and chain.valid and not chain.unhashed and evidence_count == 1
        output = {"status": "ok", "restored_workflow_status": outcome["status"], "completed_stages": receipt_count,
                  "evidence_records": evidence_count, "model_calls_before_backup": len(calls), "model_calls_after_restore": 0,
                  "report_and_evidence_restored": True, "audit_valid": chain.valid, "dump_bytes": dump.stat().st_size}
        (ROOT / "evaluation" / "durable_restore_20261108.json").write_text(json.dumps(output, indent=2)+"\n", encoding="utf-8")
        print(json.dumps(output))
    finally:
        for connection in (engine, restored_engine):
            if connection is not None:
                connection.dispose()
        status = subprocess.run([str(binaries / "pg_ctl.exe"), "-D", str(data), "status"], cwd=temp,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
        if status.returncode == 0:
            subprocess.run([str(binaries / "pg_ctl.exe"), "-D", str(data), "-m", "fast", "-w", "stop"], cwd=temp,
                           check=True, stdout=subprocess.DEVNULL, creationflags=flags)
        elif status.returncode != 3:
            raise RuntimeError("could not verify drill shutdown")
        _remove_created_test_dir(temp, temp.parent)


if __name__ == "__main__":
    main()
