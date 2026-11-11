"""CLI doctor: degraded output on SQLite, failure without a database."""
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Project

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def env_for(tmp_path, database):
    env = os.environ.copy()
    env.update({"PYTHONPATH": str(PROJECT_ROOT / "src"), "PYTHONIOENCODING": "utf-8",
                "VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}",
                "VULNMIND_REPORT_ROOT": str(tmp_path / "reports"),
                "VULNMIND_EVIDENCE_ROOT": str(tmp_path / "evidence")})
    env.pop("VULNMIND_APPROVAL_SECRET", None)
    env.pop("VULNMIND_APPROVAL_ALLOWED_SIGNERS", None)
    return env


def run_doctor(env):
    return subprocess.run([sys.executable, "-m", "vulnmind", "doctor"],
                          capture_output=True, encoding="utf-8", env=env, timeout=120)


def test_doctor_reports_degraded_without_writing(tmp_path):
    database = tmp_path / "doctor.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    engine.dispose()
    result = run_doctor(env_for(tmp_path, database))
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "degraded"
    names = {check["name"] for check in payload["checks"]}
    assert {"database", "schema", "audit_chain", "report_root", "approvals", "model_key"} <= names
    assert not (tmp_path / "reports").exists()  # doctor must not create directories


def test_doctor_fails_without_a_database(tmp_path):
    env = env_for(tmp_path, tmp_path / "missing.db")
    env["VULNMIND_DATABASE_URL"] = ""
    result = run_doctor(env)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
