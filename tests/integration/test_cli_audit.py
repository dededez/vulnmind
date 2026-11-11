"""CLI audit-verify: valid chain, tampered chain, missing database."""
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine, select, update

from vulnmind.persistence.audit import DatabaseAuditSink
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import AuditEvent

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def make_db(tmp_path):
    database = tmp_path / "audit.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    sink = DatabaseAuditSink(engine)
    for status in ("requested", "succeeded"):
        sink.record({"call_id": str(uuid4()), "tool_name": "fake", "actor": "tester",
                     "target_type": "web", "status": status})
    return database, engine


def run_cli(*arguments, env):
    return subprocess.run([sys.executable, "-m", "vulnmind", "audit-verify", *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=120)


def env_for(database):
    env = os.environ.copy()
    env.update({"PYTHONPATH": str(PROJECT_ROOT / "src"), "PYTHONIOENCODING": "utf-8",
                "VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"})
    return env


def test_valid_chain_reports_valid(tmp_path):
    database, engine = make_db(tmp_path)
    result = run_cli(env=env_for(database))
    engine.dispose()
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "valid" and payload["checked"] == 2 and payload["unhashed"] == 0


def test_tampered_chain_reports_broken_and_exits_nonzero(tmp_path):
    database, engine = make_db(tmp_path)
    with engine.begin() as connection:
        target = connection.execute(select(AuditEvent.id).order_by(AuditEvent.created_at)).all()[1][0]
        connection.execute(update(AuditEvent).where(AuditEvent.id == target).values(status="denied"))
    result = run_cli(env=env_for(database))
    engine.dispose()
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "broken" and payload["first_break_id"] == str(target)


def test_missing_database_is_blocked(tmp_path):
    env = env_for(tmp_path / "missing.db")
    result = run_cli(env=env)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"
