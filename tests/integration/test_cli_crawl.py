"""CLI crawl validation paths that must not touch the network."""
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def run_cli(tmp_path, scope_text, *extra, env_extra=None):
    scope = tmp_path / "scope.json"
    scope.write_text(scope_text, encoding="utf-8")
    env = os.environ.copy()
    env.update({"PYTHONPATH": str(PROJECT_ROOT / "src"), "PYTHONIOENCODING": "utf-8",
                "PYTHONDONTWRITEBYTECODE": "1"})
    env.update(env_extra or {})
    return subprocess.run([sys.executable, "-m", "vulnmind", "crawl", "--start", "https://app.test/",
                           "--scope-file", str(scope), *extra],
                          capture_output=True, encoding="utf-8", env=env, timeout=120)


def valid_scope():
    return json.dumps({"authorization_source": "x", "approved_by": "o",
                       "starts_at": "2026-01-01T00:00:00+00:00",
                       "expires_at": "2026-01-01T01:00:00+00:00",
                       "web_origins": ["https://app.test"]})


def test_invalid_scope_is_blocked_without_network(tmp_path):
    result = run_cli(tmp_path, '{"authorization_source": "x"}')
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"


def test_invalid_limits_are_blocked(tmp_path):
    result = run_cli(tmp_path, valid_scope(), "--max-pages", "0")
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"


def test_store_requires_a_project_before_network(tmp_path):
    result = run_cli(tmp_path, valid_scope(), "--store")
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["errors"]


def test_store_requires_a_database_before_network(tmp_path):
    result = run_cli(tmp_path, valid_scope(), "--store", "--project-id", str(uuid4()),
                     env_extra={"VULNMIND_DATABASE_URL": ""})
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "blocked"


def test_endpoints_command_lists_stored_rows(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from vulnmind.persistence.base import Base
    from vulnmind.persistence.models import Project, Scan
    from vulnmind.persistence.repositories import WebEndpointRepository
    from vulnmind.persistence.unit_of_work import transaction

    database = tmp_path / "endpoints.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="crawl")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="crawl")
        session.add(scan)
        session.flush()
        WebEndpointRepository(session).replace_for_scan(
            scan.id, project.id, [{"url": "https://app.test/a", "method": "GET", "source": "https://app.test/"}])
        scan_id = scan.id
    engine.dispose()
    env = os.environ.copy()
    env.update({"PYTHONPATH": str(PROJECT_ROOT / "src"), "PYTHONIOENCODING": "utf-8",
                "VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"})
    result = subprocess.run([sys.executable, "-m", "vulnmind", "endpoints", "--scan-id", str(scan_id)],
                            capture_output=True, encoding="utf-8", env=env, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "listed" and payload["count"] == 1
    assert payload["endpoints"][0]["url"] == "https://app.test/a"

