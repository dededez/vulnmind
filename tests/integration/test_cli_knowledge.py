"""CLI knowledge ingestion tests against a SQLite database."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import KnowledgeChunk, KnowledgeDocument


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "knowledge.db"
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    Base.metadata.create_all(engine)
    engine.dispose()
    return path


def run_knowledge(*arguments, env_overrides):
    env = os.environ.copy()
    env.update(env_overrides)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-m", "vulnmind", "knowledge", *map(str, arguments)],
                          capture_output=True, encoding="utf-8", env=env, timeout=20)


def test_ingests_a_local_file(database, tmp_path):
    source = tmp_path / "note.md"
    source.write_bytes(("CWE-89 SQL injection guidance. " * 60).encode("utf-8"))
    result = run_knowledge("ingest", "--file", source, "--title", "SQLi note", "--source-type", "CWE",
                           "--source-url", "https://cwe.mitre.org/data/definitions/89.html",
                           "--version", "4.14", "--trust-level", "high", "--size", "200", "--overlap", "20",
                           env_overrides={"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"})
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ingested" and payload["chunks"] >= 2
    assert payload["sparse_index"] is False  # SQLite has no to_tsvector

    engine = create_engine(f"sqlite:///{database.as_posix()}")
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as session:
        document = session.scalar(select(KnowledgeDocument))
        assert document.title == "SQLi note" and document.trust_level == "high"
        chunks = list(session.scalars(select(KnowledgeChunk)))
        assert len(chunks) == payload["chunks"]
        assert chunks[0].metadata_["chunk_id"]
    engine.dispose()


def test_rejects_missing_configuration_and_bad_input(database, tmp_path):
    source = tmp_path / "note.md"
    source.write_bytes(b"content")
    no_db = run_knowledge("ingest", "--file", source, "--title", "t", "--source-type", "note",
                          env_overrides={"VULNMIND_DATABASE_URL": ""})
    assert no_db.returncode == 2
    bad_overlap = run_knowledge("ingest", "--file", source, "--title", "t", "--source-type", "note",
                                "--size", "10", "--overlap", "10",
                                env_overrides={"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"})
    assert bad_overlap.returncode == 2
    missing = run_knowledge("ingest", "--file", tmp_path / "missing.md", "--title", "t",
                            "--source-type", "note",
                            env_overrides={"VULNMIND_DATABASE_URL": f"sqlite:///{database.as_posix()}"})
    assert missing.returncode == 2
    assert "missing.md" not in missing.stdout + missing.stderr
