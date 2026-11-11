"""Guard against unsafe migration and corpus import behavior."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_downgrade_with_vectors_rejects_before_ddl(monkeypatch):
    migration = load("embedding_migration_review", "migrations/versions/0014_embedding_dimension.py")
    statements = []
    monkeypatch.setattr(migration.op, "execute", lambda sql: statements.append(str(sql)))
    monkeypatch.setattr(migration.op, "get_bind", lambda: SimpleNamespace(
        execute=lambda _: SimpleNamespace(scalar_one=lambda: 1)))
    monkeypatch.setattr(migration.op, "drop_index", lambda *a, **k: pytest.fail("index changed"))
    with pytest.raises(RuntimeError, match="vectors are stored"):
        migration.downgrade()
    assert statements == ["LOCK TABLE knowledge_chunks IN ACCESS EXCLUSIVE MODE"]


def test_corpus_rejects_overlarge_file_without_unbounded_read(tmp_path, monkeypatch):
    module = load("corpus_import_review", "scripts/ingest_corpus.py")
    monkeypatch.setattr(module, "MAX_CORPUS_BYTES", 20)
    path = tmp_path / "corpus.json"
    path.write_bytes(b"x" * 21)
    with pytest.raises(SystemExit, match="too large"):
        module.load_items(path)


def test_existing_title_is_skipped_only_when_content_and_metadata_match():
    from uuid import uuid4
    module = load("corpus_match_review", "scripts/ingest_corpus.py")
    doc = SimpleNamespace(id=uuid4(), title="CWE test", source_type="CWE", source_url=None,
                          version=None, trust_level=None, metadata_=None)
    session = SimpleNamespace(scalars=lambda _: iter(["original text"]))
    options = dict(source_type="CWE", source_url=None, version=None, trust_level=None,
                   metadata=None, size=1000, overlap=100)
    assert module._matches_existing(session, doc, content="original text", **options)
    assert not module._matches_existing(session, doc, content="changed text", **options)
    assert not module._matches_existing(session, doc, content="original text",
                                        **{**options, "version": "new"})


def test_backfill_rejects_other_models_before_loading(monkeypatch):
    import sys
    module = load("embedding_backfill_review", "scripts/backfill_embeddings.py")
    monkeypatch.setattr(sys, "argv", ["backfill", "--model", "other-model"])
    with pytest.raises(SystemExit, match="model provenance"):
        module.main()
