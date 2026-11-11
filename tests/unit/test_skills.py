"""Skill discovery, selection and indexing tests."""
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from vulnmind.knowledge.skills import MAX_SKILL_BYTES, SkillError, SkillIndexer, SkillLoader, SkillMetadata
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import SkillRecord
from vulnmind.persistence.unit_of_work import transaction


def write_skill(root: Path, relative: str, *, skill_id="sqli_workflow", target_type="web",
                vuln_type="sqli", stage="analysis", version="1", body="Step 1. Confirm scope."):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "---\n"
        f"skill_id: {skill_id}\n"
        "name: SQL injection workflow\n"
        f"version: '{version}'\n"
        f"target_type: {target_type}\n"
        f"vuln_type: {vuln_type}\n"
        f"stage: {stage}\n"
        "risk_level: low\n"
        "prerequisites: [scope_validation]\n"
        "tools: [http.request]\n"
        "---\n"
        f"{body}\n",
        encoding="utf-8")
    return path


def test_load_and_select_skills(tmp_path):
    write_skill(tmp_path, "vulnerability/sqli/workflow.md")
    write_skill(tmp_path, "target/repository_audit.md", skill_id="repo_audit", target_type="repository",
                vuln_type=None, stage="recon")
    loader = SkillLoader(tmp_path)
    available = {metadata.skill_id: metadata for metadata in loader.available()}
    assert set(available) == {"sqli_workflow", "repo_audit"}
    assert available["sqli_workflow"].path == "vulnerability/sqli/workflow.md"
    assert available["sqli_workflow"].tools == ["http.request"]

    skill = loader.load("sqli_workflow")
    assert skill.content.strip() == "Step 1. Confirm scope."
    assert len(skill.sha256) == 64

    assert [item.skill_id for item in loader.select(target_type="web")] == ["sqli_workflow"]
    assert [item.skill_id for item in loader.select(target_type="repository", stage="recon")] == ["repo_audit"]
    assert loader.select(target_type="web", vuln_type="xss") == []


def test_duplicate_identifier_is_refused(tmp_path):
    write_skill(tmp_path, "a/one.md")
    write_skill(tmp_path, "b/two.md")
    with pytest.raises(SkillError, match="duplicate"):
        SkillLoader(tmp_path).available()


def test_malformed_front_matter_is_skipped_or_rejected(tmp_path):
    (tmp_path / "bad.md").write_text("no front matter", encoding="utf-8")
    assert SkillLoader(tmp_path).available() == []
    (tmp_path / "unterminated.md").write_text("---\nskill_id: x\n", encoding="utf-8")
    assert SkillLoader(tmp_path).available() == []
    write_skill(tmp_path, "good.md")
    (tmp_path / "missing.md").write_text("---\nskill_id: incomplete\n---\nbody\n", encoding="utf-8")
    assert [metadata.skill_id for metadata in SkillLoader(tmp_path).available()] == ["sqli_workflow"]
    with pytest.raises(SkillError):
        SkillLoader(tmp_path).load("unknown")


def test_size_limit_is_enforced(tmp_path):
    path = write_skill(tmp_path, "big.md")
    path.write_text(path.read_text(encoding="utf-8") + "x" * MAX_SKILL_BYTES, encoding="utf-8")
    assert SkillLoader(tmp_path).available() == []


def test_empty_body_is_rejected(tmp_path):
    write_skill(tmp_path, "empty.md", body=" ")
    assert SkillLoader(tmp_path).available() == []


def test_loader_requires_a_directory(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("x", encoding="utf-8")
    with pytest.raises((SkillError, OSError)):
        SkillLoader(file_path)
    with pytest.raises(SkillError):
        SkillLoader(tmp_path).select(target_type="mobile")


def test_load_rechecks_path_after_discovery(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    write_skill(tmp_path, "outside.md")
    loader = SkillLoader(root)
    metadata = SkillMetadata(skill_id="sqli_workflow", name="test", version="1", target_type="web", path="../outside.md")
    monkeypatch.setattr(loader, "available", lambda: [metadata])
    called = []
    monkeypatch.setattr(loader, "_read", lambda path: called.append(path))
    with pytest.raises(SkillError, match="escapes"):
        loader.load("sqli_workflow")
    assert called == []


def test_load_rejects_identity_change_after_discovery(tmp_path, monkeypatch):
    write_skill(tmp_path, "current.md", skill_id="different")
    loader = SkillLoader(tmp_path)
    metadata = SkillMetadata(skill_id="requested", name="test", version="1", target_type="web", path="current.md")
    monkeypatch.setattr(loader, "available", lambda: [metadata])
    with pytest.raises(SkillError, match="identity changed"):
        loader.load("requested")


def test_aliases_and_large_headers_are_rejected(tmp_path):
    path = tmp_path / "alias.md"
    path.write_text("---\nskill_id: &id test\nname: *id\nversion: '1'\ntarget_type: web\n---\nbody\n", encoding="utf-8")
    loader = SkillLoader(tmp_path)
    with pytest.raises(SkillError, match="aliases"):
        loader._read(path)
    path.write_text("---\nname: " + "x" * 64001 + "\n---\nbody\n", encoding="utf-8")
    with pytest.raises(SkillError, match="front matter exceeds"):
        loader._read(path)


def test_project_skill_library_loads():
    root = Path(__file__).resolve().parents[2] / "skills"
    loader = SkillLoader(root)
    available = loader.available()
    identifiers = {metadata.skill_id for metadata in available}
    assert {"scope_validation", "evidence_collection", "finding_triage", "report_generation",
            "sqli_workflow", "sqli_safe_validation", "ssrf_workflow", "xss_workflow",
            "repository_audit", "web_api_audit"} <= identifiers
    for metadata in available:
        skill = loader.load(metadata.skill_id)
        assert skill.content.strip() and len(skill.sha256) == 64
    selected = loader.select(target_type="web", vuln_type="sqli", stage="validation")
    assert [metadata.skill_id for metadata in selected] == ["sqli_safe_validation"]
    repository_skills = loader.select(target_type="repository")
    assert "repository_audit" in {metadata.skill_id for metadata in repository_skills}
    assert {metadata.target_type for metadata in repository_skills} <= {"repository", "both"}


@pytest.fixture
def factory():
    engine = create_engine("sqlite://")
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def test_indexer_syncs_metadata_and_is_idempotent(tmp_path, factory):
    write_skill(tmp_path, "vulnerability/sqli/workflow.md")
    loader = SkillLoader(tmp_path)
    with transaction(factory) as session:
        assert SkillIndexer(session).sync(loader) == (1, 0)
    with transaction(factory) as session:
        row = session.scalar(select(SkillRecord))
        row.metadata_ = {**row.metadata_, "user_tag": "keep"}
    with transaction(factory) as session:
        assert SkillIndexer(session).sync(loader) == (0, 1)
    with transaction(factory) as session:
        row = session.scalar(select(SkillRecord))
        assert row.name == "sqli_workflow" and row.target_type == "web"
        assert row.content_uri == "vulnerability/sqli/workflow.md"
        assert row.metadata_["tools"] == ["http.request"]
        assert len(row.metadata_["sha256"]) == 64
        assert row.metadata_["user_tag"] == "keep"


def test_skill_digest_covers_metadata_and_body(tmp_path):
    path = write_skill(tmp_path, "one.md")
    loader = SkillLoader(tmp_path)
    first = loader.load("sqli_workflow").sha256
    original = path.read_text(encoding="utf-8")
    path.write_text(original.replace("risk_level: low", "risk_level: high"), encoding="utf-8")
    assert loader.load("sqli_workflow").sha256 != first


def test_loaded_skill_hash_is_verified_on_revalidation(tmp_path):
    write_skill(tmp_path, "one.md")
    item = SkillLoader(tmp_path).load("sqli_workflow")
    item.tools.append("unexpected")
    with pytest.raises(ValueError, match="integrity hash"):
        type(item).model_validate(item.model_dump())


def test_indexer_rejects_same_version_content_change_without_mutating_rows(tmp_path, factory):
    path = write_skill(tmp_path, "one.md")
    loader = SkillLoader(tmp_path)
    with transaction(factory) as session:
        assert SkillIndexer(session).sync(loader) == (1, 0)
    original = path.read_text(encoding="utf-8")
    path.write_text(original.replace("Step 1.", "Modified step."), encoding="utf-8")
    with transaction(factory) as session:
        row = session.scalar(select(SkillRecord))
        previous = dict(row.metadata_)
        with pytest.raises(SkillError, match="version changed"):
            SkillIndexer(session).sync(loader)
        assert row.metadata_ == previous
    path.write_text(original.replace("version: '1'", "version: '2'"), encoding="utf-8")
    with transaction(factory) as session:
        assert SkillIndexer(session).sync(loader) == (1, 0)


def test_indexer_refuses_legacy_unhashed_version_without_overwriting(tmp_path, factory):
    write_skill(tmp_path, "one.md")
    loader = SkillLoader(tmp_path)
    with transaction(factory) as session:
        session.add(SkillRecord(id=uuid4(), name="sqli_workflow", version="1", content_uri="old.md", metadata_={}))
    with transaction(factory) as session:
        with pytest.raises(SkillError, match="legacy integrity hash"):
            SkillIndexer(session).sync(loader)
        assert session.scalar(select(SkillRecord)).content_uri == "old.md"


def test_load_verified_rejects_unindexed_or_modified_content(tmp_path, factory):
    path = write_skill(tmp_path, "one.md")
    loader = SkillLoader(tmp_path)
    with transaction(factory) as session:
        indexer = SkillIndexer(session)
        with pytest.raises(SkillError, match="not indexed"):
            indexer.load_verified(loader, skill_id="sqli_workflow", version="1")
        indexer.sync(loader)
    with transaction(factory) as session:
        indexer = SkillIndexer(session)
        assert indexer.load_verified(loader, skill_id="sqli_workflow", version="1").content.strip()
        with pytest.raises(SkillError, match="version does not match"):
            indexer.load_verified(loader, skill_id="sqli_workflow", version="2")
    path.write_text(path.read_text(encoding="utf-8").replace("Step 1.", "Changed."), encoding="utf-8")
    with transaction(factory) as session:
        with pytest.raises(SkillError, match="matching integrity"):
            SkillIndexer(session).load_verified(loader, skill_id="sqli_workflow", version="1")
