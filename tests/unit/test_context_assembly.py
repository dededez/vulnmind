"""Context assembly tests: real skill/chunk/memory sources, budget and manifest."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from vulnmind.context.assembly import assemble_context, manifest_payload
from vulnmind.context.builder import ContextBudget, ContextOverflow
from vulnmind.knowledge.retrieval import KnowledgeChunk
from vulnmind.knowledge.skills import Skill, SkillMetadata, skill_digest
from vulnmind.memory.manager import MemoryRecord
from vulnmind.persistence.base import Base
from vulnmind.persistence.repositories import ContextManifestRepository, ProjectRepository, ScanRepository
from vulnmind.persistence.models import AgentRun, ScanTask
from vulnmind.persistence.unit_of_work import transaction


def skill(skill_id="sqli_workflow", version="1", content=None):
    fields = dict(skill_id=skill_id, name="SQLi workflow", version=version, target_type="web",
                  stage="analysis", path="vulnerability/sqli/workflow.md")
    if content is not None:
        metadata = SkillMetadata(**fields)
        return Skill(**fields, content=content, sha256=skill_digest(metadata, content))
    return SkillMetadata(**fields)


def chunk(identifier="c1", content="SQL injection background"):
    return KnowledgeChunk(chunk_id=identifier, document_id="doc", source="note", content=content,
                          start_offset=0, end_offset=len(content))


def memory(content="checked /api", confidence=0.8, *, project_id="project-1", task_id="task-1"):
    now = datetime.now(timezone.utc)
    return MemoryRecord(level="working", project_id=project_id, task_id=task_id,
                        content=content, confidence=confidence, created_at=now)


def budget(total=10_000):
    return ContextBudget(total=total)


def test_assembly_maps_each_source_with_a_traceable_reference():
    assembled = assemble_context(system="Be careful.", task="Audit the API.", budget=budget(),
                                 skills=[skill()], knowledge=[chunk()], memories=[memory()],
                                 project_id="project-1", task_id="task-1")
    refs = [item.ref for item in assembled.items]
    assert refs[:4] == ["system:policy", "task:current", "skill:sqli_workflow@1", "knowledge:c1"]
    assert len(refs) == 5 and refs[4].startswith("memory:")
    assert assembled.manifest["estimated_tokens"] > 0


def test_memory_confidence_drives_relevance_but_not_selection_order_priority():
    low, high = memory("low", 0.2), memory("high", 0.9)
    assembled = assemble_context(system="s", task="t", budget=budget(), memories=[low, high],
                                 project_id="project-1", task_id="task-1")
    relevance = {item.text: item.relevance for item in assembled.items if item.kind == "memory"}
    assert relevance == {"low": 0.2, "high": 0.9}


def test_budget_excludes_optional_skills_but_keeps_them_in_the_manifest():
    combined = "x" * 400
    assembled = assemble_context(system="s", task="t", budget=ContextBudget(total=500),
                                 skills=[skill("a", "1", combined), skill("b", "1", combined)])
    selected = {item.ref for item in assembled.items}
    assert "system:policy" in selected and "task:current" in selected
    assert len([ref for ref in selected if ref.startswith("skill:")]) == 1
    assert len(assembled.manifest["items"]) == 4


def test_required_context_over_budget_fails_closed():
    with pytest.raises(ContextOverflow):
        assemble_context(system="s" * 600, task="t", budget=ContextBudget(total=100))


def test_duplicate_references_are_collapsed():
    same = chunk()
    assembled = assemble_context(system="s", task="t", budget=budget(), knowledge=[same, same])
    assert len([item for item in assembled.items if item.kind == "rag"]) == 1


def test_conflicting_sources_with_same_identity_are_rejected():
    with pytest.raises(ValueError, match="conflicting context"):
        assemble_context(system="s", task="t", budget=budget(), knowledge=[chunk(content="first"), chunk(content="other")])
    with pytest.raises(ValueError, match="conflicting context"):
        assemble_context(system="s", task="t", budget=budget(), skills=[skill(content="first"), skill(content="other")])


def test_mutated_chunk_is_revalidated_before_assembly():
    item = chunk(content="original")
    item.content = "modified but offsets are stale"
    with pytest.raises(ValueError, match="offset span"):
        assemble_context(system="s", task="t", budget=budget(), knowledge=[item])


def test_loaded_skill_reference_records_integrity_hash():
    item = skill(content="Use a scoped process.")
    assembled = assemble_context(system="s", task="t", budget=budget(), skills=[item])
    expected = f"skill:{item.skill_id}@{item.version}#sha256={item.sha256}"
    assert expected in [value.ref for value in assembled.items]
    assert expected in manifest_payload(assembled, agent_name="planner")["selected_refs"]


def test_mutated_skill_is_revalidated_before_assembly():
    item = skill(content="original")
    item.tools.append("new-tool")
    with pytest.raises(ValueError, match="integrity hash"):
        assemble_context(system="s", task="t", budget=budget(), skills=[item])


def test_memory_context_requires_matching_scope_and_active_lifetime():
    record = memory()
    with pytest.raises(ValueError, match="IDs are required"):
        assemble_context(system="s", task="t", budget=budget(), memories=[record])
    for project_id, task_id in [("wrong", "task-1"), ("project-1", "wrong")]:
        with pytest.raises(ValueError, match="outside the active scope"):
            assemble_context(system="s", task="t", budget=budget(), memories=[record], project_id=project_id, task_id=task_id)
    now = datetime.now(timezone.utc)
    expired = MemoryRecord(level="working", project_id="project-1", task_id="task-1", content="old", confidence=0.5,
                           created_at=now-timedelta(hours=2), expires_at=now-timedelta(hours=1))
    with pytest.raises(ValueError, match="not valid"):
        assemble_context(system="s", task="t", budget=budget(), memories=[expired], project_id="project-1", task_id="task-1", now=now)
    invalidated = record.model_copy(update={"invalidated": True})
    with pytest.raises(ValueError, match="not valid"):
        assemble_context(system="s", task="t", budget=budget(), memories=[invalidated], project_id="project-1", task_id="task-1")


def test_manifest_payload_drops_system_prompt_and_can_be_persisted():
    engine = create_engine("sqlite://")
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    assembled = assemble_context(system="secret policy", task="audit", budget=budget(), skills=[skill()])
    payload = manifest_payload(assembled, agent_name="planner")
    assert "system:policy" not in payload["selected_refs"]
    with transaction(factory) as session:
        project = ProjectRepository(session).create("context")
        session.flush()
        scan = ScanRepository(session).create(project.id, "analysis")
        session.flush()
        task = ScanTask(id=uuid4(), scan_id=scan.id, phase="analysis", status="running")
        session.add(task)
        session.flush()
        run = AgentRun(id=uuid4(), task_id=task.id, agent_name="planner", status="succeeded")
        session.add(run)
        session.flush()
        stored = ContextManifestRepository(session).create(run_id=run.id, **payload)
        assert stored.selected_refs == ["task:current", "skill:sqli_workflow@1"]
        assert stored.token_estimate == payload["token_estimate"]
    engine.dispose()


def test_context_snapshot_is_immutable_and_manifest_mismatch_is_rejected():
    from pydantic import ValidationError

    assembled = assemble_context(system="system", task="task", budget=budget(), knowledge=[chunk()])
    assert isinstance(assembled.items, tuple)
    with pytest.raises(ValidationError):
        assembled.items[0].text = "mutated"
    assembled.manifest["estimated_tokens"] += 1
    with pytest.raises(ValueError, match="manifest is inconsistent"):
        manifest_payload(assembled, agent_name="planner")


def test_context_manifest_rejects_replaced_item_with_changed_cost():
    assembled = assemble_context(system="system", task="task", budget=budget())
    modified = assembled.model_copy(update={"items": (assembled.items[0],
                    assembled.items[1].model_copy(update={"text": "longer task"}))})
    with pytest.raises(ValueError, match="manifest is inconsistent"):
        manifest_payload(modified, agent_name="planner")
