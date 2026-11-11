"""Assemble real context sources into the deterministic budgeted selection.

Sources stay typed: skills come from ``SkillLoader``, knowledge from the
retrieval layer or the database, memory from ``MemoryRecord``. Nothing here
fetches or summarises text, so the manifest can always be traced back to an
exact reference.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
import json

from pydantic import BaseModel, ConfigDict

from vulnmind.context.builder import ContextBudget, ContextItem, build_context, byte_estimate
from vulnmind.knowledge.retrieval import KnowledgeChunk
from vulnmind.knowledge.skills import Skill, SkillMetadata
from vulnmind.memory.manager import MemoryRecord


class AssembledContext(BaseModel):
    model_config = ConfigDict(frozen=True)
    items: tuple[ContextItem, ...]
    manifest: dict


def assemble_context(*, system: str, task: str, budget: ContextBudget,
                     skills: Sequence[Skill | SkillMetadata] = (),
                     knowledge: Sequence[KnowledgeChunk] = (),
                     memories: Sequence[MemoryRecord] = (), project_id: str | None = None,
                     task_id: str | None = None, now: datetime | None = None) -> AssembledContext:
    if memories and (not isinstance(project_id, str) or not project_id.strip()
                     or not isinstance(task_id, str) or not task_id.strip()):
        raise ValueError("project and task IDs are required for memory context")
    timestamp = now or datetime.now(timezone.utc)
    if timestamp.utcoffset() is None:
        raise ValueError("context time must be timezone-aware")
    items = [ContextItem(ref="system:policy", kind="system", text=system, required=True),
             ContextItem(ref="task:current", kind="task", text=task, required=True)]
    seen = {item.ref: "reserved" for item in items}

    def accept(reference: str, source: BaseModel) -> bool:
        canonical = json.dumps(source.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if reference in seen:
            if seen[reference] != canonical:
                raise ValueError("conflicting context source reference")
            return False
        seen[reference] = canonical
        return True

    for skill in skills:
        skill = (Skill if isinstance(skill, Skill) else SkillMetadata).model_validate(skill.model_dump())
        identity = f"skill:{skill.skill_id}@{skill.version}"
        if not accept(identity, skill):
            continue
        reference = f"{identity}#sha256={skill.sha256}" if isinstance(skill, Skill) else identity
        text = getattr(skill, "content", None) or f"{skill.name} ({skill.stage or 'no stage'})"
        items.append(ContextItem(ref=reference, kind="skill", text=text, relevance=0.7))
    for rank, chunk in enumerate(knowledge):
        chunk = KnowledgeChunk.model_validate(chunk.model_dump())
        reference = f"knowledge:{chunk.chunk_id}"
        if not accept(reference, chunk):
            continue
        items.append(ContextItem(ref=reference, kind="rag", text=chunk.content,
                                 relevance=max(0.0, 1.0 - rank * 0.1)))
    for record in memories:
        record = MemoryRecord.model_validate(record.model_dump())
        if (record.project_id != project_id or (record.level != "long_term" and record.task_id != task_id)
                or record.invalidated or record.created_at > timestamp
                or (record.expires_at is not None and record.expires_at <= timestamp)):
            raise ValueError("memory is outside the active scope or is not valid")
        reference = f"memory:{record.id}"
        if not accept(reference, record):
            continue
        items.append(ContextItem(ref=reference, kind="memory", text=record.content,
                                 relevance=record.confidence))
    chosen, manifest = build_context(items, budget)
    return AssembledContext(items=chosen, manifest=manifest)


def manifest_payload(assembled: AssembledContext, *, agent_name: str) -> dict:
    """Arguments for ``ContextManifestRepository.create``."""
    if not isinstance(agent_name, str) or not agent_name.strip() or len(agent_name) > 128:
        raise ValueError("agent name must contain 1 to 128 characters")
    try:
        items = [ContextItem.model_validate(item.model_dump()) for item in assembled.items]
        entries = [entry for entry in assembled.manifest["items"] if entry["selected"] is True]
        if (len(entries) != len(items) or len({item.ref for item in items}) != len(items)
                or any(entry["ref"] != item.ref or entry["kind"] != item.kind
                       or type(entry["estimated_tokens"]) is not int
                       or entry["estimated_tokens"] != byte_estimate(item.text)
                       for entry, item in zip(entries, items))
                or type(assembled.manifest["estimated_tokens"]) is not int
                or assembled.manifest["estimated_tokens"] != sum(byte_estimate(item.text) for item in items)):
            raise ValueError("context manifest is inconsistent")
    except (KeyError, TypeError, AttributeError, ValueError, UnicodeError):
        raise ValueError("context manifest is inconsistent") from None
    selected = [item.ref for item in items if item.kind != "system"]
    return {"agent_name": agent_name, "selected_refs": selected,
            "token_estimate": assembled.manifest["estimated_tokens"]}
