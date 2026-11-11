from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from vulnmind.memory.manager import InMemoryManager, MemoryRecord


def test_memory_is_scoped_expires_and_can_be_invalidated():
    now = datetime.now(timezone.utc)
    manager = InMemoryManager()
    first = MemoryRecord(level="working", project_id="p", task_id="t", content="finding", confidence=0.8, created_at=now, expires_at=now+timedelta(hours=1))
    other = MemoryRecord(level="working", project_id="p", task_id="other", content="other", confidence=0.8, created_at=now)
    manager.write(first, now=now)
    manager.write(other, now=now)
    assert manager.query(project_id="p", task_id="t", now=now) == [first]
    assert manager.query(project_id="other", task_id="t", now=now) == []
    assert manager.query(project_id="p", task_id="t", now=now+timedelta(hours=1)) == []
    manager.invalidate(first.id)
    assert manager.query(project_id="p", task_id="t", now=now) == []


def test_promotion_requires_explicit_validation_and_preserves_provenance():
    now = datetime.now(timezone.utc)
    manager = InMemoryManager()
    working = MemoryRecord(level="working", project_id="p", task_id="t", content="stable fact", source_refs=("evidence:1",), confidence=0.9, created_at=now)
    manager.write(working, now=now)
    with pytest.raises(ValidationError):
        manager.promote(working.id, validated_by=" ", now=now)
    promoted = manager.promote(working.id, validated_by="reviewer", now=now)
    assert promoted.level == "long_term"
    assert promoted.task_id is None
    assert promoted.source_refs == ("evidence:1", f"memory:{working.id}")
    assert manager.query(project_id="p", task_id="another", now=now) == [promoted]
    manager.invalidate(working.id)
    assert manager.query(project_id="p", task_id="another", now=now) == []


def test_unverified_or_expired_records_cannot_be_promoted():
    now = datetime.now(timezone.utc)
    manager = InMemoryManager()
    short = MemoryRecord(level="short_term", project_id="p", task_id="t", content="hypothesis", confidence=0.2, created_at=now)
    manager.write(short, now=now)
    with pytest.raises(ValueError):
        manager.promote(short.id, validated_by="reviewer", now=now)
    with pytest.raises(ValidationError):
        MemoryRecord(level="long_term", project_id="p", content="unverified", confidence=0.5, created_at=now)
    expired = MemoryRecord(level="working", project_id="p", task_id="t", content="stale", confidence=0.5, source_refs=("evidence:2",), created_at=now, expires_at=now+timedelta(seconds=1))
    manager.write(expired, now=now)
    with pytest.raises(ValueError):
        manager.promote(expired.id, validated_by="reviewer", now=now+timedelta(seconds=1))
    unsourced = MemoryRecord(level="working", project_id="p", task_id="t", content="unverified", confidence=0.5, created_at=now)
    manager.write(unsourced, now=now)
    with pytest.raises(ValueError):
        manager.promote(unsourced.id, validated_by="reviewer", now=now)


def test_working_memory_cannot_be_promoted_before_its_creation():
    now = datetime.now(timezone.utc)
    manager = InMemoryManager()
    record = MemoryRecord(level="working", project_id="p", task_id="t", content="fact",
                          source_refs=("evidence:1",), confidence=0.5, created_at=now)
    manager.write(record, now=now)
    with pytest.raises(ValueError, match="active"):
        manager.promote(record.id, validated_by="reviewer", now=now-timedelta(seconds=1))


def test_invalidation_does_not_cross_project_boundaries():
    now = datetime.now(timezone.utc)
    manager = InMemoryManager()
    original = MemoryRecord(level="working", project_id="first", task_id="t1", content="source", confidence=0.5, created_at=now)
    unrelated = MemoryRecord(level="working", project_id="second", task_id="t2", content="other project", confidence=0.5,
                             created_at=now, source_refs=("evidence:other",))
    cross_project = MemoryRecord(level="working", project_id="second", task_id="t2", content="bad source", confidence=0.5,
                                 created_at=now, source_refs=(f"memory:{original.id}",))
    manager.write(original, now=now)
    with pytest.raises(ValueError, match="provenance is unavailable"):
        manager.write(cross_project, now=now)
    manager.write(unrelated, now=now)
    manager.invalidate(original.id)
    assert manager.query(project_id="second", task_id="t2", now=now) == [unrelated]


def test_inmemory_rejects_missing_cross_task_and_expired_sources():
    from uuid import uuid4
    now = datetime.now(timezone.utc)
    manager = InMemoryManager()
    source = MemoryRecord(level="working", project_id="p", task_id="t1", content="source", confidence=0.5,
                          created_at=now, expires_at=now + timedelta(seconds=1))
    manager.write(source, now=now)
    for reference, task, timestamp in ((f"memory:{uuid4()}", "t1", now),
                                       (f"memory:{source.id}", "t2", now),
                                       (f"memory:{source.id}", "t1", now + timedelta(seconds=1)),
                                       (f"MEMORY:{source.id}", "t1", now)):
        candidate = MemoryRecord(level="working", project_id="p", task_id=task, content="derived",
                                 confidence=0.5, created_at=now, source_refs=(reference,))
        with pytest.raises(ValueError, match="provenance is unavailable"):
            manager.write(candidate, now=timestamp)


def test_inmemory_expired_ancestor_blocks_derived_query():
    now = datetime.now(timezone.utc)
    manager = InMemoryManager()
    source = MemoryRecord(level="working", project_id="p", task_id="t", content="source", confidence=0.5,
                          created_at=now, expires_at=now + timedelta(seconds=1))
    child = MemoryRecord(level="working", project_id="p", task_id="t", content="child", confidence=0.5,
                         created_at=now, source_refs=(f"memory:{source.id}",))
    manager.write(source, now=now)
    manager.write(child, now=now)
    with pytest.raises(ValueError, match="provenance is unavailable"):
        manager.query(project_id="p", task_id="t", now=now + timedelta(seconds=1))


def test_inmemory_invalidation_budget_does_not_partially_mutate(monkeypatch):
    import vulnmind.memory.manager as memory_module
    now = datetime.now(timezone.utc)
    manager = InMemoryManager()
    first = MemoryRecord(level="working", project_id="p", task_id="t", content="first", confidence=0.5,
                         created_at=now, source_refs=("evidence:a",))
    second = MemoryRecord(level="working", project_id="p", task_id="t", content="second", confidence=0.5,
                          created_at=now, source_refs=("evidence:b",))
    manager.write(first, now=now)
    manager.write(second, now=now)
    with monkeypatch.context() as patcher:
        patcher.setattr(memory_module, "MAX_MEMORY_LINEAGE_REFS", 1)
        with pytest.raises(ValueError, match="invalidation exceeds"):
            manager.invalidate(first.id)
    assert {item.id for item in manager.query(project_id="p", task_id="t", now=now)} == {first.id, second.id}
