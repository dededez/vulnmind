"""Lineage validation over injected records; PostgreSQL behavior is tested separately."""
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from vulnmind.memory.manager import MemoryRecord
from vulnmind.persistence.repositories import MemoryRepository


def test_shared_ancestor_is_not_mistaken_for_a_cycle():
    project, task = uuid4(), uuid4()
    now = datetime.now(timezone.utc)
    source = MemoryRecord(level="working", project_id=str(project), task_id=str(task),
                          content="source", confidence=0.5, created_at=now)
    left = MemoryRecord(level="working", project_id=str(project), task_id=str(task),
                        content="left", confidence=0.5, created_at=now, source_refs=(f"memory:{source.id}",))
    right = MemoryRecord(level="working", project_id=str(project), task_id=str(task),
                         content="right", confidence=0.5, created_at=now, source_refs=(f"memory:{source.id}",))
    MemoryRepository(None)._validate_active_lineage([left, right, source], project_uuid=project, timestamp=now)


def test_lineage_validation_limit_fails_closed():
    project, task = uuid4(), uuid4()
    now = datetime.now(timezone.utc)
    record = MemoryRecord(level="working", project_id=str(project), task_id=str(task),
                          content="large provenance", confidence=0.5, created_at=now,
                          source_refs=tuple(f"evidence:{index}" for index in range(1001)))
    with pytest.raises(ValueError, match="validation limit"):
        MemoryRepository(None)._validate_active_lineage([record], project_uuid=project, timestamp=now)


def test_total_reference_budget_bounds_multiple_small_records():
    project, task = uuid4(), uuid4()
    now = datetime.now(timezone.utc)
    records = [MemoryRecord(level="working", project_id=str(project), task_id=str(task),
                            content=f"record {index}", confidence=0.5, created_at=now,
                            source_refs=tuple(f"evidence:{ref}" for ref in range(1000)))
               for index in range(11)]
    with pytest.raises(ValueError, match="validation limit"):
        MemoryRepository(None)._validate_active_lineage(records, project_uuid=project, timestamp=now)


@pytest.mark.parametrize("reference", ["MEMORY:{}", " memory:{}", "memory :{}", "memory:{} "])
def test_ambiguous_memory_namespace_is_not_treated_as_opaque(reference):
    project, task = uuid4(), uuid4()
    now = datetime.now(timezone.utc)
    record = MemoryRecord(level="working", project_id=str(project), task_id=str(task), content="derived",
                          confidence=0.5, created_at=now, source_refs=(reference.format(uuid4()),))
    with pytest.raises(ValueError, match="provenance is unavailable"):
        MemoryRepository(None)._validate_active_lineage([record], project_uuid=project, timestamp=now)
