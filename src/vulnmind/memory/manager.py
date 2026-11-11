"""Process-local memory prototype; not a replacement for durable storage."""
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_MEMORY_LINEAGE_RECORDS = 5000
MAX_MEMORY_REFS_PER_RECORD = 1000
MAX_MEMORY_LINEAGE_REFS = 10_000


def parse_memory_reference(reference: str) -> UUID | None:
    """Parse the reserved memory namespace; other source types stay opaque."""
    prefix, separator, raw_id = reference.partition(":")
    if not separator or prefix.strip().casefold() != "memory":
        return None
    if prefix != "memory" or reference != reference.strip():
        raise ValueError("memory provenance is unavailable")
    try:
        identifier = UUID(raw_id)
    except (ValueError, TypeError, AttributeError):
        raise ValueError("memory provenance is unavailable") from None
    if str(identifier) != raw_id:
        raise ValueError("memory provenance is unavailable")
    return identifier


class MemoryRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: UUID = Field(default_factory=uuid4)
    level: Literal["short_term", "working", "long_term"]
    project_id: str = Field(min_length=1)
    task_id: str | None = None
    content: str = Field(min_length=1)
    source_refs: tuple[str, ...] = ()
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    validated_by: str | None = None
    invalidated: bool = False

    @field_validator("project_id", "content")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("memory project and content cannot be blank")
        return value

    @model_validator(mode="after")
    def validate_scope_and_provenance(self):
        if self.created_at.utcoffset() is None or (self.expires_at is not None and self.expires_at.utcoffset() is None):
            raise ValueError("memory timestamps must be timezone-aware")
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise ValueError("memory expiry must follow creation")
        if any(not ref.strip() for ref in self.source_refs):
            raise ValueError("memory source references cannot be blank")
        if self.level in {"short_term", "working"} and (self.task_id is None or not self.task_id.strip()):
            raise ValueError("task-scoped memory requires a task ID")
        if self.level == "long_term" and (self.task_id is not None or not self.source_refs or not self.validated_by or not self.validated_by.strip()):
            raise ValueError("long-term memory requires validation, sources, and project scope")
        return self


class InMemoryManager:
    """Non-thread-safe, process-local store for tests and local experiments."""
    def __init__(self):
        self._records: dict[UUID, MemoryRecord] = {}

    def write(self, record: MemoryRecord, *, now: datetime | None = None) -> None:
        record = MemoryRecord.model_validate(record.model_dump())
        timestamp = _time(now)
        if (record.id in self._records or record.invalidated or record.created_at > timestamp
                or (record.expires_at is not None and record.expires_at <= timestamp)):
            raise ValueError("memory is duplicate, invalidated, future-dated, or expired")
        self._validate_lineage([record], timestamp=timestamp)
        self._records[record.id] = record

    def query(self, *, project_id: str, task_id: str, now: datetime | None = None) -> list[MemoryRecord]:
        if not project_id.strip() or not task_id.strip():
            raise ValueError("project and task IDs are required")
        timestamp = _time(now)
        records = []
        for record in self._records.values():
            if (record.project_id != project_id or record.invalidated or record.created_at > timestamp
                    or (record.expires_at is not None and timestamp >= record.expires_at)
                    or (record.level != "long_term" and record.task_id != task_id)):
                continue
            if len(records) >= MAX_MEMORY_LINEAGE_RECORDS:
                raise ValueError("active memory exceeds the validation limit")
            records.append(record)
        self._validate_lineage(records, timestamp=timestamp)
        return records

    def _validate_lineage(self, roots: list[MemoryRecord], *, timestamp: datetime) -> None:
        cache = {record.id: record for record in roots}
        state: dict[UUID, int] = {}
        references_checked = 0
        for root in roots:
            pending: list[tuple[MemoryRecord, bool]] = [(root, False)]
            while pending:
                record, exiting = pending.pop()
                if exiting:
                    state[record.id] = 2
                    continue
                if state.get(record.id) == 1:
                    raise ValueError("memory provenance is cyclic")
                if state.get(record.id) == 2:
                    continue
                references_checked += len(record.source_refs)
                if (len(state) >= MAX_MEMORY_LINEAGE_RECORDS
                        or len(record.source_refs) > MAX_MEMORY_REFS_PER_RECORD
                        or references_checked > MAX_MEMORY_LINEAGE_REFS):
                    raise ValueError("memory provenance exceeds the validation limit")
                state[record.id] = 1
                pending.append((record, True))
                for reference in reversed(record.source_refs):
                    source_id = parse_memory_reference(reference)
                    if source_id is None:
                        continue
                    source = cache.get(source_id) or self._records.get(source_id)
                    if (source is None or source.project_id != record.project_id or source.invalidated
                            or source.created_at > timestamp
                            or (source.expires_at is not None and source.expires_at <= timestamp)
                            or (record.level != "long_term" and source.level != "long_term"
                                and record.task_id != source.task_id)):
                        raise ValueError("memory provenance is unavailable")
                    pending.append((source, False))

    def invalidate(self, record_id: UUID) -> None:
        if record_id not in self._records:
            raise KeyError(record_id)
        project_id = self._records[record_id].project_id
        records = []
        for record in self._records.values():
            if record.project_id == project_id:
                if len(records) >= MAX_MEMORY_LINEAGE_RECORDS:
                    raise ValueError("memory invalidation exceeds the validation limit")
                records.append(record)
        dependents: dict[UUID, list[UUID]] = {}
        references_checked = 0
        for record in records:
            references_checked += len(record.source_refs)
            if (len(record.source_refs) > MAX_MEMORY_REFS_PER_RECORD
                    or references_checked > MAX_MEMORY_LINEAGE_REFS):
                raise ValueError("memory invalidation exceeds the validation limit")
            for reference in record.source_refs:
                source_id = parse_memory_reference(reference)
                if source_id is not None:
                    dependents.setdefault(source_id, []).append(record.id)
        pending = [record_id]
        seen: set[UUID] = set()
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            self._records[current] = self._records[current].model_copy(update={"invalidated": True})
            pending.extend(item_id for item_id in dependents.get(current, ()) if item_id not in seen)

    def promote(self, record_id: UUID, *, validated_by: str, now: datetime | None = None,
                expires_at: datetime | None = None) -> MemoryRecord:
        timestamp = _time(now)
        record = self._records.get(record_id)
        if (record is None or record.level != "working" or record.invalidated or not record.source_refs
                or record.created_at > timestamp
                or (record.expires_at is not None and record.expires_at <= timestamp)):
            raise ValueError("only active, sourced working memory can be promoted")
        promoted = MemoryRecord(level="long_term", project_id=record.project_id, content=record.content,
                                source_refs=(*record.source_refs, f"memory:{record.id}"), confidence=record.confidence,
                                created_at=timestamp, expires_at=expires_at, validated_by=validated_by)
        self.write(promoted, now=timestamp)
        return promoted


def _time(now: datetime | None) -> datetime:
    timestamp = now or datetime.now(timezone.utc)
    if timestamp.utcoffset() is None:
        raise ValueError("current time must be timezone-aware")
    return timestamp
