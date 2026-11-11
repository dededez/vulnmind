"""Minimal persistence interfaces. The caller owns the surrounding transaction."""
from collections.abc import Sequence
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import delete, func, literal_column, or_, select, text
from sqlalchemy.orm import Session

from vulnmind.knowledge.vector import MAX_FLOAT32, MIN_COSINE_NORM, validate_vector
from vulnmind.memory.manager import (MAX_MEMORY_LINEAGE_RECORDS, MAX_MEMORY_LINEAGE_REFS,
                                     MAX_MEMORY_REFS_PER_RECORD, MemoryRecord, parse_memory_reference)
from vulnmind.persistence.models import (
    ContextManifestRecord, Evidence, Finding, FindingFeedback, KnowledgeChunk, KnowledgeDocument,
    MemoryRecordRow, Project, Report, Scan, ScanTask, ScopeRecord, SkillRecord, TargetRecord, WebEndpoint,
)
from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import check_target


class ProjectRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, name: str, description: str | None = None) -> Project:
        if not name.strip() or len(name) > 255:
            raise ValueError("project name must contain 1 to 255 characters")
        row = Project(id=uuid4(), name=name, description=description)
        self.session.add(row)
        return row

    def get(self, project_id: UUID) -> Project | None:
        return self.session.get(Project, project_id)


class TargetRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, project_id: UUID, target: Target) -> TargetRecord:
        row = TargetRecord(id=uuid4(), project_id=project_id, target_type=target.type.value, locator=target.locator)
        self.session.add(row)
        return row

    def get(self, target_id: UUID) -> TargetRecord | None:
        return self.session.get(TargetRecord, target_id)


class ScopeRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, target_id: UUID, authorization: Authorization) -> ScopeRecord:
        # Preserve every authorization field, including per-origin path rules.
        snapshot = Authorization.model_validate(authorization.model_dump()).model_dump(mode="python")
        row = ScopeRecord(
            id=uuid4(), target_id=target_id,
            allowlist={"repository_roots": snapshot["repository_roots"], "web_origins": snapshot["web_origins"],
                       "allowed_web_paths": snapshot["allowed_web_paths"], "allowed_ip_networks": snapshot["allowed_ip_networks"]},
            denylist={"denied_repository_roots": snapshot["denied_repository_roots"],
                      "denied_web_origins": snapshot["denied_web_origins"],
                      "denied_web_paths": snapshot["denied_web_paths"], "denied_ip_networks": snapshot["denied_ip_networks"]},
            starts_at=snapshot["starts_at"], expires_at=snapshot["expires_at"],
            approved_by=snapshot["approved_by"], authorization_source=snapshot["authorization_source"],
        )
        self.session.add(row)
        return row

    def get(self, scope_id: UUID) -> ScopeRecord | None:
        return self.session.get(ScopeRecord, scope_id)

    def load_authorization(self, scope_id: UUID, *, target_id: UUID) -> Authorization:
        row = self.get(scope_id)
        if row is None or row.target_id != target_id:
            raise ValueError("scope is absent or belongs to a different target")
        allow_keys = {"repository_roots", "web_origins", "allowed_web_paths", "allowed_ip_networks"}
        deny_keys = {"denied_repository_roots", "denied_web_origins", "denied_web_paths", "denied_ip_networks"}
        if not isinstance(row.allowlist, dict) or set(row.allowlist) != allow_keys:
            raise ValueError("unsupported or incomplete stored allowlist")
        if not isinstance(row.denylist, dict) or set(row.denylist) != deny_keys:
            raise ValueError("unsupported or incomplete stored denylist")
        return Authorization.model_validate({**row.allowlist, **row.denylist,
            "starts_at": row.starts_at, "expires_at": row.expires_at,
            "approved_by": row.approved_by, "authorization_source": row.authorization_source})

    def load_for_scan(self, scope_id: UUID, *, target_id: UUID, scan_id: UUID,
                      now: datetime | None = None) -> tuple[Target, Authorization]:
        """Load the stored target and policy for a scan in the same project.

        This validates database associations and current scope only. It does not
        authenticate an actor, prevent database tampering, or detect later policy
        changes; callers must recheck before any side effect.
        """
        scan = self.session.get(Scan, scan_id)
        target_row = self.session.get(TargetRecord, target_id)
        if scan is None or target_row is None or scan.project_id != target_row.project_id:
            raise ValueError("scan and target must belong to the same project")
        authorization = self.load_authorization(scope_id, target_id=target_id)
        target = Target(type=target_row.target_type, locator=target_row.locator)
        check_target(target, authorization, now=now)
        return target, authorization


class ScanRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, project_id: UUID, mode: str) -> Scan:
        if not mode.strip() or len(mode) > 32:
            raise ValueError("scan mode must contain 1 to 32 characters")
        row = Scan(id=uuid4(), project_id=project_id, status="created", mode=mode)
        self.session.add(row)
        return row

    def get(self, scan_id: UUID) -> Scan | None:
        return self.session.get(Scan, scan_id)

    def list_for_project(self, project_id: UUID, *, limit: int = 50) -> list[Scan]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("scan limit must be between 1 and 500")
        statement = (select(Scan).where(Scan.project_id == project_id)
                     .order_by(Scan.started_at.desc().nullslast(), Scan.id).limit(limit))
        return list(self.session.scalars(statement))


class KnowledgeRepository:
    """Document/chunk storage. Sparse search runs only on PostgreSQL."""

    def __init__(self, session: Session):
        self.session = session

    def create_document(self, *, title: str, source_type: str, source_url: str | None = None,
                        version: str | None = None, trust_level: str | None = None,
                        metadata: dict | list | None = None, document_id: UUID | None = None) -> KnowledgeDocument:
        if not title.strip() or len(title) > 1000:
            raise ValueError("document title must contain 1 to 1000 characters")
        if not source_type.strip() or len(source_type) > 32:
            raise ValueError("document source type must contain 1 to 32 characters")
        if document_id is not None and not isinstance(document_id, UUID):
            raise ValueError("document ID must be a UUID")
        row = KnowledgeDocument(id=document_id or uuid4(), title=title, source_type=source_type, source_url=source_url,
                                version=version, trust_level=trust_level, metadata_=metadata)
        self.session.add(row)
        return row

    def add_chunks(self, document_id: UUID, chunks: Sequence[tuple[int, str]],
                   *, metadata: dict | list | None = None,
                   chunk_metadata: Sequence[dict] | None = None) -> list[KnowledgeChunk]:
        if self.session.get(KnowledgeDocument, document_id) is None:
            raise ValueError("document is not stored")
        if not chunks:
            return []
        indices = [index for index, _ in chunks]
        if any(index < 0 for index in indices) or len(set(indices)) != len(indices):
            raise ValueError("chunk indices must be unique and non-negative")
        if any(not content.strip() for _, content in chunks):
            raise ValueError("chunk content cannot be blank")
        if chunk_metadata is not None and len(chunk_metadata) != len(chunks):
            raise ValueError("per-chunk metadata must match the chunk count")
        rows = [KnowledgeChunk(id=uuid4(), document_id=document_id, chunk_index=index,
                               content=content,
                               metadata_=chunk_metadata[position] if chunk_metadata is not None else metadata)
                for position, (index, content) in enumerate(chunks)]
        if self.session.get_bind().dialect.name == "postgresql":
            config = literal_column("'pg_catalog.simple'::pg_catalog.regconfig")
            for row in rows:
                row.tsvector = func.to_tsvector(config, row.content)
        self.session.add_all(rows)
        return rows

    def get_document(self, document_id: UUID) -> KnowledgeDocument | None:
        return self.session.get(KnowledgeDocument, document_id)

    def list_chunks(self, document_id: UUID) -> list[KnowledgeChunk]:
        statement = select(KnowledgeChunk).where(KnowledgeChunk.document_id == document_id).order_by(KnowledgeChunk.chunk_index)
        return list(self.session.scalars(statement))

    def search_chunks(self, query: str, *, limit: int = 10,
                      filters: dict[str, str] | None = None) -> list[KnowledgeChunk]:
        """PostgreSQL full-text search; raises on other dialects."""
        statement = build_sparse_statement(query, limit=limit, filters=filters)
        if self.session.get_bind().dialect.name != "postgresql":
            raise ValueError("sparse knowledge search requires PostgreSQL")
        return list(self.session.scalars(statement))

    def set_embedding(self, chunk_id: UUID, values: Sequence[float]) -> None:
        """Store a dense vector; requires PostgreSQL with the vector extension."""
        if self.session.get_bind().dialect.name != "postgresql":
            raise ValueError("dense embeddings require PostgreSQL with pgvector")
        vector = validate_vector(values)
        row = self.session.get(KnowledgeChunk, chunk_id)
        if row is None:
            raise ValueError("chunk is not stored")
        if isinstance(row.metadata_, dict) and "embedding_provenance_v1" in row.metadata_:
            raise ValueError("provenance-tagged embeddings require the provenance-aware backfill")
        row.embedding = vector

    def dense_search(self, values: Sequence[float], *, limit: int = 10,
                     filters: dict[str, str] | None = None) -> list[KnowledgeChunk]:
        """Cosine-distance search over stored embeddings; PostgreSQL only."""
        if self.session.get_bind().dialect.name != "postgresql":
            raise ValueError("dense knowledge search requires PostgreSQL with pgvector")
        return list(self.session.scalars(build_dense_statement(values, limit=limit, filters=filters)))


def validate_knowledge_filters(filters: dict[str, str] | None) -> dict[str, str]:
    columns = _knowledge_filter_columns()
    if filters is None:
        return {}
    if not isinstance(filters, dict) or set(filters) - set(columns) or any(
        not isinstance(value, str) or not value.strip() or len(value) > 255 for value in filters.values()
    ):
        raise ValueError("unsupported or invalid metadata filter")
    return dict(filters)


def _knowledge_filter_columns() -> dict:
    return {"source": func.coalesce(func.nullif(KnowledgeDocument.source_url, ""), KnowledgeDocument.title),
            "source_type": KnowledgeDocument.source_type, "version": KnowledgeDocument.version,
            "trust_level": KnowledgeDocument.trust_level,
            "vulnerability_type": KnowledgeChunk.metadata_["vulnerability_type"].astext,
            "language": KnowledgeChunk.metadata_["language"].astext,
            "framework": KnowledgeChunk.metadata_["framework"].astext}


def build_dense_statement(values: Sequence[float], *, limit: int = 10,
                          filters: dict[str, str] | None = None):
    """Build filtered pgvector search; metadata filtering precedes the limit."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("search limit must be between 1 and 100")
    selected = validate_knowledge_filters(filters)
    vector = validate_vector(values)
    statement = (select(KnowledgeChunk).join(KnowledgeDocument, KnowledgeDocument.id == KnowledgeChunk.document_id)
                 .where(KnowledgeChunk.embedding.is_not(None))
                 # Legacy or externally inserted vectors bypass write validation.
                 .where(func.vector_norm(KnowledgeChunk.embedding) >= MIN_COSINE_NORM)
                 .where(func.vector_norm(KnowledgeChunk.embedding) <= (MAX_FLOAT32 / 2) ** 0.5))
    columns = _knowledge_filter_columns()
    for name, value in selected.items():
        statement = statement.where(columns[name] == value)
    return statement.order_by(KnowledgeChunk.embedding.cosine_distance(vector), KnowledgeChunk.document_id,
                              KnowledgeChunk.chunk_index, KnowledgeChunk.id).limit(limit)


def build_sparse_statement(query: str, *, limit: int = 10, filters: dict[str, str] | None = None):
    """Build a parameterized query using the indexed stored tsvector."""
    if not isinstance(query, str) or not query.strip() or len(query) > 4096:
        raise ValueError("search query must contain 1 to 4096 characters")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("search limit must be between 1 and 100")
    filters = validate_knowledge_filters(filters)
    filter_columns = _knowledge_filter_columns()
    tsquery = func.plainto_tsquery(literal_column("'pg_catalog.simple'::pg_catalog.regconfig"), query)
    vector = KnowledgeChunk.tsvector
    statement = select(KnowledgeChunk).join(KnowledgeDocument, KnowledgeDocument.id == KnowledgeChunk.document_id)
    statement = statement.where(vector.bool_op("@@")(tsquery))
    for name, value in filters.items():
        statement = statement.where(filter_columns[name] == value)
    return statement.order_by(func.pg_catalog.ts_rank(vector, tsquery).desc(), KnowledgeChunk.document_id,
                              KnowledgeChunk.chunk_index, KnowledgeChunk.id).limit(limit)


class SkillRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, *, name: str, version: str, content_uri: str, target_type: str | None = None,
               vuln_type: str | None = None, stage: str | None = None,
               metadata: dict | list | None = None) -> SkillRecord:
        if not name.strip() or len(name) > 255:
            raise ValueError("skill name must contain 1 to 255 characters")
        if not version.strip() or len(version) > 64:
            raise ValueError("skill version must contain 1 to 64 characters")
        if not content_uri.strip():
            raise ValueError("skill content URI cannot be blank")
        row = SkillRecord(id=uuid4(), name=name, version=version, content_uri=content_uri,
                          target_type=target_type, vuln_type=vuln_type, stage=stage, metadata_=metadata)
        self.session.add(row)
        return row

    def get(self, skill_id: UUID) -> SkillRecord | None:
        return self.session.get(SkillRecord, skill_id)

    def list_skills(self, *, target_type: str | None = None, vuln_type: str | None = None,
                    stage: str | None = None) -> list[SkillRecord]:
        statement = select(SkillRecord)
        if target_type is not None:
            statement = statement.where(SkillRecord.target_type == target_type)
        if vuln_type is not None:
            statement = statement.where(SkillRecord.vuln_type == vuln_type)
        if stage is not None:
            statement = statement.where(SkillRecord.stage == stage)
        return list(self.session.scalars(statement.order_by(SkillRecord.name, SkillRecord.version)))


class MemoryRepository:
    """Durable three-level memory; validation stays in ``vulnmind.memory``."""

    def __init__(self, session: Session):
        self.session = session

    def _lock_project_writes(self, project_id: UUID) -> None:
        """Serialize cooperating memory writers until the transaction ends."""
        dialect = self.session.get_bind().dialect.name
        if dialect == "postgresql":
            isolation = self.session.execute(text("SHOW transaction_isolation")).scalar_one()
            if isolation.lower() != "read committed":
                raise ValueError("PostgreSQL memory writes require read committed isolation")
            locked = self.session.scalar(select(Project.id).where(Project.id == project_id).with_for_update())
            if locked is None:
                raise ValueError("memory project is unavailable")
        elif dialect == "sqlite":
            # A no-op UPDATE acquires SQLite's writer lock before validation.
            self.session.execute(text("UPDATE memory_records SET id = id WHERE 1 = 0"))
        else:
            raise ValueError("memory writes are unavailable for this database")

    def save(self, record: MemoryRecord) -> MemoryRecordRow:
        if not isinstance(record, MemoryRecord):
            raise ValueError("memory record is required")
        record = MemoryRecord.model_validate(record.model_dump())
        project_id = _as_uuid(record.project_id, "project")
        task_id = _as_uuid(record.task_id, "task") if record.task_id is not None else None
        if not self.session.autoflush and (self.session.new or self.session.dirty or self.session.deleted):
            raise ValueError("memory save cannot validate unflushed session changes")
        self._lock_project_writes(project_id)
        if task_id is not None:
            self._require_task_in_project(project_id, task_id)
        if self.session.get(MemoryRecordRow, record.id) is not None:
            raise ValueError("memory record already stored")
        if len(record.source_refs) > MAX_MEMORY_REFS_PER_RECORD:
            raise ValueError("memory provenance exceeds the validation limit")
        memory_ids = [source_id for reference in record.source_refs
                      if (source_id := parse_memory_reference(reference)) is not None]
        for source_id in dict.fromkeys(memory_ids):
            if source_id == record.id:
                raise ValueError("memory provenance is unavailable")
            query = select(MemoryRecordRow.id).where(
                MemoryRecordRow.id == source_id, MemoryRecordRow.project_id == project_id,
                MemoryRecordRow.invalidated.is_(False))
            if record.level != "long_term":
                query = query.where(or_(MemoryRecordRow.level == "long_term", MemoryRecordRow.task_id == task_id))
            if self.session.scalar(query) is None:
                raise ValueError("memory provenance is unavailable")
        if memory_ids and self.session.get_bind().dialect.name == "postgresql":
            # PostgreSQL preserves aware timestamps; validate the full active
            # chain while holding the cooperating writer lock. SQLite's naive
            # timestamp round-trip remains fail-closed at read time instead.
            self._validate_active_lineage([record], project_uuid=project_id, timestamp=_current_time(None))
        row = MemoryRecordRow(
            id=record.id, level=record.level, project_id=project_id, task_id=task_id,
            content=record.content, source_refs=list(record.source_refs), confidence=record.confidence,
            validated_by=record.validated_by, invalidated=record.invalidated,
            created_at=record.created_at, expires_at=record.expires_at)
        self.session.add(row)
        return row

    def get(self, record_id: UUID) -> MemoryRecord | None:
        row = self.session.get(MemoryRecordRow, record_id)
        return None if row is None else self._to_record(row)

    def query_active(self, *, project_id: str, task_id: str, now: datetime | None = None) -> list[MemoryRecord]:
        if not str(project_id).strip() or not str(task_id).strip():
            raise ValueError("project and task IDs are required")
        if not self.session.autoflush and (self.session.new or self.session.dirty or self.session.deleted):
            raise ValueError("memory query cannot refresh a session with unflushed changes")
        timestamp = _current_time(now)
        project_uuid = _as_uuid(project_id, "project")
        task_uuid = _as_uuid(task_id, "task")
        self._require_task_in_project(project_uuid, task_uuid)
        statement = select(MemoryRecordRow).where(
            MemoryRecordRow.project_id == project_uuid,
            MemoryRecordRow.invalidated.is_(False),
            MemoryRecordRow.created_at <= timestamp,
            or_(MemoryRecordRow.expires_at.is_(None), MemoryRecordRow.expires_at > timestamp),
            or_(MemoryRecordRow.level == "long_term", MemoryRecordRow.task_id == task_uuid))
        rows = list(self.session.scalars(statement.order_by(MemoryRecordRow.id).limit(MAX_MEMORY_LINEAGE_RECORDS + 1)
                                         .execution_options(populate_existing=True)))
        if len(rows) > MAX_MEMORY_LINEAGE_RECORDS:
            raise ValueError("active memory exceeds the validation limit")
        records = [self._to_record(row) for row in rows]
        self._validate_active_lineage(records, project_uuid=project_uuid, timestamp=timestamp)
        return records

    def _validate_active_lineage(self, roots: list[MemoryRecord], *, project_uuid: UUID,
                                 timestamp: datetime) -> None:
        """Fail closed on missing, stale, cross-scope or cyclic memory sources.

        This is a read-time check, not a cross-transaction revocation lock.
        Other source types are opaque and are not authenticated here.
        """
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
                    source = cache.get(source_id)
                    if source is None:
                        query = select(MemoryRecordRow).where(
                            MemoryRecordRow.id == source_id, MemoryRecordRow.project_id == project_uuid)
                        if record.level != "long_term":
                            query = query.where(or_(MemoryRecordRow.level == "long_term",
                                                    MemoryRecordRow.task_id == _as_uuid(record.task_id, "task")))
                        row = self.session.scalar(query.execution_options(populate_existing=True))
                        if row is None:
                            raise ValueError("memory provenance is unavailable")
                        try:
                            source = self._to_record(row)
                        except (ValueError, TypeError):
                            raise ValueError("memory provenance is unavailable") from None
                        cache[source_id] = source
                    if (source.project_id != str(project_uuid) or source.invalidated
                            or source.created_at > timestamp
                            or (source.expires_at is not None and source.expires_at <= timestamp)
                            or (record.level != "long_term" and source.level != "long_term"
                                and record.task_id != source.task_id)):
                        raise ValueError("memory provenance is unavailable")
                    pending.append((source, False))

    def _require_task_in_project(self, project_id: UUID, task_id: UUID) -> None:
        task_project = self.session.scalar(select(Scan.project_id).join(ScanTask, ScanTask.scan_id == Scan.id)
                                           .where(ScanTask.id == task_id))
        if task_project != project_id:
            raise ValueError("task does not belong to the requested project")

    def invalidate(self, record_id: UUID) -> None:
        """Mark a record and everything citing ``memory:<id>`` as invalidated."""
        if not self.session.autoflush and (self.session.new or self.session.dirty or self.session.deleted):
            raise ValueError("memory invalidation cannot refresh unflushed session changes")
        target = self.session.get(MemoryRecordRow, record_id)
        if target is None:
            raise KeyError(record_id)
        project_id = target.project_id
        self._lock_project_writes(project_id)
        rows = list(self.session.scalars(select(MemoryRecordRow).where(MemoryRecordRow.project_id == project_id)
                                         .order_by(MemoryRecordRow.id).limit(MAX_MEMORY_LINEAGE_RECORDS + 1)
                                         .execution_options(populate_existing=True)))
        if len(rows) > MAX_MEMORY_LINEAGE_RECORDS:
            raise ValueError("memory invalidation exceeds the validation limit")
        by_id = {row.id: row for row in rows}
        if record_id not in by_id:
            raise KeyError(record_id)
        dependents: dict[str, list[UUID]] = {}
        references_checked = 0
        for row in rows:
            references = row.source_refs if row.source_refs is not None else []
            if (not isinstance(references, (list, tuple)) or len(references) > MAX_MEMORY_REFS_PER_RECORD
                    or any(not isinstance(ref, str) for ref in references)):
                raise ValueError("memory invalidation provenance is invalid")
            references_checked += len(references)
            if references_checked > MAX_MEMORY_LINEAGE_REFS:
                raise ValueError("memory invalidation exceeds the validation limit")
            for reference in references:
                source_id = parse_memory_reference(reference)
                if source_id is not None:
                    dependents.setdefault(f"memory:{source_id}", []).append(row.id)
        pending, seen = [record_id], set()
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            row = by_id.get(current)
            if row is None:
                continue
            row.invalidated = True
            reference = f"memory:{current}"
            pending.extend(item_id for item_id in dependents.get(reference, ()) if item_id not in seen)

    @staticmethod
    def _to_record(row: MemoryRecordRow) -> MemoryRecord:
        if row.source_refs is not None and not isinstance(row.source_refs, (list, tuple)):
            raise ValueError("memory source references are invalid")
        return MemoryRecord.model_validate({
            "id": row.id, "level": row.level, "project_id": str(row.project_id),
            "task_id": None if row.task_id is None else str(row.task_id), "content": row.content,
            "source_refs": tuple(row.source_refs or ()), "confidence": row.confidence,
            "created_at": row.created_at, "expires_at": row.expires_at,
            "validated_by": row.validated_by, "invalidated": row.invalidated})


class ContextManifestRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, *, run_id: UUID, agent_name: str, selected_refs: list | dict,
               token_estimate: int) -> ContextManifestRecord:
        if not agent_name.strip() or len(agent_name) > 128:
            raise ValueError("agent name must contain 1 to 128 characters")
        if not isinstance(selected_refs, (list, dict)):
            raise ValueError("selected references must be a list or mapping")
        if token_estimate < 0:
            raise ValueError("token estimate cannot be negative")
        row = ContextManifestRecord(id=uuid4(), run_id=run_id, agent_name=agent_name,
                                    selected_refs=selected_refs, token_estimate=token_estimate)
        self.session.add(row)
        return row

    def get(self, manifest_id: UUID) -> ContextManifestRecord | None:
        return self.session.get(ContextManifestRecord, manifest_id)

    def list_for_run(self, run_id: UUID) -> list[ContextManifestRecord]:
        statement = select(ContextManifestRecord).where(ContextManifestRecord.run_id == run_id).order_by(
            ContextManifestRecord.created_at)
        return list(self.session.scalars(statement))


class EvidenceRepository:
    """Links stored evidence bytes to a finding; the bytes live elsewhere."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, finding_id: UUID, *, evidence_type: str, locator: str, content_ref: str,
               hash: str | None = None) -> Evidence:
        if not evidence_type.strip() or len(evidence_type) > 64:
            raise ValueError("evidence type must contain 1 to 64 characters")
        if not locator.strip():
            raise ValueError("evidence locator cannot be blank")
        if not content_ref.strip():
            raise ValueError("evidence reference cannot be blank")
        if hash is not None and (len(hash) != 64 or any(character not in "0123456789abcdef" for character in hash)):
            raise ValueError("evidence hash must be a lowercase SHA-256 hex digest")
        from vulnmind.evidence.coordination import lock_evidence_transaction
        lock_evidence_transaction(self.session)
        row = Evidence(id=uuid4(), finding_id=finding_id, evidence_type=evidence_type,
                       locator=locator, content_ref=content_ref, hash=hash)
        self.session.add(row)
        return row

    def list_for_finding(self, finding_id: UUID) -> list[Evidence]:
        statement = select(Evidence).where(Evidence.finding_id == finding_id).order_by(Evidence.collected_at)
        return list(self.session.scalars(statement))


class ReportRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, scan_id: UUID, *, format: str, storage_uri: str) -> Report:
        if not format.strip() or len(format) > 32:
            raise ValueError("report format must contain 1 to 32 characters")
        if not storage_uri.strip():
            raise ValueError("report storage URI cannot be blank")
        # Client-side timestamp keeps sub-second ordering, so a regenerated
        # report is not confused with an earlier one written in the same second.
        row = Report(id=uuid4(), scan_id=scan_id, format=format, storage_uri=storage_uri,
                     created_at=datetime.now(timezone.utc))
        self.session.add(row)
        return row

    def get(self, report_id: UUID) -> Report | None:
        return self.session.get(Report, report_id)

    def list_for_scan(self, scan_id: UUID) -> list[Report]:
        statement = select(Report).where(Report.scan_id == scan_id).order_by(Report.created_at)
        return list(self.session.scalars(statement))


class WebEndpointRepository:
    """Store crawl observations per scan; rows are not validation results."""

    MAX_URL_CHARS = 2048
    MAX_STATUS_CHARS = 32

    def __init__(self, session: Session):
        self.session = session

    def replace_for_scan(self, scan_id: UUID, project_id: UUID, endpoints: Sequence[dict],
                         *, status: str = "discovered") -> list[WebEndpoint]:
        scan = self.session.get(Scan, scan_id)
        if scan is None or scan.project_id != project_id:
            raise ValueError("scan and project do not match the stored scan")
        if not isinstance(status, str) or not status.strip() or len(status) > self.MAX_STATUS_CHARS:
            raise ValueError("endpoint status must contain 1 to 32 characters")
        rows = self._validated(scan_id, project_id, endpoints, status)
        self.session.execute(delete(WebEndpoint).where(WebEndpoint.scan_id == scan_id))
        self.session.add_all(rows)
        self.session.flush()
        return rows

    def list_for_scan(self, scan_id: UUID, *, limit: int = 500) -> list[WebEndpoint]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 2000:
            raise ValueError("limit must be between 1 and 2000")
        statement = (select(WebEndpoint).where(WebEndpoint.scan_id == scan_id)
                     .order_by(WebEndpoint.method, WebEndpoint.url).limit(limit))
        return list(self.session.scalars(statement))

    def _validated(self, scan_id: UUID, project_id: UUID, endpoints: Sequence[dict],
                   status: str) -> list[WebEndpoint]:
        if isinstance(endpoints, (str, bytes)) or not isinstance(endpoints, Sequence):
            raise ValueError("endpoints must be a sequence of mappings")
        rows: list[WebEndpoint] = []
        seen: dict[tuple[str, str], WebEndpoint] = {}
        for item in endpoints:
            if not isinstance(item, dict):
                raise ValueError("each endpoint must be a mapping")
            method = item.get("method", "GET")
            if not isinstance(method, str) or not method.isalpha() or len(method) > 10:
                raise ValueError("endpoint method must be a short alphabetic token")
            method = method.upper()
            url = self._clean_url(item.get("url"), allow_empty=False)
            # Extractors use ``source`` for the HTML element type, not its URL.
            # Accept the historical source field when no explicit URL is given.
            source_value = item.get("source_url", item.get("source", ""))
            source = self._clean_url(source_value, allow_empty=True) or url
            parameters = item.get("parameters")
            if parameters is not None:
                if (not isinstance(parameters, list) or len(parameters) > 256
                        or any(not isinstance(name, str) or not name or len(name) > 255
                               or any(ord(c) < 32 or ord(c) == 127 for c in name)
                               for name in parameters)
                        or len(set(parameters)) != len(parameters)):
                    raise ValueError("endpoint parameters are invalid")
            key = (method, url)
            if key in seen:
                existing = seen[key]
                if parameters is None or existing.parameters is None:
                    existing.parameters = None
                else:
                    merged = list(dict.fromkeys([*existing.parameters, *parameters]))
                    if len(merged) > 256:
                        raise ValueError("merged endpoint parameters exceed the limit")
                    existing.parameters = merged
                continue
            row = WebEndpoint(id=uuid4(), scan_id=scan_id, project_id=project_id,
                              method=method, url=url, source_url=source, parameters=parameters, status=status)
            rows.append(row)
            seen[key] = row
        return rows

    @classmethod
    def _clean_url(cls, value, *, allow_empty: bool) -> str:
        if not isinstance(value, str):
            raise ValueError("endpoint URL must be a string")
        cleaned = value.strip()
        if not cleaned and allow_empty:
            return ""
        if not cleaned or len(cleaned) > cls.MAX_URL_CHARS:
            raise ValueError("endpoint URL length is invalid")
        if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
            raise ValueError("endpoint URL must not contain control characters")
        if any(character.isspace() for character in cleaned):
            raise ValueError("endpoint URL must not contain whitespace")
        return cleaned


class FeedbackRepository:
    """Append-only operator verdicts; the newest revision per finding wins.

    A verdict is recorded, not verified: it does not change the finding status,
    severity or evidence. The caller owns the transaction, and the unique
    ``(finding_id, revision)`` constraint fails closed if two writers race.
    """

    VERDICTS = ("false_positive", "confirmed", "accepted_risk", "needs_more_info")
    MAX_NOTE_CHARS = 2000
    MAX_ACTOR_CHARS = 255
    MAX_ROWS = 5000

    def __init__(self, session: Session):
        self.session = session

    def record(self, scan_id: UUID, fingerprint: str, verdict: str, *, actor: str,
               note: str | None = None) -> FindingFeedback:
        if not isinstance(verdict, str) or verdict not in self.VERDICTS:
            raise ValueError("feedback verdict is not supported")
        if not isinstance(fingerprint, str) or not fingerprint.strip() or len(fingerprint) > 128:
            raise ValueError("finding fingerprint is invalid")
        clean_actor = self._text(actor, label="actor", max_chars=self.MAX_ACTOR_CHARS, allow_empty=False)
        clean_note = self._text(note, label="note", max_chars=self.MAX_NOTE_CHARS, allow_empty=True)
        scan = self.session.get(Scan, scan_id)
        if scan is None:
            raise ValueError("scan is not stored")
        finding = self.session.scalar(select(Finding).where(
            Finding.scan_id == scan_id, Finding.fingerprint == fingerprint))
        if finding is None:
            raise ValueError("finding is not stored for this scan")
        latest = self.session.scalar(select(func.max(FindingFeedback.revision)).where(
            FindingFeedback.finding_id == finding.id))
        revision = int(latest or 0) + 1
        row = FindingFeedback(id=uuid4(), scan_id=scan_id, finding_id=finding.id, revision=revision,
                             verdict=verdict, note=clean_note or None, actor=clean_actor)
        self.session.add(row)
        self.session.flush()
        return row

    def latest_for_scan(self, scan_id: UUID, *, limit: int = 1000) -> dict[str, FindingFeedback]:
        """Map fingerprint → newest recorded verdict; no claim about its truth."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 2000:
            raise ValueError("limit must be between 1 and 2000")
        rows = self.session.execute(
            select(FindingFeedback, Finding.fingerprint)
            .join(Finding, Finding.id == FindingFeedback.finding_id)
            .where(FindingFeedback.scan_id == scan_id)
            .order_by(FindingFeedback.revision.desc(), FindingFeedback.created_at.desc(),
                      FindingFeedback.id.desc())
            .limit(self.MAX_ROWS)).all()
        if len(rows) >= self.MAX_ROWS:
            raise ValueError("too many feedback rows to resolve deterministically")
        latest: dict[str, FindingFeedback] = {}
        for row, fingerprint in rows:
            latest.setdefault(fingerprint, row)
        if len(latest) > limit:
            raise ValueError("too many findings with feedback")
        return latest

    @classmethod
    def _text(cls, value, *, label: str, max_chars: int, allow_empty: bool) -> str:
        if value is None:
            if allow_empty:
                return ""
            raise ValueError(f"{label} is required")
        if not isinstance(value, str):
            raise ValueError(f"{label} must be text")
        cleaned = value.strip()
        if not cleaned:
            if allow_empty:
                return ""
            raise ValueError(f"{label} must not be blank")
        if len(cleaned) > max_chars:
            raise ValueError(f"{label} is too long")
        if any(ord(character) < 32 and character not in "\n\t" for character in cleaned):
            raise ValueError(f"{label} must not contain control characters")
        return cleaned


def _as_uuid(value: str | UUID, label: str) -> UUID:
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        raise ValueError(f"{label} identifier must be a UUID") from None


def _current_time(now: datetime | None) -> datetime:
    timestamp = now or datetime.now(timezone.utc)
    if timestamp.utcoffset() is None:
        raise ValueError("current time must be timezone-aware")
    return timestamp

