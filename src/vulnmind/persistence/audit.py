"""Durable audit sinks with a tamper-evident hash chain.

Each new event links to the previous hashed event via ``entry_hash =
sha256(prev_hash + canonical payload)``. Legacy rows (NULL hashes) are reported
as unhashed. The chain detects accidental or naive edits; it is not proof against
an attacker who can rewrite the whole table and recompute every hash. Writers
using these sinks coordinate with database transaction locks.

``DatabaseAuditSink`` uses one transaction per event, ``SessionAuditSink`` writes
inside the caller's transaction (rows commit or roll back with the work they
describe; a rollback also discards that audit trail).
"""
from __future__ import annotations

import hashlib
import json
import time
import weakref
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import Engine, and_, func, insert, or_, select, text
from sqlalchemy.exc import SQLAlchemyError

from vulnmind.persistence.models import AuditEvent

MAX_VERIFY_EVENTS = 10_000
_SCAN_LIFECYCLE_TOOLS = ("repository.scan.transaction", "web.scan.transaction", "web.validation-plan.transaction")
_LIFECYCLE_TOOLS = (*_SCAN_LIFECYCLE_TOOLS, "repository.plan.transaction", "repository.knowledge.transaction")
_CHAIN_FIELDS = ("id", "call_id", "tool_name", "actor", "target_type", "status", "args_hash",
                 "created_at")


class AuditRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    call_id: UUID
    tool_name: str = Field(min_length=1, max_length=255)
    actor: str = Field(min_length=1, max_length=255)
    target_type: Literal["repository", "web", "knowledge"]
    status: Literal["requested", "started", "retrying", "succeeded", "failed", "cancelled", "denied", "pending_commit"]
    args_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("tool_name", "actor")
    @classmethod
    def safe_identifier(cls, value: str) -> str:
        if not value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("audit identifier is invalid")
        return value


class AuditError(RuntimeError):
    pass


class ChainReport(BaseModel):
    model_config = ConfigDict(frozen=True)
    checked: int
    unhashed: int
    valid: bool
    complete: bool = True
    first_break_id: str | None = None
    reason: str | None = None


def _normalise(value):
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return _iso(value)
    return value


def _iso(value: datetime) -> str:
    aware = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc).isoformat()


def _payload(values: dict) -> bytes:
    data = {key: _normalise(values[key]) for key in sorted(values)}
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def entry_hash(prev_hash: str | None, values: dict) -> str:
    """Hash one canonical event payload chained to its predecessor."""
    return hashlib.sha256(((prev_hash or "") + "|").encode("utf-8") + _payload(values)).hexdigest()


def _flat(values: dict) -> dict:
    return {key: values[key] for key in _CHAIN_FIELDS}


def _latest(connection) -> tuple[str | None, datetime | None]:
    row = connection.execute(
        select(AuditEvent.entry_hash, AuditEvent.created_at)
        .where(AuditEvent.entry_hash.is_not(None))
        .order_by(AuditEvent.created_at.desc()).limit(1)).first()
    if row is None:
        return None, None
    return row[0], row[1]


def _chained_values(connection, record: AuditRecord, entry_id: UUID) -> dict:
    # Hold a database-wide writer lock until the caller's transaction ends.
    # SQLite's no-op update acquires its writer lock before reading the tail.
    bind = connection.get_bind() if hasattr(connection, "get_bind") else connection
    dialect = bind.dialect.name
    if dialect == "postgresql":
        # Transaction-scoped advisory locks serialize writers, but a fixed
        # transaction snapshot can predate the writer ahead of us. In that
        # case reading the tail after waiting can still fork the chain.
        isolation = connection.execute(text("SHOW transaction_isolation")).scalar_one()
        if isolation.lower() != "read committed":
            raise AuditError("PostgreSQL audit writes require read committed isolation")
        connection.execute(text("SELECT pg_advisory_xact_lock(621842500317)"))
    elif dialect == "sqlite":
        connection.execute(text("UPDATE audit_events SET id = id WHERE 1 = 0"))
    else:
        raise AuditError("audit chain is unavailable for this database")
    previous, latest_created = _latest(connection)
    created = datetime.now(timezone.utc)
    if latest_created is not None:
        aware = latest_created if latest_created.tzinfo is not None else latest_created.replace(tzinfo=timezone.utc)
        if created <= aware:
            created = aware + timedelta(microseconds=1)
    values = {"id": entry_id, "call_id": record.call_id, "tool_name": record.tool_name,
              "actor": record.actor, "target_type": record.target_type, "status": record.status,
              "args_hash": record.args_hash, "created_at": created}
    return {**values, "prev_hash": previous, "entry_hash": entry_hash(previous, values)}


class DatabaseAuditSink:
    def __init__(self, engine: Engine):
        self._engine = engine

    def record(self, event: dict) -> None:
        record = _validate(event)
        try:
            with self._engine.begin() as connection:
                if connection.dialect.name == "postgresql":
                    # Bound contention with another writer holding the chain
                    # lock; an unavailable audit must not hang tool execution.
                    connection.execute(text("SET LOCAL lock_timeout = '3000ms'"))
                values = _chained_values(connection, record, uuid4())
                connection.execute(insert(AuditEvent).values(**values))
        except SQLAlchemyError:
            raise AuditError("audit storage unavailable") from None


class SessionAuditSink:
    """Write audit rows in the caller's transaction.

    Use this when the caller already holds a write transaction (for example a
    SQLite CLI scan): a second connection would block on the write lock. Rows
    commit or roll back together with the work they describe, so a rollback
    also discards the audit trail; that is visible and intentional.
    """

    def __init__(self, session):
        self._session = session

    def record(self, event: dict) -> None:
        record = _validate(event)
        try:
            values = _chained_values(self._session, record, uuid4())
            self._session.add(AuditEvent(**values))
            self._session.flush()
        except SQLAlchemyError:
            raise AuditError("audit storage unavailable") from None


def verify_audit_chain(connection, *, limit: int = 2000) -> ChainReport:
    """Recompute the chain in insertion order; stop at the first broken link."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_VERIFY_EVENTS:
        raise ValueError(f"limit must be between 1 and {MAX_VERIFY_EVENTS}")
    rows = connection.execute(
        select(AuditEvent.__table__).order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        .limit(limit + 1)).mappings().all()
    complete = len(rows) <= limit
    rows = rows[:limit]
    previous = None
    checked = unhashed = 0
    for row in rows:
        if row["entry_hash"] is None:
            unhashed += 1
            continue
        values = _flat(dict(row))
        if row["prev_hash"] != previous:
            return ChainReport(checked=checked, unhashed=unhashed, valid=False,
                               first_break_id=str(row["id"]), reason="previous link mismatch")
        if row["entry_hash"] != entry_hash(previous, values):
            return ChainReport(checked=checked, unhashed=unhashed, valid=False,
                               first_break_id=str(row["id"]), reason="entry hash mismatch")
        previous = row["entry_hash"]
        checked += 1
    if not complete:
        return ChainReport(checked=checked, unhashed=unhashed, valid=False, complete=False,
                           reason="verification limit reached")
    return ChainReport(checked=checked, unhashed=unhashed, valid=True)


def _verify_full_chain(connection) -> ChainReport:
    """Stream a single-query snapshot without the interactive CLI row limit."""
    rows = connection.execute(
        select(AuditEvent.__table__).order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        .execution_options(stream_results=True)).mappings()
    previous = None
    checked = unhashed = 0
    try:
        for row in rows:
            if row["entry_hash"] is None:
                unhashed += 1
                continue
            if row["prev_hash"] != previous or row["entry_hash"] != entry_hash(previous, _flat(dict(row))):
                return ChainReport(checked=checked, unhashed=unhashed, valid=False,
                                   first_break_id=str(row["id"]), reason="audit chain mismatch")
            previous = row["entry_hash"]
            checked += 1
        return ChainReport(checked=checked, unhashed=unhashed, valid=True)
    finally:
        rows.close()


# Journal replays verify the chain before every completed stage. A full pass over
# 10^5+ events per stage dominated resume time, so a verified head is cached and
# only appended rows are checked. The cache is process-local, expires quickly and
# never replaces the full verification used by `verify`/the CLI.
_CHAIN_CACHE: "weakref.WeakKeyDictionary[Engine, dict]" = weakref.WeakKeyDictionary()
_CHAIN_CACHE_TTL = 120.0


def _chain_head(connection):
    row = connection.execute(
        select(AuditEvent.id, AuditEvent.created_at, AuditEvent.entry_hash)
        .where(AuditEvent.entry_hash.is_not(None))
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(1)).first()
    return (row[0], row[1], row[2]) if row else None


def verify_complete_audit_chain(connection, *, use_cache: bool = False) -> ChainReport:
    """Verify the whole chain; with ``use_cache`` only newly appended rows are re-checked."""
    if not use_cache:
        return _verify_full_chain(connection)
    engine = connection.engine
    database = str(engine.url.database or "")
    entry = _CHAIN_CACHE.get(engine)
    if entry is None or entry.get("database") != database:
        report = _verify_full_chain(connection)
        if report.valid:
            head = _chain_head(connection)
            if head:
                _CHAIN_CACHE[engine] = dict(database=database, count=report.checked, last_id=head[0],
                                            last_created=head[1], head=head[2], verified_at=time.monotonic())
        return report
    total = connection.execute(
        select(func.count()).select_from(AuditEvent).where(AuditEvent.entry_hash.is_not(None))).scalar_one()
    if total < entry["count"]:
        _CHAIN_CACHE.pop(engine, None)
        return ChainReport(checked=entry["count"], unhashed=0, valid=False, reason="audit rows removed")
    if time.monotonic() - entry["verified_at"] > _CHAIN_CACHE_TTL:
        report = _verify_full_chain(connection)
        if report.valid:
            head = _chain_head(connection)
            entry.update(count=report.checked, last_id=head[0] if head else entry["last_id"],
                         last_created=head[1] if head else entry["last_created"],
                         head=head[2] if head else entry["head"], verified_at=time.monotonic())
        return report
    rows = connection.execute(
        select(AuditEvent.__table__)
        .where(or_(AuditEvent.created_at > entry["last_created"],
                   and_(AuditEvent.created_at == entry["last_created"], AuditEvent.id > entry["last_id"])))
        .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())).mappings().all()
    previous = entry["head"]
    checked = entry["count"]
    unhashed = 0
    last_id, last_created = entry["last_id"], entry["last_created"]
    for row in rows:
        if row["entry_hash"] is None:
            unhashed += 1
            continue
        if row["prev_hash"] != previous or row["entry_hash"] != entry_hash(previous, _flat(dict(row))):
            return ChainReport(checked=checked, unhashed=unhashed, valid=False,
                               first_break_id=str(row["id"]), reason="audit chain mismatch")
        previous = row["entry_hash"]
        checked += 1
        last_id, last_created = row["id"], row["created_at"]
    if checked != total:
        # Unhashed or out-of-order rows appeared; fall back to the authoritative pass.
        report = _verify_full_chain(connection)
        if report.valid:
            head = _chain_head(connection)
            entry.update(count=report.checked, last_id=head[0] if head else entry["last_id"],
                         last_created=head[1] if head else entry["last_created"],
                         head=head[2] if head else entry["head"], verified_at=time.monotonic())
        return report
    entry.update(count=checked, last_id=last_id, last_created=last_created, head=previous,
                 verified_at=entry["verified_at"])
    return ChainReport(checked=checked, unhashed=unhashed, valid=True)



def trace_scan_audit(connection, parent_id: UUID, *, limit: int = 2000) -> dict:
    """Return bounded lifecycle and linked events; missing terminal means unknown.

    This is a diagnostic view, not authentication or hash-chain verification.
    """
    if not isinstance(parent_id, UUID) or isinstance(limit, bool) or not 1 <= limit <= MAX_VERIFY_EVENTS:
        raise ValueError("invalid trace request")
    table = AuditEvent.__table__
    linked = select(table.c.call_id).where(table.c.tool_name == f"correlation.{parent_id}")
    rows = connection.execute(select(table.c.call_id, table.c.tool_name, table.c.status, table.c.created_at)
        .where((table.c.call_id == parent_id) | table.c.call_id.in_(linked))
        .order_by(table.c.created_at, table.c.id).limit(limit + 1)).all()
    complete = len(rows) <= limit
    rows = rows[:limit]
    lifecycle = [row.status for row in rows if row.call_id == parent_id
                 and row.tool_name in _LIFECYCLE_TOOLS]
    outcome = "unknown"
    if complete and lifecycle == ["requested", "succeeded"]:
        outcome = "committed"
    elif complete and lifecycle == ["requested", "failed"]:
        outcome = "failed"
    elif complete and not rows:
        outcome = "not_found"
    # Keep the transaction result distinct from individual tool outcomes.
    # A completed transaction does not prove an interrupted child call finished.
    children = {}
    for row in rows:
        if row.call_id == parent_id:
            continue
        child = children.setdefault(row.call_id, {"tools": set(), "statuses": []})
        if row.tool_name == f"correlation.{parent_id}":
            continue
        child["tools"].add(row.tool_name)
        child["statuses"].append(row.status)
    operations = []
    terminal = {"succeeded", "failed", "cancelled", "denied", "pending_commit"}
    for call_id, child in children.items():
        statuses = child["statuses"]
        end = [status for status in statuses if status in terminal]
        state = (end[0] if complete and len(child["tools"]) == 1 and statuses and statuses[0] == "requested"
                 and len(end) == 1 and statuses[-1] == end[0] else "unknown")
        operations.append({"call_id": str(call_id), "tool_name": sorted(child["tools"])[0]
                           if len(child["tools"]) == 1 else None, "outcome": state})
    transactional_children = connection.dialect.name == "sqlite"
    operations_may_be_missing = not complete or (transactional_children and outcome != "committed")
    return {"audit_call_id": str(parent_id), "outcome": outcome, "complete": complete,
            "operations_may_be_missing": operations_may_be_missing,
            "operations": operations,
            "chain_verified": False, "events": [{"call_id": str(row.call_id), "tool_name": row.tool_name,
            "status": row.status, "created_at": _iso(row.created_at)} for row in rows]}


def recent_scan_audits(connection, *, limit: int = 20) -> dict:
    """Find repository and web scans, including interruptions before CLI output."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("invalid scan list limit")
    table = AuditEvent.__table__
    rows = connection.execute(select(table.c.call_id, table.c.created_at)
        .where(table.c.tool_name.in_(_SCAN_LIFECYCLE_TOOLS),
               table.c.status == "requested")
        .order_by(table.c.created_at.desc(), table.c.id.desc()).limit(limit + 1)).all()
    items = []
    for row in rows[:limit]:
        trace = trace_scan_audit(connection, row.call_id)
        items.append({"audit_call_id": str(row.call_id), "requested_at": _iso(row.created_at),
                      "outcome": trace["outcome"], "trace_complete": trace["complete"],
                      "operations_unknown": (sum(op["outcome"] == "unknown" for op in trace["operations"])
                                             if not trace["operations_may_be_missing"] else None)})
    return {"scans": items, "window_limited": len(rows) > limit, "chain_verified": False}


def _validate(event: dict) -> AuditRecord:
    try:
        return AuditRecord.model_validate(event)
    except ValidationError:
        raise AuditError("invalid audit event") from None
