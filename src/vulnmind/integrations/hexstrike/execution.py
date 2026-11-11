"""Durable acceptance and reconciliation, independent of MCP connection lifetime.

An accepted/running row is never automatically re-executed after a restart.
The register/spawn gap is intentionally reported as unknown, not exactly once.
"""
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import time
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from vulnmind.integrations.mcp.client import fingerprint


class ResourceScope(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    kind: Literal['web', 'network', 'cloud', 'cluster', 'sample', 'workspace', 'execution', 'intelligence']
    origins: list[str] = Field(default_factory=list, max_length=20)
    networks: list[str] = Field(default_factory=list, max_length=20)
    ports: list[int] = Field(default_factory=list, max_length=100)
    account: str | None = None
    regions: list[str] = Field(default_factory=list, max_length=20)
    cluster: str | None = None
    sample_sha256: str | None = Field(default=None, pattern=r'^[0-9a-f]{64}$')
    workspace: str | None = Field(default=None, pattern=r'^[0-9a-f-]{36}$')
    execution_ids: list[UUID] = Field(default_factory=list, max_length=20)


class Budget(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    seconds: int = Field(default=20, ge=1, le=120)
    output_bytes: int = Field(default=100000, ge=1, le=200000)
    requests: int = Field(default=0, ge=0, le=1000)
    connections: int = Field(default=0, ge=0, le=1000)
    memory_mb: int = Field(default=128, ge=32, le=512)


class ExecutionPlan(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    version: Literal[1] = 1
    execution_id: UUID
    job_id: UUID
    tool_id: str
    arguments: dict
    scope: ResourceScope
    budget: Budget = Field(default_factory=Budget)
    schema_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    profile_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    skill_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    environment_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    expires_at: datetime

    def value(self): return self.model_dump(mode='json')
    def digest(self): return fingerprint(self.value())


def sign_plan(plan, key):
    if len(key) < 32: raise ValueError('execution approval key must contain at least 32 bytes')
    return hmac.new(key, plan.digest().encode(), hashlib.sha256).hexdigest()


def verify_approval(plan, signature, key):
    if not hmac.compare_digest(sign_plan(plan, key), signature): raise ValueError('execution approval mismatch')
    if plan.expires_at.tzinfo is None or plan.expires_at <= datetime.now(timezone.utc):
        raise ValueError('execution approval expired')


class ExecutionLedger:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('''CREATE TABLE IF NOT EXISTS executions (
                id TEXT PRIMARY KEY, job_id TEXT NOT NULL, digest TEXT NOT NULL,
                plan TEXT NOT NULL, status TEXT NOT NULL, updated REAL NOT NULL,
                result TEXT, result_sha256 TEXT)''')

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA synchronous=FULL')
        return conn

    def accept(self, plan):
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            old = conn.execute('SELECT * FROM executions WHERE id=?', (str(plan.execution_id),)).fetchone()
            if old:
                if old['digest'] != plan.digest() or old['job_id'] != str(plan.job_id):
                    raise ValueError('execution ID already binds a different plan')
                return False
            conn.execute('INSERT INTO executions VALUES (?,?,?,?,?,?,NULL,NULL)',
                         (str(plan.execution_id), str(plan.job_id), plan.digest(),
                          json.dumps(plan.value(), ensure_ascii=False), 'accepted', time.time()))
            return True

    def start(self, identifier):
        with self.connect() as conn:
            changed = conn.execute("UPDATE executions SET status='running',updated=? WHERE id=? AND status='accepted'",
                                   (time.time(), str(identifier))).rowcount
            if changed != 1: raise ValueError('execution cannot be started twice')

    def finish(self, identifier, status, result):
        if status not in {'succeeded', 'tool_failed', 'unknown', 'rejected', 'parse_failed'}:
            raise ValueError('invalid terminal status')
        with self.connect() as conn:
            changed = conn.execute("UPDATE executions SET status=?,updated=?,result=?,result_sha256=? WHERE id=? AND status='running'",
                (status, time.time(), json.dumps(result, ensure_ascii=False), fingerprint(result), str(identifier))).rowcount
            if changed != 1: raise ValueError('terminal receipt is immutable')

    def get(self, identifier, *, job_id):
        with self.connect() as conn:
            row = conn.execute('SELECT * FROM executions WHERE id=? AND job_id=?', (str(identifier), str(job_id))).fetchone()
        if row is None: return dict(status='not_found')
        result = json.loads(row['result']) if row['result'] else None
        plan = json.loads(row['plan'])
        if fingerprint(plan) != row['digest'] or (result is not None and fingerprint(result) != row['result_sha256']):
            raise ValueError('execution receipt integrity mismatch')
        status = row['status']
        # No process ownership proof after a worker crash: stale is unknown, never failed.
        stale = status in {'accepted', 'running'} and time.time()-row['updated'] > plan['budget']['seconds']+30
        return dict(execution_id=row['id'], job_id=row['job_id'], digest=row['digest'],
                    status='unknown' if stale else status, stored_status=status, updated=row['updated'],
                    result=result, result_sha256=row['result_sha256'],
                    reconciliation_required=stale or status == 'unknown')
