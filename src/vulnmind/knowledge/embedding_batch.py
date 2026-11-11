"""Optimistic, provenance-aware embedding backfill for PostgreSQL.

Only use this with a trusted model fingerprint. Legacy vectors are recomputed
before attaching provenance. Expensive model encoding happens without a table
lock; a later short transaction locks and rejects any concurrent data change.
"""
from __future__ import annotations

import hashlib
import json
import struct
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from vulnmind.knowledge.vector import validate_vector
from vulnmind.persistence.models import KnowledgeChunk, KnowledgeDocument

MAX_CHUNKS = 5000
MAX_CHARACTERS = 10_000_000
TOLERANCE = 0.000002
KEY = 'embedding_provenance_v1'


def vector_hash(vector):
    values = [float(v) for v in vector]
    # Validate without hashing the rounded return value: PostgreSQL stores
    # float32, and rounding again would mask small changes to stored vectors.
    validate_vector(values)
    return hashlib.sha256(b''.join(struct.pack('<f', v) for v in values)).hexdigest()


def content_hash(content):
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


@dataclass(frozen=True)
class Snapshot:
    identifier: object
    document_id: object
    index: int
    content: str
    version: str | None
    title: str
    source: str | None
    source_type: str
    trust_level: str | None
    document_metadata_json: str
    metadata_json: str
    vector_sha256: str | None
    vector: tuple[float, ...] | None


def _read_snapshot(session):
    count, chars = session.execute(select(func.count(KnowledgeChunk.id),
        func.coalesce(func.sum(func.length(KnowledgeChunk.content)), 0))).one()
    if count > MAX_CHUNKS or chars > MAX_CHARACTERS:
        raise ValueError('knowledge corpus exceeds backfill limits')
    rows = session.execute(select(KnowledgeChunk, KnowledgeDocument)
        .join(KnowledgeDocument, KnowledgeDocument.id == KnowledgeChunk.document_id)
        .order_by(KnowledgeChunk.document_id, KnowledgeChunk.chunk_index, KnowledgeChunk.id)).all()
    if len(rows) != count:
        raise ValueError('knowledge corpus has missing documents')
    result = []
    for c, d in rows:
        if c.metadata_ is not None and not isinstance(c.metadata_, dict):
            raise ValueError('chunk metadata must be a mapping')
        vector = tuple(float(v) for v in c.embedding) if c.embedding is not None else None
        result.append(Snapshot(c.id, c.document_id, c.chunk_index, c.content, d.version, d.title,
            d.source_url, d.source_type, d.trust_level, canonical(d.metadata_),
            canonical(c.metadata_ or {}), vector_hash(vector) if vector else None, vector))
    return result


def _record(info, row, digest):
    return {**info, 'document_version': row.version, 'content_sha256': content_hash(row.content),
            'vector_sha256': digest}


def optimistic_backfill(engine, model, *, model_info: dict, verify_model: Callable[[], None], batch_size=8):
    if engine.dialect.name != 'postgresql':
        raise ValueError('dense embeddings require PostgreSQL')
    if not isinstance(model_info, dict) or set(model_info) != {'model', 'revision', 'files_sha256'} or any(
        not isinstance(v, str) or not v.strip() for v in model_info.values()):
        raise ValueError('model provenance is incomplete')
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= 128:
        raise ValueError('invalid batch size')
    if not callable(verify_model): raise ValueError('model verification is required')
    verify_model()
    with Session(engine) as session, session.begin():
        session.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'))
        original = _read_snapshot(session)
    need = []
    reused = 0
    for row in original:
        metadata = json.loads(row.metadata_json)
        marker = metadata.get(KEY)
        if marker is not None:
            if row.vector is None or marker != _record(model_info, row, row.vector_sha256):
                raise ValueError('stored embedding provenance mismatch')
            reused += 1
        else:
            need.append(row)
    computed = {}
    for offset in range(0, len(need), batch_size):
        batch = need[offset:offset + batch_size]
        vectors = model.encode([x.content for x in batch], batch_size=len(batch),
                               normalize_embeddings=True, show_progress_bar=False)
        if len(vectors) != len(batch): raise ValueError('embedding model returned wrong vector count')
        for row, vector in zip(batch, vectors):
            values = validate_vector([float(v) for v in vector])
            if row.vector is not None and any(abs(a-b) > TOLERANCE for a,b in zip(row.vector, values)):
                raise ValueError('existing embeddings do not match current model and content')
            computed[row.identifier] = values
    verify_model()
    if not need:
        return {'new_vectors': 0, 'legacy_verified': 0, 'reused': reused}
    with Session(engine) as session, session.begin():
        isolation = session.execute(text('SHOW transaction_isolation')).scalar_one()
        if isolation.lower() != 'read committed': raise ValueError('READ COMMITTED required')
        session.execute(text('LOCK TABLE knowledge_documents IN SHARE ROW EXCLUSIVE MODE'))
        session.execute(text('LOCK TABLE knowledge_chunks IN SHARE ROW EXCLUSIVE MODE'))
        if _read_snapshot(session) != original:
            raise ValueError('knowledge corpus changed while encoding; retry')
        new_vectors = 0
        legacy_verified = 0
        for row in need:
            stored = session.get(KnowledgeChunk, row.identifier)
            value = computed[row.identifier]
            if row.vector is None:
                stored.embedding = value
                digest = vector_hash(value)
                new_vectors += 1
            else:
                digest = row.vector_sha256
                legacy_verified += 1
            stored.metadata_ = {**json.loads(row.metadata_json), KEY: _record(model_info, row, digest)}
    return {'new_vectors': new_vectors, 'legacy_verified': legacy_verified, 'reused': reused}
