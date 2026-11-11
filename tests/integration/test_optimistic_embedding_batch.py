"""Optimistic backfill on a disposable PostgreSQL schema."""
import os
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from vulnmind.knowledge.embedding_batch import KEY, optimistic_backfill
from vulnmind.knowledge.ingestion import ingest_document
from vulnmind.knowledge.postgres_adapters import PostgresDenseRetriever
from vulnmind.persistence.models import KnowledgeChunk
from vulnmind.persistence.repositories import KnowledgeRepository

pytestmark = pytest.mark.skipif(not os.getenv('VULNMIND_TEST_DATABASE_URL'), reason='dedicated PostgreSQL test database not configured')
INFO = {'model': 'test-model', 'revision': 'test-revision', 'files_sha256': 'a' * 64}
VECTOR = [1.0] + [0.0] * 1023


class Model:
    def __init__(self, callback=None): self.calls = []; self.callback = callback
    def encode(self, texts, **kwargs):
        self.calls.extend(texts)
        if self.callback:
            callback, self.callback = self.callback, None
            callback()
        return [VECTOR[:] for _ in texts]


def test_optimistic_backfill_provenance_concurrency_and_rollback(monkeypatch):
    url = make_url(os.environ['VULNMIND_TEST_DATABASE_URL'])
    assert url.get_backend_name() == 'postgresql'
    schema = 'vulnmind_opt_' + uuid4().hex
    admin = create_engine(url, isolation_level='AUTOCOMMIT')
    with admin.connect() as c: c.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = url.update_query_dict({'options': f'-csearch_path={schema},public'})
    monkeypatch.setenv('VULNMIND_DATABASE_URL', scoped.render_as_string(hide_password=False))
    cfg = Config(str(Path(__file__).resolve().parents[2] / 'alembic.ini'))
    cfg.set_main_option('script_location', str(Path(__file__).resolve().parents[2] / 'migrations'))
    engine = None
    try:
        command.upgrade(cfg, 'head')
        engine = create_engine(scoped)
        with Session(engine) as s, s.begin():
            first = ingest_document(s,title='first',content='first content',source_type='test')
        model = Model()
        assert optimistic_backfill(engine,model,model_info=INFO,verify_model=lambda: None) == {'new_vectors':1,'legacy_verified':0,'reused':0}
        with Session(engine) as s:
            row = KnowledgeRepository(s).list_chunks(first.document_id)[0]
            assert row.metadata_[KEY]['model'] == 'test-model'
            assert row.metadata_[KEY]['content_sha256'] and row.metadata_[KEY]['vector_sha256']
            with pytest.raises(ValueError, match='provenance-tagged'):
                KnowledgeRepository(s).set_embedding(row.id, VECTOR)
            with pytest.raises(ValueError, match='expected model identity'):
                PostgresDenseRetriever(s, encode=lambda _: VECTOR).search('first', limit=5)
            assert len(PostgresDenseRetriever(s, encode=lambda _: VECTOR,
                expected_model_info=INFO).search('first', limit=5)) == 1
            with pytest.raises(ValueError, match='provenance mismatch'):
                PostgresDenseRetriever(s, encode=lambda _: VECTOR,
                    expected_model_info={**INFO, 'revision': 'different'}).search('first', limit=5)
        with Session(engine) as s, s.begin():
            legacy = ingest_document(s,title='legacy',content='legacy content',source_type='test')
            row = KnowledgeRepository(s).list_chunks(legacy.document_id)[0]
            row.embedding = VECTOR
        with Session(engine) as s:
            with pytest.raises(ValueError, match='mixed'):
                PostgresDenseRetriever(s, encode=lambda _: VECTOR, expected_model_info=INFO).search('first', limit=5)
        model=Model()
        assert optimistic_backfill(engine,model,model_info=INFO,verify_model=lambda: None) == {'new_vectors':0,'legacy_verified':1,'reused':1}
        assert model.calls == ['legacy content']
        with pytest.raises(ValueError,match='provenance mismatch'):
            optimistic_backfill(engine,Model(),model_info={**INFO,'revision':'another'},verify_model=lambda: None)
        with Session(engine) as s, s.begin():
            row = KnowledgeRepository(s).list_chunks(first.document_id)[0]
            row.embedding = [0.0, 1.0] + [0.0] * 1022
        with pytest.raises(ValueError,match='provenance mismatch'):
            optimistic_backfill(engine,Model(),model_info=INFO,verify_model=lambda: None)
        with Session(engine) as s, s.begin():
            row = KnowledgeRepository(s).list_chunks(first.document_id)[0]
            row.embedding = VECTOR
        with Session(engine) as s, s.begin():
            pending=ingest_document(s,title='pending',content='pending content',source_type='test')
        count = [0]
        def changed_model():
            count[0] += 1
            if count[0] == 2: raise ValueError('synthetic model change')
        with pytest.raises(ValueError, match='synthetic model change'):
            optimistic_backfill(engine, Model(), model_info=INFO, verify_model=changed_model)
        with Session(engine) as s:
            assert KnowledgeRepository(s).list_chunks(pending.document_id)[0].embedding is None
        def concurrent_write():
            with Session(engine) as s,s.begin():
                row=KnowledgeRepository(s).list_chunks(first.document_id)[0]
                row.content='concurrent update'
        with pytest.raises(ValueError,match='changed while encoding'):
            optimistic_backfill(engine,Model(concurrent_write),model_info=INFO,verify_model=lambda: None)
        with Session(engine) as s:
            row=KnowledgeRepository(s).list_chunks(pending.document_id)[0]
            assert row.embedding is None and KEY not in (row.metadata_ or {})
    finally:
        if engine is not None: engine.dispose()
        with admin.connect() as c: c.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()
