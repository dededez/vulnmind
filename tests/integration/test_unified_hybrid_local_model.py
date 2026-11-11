"""Opt-in local model + disposable PostgreSQL integration; no network model calls."""
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session


@pytest.mark.skipif(os.getenv("VULNMIND_TEST_LOCAL_EMBEDDING") != "1",
                    reason="explicit local model integration test not requested")
def test_local_embedding_and_postgres_hybrid_together(monkeypatch, tmp_path, capsys):
    import json
    import sys
    from datetime import datetime, timedelta, timezone
    from vulnmind.knowledge.embedding_batch import KEY, content_hash, vector_hash
    from vulnmind.knowledge.hybrid import LocalQueryEncoder, PostgresHybridRetriever
    from vulnmind.knowledge.ingestion import ingest_document
    from vulnmind.persistence.base import Base
    from vulnmind.persistence.models import ContextManifestRecord, KnowledgeChunk, Project
    from sqlalchemy import select

    url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
    if url.get_backend_name() != "postgresql" or url.host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("test requires an explicit local PostgreSQL database")
    schema = "vulnmind_model_test_" + uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    scoped = create_engine(url.update_query_dict({"options": f"-csearch_path={schema},public"}))
    try:
        with admin.connect() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        Base.metadata.create_all(scoped)
        encoder = LocalQueryEncoder()
        query = "sql injection parameterized queries"
        vector = encoder(query)  # Same synthetic text on both sides; this checks wiring, not quality.
        with Session(scoped) as session, session.begin():
            document = ingest_document(session, title="synthetic", source_type="reference",
                                       content=query, size=500, overlap=0)
            row = session.scalar(select(KnowledgeChunk).where(KnowledgeChunk.document_id == document.document_id))
            row.embedding = vector
            row.metadata_ = {**(row.metadata_ or {}), KEY: {**encoder.model_info, "document_version": None,
                "content_sha256": content_hash(row.content), "vector_sha256": vector_hash(vector)}}
            chunk_id = str(row.id)
        with Session(scoped) as session:
            result = PostgresHybridRetriever(session, encoder=encoder).search_with_diagnostics(query, limit=5)
            assert result.identifiers == (chunk_id,)
            assert result.fused[0]["ranks"] == {"dense": 1, "sparse": 1}
        # The real workflow CLI uses the same encoder + PG hybrid retriever;
        # reuse the already-loaded model to keep this integration bounded.
        from vulnmind import __main__
        from vulnmind.knowledge import hybrid as hybrid_module
        tls_query = "tls certificate verification"
        tls_vector = encoder(tls_query)
        project_id = uuid4()
        with Session(scoped) as session, session.begin():
            session.add(Project(id=project_id, name="synthetic workflow"))
            document = ingest_document(session, title="synthetic TLS", source_type="reference",
                                       content=tls_query, size=500, overlap=0)
            row = session.scalar(select(KnowledgeChunk).where(KnowledgeChunk.document_id == document.document_id))
            row.embedding = tls_vector
            row.metadata_ = {**(row.metadata_ or {}), KEY: {**encoder.model_info, "document_version": None,
                "content_sha256": content_hash(row.content), "vector_sha256": vector_hash(tls_vector)}}
            tls_chunk_id = str(row.id)
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("import requests\nrequests.get('https://example.test', verify=False)\n", encoding="utf-8")
        now = datetime.now(timezone.utc)
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(json.dumps({"authorization_source": "synthetic", "approved_by": "owner",
            "starts_at": (now - timedelta(hours=1)).isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(),
            "repository_roots": [str(repo)]}), encoding="utf-8")
        monkeypatch.setattr(hybrid_module, "LocalQueryEncoder", lambda: encoder)
        monkeypatch.setenv("VULNMIND_DATABASE_URL", str(scoped.url.render_as_string(hide_password=False)))
        monkeypatch.setenv("VULNMIND_REPORT_ROOT", str(tmp_path / "reports"))
        monkeypatch.setenv("VULNMIND_EVIDENCE_ROOT", "")
        monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(uuid4()),
            "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
            "--knowledge-context"])
        assert __main__.main() == 0
        assert json.loads(capsys.readouterr().out)["status"] == "finished"
        with Session(scoped) as session:
            manifest = session.scalar(select(ContextManifestRecord))
            assert manifest.selected_refs["retrieval_status"] == "matched"
            assert tls_chunk_id in {item["chunk_id"] for item in manifest.selected_refs["knowledge"]}
        # The separately persisted stage uses the same real encoder and PG
        # retriever; synthetic inputs validate wiring, not retrieval quality.
        from vulnmind.persistence.models import WorkflowOperation
        staged_id = uuid4()
        monkeypatch.setattr(sys, "argv", ["vulnmind", "workflow-scan", "--workflow-id", str(staged_id),
            "--project-id", str(project_id), "--repository", str(repo), "--scope-file", str(scope_file),
            "--knowledge-context", "--staged-knowledge"])
        assert __main__.main() == 0
        assert json.loads(capsys.readouterr().out)["status"] == "finished"
        with Session(scoped) as session:
            stage = session.scalar(select(WorkflowOperation).where(WorkflowOperation.workflow_id == staged_id,
                                                                    WorkflowOperation.stage == "knowledge_context"))
            assert stage.status == "completed"
            manifest = session.get(ContextManifestRecord, __import__("uuid").UUID(stage.result_ref))
            assert manifest.selected_refs["retrieval_status"] == "matched"
            assert tls_chunk_id in {item["chunk_id"] for item in manifest.selected_refs["knowledge"]}
    finally:
        scoped.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin.dispose()
