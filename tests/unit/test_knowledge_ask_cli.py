"""Knowledge ask CLI: explicit egress and saved citation handling."""
import json
from contextlib import nullcontext
from types import SimpleNamespace

from vulnmind import __main__
from vulnmind.agents.model import ModelResponse
from vulnmind.knowledge.retrieval import KnowledgeChunk


def args(**changes):
    values = dict(question="sql injection", send_to_model=True, retrieval="hybrid", actor="tester", output=None)
    return SimpleNamespace(**{**values, **changes})


def test_knowledge_ask_requires_explicit_outbound_consent(capsys):
    assert __main__._knowledge_ask(args(send_to_model=False)) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"


def test_knowledge_ask_saves_verified_refs_without_source_url(tmp_path, monkeypatch, capsys):
    import sqlalchemy
    import sqlalchemy.orm
    import vulnmind.agents.deepseek as deepseek
    import vulnmind.config as config
    import vulnmind.knowledge.postgres_adapters as adapters
    import vulnmind.knowledge.hybrid as hybrid
    import vulnmind.persistence.audit as audit

    class Engine:
        def dispose(self): pass
    class Session:
        def __init__(self, engine): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def begin(self): return nullcontext()
        def execute(self, statement): pass
    class Retriever:
        def __init__(self, session, *, encoder): pass
        def search_with_diagnostics(self, query, *, limit):
            return SimpleNamespace(identifiers=("chunk-id",), sparse_count=1, dense_count=1,
                sparse_limit_reached=False, dense_limit_reached=False,
                fused=({"chunk_id": "chunk-id", "score": 0.1, "ranks": {"sparse": 1, "dense": 1}},))
    class Store:
        def __init__(self, session): pass
        def get(self, identifier):
            return KnowledgeChunk(chunk_id=identifier, document_id="doc-id", content="Use parameterized SQL.",
                                  source="https://private.test/?token=secret")
    class Provider:
        def complete(self, request):
            if "Independently assess" in request.messages[0].content:
                return ModelResponse(text=json.dumps({"relevant": True, "supported": True, "conflicting": False}))
            return ModelResponse(text=json.dumps({"answer": "parameterized SQL", "cited_refs": ["knowledge:0"],
                "supporting_quotes": [{"ref": "knowledge:0", "quote": "parameterized SQL"}]}))
    class Sink:
        def __init__(self, engine): pass
        def record(self, event): pass
    monkeypatch.setattr(sqlalchemy, "create_engine", lambda *_: Engine())
    monkeypatch.setattr(sqlalchemy.orm, "Session", Session)
    monkeypatch.setattr(config, "Settings", lambda: SimpleNamespace(database_url="postgresql://redacted"))
    monkeypatch.setattr(hybrid, "LocalQueryEncoder", lambda: object())
    monkeypatch.setattr(hybrid, "PostgresHybridRetriever", Retriever)
    monkeypatch.setattr(adapters, "DatabaseChunkStore", Store)
    monkeypatch.setattr(deepseek, "DeepSeekClient", Provider)
    monkeypatch.setattr(audit, "DatabaseAuditSink", Sink)
    output = tmp_path / "answer.json"
    assert __main__._knowledge_ask(args(output=output)) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["references"][0]["chunk_id"] == "chunk-id"
    assert result["references"][0]["cited"] is True
    assert result["review_status"] == "accepted"
    assert result["retrieval_diagnostics"]["fused"][0]["ranks"] == {"sparse": 1, "dense": 1}
    assert "secret" not in output.read_text(encoding="utf-8")
    assert json.loads(capsys.readouterr().out)["status"] == "answered"
    assert __main__._knowledge_ask(args(output=output)) == 2
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "answered"


def test_knowledge_ask_rejects_removed_sparse_mode(monkeypatch, capsys):
    import sqlalchemy
    import vulnmind.config as config
    class Engine:
        def dispose(self): pass
    monkeypatch.setattr(sqlalchemy, "create_engine", lambda *_: Engine())
    monkeypatch.setattr(config, "Settings", lambda: SimpleNamespace(database_url="postgresql://redacted"))
    assert __main__._knowledge_ask(args(retrieval="sparse")) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"
