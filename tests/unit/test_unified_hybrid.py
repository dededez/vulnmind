"""Both sources participate in shared retrieval; failures do not downgrade."""
from types import SimpleNamespace

import pytest

from vulnmind.knowledge import hybrid


def test_both_rankings_are_fused_and_dense_failure_is_propagated(monkeypatch):
    calls = []
    class Sparse:
        def __init__(self, session): pass
        def search(self, query, *, limit):
            calls.append("sparse")
            return ["lexical", "shared"]
    class Dense:
        def __init__(self, session, *, encode, expected_model_info):
            assert expected_model_info == {"model": "fixture"}
        def search(self, query, *, limit):
            calls.append("dense")
            return ["semantic", "shared"]
    monkeypatch.setattr(hybrid, "PostgresSparseRetriever", Sparse)
    monkeypatch.setattr(hybrid, "PostgresDenseRetriever", Dense)
    retriever = hybrid.PostgresHybridRetriever(object(), encoder=SimpleNamespace(model_info={"model": "fixture"}))
    diagnostics = retriever.search_with_diagnostics("question", limit=3)
    assert list(diagnostics.identifiers) == ["shared", "lexical", "semantic"]
    assert diagnostics.fused[0]["ranks"] == {"dense": 2, "sparse": 2}
    assert diagnostics.sparse_count == diagnostics.dense_count == 2
    assert calls == ["sparse", "dense"]
    def fail(*args, **kwargs):
        raise ValueError("dense unavailable")
    monkeypatch.setattr(retriever._dense, "search", fail)
    with pytest.raises(ValueError, match="dense unavailable"):
        retriever.search("question", limit=3)
    monkeypatch.setattr(retriever._dense, "search", lambda *args, **kwargs: [])
    with pytest.raises(ValueError, match="no candidates"):
        retriever.search("question", limit=3)


def test_sparse_failure_does_not_return_vector_only_results(monkeypatch):
    class Sparse:
        def __init__(self, session): pass
        def search(self, query, *, limit):
            raise RuntimeError("keyword index unavailable")
    class Dense:
        def __init__(self, session, *, encode, expected_model_info): pass
        def search(self, query, *, limit):
            pytest.fail("dense results must not hide keyword failure")
    monkeypatch.setattr(hybrid, "PostgresSparseRetriever", Sparse)
    monkeypatch.setattr(hybrid, "PostgresDenseRetriever", Dense)
    retriever = hybrid.PostgresHybridRetriever(object(), encoder=SimpleNamespace(model_info={}))
    with pytest.raises(RuntimeError, match="keyword index unavailable"):
        retriever.search("question", limit=3)
