import pytest
from vulnmind.knowledge.retrieval import HybridRetriever, KnowledgeChunk, hybrid_search


class Retriever:
    def __init__(self, ids): self.ids = ids
    def search(self, query, *, limit): return self.ids[:limit]


class Store:
    def __init__(self, ids): self.ids = ids
    def get(self, chunk_id):
        if chunk_id not in self.ids: return None
        return KnowledgeChunk(chunk_id=chunk_id, document_id="doc-" + chunk_id, content="text", source="source-" + chunk_id)


class Reranker:
    def __init__(self, ids): self.ids = ids
    def rank(self, query, candidates): return self.ids


def test_hybrid_pipeline_preserves_provenance_and_rerank_order():
    result = hybrid_search("query", dense=Retriever(["a", "b"]), sparse=Retriever(["b", "c"]), store=Store("abc"), reranker=Reranker(["c", "b", "a"]), final=2)
    assert [entry.chunk.chunk_id for entry in result] == ["c", "b"]
    assert result[1].ranks == {"dense": 2, "sparse": 1}
    assert result[1].chunk.source == "source-b"


def test_empty_or_missing_results_are_not_fabricated():
    assert hybrid_search("query", dense=Retriever([]), sparse=Retriever([]), store=Store(""), reranker=Reranker([])) == []
    with pytest.raises(ValueError, match="missing"):
        hybrid_search("query", dense=Retriever(["a"]), sparse=Retriever([]), store=Store(""), reranker=Reranker([]))


@pytest.mark.parametrize("output", [["a", "a"], ["invented"]])
def test_reranker_cannot_insert_or_duplicate_ids(output):
    with pytest.raises(ValueError, match="reranker"):
        hybrid_search("query", dense=Retriever(["a"]), sparse=Retriever([]), store=Store("a"), reranker=Reranker(output))


def test_metadata_filter_applies_before_reranking():
    result = hybrid_search("query", dense=Retriever(["a", "b"]), sparse=Retriever([]), store=Store("ab"), reranker=Reranker(["b"]), filters={"source": "source-b"})
    assert [entry.chunk.chunk_id for entry in result] == ["b"]
    assert hybrid_search("query", dense=Retriever(["a"]), sparse=Retriever([]), store=Store("a"), reranker=Reranker(["a"]), filters={"source": "untrusted"}) == []
    with pytest.raises(ValueError, match="filter"):
        hybrid_search("query", dense=Retriever([]), sparse=Retriever([]), store=Store(""), reranker=Reranker([]), filters={"unsupported": "x"})


@pytest.mark.parametrize("options", [{"per_retriever": True}, {"per_retriever": 101},
                                      {"candidates": 201}, {"final": 0}, {"k": 0},
                                      {"filters": []}, {"filters": {"source": "x" * 256}}])
def test_invalid_limits_and_filters_fail_before_calling_retrievers(options):
    class MustNotRun:
        def search(self, query, *, limit):
            raise AssertionError("retriever was called")
    with pytest.raises(ValueError):
        hybrid_search("query", dense=MustNotRun(), sparse=MustNotRun(), store=Store(""),
                      reranker=Reranker([]), **options)


def test_malformed_reranker_response_is_rejected():
    with pytest.raises(ValueError, match="reranker"):
        hybrid_search("query", dense=Retriever(["a"]), sparse=Retriever([]), store=Store("a"),
                      reranker=Reranker([["unhashable"]]))


def test_hybrid_pushes_filters_before_candidate_limit_when_supported():
    class Filtered:
        def __init__(self):
            self.calls = []
        def search(self, query, *, limit):
            raise AssertionError("filter-aware path should be used")
        def search_filtered(self, query, *, limit, filters):
            self.calls.append((limit, filters))
            return ["b"]
    dense, sparse = Filtered(), Filtered()
    results = hybrid_search("query", dense=dense, sparse=sparse, store=Store("ab"),
                            reranker=Reranker(["b"]), per_retriever=1, filters={"source": "source-b"})
    assert [item.chunk.chunk_id for item in results] == ["b"]
    assert dense.calls == sparse.calls == [(1, {"source": "source-b"})]


def test_hybrid_retriever_contract_preserves_order_and_configured_filters():
    filters = {"source": "source-b"}
    adapter = HybridRetriever(dense=Retriever(["a", "b"]), sparse=Retriever(["b"]), store=Store("ab"),
                              reranker=Reranker(["b"]), filters=filters)
    filters["source"] = "source-a"
    assert adapter.search("query", limit=1) == ["b"]
    with pytest.raises(ValueError, match="result limits"):
        adapter.search("query", limit=0)


def test_hybrid_retriever_propagates_failures_and_does_not_invent_results():
    class Broken:
        def search(self, query, *, limit):
            raise RuntimeError("retrieval failed")
    with pytest.raises(ValueError, match="interfaces"):
        HybridRetriever(dense=None, sparse=Retriever([]), store=Store(""), reranker=Reranker([]))
    adapter = HybridRetriever(dense=Broken(), sparse=Retriever([]), store=Store(""), reranker=Reranker([]))
    with pytest.raises(RuntimeError, match="retrieval failed"):
        adapter.search("query", limit=1)
    empty = HybridRetriever(dense=Retriever([]), sparse=Retriever([]), store=Store(""), reranker=Reranker([]))
    assert empty.search("query", limit=1) == []
