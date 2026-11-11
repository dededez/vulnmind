import pytest

from vulnmind.knowledge.inmemory import InMemoryLexicalIndex, MAX_DOCUMENTS, MAX_TOTAL_CHARACTERS
from vulnmind.knowledge.retrieval import KnowledgeChunk, hybrid_search


def chunk(chunk_id, content, source="local-note"):
    return KnowledgeChunk(chunk_id=chunk_id, document_id="doc-" + chunk_id, content=content, source=source)


def test_keyword_ranking_is_deterministic_and_has_no_fabricated_hits():
    index = InMemoryLexicalIndex([chunk("b", "query query parameter"),
                                  chunk("a", "query query parameter"),
                                  chunk("c", "unrelated text")])
    assert index.search("QUERY parameter", limit=2) == ["a", "b"]
    assert index.search("missingterm", limit=10) == []
    assert index.search("!!!", limit=10) == []


def test_index_uses_validated_snapshots_and_get_returns_a_copy():
    source = chunk("a", "original keyword")
    index = InMemoryLexicalIndex([source])
    source.content = "mutated text"
    first = index.get("a")
    first.content = "changed by caller"
    assert index.get("a").content == "original keyword"
    assert index.search("original", limit=1) == ["a"]
    assert index.get("missing") is None


def test_bounds_and_duplicate_ids_fail_closed():
    with pytest.raises(ValueError, match="duplicate"):
        InMemoryLexicalIndex([chunk("a", "x"), chunk("a", "y")])
    with pytest.raises(ValueError, match="document limit"):
        InMemoryLexicalIndex([chunk(str(i), "x") for i in range(MAX_DOCUMENTS + 1)])
    with pytest.raises(ValueError, match="character limit"):
        InMemoryLexicalIndex([chunk("a", "x" * (MAX_TOTAL_CHARACTERS + 1))])
    index = InMemoryLexicalIndex([])
    for bad_limit in (0, True, 101):
        with pytest.raises(ValueError, match="limit"):
            index.search("query", limit=bad_limit)


def test_index_integrates_with_hybrid_pipeline_without_claiming_dense_results():
    index = InMemoryLexicalIndex([chunk("sql", "parameterized query prevents injection"),
                                  chunk("tls", "verify certificate")])
    class NoDense:
        def search(self, query, *, limit):
            return []
    class Preserve:
        def rank(self, query, candidates):
            return [item.chunk_id for item in candidates]
    results = hybrid_search("parameterized query", dense=NoDense(), sparse=index, store=index,
                            reranker=Preserve())
    assert [item.chunk.chunk_id for item in results] == ["sql"]
    assert results[0].ranks == {"sparse": 1} and results[0].chunk.source == "local-note"
