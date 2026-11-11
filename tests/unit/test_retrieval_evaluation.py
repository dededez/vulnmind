import pytest

from vulnmind.knowledge.evaluation import RetrievalCase, evaluate_retrieval


def test_metrics_measure_only_labeled_relevance_at_cutoff():
    cases = [RetrievalCase(case_id="first", relevant_ids=("a", "b"), retrieved_ids=("x", "a", "b")),
             RetrievalCase(case_id="second", relevant_ids=("c",), retrieved_ids=("z",))]
    result = evaluate_retrieval(cases, cutoff=2)
    assert result.cases[0].hits == 1 and result.cases[0].recall == 0.5
    assert result.cases[0].reciprocal_rank == 0.5
    assert result.cases[1].hits == 0 and result.cases[1].reciprocal_rank == 0
    assert result.hit_rate == 0.5 and result.mean_recall == 0.25
    assert result.mean_reciprocal_rank == 0.25


def test_invalid_or_ambiguous_labels_fail_closed():
    with pytest.raises(ValueError):
        RetrievalCase(case_id="x", relevant_ids=(), retrieved_ids=())
    with pytest.raises(ValueError, match="distinct"):
        RetrievalCase(case_id="x", relevant_ids=("a",), retrieved_ids=("a", "a"))
    case = RetrievalCase(case_id="x", relevant_ids=("a",), retrieved_ids=())
    with pytest.raises(ValueError, match="unique"):
        evaluate_retrieval([case, case])
    for cutoff in (0, True, 101):
        with pytest.raises(ValueError, match="cutoff"):
            evaluate_retrieval([case], cutoff=cutoff)
    with pytest.raises(ValueError, match="labeled cases"):
        evaluate_retrieval([])


def test_offline_metrics_can_evaluate_actual_lexical_results():
    from vulnmind.knowledge.inmemory import InMemoryLexicalIndex
    from vulnmind.knowledge.retrieval import KnowledgeChunk

    chunks = [KnowledgeChunk(chunk_id="sql", document_id="one", source="fixture", content="parameterized query"),
              KnowledgeChunk(chunk_id="tls", document_id="two", source="fixture", content="certificate validation")]
    index = InMemoryLexicalIndex(chunks)
    case = RetrievalCase(case_id="fixture-query", relevant_ids=("sql",),
                         retrieved_ids=tuple(index.search("parameterized query", limit=2)))
    result = evaluate_retrieval([case], cutoff=1)
    assert result.hit_rate == result.mean_recall == result.mean_reciprocal_rank == 1.0
