import pytest
from vulnmind.knowledge.fusion import reciprocal_rank_fusion


def test_rrf_fuses_dense_and_sparse_with_source_ranks():
    results = reciprocal_rank_fusion({"dense": ["a", "b"], "sparse": ["b", "c"]}, k=60)
    assert [result.chunk_id for result in results] == ["b", "a", "c"]
    assert results[0].score == pytest.approx(1/62 + 1/61)
    assert results[0].ranks == {"dense": 2, "sparse": 1}


def test_duplicates_do_not_boost_a_source_and_ties_are_stable():
    first = reciprocal_rank_fusion({"sparse": ["b", "a"], "dense": ["a", "a", "b"]})
    second = reciprocal_rank_fusion({"dense": ["a", "a", "b"], "sparse": ["b", "a"]})
    assert first == second
    assert first[0].chunk_id == "a"
    assert first[0].ranks["dense"] == 1
    assert len(reciprocal_rank_fusion({"dense": ["b", "a"]}, limit=1)) == 1


@pytest.mark.parametrize("kwargs", [{"k": 0}, {"k": True}, {"k": 10**1000}, {"limit": 0}])
def test_invalid_fusion_options_are_rejected(kwargs):
    with pytest.raises(ValueError):
        reciprocal_rank_fusion({"dense": ["a"]}, **kwargs)


def test_empty_results_stay_empty_without_fabricated_knowledge():
    assert reciprocal_rank_fusion({"dense": [], "sparse": []}) == []
    with pytest.raises(ValueError):
        reciprocal_rank_fusion({"dense": [""]})
