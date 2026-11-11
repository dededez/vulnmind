"""Curated retrieval benchmark tests (small, hand-written, lexical only)."""
import json

import pytest

from vulnmind.knowledge.benchmark import EVALUATION_ROOT, load_corpus, load_labels, run_benchmark


def test_benchmark_runs_on_the_project_corpus():
    result = run_benchmark()
    assert result.cutoff == 5
    assert len(result.metrics.cases) == 8
    assert result.metrics.hit_rate == 1.0
    assert result.metrics.mean_reciprocal_rank == 1.0


def test_every_label_is_found_within_the_cutoff():
    corpus = load_corpus()
    labeled, cutoff = load_labels()
    known = {chunk.chunk_id for chunk in corpus}
    assert len(corpus) == len(known) == 8
    for case in labeled:
        assert set(case.relevant_ids) <= known
        assert cutoff >= len(case.relevant_ids)


def test_unknown_labels_and_duplicate_chunks_are_rejected(tmp_path):
    corpus = tmp_path / "corpus.json"
    corpus.write_text(json.dumps([{"id": "a", "source": "s", "source_type": "CWE",
                                   "document_id": "d", "content": "text"}]), encoding="utf-8")
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps({"cutoff": 5, "cases": [
        {"case_id": "q", "query": "text", "relevant_ids": ["missing"]}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown chunk"):
        run_benchmark(corpus, labels)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(json.dumps([
        {"id": "a", "source": "s", "source_type": "CWE", "document_id": "d", "content": "text"},
        {"id": "a", "source": "s", "source_type": "CWE", "document_id": "d", "content": "other"},
    ]), encoding="utf-8")
    with pytest.raises(ValueError, match="unique"):
        load_corpus(duplicate)


def test_empty_label_sets_are_rejected(tmp_path):
    corpus = tmp_path / "corpus.json"
    corpus.write_text(json.dumps([{"id": "a", "source": "s", "source_type": "CWE",
                                   "document_id": "d", "content": "text"}]), encoding="utf-8")
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps({"cutoff": 5, "cases": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="must contain cases"):
        load_labels(labels)


def test_paraphrases_expose_keyword_retrieval_limits():
    from vulnmind.knowledge.inmemory import _tokens

    labels_path = EVALUATION_ROOT / "paraphrase_labels.json"
    cases, _ = load_labels(labels_path)
    corpus = {item.chunk_id: item for item in load_corpus()}
    assert len(cases) == 4
    for case in cases:
        assert all(not (set(_tokens(case.query)) & set(_tokens(corpus[identifier].content)))
                   for identifier in case.relevant_ids)
    result = run_benchmark(labels_path=labels_path)
    assert result.metrics.hit_rate == 0.0
