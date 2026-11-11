"""Load the project's curated retrieval corpus and run the offline benchmark.

The corpus and its labels are small and hand-written for this repository; they
check the lexical index and metric plumbing, not production retrieval quality.
"""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from vulnmind.knowledge.evaluation import RetrievalCase, RetrievalMetrics, evaluate_retrieval
from vulnmind.knowledge.inmemory import InMemoryLexicalIndex
from vulnmind.knowledge.retrieval import KnowledgeChunk

EVALUATION_ROOT = Path(__file__).resolve().parents[3] / "evaluation"


class CorpusEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(min_length=1, max_length=255)
    source: str = Field(min_length=1)
    source_type: str = Field(min_length=1)
    document_id: str = Field(min_length=1)
    content: str = Field(min_length=1)


class LabeledQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    case_id: str = Field(min_length=1)
    query: str = Field(min_length=1, max_length=4096)
    relevant_ids: list[str] = Field(min_length=1)


class BenchmarkResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    metrics: RetrievalMetrics
    cutoff: int


def load_corpus(path: Path | None = None) -> list[KnowledgeChunk]:
    payload = json.loads((path or EVALUATION_ROOT / "corpus.json").read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not payload:
        raise ValueError("corpus must be a non-empty JSON array")
    chunks = []
    for entry in payload:
        item = CorpusEntry.model_validate(entry)
        chunks.append(KnowledgeChunk(chunk_id=item.id, document_id=item.document_id, source=item.source,
                                     content=item.content, start_offset=0, end_offset=len(item.content)))
    if len({chunk.chunk_id for chunk in chunks}) != len(chunks):
        raise ValueError("corpus chunk identifiers must be unique")
    return chunks


def load_labels(path: Path | None = None) -> tuple[list[LabeledQuery], int]:
    payload = json.loads((path or EVALUATION_ROOT / "labels.json").read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("labels must be a JSON object")
    cases = [LabeledQuery.model_validate(item) for item in payload.get("cases", [])]
    if not cases:
        raise ValueError("labels must contain cases")
    return cases, int(payload.get("cutoff", 5))


def run_benchmark(corpus_path: Path | None = None, labels_path: Path | None = None) -> BenchmarkResult:
    chunks = load_corpus(corpus_path)
    labeled, cutoff = load_labels(labels_path)
    index = InMemoryLexicalIndex(chunks)
    known = {chunk.chunk_id for chunk in chunks}
    cases = []
    for item in labeled:
        unknown = set(item.relevant_ids) - known
        if unknown:
            raise ValueError("labels reference unknown chunk identifiers")
        retrieved = index.search(item.query, limit=cutoff)
        cases.append(RetrievalCase(case_id=item.case_id, relevant_ids=tuple(item.relevant_ids),
                                   retrieved_ids=tuple(retrieved)))
    return BenchmarkResult(metrics=evaluate_retrieval(cases, cutoff=cutoff), cutoff=cutoff)


def main() -> int:
    result = run_benchmark()
    print(json.dumps({"cutoff": result.cutoff,
                      "hit_rate": result.metrics.hit_rate,
                      "mean_recall": result.metrics.mean_recall,
                      "mrr": result.metrics.mean_reciprocal_rank,
                      "cases": [case.model_dump() for case in result.metrics.cases]},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
