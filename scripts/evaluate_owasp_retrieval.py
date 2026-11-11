"""Small, provisional retrieval smoke evaluation against curated OWASP titles."""
import json
import argparse
from time import perf_counter
from pathlib import Path
from uuid import UUID

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from vulnmind.config import Settings
from vulnmind.knowledge.fusion import reciprocal_rank_fusion
from vulnmind.knowledge.postgres_adapters import PostgresDenseRetriever, PostgresSparseRetriever
from vulnmind.persistence.models import KnowledgeChunk, KnowledgeDocument


def main():
    from sentence_transformers import SentenceTransformer
    from huggingface_hub import snapshot_download
    from vulnmind.knowledge.model_fingerprint import MODEL, fingerprint, model_identity
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=Path(__file__).resolve().parents[1]
                        / "evaluation/owasp_retrieval_cases.json")
    cases = json.loads(parser.parse_args().cases.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases or len(cases) > 100:
        raise ValueError("invalid evaluation cases")
    manifest = fingerprint()
    model_info = model_identity(manifest)
    model_path = snapshot_download(MODEL, revision=model_info["revision"], local_files_only=True)
    model = SentenceTransformer(model_path, device="cpu", trust_remote_code=False,
                                local_files_only=True)
    vectors = model.encode([case["query"] for case in cases], prompt_name="query",
                           normalize_embeddings=True, show_progress_bar=False)
    if fingerprint() != manifest:
        raise ValueError("embedding model files changed during query encoding")
    engine = create_engine(Settings().database_url)
    try:
        with Session(engine) as session, session.begin():
            session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
            available = set(session.scalars(select(KnowledgeDocument.title)))
            if any(case["expected_title"] not in available for case in cases):
                raise ValueError("required OWASP evaluation documents are missing")
            sparse = PostgresSparseRetriever(session)
            results = []
            for case, vector in zip(cases, vectors):
                dense = PostgresDenseRetriever(session, encode=lambda _q, vector=vector: [float(v) for v in vector],
                                                expected_model_info=model_info)
                started = perf_counter()
                sparse_ids = sparse.search(case["query"], limit=10)
                sparse_ms = (perf_counter() - started) * 1000
                started = perf_counter()
                dense_ids = dense.search(case["query"], limit=10)
                dense_ms = (perf_counter() - started) * 1000
                ranks = {"sparse": sparse_ids, "dense": dense_ids}
                hybrid = [item.chunk_id for item in reciprocal_rank_fusion(ranks, limit=10)]
                def contains_expected(ids):
                    for identifier in ids[:5]:
                        title = session.scalar(select(KnowledgeDocument.title)
                            .join(KnowledgeChunk, KnowledgeChunk.document_id == KnowledgeDocument.id)
                            .where(KnowledgeChunk.id == UUID(identifier)))
                        if title == case["expected_title"]:
                            return True
                    return False
                def contains_excerpt(ids):
                    excerpt = case.get("expected_excerpt")
                    if not excerpt:
                        return None
                    for identifier in ids[:5]:
                        result = session.execute(select(KnowledgeDocument.title, KnowledgeChunk.content)
                            .join(KnowledgeChunk, KnowledgeChunk.document_id == KnowledgeDocument.id)
                            .where(KnowledgeChunk.id == UUID(identifier))).one_or_none()
                        if result is not None and result.title == case["expected_title"] and excerpt in result.content:
                            return True
                    return False
                results.append({"query": case["query"], "expected_title": case["expected_title"],
                                "sparse_hit_at_5": contains_expected(ranks["sparse"]),
                                "dense_hit_at_5": contains_expected(ranks["dense"]),
                                "hybrid_hit_at_5": contains_expected(hybrid),
                                "sparse_excerpt_hit_at_5": contains_excerpt(ranks["sparse"]),
                                "dense_excerpt_hit_at_5": contains_excerpt(ranks["dense"]),
                                "hybrid_excerpt_hit_at_5": contains_excerpt(hybrid),
                                "sparse_query_ms": round(sparse_ms, 3),
                                "dense_query_ms": round(dense_ms, 3)})
            print(json.dumps({"cases": len(results), "results": results,
                              "note": "provisional manually selected cases; not a production quality estimate"},
                             ensure_ascii=False))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
