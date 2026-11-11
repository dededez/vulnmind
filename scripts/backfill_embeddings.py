"""Backfill dense embeddings for stored knowledge chunks.

Encodes chunk text with a local sentence-transformers model and stores the
vectors through the same validation path as the application. Documents are
encoded without an instruction prompt; queries must use the model's ``query``
prompt (see the model card), so do not reuse this script for query encoding.

The model runs locally: the only network use is sentence-transformers fetching
model weights on first run. Nothing is sent to an external API.

Usage (run from the project root so the project ``.env`` is read):

    .venv\\Scripts\\python.exe scripts\\backfill_embeddings.py
    .venv\\Scripts\\python.exe scripts\\backfill_embeddings.py --device cuda

By default existing vectors are recomputed and compared before filling NULLs;
``--all`` explicitly replaces all vectors in a single transaction. The script
does not persist model provenance. It refuses a mismatched existing vector and
also refuses to run when the model's dimension does not match
``EMBEDDING_DIMENSIONS``; resize the schema with a migration first.
"""
from __future__ import annotations

import argparse
import json
from collections.abc import Iterator

from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session

from vulnmind.config import Settings
from vulnmind.knowledge.vector import EMBEDDING_DIMENSIONS, validate_vector
from vulnmind.persistence.models import KnowledgeChunk
from vulnmind.persistence.repositories import KnowledgeRepository

DEFAULT_MODEL = "Qwen/Qwen3-Embedding-0.6B"
MAX_CHUNKS = 5000
MAX_TOTAL_CHARACTERS = 10_000_000
COMPARISON_TOLERANCE = 0.000002


def _batches(rows: list[KnowledgeChunk], size: int) -> Iterator[list[KnowledgeChunk]]:
    for start in range(0, len(rows), size):
        yield rows[start:start + size]


def backfill(session: Session, model, *, batch_size: int, replace_all: bool = False) -> tuple[int, int]:
    """Verify existing vectors and atomically update a bounded, locked corpus.

    The caller owns the transaction. The table lock coordinates with ordinary
    database writes until commit; the comparison tests numerical consistency,
    not provenance or authenticity of the model files.
    """
    if session.get_bind().dialect.name != "postgresql":
        raise ValueError("dense embeddings require PostgreSQL")
    if session.new or session.dirty or session.deleted:
        raise ValueError("backfill requires a clean dedicated session")
    isolation = session.execute(text("SHOW transaction_isolation")).scalar_one()
    if isolation.lower() != "read committed":
        raise ValueError("backfill requires READ COMMITTED isolation")
    session.execute(text("LOCK TABLE knowledge_chunks IN SHARE ROW EXCLUSIVE MODE"))
    count, characters = session.execute(select(func.count(KnowledgeChunk.id),
        func.coalesce(func.sum(func.length(KnowledgeChunk.content)), 0))).one()
    if count > MAX_CHUNKS or characters > MAX_TOTAL_CHARACTERS:
        raise ValueError("knowledge corpus exceeds backfill limits")
    chunks = list(session.scalars(select(KnowledgeChunk).execution_options(populate_existing=True)
                                  .order_by(KnowledgeChunk.document_id, KnowledgeChunk.chunk_index)
                                  .limit(MAX_CHUNKS)))
    if any(isinstance(row.metadata_, dict) and "embedding_provenance_v1" in row.metadata_ for row in chunks):
        raise ValueError("provenance-tagged embeddings require the provenance-aware backfill")
    if not 1 <= batch_size <= 128:
        raise ValueError("batch size must be between 1 and 128")
    computed = []
    checked = 0
    for batch in _batches(chunks, batch_size):
        vectors = model.encode([chunk.content for chunk in batch], batch_size=len(batch),
                               normalize_embeddings=True, show_progress_bar=False)
        if len(vectors) != len(batch):
            raise ValueError("embedding model returned the wrong number of vectors")
        for chunk, vector in zip(batch, vectors):
            validated = validate_vector([float(value) for value in vector])
            if chunk.embedding is not None and not replace_all:
                try:
                    previous = validate_vector([float(value) for value in chunk.embedding])
                except (TypeError, ValueError, OverflowError):
                    raise ValueError("existing embeddings are invalid") from None
                if any(abs(old - new) > COMPARISON_TOLERANCE
                       for old, new in zip(previous, validated)):
                    raise ValueError("existing embeddings do not match the current model and content")
                checked += 1
            else:
                computed.append((chunk.id, validated))
    repository = KnowledgeRepository(session)
    for chunk_id, vector in computed:
        repository.set_embedding(chunk_id, vector)
    return len(computed), checked


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill knowledge chunk embeddings locally")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="configured model id (alternatives currently blocked)")
    parser.add_argument("--device", default=None, help="torch device, for example cuda or cpu")
    parser.add_argument("--batch-size", type=int, default=16, help="chunks per encode call")
    parser.add_argument("--all", action="store_true", help="atomically re-embed the entire bounded corpus")
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 128:
        raise SystemExit("batch size must be between 1 and 128")
    # Dimension alone does not identify a compatible embedding space. Until
    # model provenance is stored per chunk, do not mix alternative models.
    if args.model != DEFAULT_MODEL:
        raise SystemExit("only the configured embedding model is supported; model provenance is not stored")

    settings = Settings()
    if not settings.database_url:
        raise SystemExit("VULNMIND_DATABASE_URL is not configured")
    if settings.database_url.startswith("sqlite"):
        raise SystemExit("dense embeddings require PostgreSQL with pgvector")

    try:
        from sentence_transformers import SentenceTransformer
    except ModuleNotFoundError:
        raise SystemExit("sentence-transformers is not installed in this environment") from None

    model = SentenceTransformer(args.model, device=args.device, trust_remote_code=False)
    dimensions = model.get_sentence_embedding_dimension()
    if dimensions != EMBEDDING_DIMENSIONS:
        raise SystemExit(
            f"model emits {dimensions} dimensions but the schema stores {EMBEDDING_DIMENSIONS}; "
            "add a migration (and re-embed every chunk) before switching models")

    engine = create_engine(settings.database_url)
    try:
        with Session(engine) as session, session.begin():
            embedded, verified = backfill(session, model, batch_size=args.batch_size, replace_all=args.all)
    finally:
        engine.dispose()
    print(json.dumps({"model": args.model, "dimensions": dimensions, "embedded": embedded,
                      "existing_verified": verified},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
