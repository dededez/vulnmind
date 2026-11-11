"""Ingest a JSON corpus of knowledge documents into the RAG tables.

The project's knowledge base lives in ``knowledge_documents`` /
``knowledge_chunks``, not in files; this script is a thin batch front end for
``vulnmind.knowledge.ingestion.ingest_document`` so a corpus file can be loaded
without one CLI call per document.

Usage (run from the project root so the project ``.env`` is read):

    .venv\\Scripts\\python.exe scripts\\ingest_corpus.py evaluation\\corpus.json

Each array item needs ``content`` and ``source_type``. ``title`` defaults to
``"<source_type> <source>"`` when ``source`` is present; ``source_url``,
``version``, ``trust_level`` and ``id`` (kept as ``corpus_id`` metadata) are
optional. Items whose title already exists are skipped, so re-running the same
corpus is safe.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from vulnmind.config import Settings
from vulnmind.knowledge.ingestion import ingest_document
from vulnmind.knowledge.chunking import KnowledgeDocument as ChunkDocument, chunk_document
from vulnmind.persistence.models import KnowledgeChunk, KnowledgeDocument

MAX_CORPUS_BYTES = 5_000_000


def load_items(path: Path) -> list[dict]:
    if not path.is_file():
        raise SystemExit(f"corpus file not found: {path}")
    with path.open("rb") as stream:
        data = stream.read(MAX_CORPUS_BYTES + 1)
    if len(data) > MAX_CORPUS_BYTES:
        raise SystemExit("corpus file is too large")
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise SystemExit("corpus must be a UTF-8 JSON array") from None
    if not isinstance(parsed, list) or not parsed:
        raise SystemExit("corpus must be a non-empty JSON array")
    if any(not isinstance(item, dict) for item in parsed):
        raise SystemExit("every corpus item must be a JSON object")
    return parsed


def item_title(item: dict) -> str | None:
    title = item.get("title")
    if isinstance(title, str) and title.strip():
        return title.strip()[:1000]
    source = item.get("source")
    source_type = item.get("source_type")
    if isinstance(source, str) and source.strip() and isinstance(source_type, str):
        return f"{source_type.strip()} {source.strip()}"[:1000]
    return None


def _matches_existing(session, document, *, content, source_type, source_url, version,
                      trust_level, metadata, size, overlap):
    """Only skip an exact re-import; a title collision must never hide changes."""
    if (document.source_type != source_type or document.source_url != source_url
            or document.version != version or document.trust_level != trust_level
            or document.metadata_ != metadata):
        return False
    incoming = ChunkDocument(document_id=str(document.id), content=content,
                             source=source_url or document.title, version=version,
                             source_type=source_type, trust_level=trust_level)
    expected = [item.content for item in chunk_document(incoming, size=size, overlap=overlap)]
    stored = list(session.scalars(select(KnowledgeChunk.content)
                                  .where(KnowledgeChunk.document_id == document.id)
                                  .order_by(KnowledgeChunk.chunk_index)))
    return stored == expected


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest a JSON corpus into PostgreSQL knowledge tables")
    parser.add_argument("corpus", type=Path, help="UTF-8 JSON array of knowledge documents")
    parser.add_argument("--size", type=int, default=1000, help="chunk size in characters")
    parser.add_argument("--overlap", type=int, default=100, help="chunk overlap in characters")
    args = parser.parse_args()

    settings = Settings()
    if not settings.database_url:
        raise SystemExit("VULNMIND_DATABASE_URL is not configured")
    if settings.database_url.startswith("sqlite"):
        raise SystemExit("knowledge ingestion requires PostgreSQL (sparse index and metadata filters)")

    items = load_items(args.corpus)
    engine = create_engine(settings.database_url)
    ingested = skipped = chunks = 0
    with Session(engine) as session:
        for index, item in enumerate(items, start=1):
            content = item.get("content")
            source_type = item.get("source_type")
            if not isinstance(content, str) or not content.strip():
                raise SystemExit(f"item {index}: content must be a non-blank string")
            if not isinstance(source_type, str) or not source_type.strip():
                raise SystemExit(f"item {index}: source_type must be a non-blank string")
            title = item_title(item)
            if title is None:
                raise SystemExit(f"item {index}: needs a title or source/source_type pair")
            metadata = {"corpus_id": item["id"]} if isinstance(item.get("id"), str) and item["id"].strip() else {}
            for key in ('vulnerability_type','language','framework'):
                if key in item:
                    if not isinstance(item[key],str) or not item[key].strip() or len(item[key])>128:
                        raise SystemExit(f'item {index}: invalid {key}')
                    metadata[key]=item[key]
            license_name = item.get("license")
            if license_name is not None:
                if not isinstance(license_name, str) or not license_name.strip() or len(license_name) > 128:
                    raise SystemExit(f"item {index}: invalid license")
                metadata["license"] = license_name.strip()
            digest = item.get("content_sha256")
            if digest is not None:
                actual = hashlib.sha256(content.encode("utf-8")).hexdigest()
                if not isinstance(digest, str) or digest != actual:
                    raise SystemExit(f"item {index}: content hash mismatch")
                metadata["content_sha256"] = actual
            metadata = metadata or None
            source_url = item.get("source_url") if isinstance(item.get("source_url"), str) else None
            version = item.get("version") if isinstance(item.get("version"), str) else None
            trust_level = item.get("trust_level") if isinstance(item.get("trust_level"), str) else None
            existing = list(session.scalars(select(KnowledgeDocument).where(KnowledgeDocument.title == title).limit(2)))
            if existing:
                if len(existing) != 1 or not _matches_existing(
                        session, existing[0], content=content, source_type=source_type.strip(),
                        source_url=source_url, version=version, trust_level=trust_level,
                        metadata=metadata, size=args.size, overlap=args.overlap):
                    raise SystemExit(f"item {index}: title conflicts with existing knowledge")
                skipped += 1
                continue
            result = ingest_document(
                session, title=title, content=content, source_type=source_type.strip(),
                source_url=source_url, version=version, trust_level=trust_level,
                metadata=metadata, size=args.size, overlap=args.overlap)
            ingested += 1
            chunks += result.chunk_count
        session.commit()
    print(json.dumps({"ingested": ingested, "skipped": skipped, "chunks": chunks}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
