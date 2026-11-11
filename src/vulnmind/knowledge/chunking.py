"""Deterministic text chunking; no network access or storage side effects."""
import hashlib
import json

from pydantic import BaseModel, ConfigDict, Field, field_validator
from vulnmind.knowledge.retrieval import KnowledgeChunk

MAX_DOCUMENT_CHARACTERS = 10_000_000
MAX_CHUNK_WINDOWS = 10_000
MAX_CHUNK_CHARACTERS = 1_000_000
MAX_CHUNKED_CHARACTERS = 20_000_000


class KnowledgeDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document_id: str = Field(min_length=1)
    content: str = Field(min_length=1)
    source: str = Field(min_length=1)
    version: str | None = None
    source_type: str | None = None
    vulnerability_type: str | None = None
    language: str | None = None
    framework: str | None = None
    trust_level: str | None = None

    @field_validator("document_id", "content", "source")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("document ID, content and source must not be blank")
        return value


def chunk_document(document: KnowledgeDocument, *, size: int = 1000, overlap: int = 100) -> list[KnowledgeChunk]:
    if (isinstance(size, bool) or isinstance(overlap, bool) or not isinstance(size, int)
            or not isinstance(overlap, int) or not 0 < size <= MAX_CHUNK_CHARACTERS or not 0 <= overlap < size):
        raise ValueError("require integer size > overlap >= 0 within the configured limit")
    length = len(document.content)
    if length > MAX_DOCUMENT_CHARACTERS:
        raise ValueError("knowledge document exceeds the character limit")
    windows = 1 if length <= size else 1 + (length - size + (size - overlap) - 1) // (size - overlap)
    if windows > MAX_CHUNK_WINDOWS:
        raise ValueError("knowledge document exceeds the chunk window limit")
    total_characters = (windows - 1) * size + length - (windows - 1) * (size - overlap)
    if total_characters > MAX_CHUNKED_CHARACTERS:
        raise ValueError("knowledge document exceeds the total chunk character limit")
    result = []
    start = 0
    metadata = document.model_dump(exclude={"content", "document_id"})
    while start < len(document.content):
        end = min(start + size, len(document.content))
        content = document.content[start:end]
        if content.strip():
            identity = json.dumps([document.document_id, document.version, start, end, content], ensure_ascii=False, separators=(",", ":"))
            result.append(KnowledgeChunk(chunk_id=hashlib.sha256(identity.encode("utf-8")).hexdigest(),
                                         document_id=document.document_id, content=content,
                                         start_offset=start, end_offset=end, **metadata))
        if end == len(document.content):
            break
        start = end - overlap
    return result
