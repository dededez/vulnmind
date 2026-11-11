"""Bounded in-memory lexical retrieval for local evaluation.

This is a sparse keyword index, not a dense embedding or a trust decision. It
does not persist data, call models, or contact an external service. Tokenization
is intentionally simple and does not provide Chinese word segmentation.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import math
import re
from collections.abc import Sequence

from vulnmind.knowledge.retrieval import KnowledgeChunk

MAX_DOCUMENTS = 1_000
MAX_TOTAL_CHARACTERS = 1_000_000
MAX_TOKENS = 200_000
_TOKEN = re.compile(r"[^\W_]+", re.UNICODE)


def _tokens(text: str) -> list[str]:
    return _TOKEN.findall(text.casefold())


class InMemoryLexicalIndex:
    """A small BM25 index implementing both Retriever and ChunkStore."""

    def __init__(self, chunks: Sequence[KnowledgeChunk]):
        if not isinstance(chunks, (list, tuple)) or len(chunks) > MAX_DOCUMENTS:
            raise ValueError("lexical index exceeds its document limit")
        self._chunks: dict[str, KnowledgeChunk] = {}
        self._postings: dict[str, list[tuple[str, int]]] = defaultdict(list)
        self._lengths: dict[str, int] = {}
        characters = tokens = 0
        for original in chunks:
            if not isinstance(original, KnowledgeChunk):
                raise ValueError("lexical index requires knowledge chunks")
            chunk = KnowledgeChunk.model_validate(original.model_dump())
            if chunk.chunk_id in self._chunks:
                raise ValueError("duplicate knowledge chunk ID")
            characters += len(chunk.content)
            if characters > MAX_TOTAL_CHARACTERS:
                raise ValueError("lexical index exceeds its character limit")
            words = _tokens(chunk.content)
            tokens += len(words)
            if tokens > MAX_TOKENS:
                raise ValueError("lexical index exceeds its token limit")
            self._chunks[chunk.chunk_id] = chunk
            self._lengths[chunk.chunk_id] = len(words)
            for token, count in Counter(words).items():
                self._postings[token].append((chunk.chunk_id, count))
        self._average_length = tokens / len(self._chunks) if self._chunks else 0.0

    def get(self, chunk_id: str) -> KnowledgeChunk | None:
        chunk = self._chunks.get(chunk_id)
        return chunk.model_copy(deep=True) if chunk is not None else None

    def search(self, query: str, *, limit: int) -> list[str]:
        if not isinstance(query, str) or not query.strip() or len(query) > 4096:
            raise ValueError("search query must contain 1 to 4096 characters")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("search limit must be between 1 and 100")
        if not self._average_length:
            return []
        scores: dict[str, float] = defaultdict(float)
        for token in sorted(set(_tokens(query))):
            postings = self._postings.get(token, ())
            if not postings:
                continue
            idf = math.log1p((len(self._chunks) - len(postings) + 0.5) / (len(postings) + 0.5))
            for chunk_id, frequency in postings:
                length = self._lengths[chunk_id]
                denominator = frequency + 1.2 * (0.25 + 0.75 * length / self._average_length)
                scores[chunk_id] += idf * frequency * 2.2 / denominator
        return sorted(scores, key=lambda chunk_id: (-scores[chunk_id], chunk_id))[:limit]
