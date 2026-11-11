import pytest
from vulnmind.knowledge.chunking import KnowledgeDocument, chunk_document


def test_chunking_offsets_overlap_and_provenance_are_reproducible():
    doc = KnowledgeDocument(document_id="doc", content="abcdef中文gh", source="ref", version="v1", language="python")
    chunks = chunk_document(doc, size=5, overlap=2)
    assert [(chunk.start_offset, chunk.end_offset) for chunk in chunks] == [(0, 5), (3, 8), (6, 10)]
    assert all(chunk.content == doc.content[chunk.start_offset:chunk.end_offset] for chunk in chunks)
    assert all(chunk.source == "ref" and chunk.language == "python" for chunk in chunks)
    assert chunks == chunk_document(doc, size=5, overlap=2)
    newer = doc.model_copy(update={"version": "v2"})
    assert chunks[0].chunk_id != chunk_document(newer, size=5, overlap=2)[0].chunk_id


@pytest.mark.parametrize("size,overlap", [(0, 0), (5, 5), (5, -1), (True, 0)])
def test_invalid_chunk_windows_rejected(size, overlap):
    with pytest.raises(ValueError):
        chunk_document(KnowledgeDocument(document_id="d", content="text", source="source"), size=size, overlap=overlap)


def test_blank_windows_are_not_indexed():
    doc = KnowledgeDocument(document_id="d", content="x          y", source="source")
    chunks = chunk_document(doc, size=3, overlap=0)
    assert all(chunk.content.strip() for chunk in chunks)
    assert [chunk.content for chunk in chunks] == ["x  ", "  y"]


def test_chunk_rejects_inconsistent_provenance_offsets():
    from vulnmind.knowledge.retrieval import KnowledgeChunk
    with pytest.raises(ValueError, match="span"):
        KnowledgeChunk(chunk_id="c", document_id="d", content="abc", source="s", start_offset=5, end_offset=7)


def test_chunking_rejects_excessive_overlapping_windows():
    doc = KnowledgeDocument(document_id="d", content="x" * 10002, source="source")
    with pytest.raises(ValueError, match="window limit"):
        chunk_document(doc, size=2, overlap=1)


def test_chunking_rejects_excessive_total_chunk_characters():
    doc = KnowledgeDocument(document_id="d", content="x" * 1_000_020, source="source")
    with pytest.raises(ValueError, match="total chunk character limit"):
        chunk_document(doc, size=1_000_000, overlap=999_999)
