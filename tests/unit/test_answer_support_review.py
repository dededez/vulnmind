"""Separate model review must fail closed; fake judgments do not prove accuracy."""
import json

import pytest

from vulnmind.agents.model import ModelResponse
from vulnmind.agents.runtime import AgentRuntime
from vulnmind.knowledge.answer import answer_question
from vulnmind.knowledge.retrieval import KnowledgeChunk


class Audit:
    def record(self, event):
        pass


class Model:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def complete(self, request):
        self.requests.append(request)
        if self.response is None:
            raise RuntimeError("private provider error")
        return ModelResponse(text=json.dumps(self.response))


def runtime(response):
    model = Model(response)
    return AgentRuntime(model, Audit()), model


def inputs():
    chunks = [KnowledgeChunk(chunk_id="1", document_id="a", content="Use bound parameters.", source="local"),
              KnowledgeChunk(chunk_id="2", document_id="b", content="Contradictory reference.", source="local")]
    draft = {"answer": "bound parameters", "cited_refs": ["knowledge:0"],
             "supporting_quotes": [{"ref": "knowledge:0", "quote": "bound parameters"}]}
    return chunks, draft


@pytest.mark.parametrize("review", [
    {"relevant": False, "supported": True, "conflicting": False},
    {"relevant": True, "supported": False, "conflicting": False},
    {"relevant": True, "supported": True, "conflicting": True},
])
def test_review_rejects_and_sees_uncited_context(review):
    chunks, draft = inputs()
    producer, _ = runtime(draft)
    reviewer, model = runtime(review)
    result = answer_question("How?", chunks, producer, review_runtime=reviewer)
    assert result.status == "insufficient_evidence" and result.review_status == "rejected"
    assert not any(ref.cited for ref in result.references)
    assert "Contradictory reference." in " ".join(m.content for m in model.requests[0].messages)


def test_review_acceptance_does_not_claim_verified_support():
    chunks, draft = inputs()
    producer, _ = runtime(draft)
    reviewer, _ = runtime({"relevant": True, "supported": True, "conflicting": False})
    result = answer_question("How?", chunks, producer, review_runtime=reviewer)
    assert result.status == "answered" and result.review_status == "accepted"
    assert result.references[0].support_verified is False


@pytest.mark.parametrize("response", [None, {"relevant": "true", "supported": True, "conflicting": False}])
def test_failed_or_invalid_review_abstains(response):
    chunks, draft = inputs()
    producer, _ = runtime(draft)
    reviewer, _ = runtime(response)
    result = answer_question("How?", chunks, producer, review_runtime=reviewer)
    assert result.status == "insufficient_evidence" and result.review_status == "failed"
    assert "private provider error" not in result.answer
