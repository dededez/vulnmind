"""Opt-in knowledge guidance for repository findings using fixed queries."""
from vulnmind.context.scan_manifest import _BANDIT_QUERIES, _FINDING_QUERIES
from vulnmind.knowledge.answer import answer_question


def scan_knowledge_advisor(retriever, store, runtime):
    if not callable(getattr(retriever, "search", None)) or not callable(getattr(store, "get", None)):
        raise ValueError("knowledge retrieval interfaces are required")

    def advise(analysis, actor):
        candidates = [candidate for group in analysis.groups for candidate in group.candidates]
        types = {item.vulnerability_type for item in candidates}
        queries = [_FINDING_QUERIES[name] for name in sorted(types & _FINDING_QUERIES.keys())]
        bandit = {item.vulnerability_type for item in candidates
                  if item.source_tool == "bandit" and item.vulnerability_type in _BANDIT_QUERIES}
        queries = list(dict.fromkeys([*queries, *(_BANDIT_QUERIES[name] for name in sorted(bandit))]))
        ids = []
        for query in queries:
            results = retriever.search(query, limit=10)
            if not isinstance(results, list) or len(results) > 10 or len(results) != len(set(results)):
                raise ValueError("invalid knowledge retrieval results")
            for identifier in results:
                if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 255:
                    raise ValueError("invalid knowledge reference")
                if identifier not in ids:
                    ids.append(identifier)
        chunks = [store.get(identifier) for identifier in ids[:20]]
        if any(chunk is None or chunk.chunk_id != identifier for identifier, chunk in zip(ids, chunks)):
            raise ValueError("knowledge reference could not be resolved")
        question = ("Provide general security guidance for these possible categories: " + ", ".join(queries)
                    + ". Do not claim any specific vulnerability is confirmed.")
        if not queries:
            return None
        return answer_question(question, chunks, runtime, actor=actor, review_runtime=runtime)
    return advise
