"""Persistable skill and RAG context, shared by planner and independent critic."""
import hashlib
import threading
from pathlib import Path

from sqlalchemy.orm import Session

from vulnmind.knowledge.skills import SkillLoader
from vulnmind.knowledge.postgres_adapters import DatabaseChunkStore,PostgresSparseRetriever

_lock=threading.Lock()
_encoder=None
QUERIES={
    'information_disclosure':'information disclosure directory listing debug stack trace false positives',
    'nosql_injection':'NoSQL injection input type validation query operators',
    'sql_injection':'SQL injection boolean differential parameterized queries false positives',
    'xss':'cross site scripting XSS output encoding HTML context reflected input',
    'ssti':'server side template injection expression evaluation untrusted template',
    'cors':'CORS origin credentials access control sensitive response',
    'security_headers':'HTTP security headers content security policy nosniff HTML',
    'ssrf':'server side request forgery SSRF outbound URL validation',
    'path_traversal':'path traversal file access canonical path validation',
    'command_injection':'OS command injection argument separation shell execution',
    'deserialization':'insecure deserialization untrusted data safe formats',
    'xxe':'XML external entity XXE parser external entities',
    'open_redirect':'unvalidated redirect destination allowlist',
    'broken_authentication':'weak password default credentials authentication bypass login',
    'broken_access_control':'object level authorization IDOR horizontal privilege basket ownership',
}
ROOT=Path(__file__).parent/'resources'


def snapshot(engine,categories,mode):
    """No fallback: failure is a recoverable stage error, empty is explicit."""
    global _encoder
    loader=SkillLoader(ROOT/'skills')
    skills=[loader.load(m.skill_id).model_dump() for m in loader.available() if m.vuln_type in categories]
    missing=set(categories)-{s['vuln_type'] for s in skills}
    if missing: raise ValueError('missing required detector skills: '+','.join(sorted(missing)))
    retrievals=[];chunks={}
    with _lock,Session(engine) as session:
        if mode=='hybrid':
            from vulnmind.knowledge.hybrid import LocalQueryEncoder,PostgresHybridRetriever
            if _encoder is None: _encoder=LocalQueryEncoder()
            retriever=PostgresHybridRetriever(session,encoder=_encoder)
        elif mode=='keyword': retriever=PostgresSparseRetriever(session)
        else: raise ValueError('unknown retrieval mode')
        store=DatabaseChunkStore(session)
        for category in sorted(categories):
            query=QUERIES[category]
            if mode=='hybrid':
                found=retriever.search_with_diagnostics(query,limit=3)
                ids=list(found.identifiers)
                diagnostics=dict(sparse_count=found.sparse_count,dense_count=found.dense_count,fused=list(found.fused))
            else:
                # PostgreSQL plain text query ANDs tokens; use category-specific terms.
                query={'sql_injection':'SQL injection','xss':'XSS','ssti':'template injection',
                       'cors':'CORS','security_headers':'security headers'}.get(category,category.replace('_',' '))
                ids=retriever.search(query,limit=3);diagnostics={}
            retrievals.append(dict(category=category,query=query,mode=mode,chunk_ids=ids,
                                   status='retrieved' if ids else 'no_matches',diagnostics=diagnostics))
            for identifier in ids:
                chunk=store.get(identifier)
                if chunk is None: raise ValueError('retrieved knowledge chunk disappeared')
                value=chunk.model_dump(mode='json')
                chunks[identifier]={**value,'ref':'rag:'+identifier,
                    'sha256':hashlib.sha256(chunk.content.encode()).hexdigest()}
    return dict(schema_version='knowledge-1',mode=mode,encoder=dict(_encoder.model_info) if mode=='hybrid' else None,
                skills=skills,chunks=list(chunks.values()),retrievals=retrievals,
                interpretation='知识支持方法和复核，不构成目标漏洞证据；无匹配不会伪造引用')


def context(saved):
    from vulnmind.context.builder import ContextItem
    import json
    return ([ContextItem(ref='skill:'+s['skill_id'],kind='skill',text=s['content']) for s in saved['skills']]
            +[ContextItem(ref=c['ref'],kind='rag',text=c['content']) for c in saved['chunks']]
            +([ContextItem(ref='tool-routing',kind='execution',text=json.dumps(saved['tool_context'],ensure_ascii=False))]
              if saved.get('tool_context') else []))


def filter_references(refs, allowed):
    """Return (valid unique refs, unknown unique refs) without raising."""
    valid, unknown = [], []
    for ref in refs:
        if ref in allowed:
            if ref not in valid:
                valid.append(ref)
        elif ref not in unknown:
            unknown.append(ref)
    return valid, unknown


def validate_references(refs,saved,*,strict=True,allowed=None):
    if allowed is None:
        allowed={'skill:'+s['skill_id'] for s in saved['skills']}|{c['ref'] for c in saved['chunks']}
    valid,unknown=filter_references(refs,allowed)
    if unknown and strict: raise ValueError('agent cited unknown knowledge reference')
    return valid
