"""Freeze provider skills and actual database retrieval with the investigation."""
import hashlib
from sqlalchemy.orm import Session
from vulnmind.integrations.hexstrike.catalog import ROOT,get_tool
from vulnmind.knowledge.skills import SkillLoader
from vulnmind.knowledge.postgres_adapters import DatabaseChunkStore,PostgresSparseRetriever


def _compact_choice(choice):
    """Keep the decision, not the whole considered list."""
    compact={key:choice.get(key) for key in ('selected','reason','policy','cost') if choice.get(key) is not None}
    blocked=[]
    for candidate in choice.get('considered') or []:
        if candidate.get('blockers'):
            blocked.append(dict(tool_id=candidate.get('tool_id'),
                                blockers=list(candidate.get('blockers'))[:3]))
        if len(blocked)>=2: break
    if blocked: compact['blocked']=blocked
    return compact


def planner_tool_context(choices, action_ids, policy):
    """Bounded planner view: external actions keep tool+cost, builtin keep IDs."""
    filtered={identifier:choices[identifier] for identifier in action_ids if identifier in choices}
    external={};builtin=[]
    for identifier,choice in filtered.items():
        selected=str(choice.get('selected') or '')
        if selected.startswith('hexstrike.'):
            external[identifier]=[selected,choice.get('cost')]
        else:
            builtin.append(identifier)
    return dict(policy=policy,external=external,builtin=builtin,compact=True)


def extend_context(engine,saved,routing,action_ids=None,*,selected_only=False):
    all_choices=routing.get('choices') or {}
    if action_ids is None:
        filtered=all_choices
    else:
        filtered={identifier:all_choices[identifier] for identifier in action_ids if identifier in all_choices}
    tool_ids={c['tool_id'] for choice in filtered.values() for c in choice.get('considered',[])
              if c['provider']=='hexstrike'}
    if selected_only: tool_ids=set()
    tool_ids.update(choice['selected'] for choice in filtered.values()
                    if str(choice.get('selected','')).startswith('hexstrike.'))
    loader=SkillLoader(ROOT/'skills')
    skill_ids={'hexstrike-planning-1'}|{get_tool(t)['skill_id'] for t in tool_ids if get_tool(t)}
    skills=[loader.load(identifier).model_dump() for identifier in sorted(skill_ids)]
    chunks={c['ref']:c for c in saved['chunks']};retrievals=[]
    queries=sorted({t.removeprefix('hexstrike.').split('_')[0] for t in tool_ids})
    with Session(engine) as session:
        retriever=PostgresSparseRetriever(session);store=DatabaseChunkStore(session)
        for query in queries:
            ids=retriever.search(query,limit=2)
            retrievals.append(dict(category='external_tool',query=query,mode='keyword',chunk_ids=ids,
                                   status='retrieved' if ids else 'no_matches',diagnostics={}))
            for identifier in ids:
                chunk=store.get(identifier)
                if chunk is None: raise ValueError('external tool knowledge disappeared')
                value=chunk.model_dump(mode='json')
                chunks['rag:'+identifier]={**value,'ref':'rag:'+identifier,
                    'sha256':hashlib.sha256(chunk.content.encode()).hexdigest()}
    if action_ids is None:
        tool_context=dict(policy=routing['policy'],choices=filtered,compact=False)
    else:
        tool_context=planner_tool_context(filtered,action_ids,routing['policy'])
    return {**saved,'skills':saved['skills']+skills,'chunks':list(chunks.values()),
            'retrievals':saved['retrievals']+retrievals,'tool_context':tool_context}
