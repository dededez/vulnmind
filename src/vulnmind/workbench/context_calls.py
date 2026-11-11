"""Required action/evidence indexes and budgets measured after prompt rendering."""
import hashlib
import json
from urllib.parse import urlsplit
from vulnmind.context.builder import ContextItem, ContextOverflow, build_context
from vulnmind.context.profiles import budget_for
from vulnmind.context.tokens import estimate_tokens
from vulnmind.agents.runtime import build_prompt, AgentBudgetError

POLICY = 'rendered-context-1'
# Runtime permits 60k chars. Keep room for its 20k response retry + instruction.
MAX_INITIAL_CHARS = 37_000


def action_index(actions):
    return json.dumps([dict(id=a['id'],kind=a.get('kind'),method=a.get('method'),
        url=a.get('url','')[:96],parameter=a.get('parameter'),location=a.get('parameter_location','query'),
        cost=a.get('cost'),tool=a.get('execution_tool'),
        source_supported=bool(a.get('source',{}).get('signals')),
        followup_of=a.get('followup_of')) for a in actions],ensure_ascii=False,separators=(',',':'))


def observation_index(observations):
    return json.dumps([{**{k:o.get(k) for k in ('action_id','kind','verdict','tool_state',
        'evidence_id','behavior')},'statuses':sorted(set(o.get('statuses',[]))),
        'response_count':len(o.get('response_hashes',[])),
        'response_set_sha256':hashlib.sha256(json.dumps(o.get('response_hashes',[])).encode()).hexdigest(),
        'detail':o.get('detail','')[:400]} for o in observations],ensure_ascii=False,separators=(',',':'))


def batch_index(actions):
    """Dictionary-coded columns keep all 240 identifiers within the mandatory budget."""
    kinds=list(dict.fromkeys(a['kind'] for a in actions))
    tools=list(dict.fromkeys(a.get('execution_tool','builtin.'+a['kind']) for a in actions))
    endpoints=list(dict.fromkeys(a['method']+' '+a['url'] for a in actions))
    return json.dumps(dict(columns=['id','kind','cost','tool','endpoint','parameter','source_supported'],
        kinds=kinds,tools=tools,endpoint_previews=[u.split(' ',1)[0]+' '+urlsplit(u.split(' ',1)[1]).path[:64] for u in endpoints],
        actions=[[a['id'],kinds.index(a['kind']),a['cost'],tools.index(a.get('execution_tool','builtin.'+a['kind'])),
            endpoints.index(a['method']+' '+a['url']),a.get('parameter',''),bool(a.get('source',{}).get('signals'))] for a in actions]),
        ensure_ascii=False,separators=(',',':'))


def assemble(items, profile, spec, task, schema):
    budget=budget_for(profile)
    if schema.__name__=='BatchPlan': budget.by_group['candidates']=8_000
    selected, manifest = build_context(items,budget)
    required={i.ref for i in items if i.required or i.kind in {'system','task'}}
    rows={r['ref']:r for r in manifest['items']}
    while True:
        refs=[i for i in selected if i.kind not in {'system','task'}]
        try:
            messages=build_prompt(spec,task,refs,schema)
            rendered='\n'.join(m.content for m in messages)
            fits=len(rendered)<=MAX_INITIAL_CHARS and estimate_tokens(rendered)+spec.max_output_tokens<=24_000
        except AgentBudgetError:
            fits=False
        if fits: break
        removable=[i for i in selected if i.ref not in required]
        if not removable: raise ContextOverflow('required rendered context exceeds budget; split the batch')
        removed=removable[-1]
        selected.remove(removed)
        rows[removed.ref].update(selected=False,reason='rendered_prompt_budget')
    by_group={}
    for i in selected:
        group=i.budget_group or i.kind
        by_group[group]=by_group.get(group,0)+estimate_tokens(i.text)
    for i in items: rows[i.ref].update(sha256=hashlib.sha256(i.text.encode()).hexdigest(),required=i.ref in required)
    manifest.update(policy_version=POLICY,estimated_tokens=sum(by_group.values()),by_group=by_group,
        rendered_chars=len(rendered),rendered_estimated_tokens=estimate_tokens(rendered),
        rendered_sha256=hashlib.sha256(rendered.encode()).hexdigest(),retry_reserved_chars=23_000)
    return selected, manifest


def validate_manifest(value, knowledge, stage):
    manifest=value.get('context_manifest')
    if not manifest: raise ValueError('model context manifest missing')
    rows=manifest.get('items',[])
    if len({r['ref'] for r in rows})!=len(rows): raise ValueError('duplicate manifest reference')
    sent={r['ref']:r for r in rows if r.get('selected')}
    if any(ref not in sent for ref in value.get('knowledge_refs',[])):
        raise ValueError('model cited unsent knowledge')
    if manifest.get('policy_version')==POLICY:
        required={'system','task','candidates' if stage.startswith('plan_') else 'observations'}
        if not required.issubset(sent): raise ValueError('required context missing')
        if any(r.get('required') and not r.get('selected') for r in rows): raise ValueError('required context dropped')
        known={'skill:'+s['skill_id']:s['content'] for s in knowledge['skills']}
        known.update({c['ref']:c['content'] for c in knowledge['chunks']})
        for ref,row in sent.items():
            if ref.startswith(('skill:','rag:')) and (ref not in known or row['sha256']!=hashlib.sha256(known[ref].encode()).hexdigest()):
                raise ValueError('manifest knowledge hash mismatch')
        if manifest['rendered_chars']>MAX_INITIAL_CHARS: raise ValueError('rendered context budget mismatch')
