"""Versioned diversity scheduling and bounded tool cost profiles."""
from collections import defaultdict,deque
from vulnmind.integrations.mcp.client import fingerprint


def schedule(actions):
    """Keep the full bounded catalog; interleave kinds before repeated endpoints."""
    buckets=defaultdict(deque)
    for a in actions:
        buckets[a['kind']].append(a)
    result=[]
    while any(buckets.values()):
        for bucket in buckets.values():
            if bucket: result.append(bucket.popleft())
    return result


def price(actions,routing,*,authenticated=False):
    # Per-call caps, not claims that every scanner completes under the cap.
    caps={'hexstrike.sqlmap_scan':60,'hexstrike.dalfox_xss_scan':45,'hexstrike.nuclei_scan':6}
    seen=set()
    for a in actions:
        choice=routing['choices'][a['id']];tool=choice['selected'];a['builtin_cost']=a['cost']
        identity=(tool,a['url'],a['parameter'])
        if tool in caps and (authenticated or a['method']!='GET' or a['kind']=='cors' or identity in seen):
            tool='builtin.'+a['kind'];choice.update(selected=tool,reason='request_context_or_duplicate_builtin')
        elif tool in caps: seen.add(identity)
        a.update(execution_tool=tool,cost=caps.get(tool,a['cost']))
        choice['cost']=a['cost']
    return actions


def batch_limit(round_number,used,total):
    # Keep third-round resources; release unused allocations into subsequent rounds.
    ceilings=(min(total,60),min(total,210),total)
    return max(0,ceilings[min(round_number,2)]-used)


def deduplicated_findings(observations):
    groups={}
    for o in observations:
        if o['verdict'] not in {'candidate','verified_behavior'}: continue
        family='sql_injection' if o['kind'].startswith('sql_') else o.get('category',o['kind'])
        key=fingerprint([o['method'],o['url'],o['parameter'],family])
        group=groups.setdefault(key,dict(root_cause_id=key,url=o['url'],parameter=o['parameter'],category=family,
            evidence_ids=[],methods=[],status='candidate',counts_as_confirmed_vulnerability=False))
        group['evidence_ids'].append(o.get('evidence_id'));group['methods'].append(o['kind'])
    return list(groups.values())
