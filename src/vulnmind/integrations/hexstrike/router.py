"""Pure eligibility-first routing. This does not execute or grant permission."""
from vulnmind.integrations.mcp.client import fingerprint


def select_tool(capability, candidates, *, policy='external_preferred', pinned=None, unknown_execution=False):
    if policy not in {'external_preferred','builtin_only'}: raise ValueError('unknown tool policy')
    if unknown_execution:
        return dict(selected=None,reason='reconciliation_required',considered=[],policy=policy)
    considered=[];eligible=[]
    for item in candidates:
        if capability not in item['capabilities']: continue
        blockers=list(item.get('blockers',[]))
        if not item.get('eligible'): blockers=blockers or ['not_eligible']
        if policy=='builtin_only' and item['provider']!='builtin': blockers.append('builtin_only_policy')
        if pinned and item['tool_id']!=pinned: blockers.append('user_pinned_another_tool')
        considered.append(dict(tool_id=item['tool_id'],provider=item['provider'],blockers=blockers))
        if not blockers: eligible.append(item)
    eligible.sort(key=lambda t:(0 if t['provider']=='hexstrike' else 1,t['tool_id']))
    chosen=eligible[0] if eligible else None
    return dict(selected=chosen['tool_id'] if chosen else None,
                reason=('user_pinned' if pinned else 'eligible_external_preferred' if chosen and chosen['provider']=='hexstrike'
                        else 'explicit_builtin_fallback' if chosen else 'no_eligible_tool'),
                policy=policy,considered=considered)


def workbench_snapshot(actions, *, policy='external_preferred', validation=None):
    from vulnmind.integrations.hexstrike.catalog import directory
    saved=directory(validation=validation)
    # Workbench v3 prefers validated external MCP tools when validation receipts
    # are supplied, and falls back to exact-request builtin execution otherwise.
    candidates=saved['tools']+[dict(tool_id='builtin.'+a['kind'],provider='builtin',
                                   capabilities=[a['kind']],eligible=True,blockers=[]) for a in actions]
    unique={c['tool_id']:c for c in candidates}
    choices={a['id']:select_tool(a['kind'],list(unique.values()),policy=policy) for a in actions}
    return dict(version=1,policy=policy,upstream_commit=saved['upstream_commit'],
                catalog_sha256=fingerprint(saved),choices=choices,
                interpretation='能力等价且验证通过后外部优先；未知执行先对账；本快照固定用于恢复')
