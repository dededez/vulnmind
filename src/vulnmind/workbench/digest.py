"""Compact round digest for bounded multi-round context.

The digest keeps what a planner or critic still needs: unfinished actions,
candidate/verified observations, disputed actions and the most recent round.
Completed and undisputed history is reduced to a reference, not replayed in
full. It is advisory context, never evidence.
"""

MAX_DETAIL = 240
MAX_LIST = 40
RECENT_LIMIT = 8


def _statuses(value):
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, int)][:32]


def _compact(observation):
    return dict(
        action_id=observation.get('action_id'),
        kind=observation.get('kind'),
        url=observation.get('url'),
        parameter=observation.get('parameter'),
        verdict=observation.get('verdict'),
        tool_state=observation.get('tool_state'),
        statuses=_statuses(observation.get('statuses')),
        evidence_id=observation.get('evidence_id'),
        external_tool=observation.get('external_tool'),
        detail=str(observation.get('detail') or '')[:MAX_DETAIL],
    )


def _disputed(critique):
    if isinstance(critique, dict):
        return list(critique.get('disputed_action_ids') or [])
    ids = []
    for item in critique or []:
        if isinstance(item, dict):
            ids.extend(item.get('disputed_action_ids') or [])
    return list(dict.fromkeys(ids))


def build_digest(observations, remaining, critique=None, *, requests_used=None, budget_total=None):
    """Return a JSON-safe digest; lists are capped so growth stays bounded."""
    observations = [item for item in (observations or []) if isinstance(item, dict)]
    remaining = [item for item in (remaining or []) if isinstance(item, dict)]
    attempted = {item.get('action_id') for item in observations if item.get('action_id')}
    active = [_compact(item) for item in observations
              if item.get('verdict') in {'candidate', 'verified_behavior'}]
    pending = [dict(id=item.get('id'), kind=item.get('kind'), url=item.get('url'),
                    parameter=item.get('parameter'), cost=item.get('cost'))
               for item in remaining[:MAX_LIST]]
    recent = [_compact(item) for item in observations[-RECENT_LIMIT:]]
    digest = dict(
        schema_version='round-digest-1',
        coverage=dict(total=len(attempted) + len(remaining),
                      completed=len(attempted), pending=len(remaining)),
        active_findings=active[:20],
        pending_actions=pending,
        disputed_actions=_disputed(critique),
        recent_actions=recent,
        interpretation='摘要不是证据；需要完整内容时按 evidence_id/action_id 读取',
    )
    if requests_used is not None:
        digest['requests_used'] = int(requests_used)
    if budget_total is not None:
        digest['budget_total'] = int(budget_total)
    return digest
