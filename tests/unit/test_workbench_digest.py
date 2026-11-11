import json

from vulnmind.integrations.hexstrike.knowledge import _compact_choice, planner_tool_context
from vulnmind.workbench.digest import build_digest


def test_digest_keeps_pending_candidates_disputed_and_recent():
    observations = [
        dict(action_id='a1', kind='sql_boolean', url='http://x/?q=1', parameter='q',
             verdict='candidate', tool_state='candidate', statuses=[200, 500],
             evidence_id='e1', detail='x' * 2000),
        dict(action_id='a2', kind='xss_context', url='http://x/p', parameter='name',
             verdict='inconclusive', tool_state='negative', statuses=[200], detail='ok'),
    ]
    remaining = [dict(id='a3', kind='cors', url='http://x/c', parameter=None, cost=3),
                 dict(id='a4', kind='security_headers', url='http://x/h', parameter=None, cost=3)]
    critique = [dict(disputed_action_ids=['a1'], summary='unsupported')]
    digest = build_digest(observations, remaining, critique)
    assert digest['schema_version'] == 'round-digest-1'
    assert digest['coverage'] == {'total': 4, 'completed': 2, 'pending': 2}
    assert [item['action_id'] for item in digest['active_findings']] == ['a1']
    assert [item['id'] for item in digest['pending_actions']] == ['a3', 'a4']
    assert digest['disputed_actions'] == ['a1']
    assert len(digest['recent_actions']) == 2
    assert len(digest['active_findings'][0]['detail']) == 240
    assert 'x' * 2000 not in json.dumps(digest)


def test_compact_choice_keeps_decision_and_limits_blockers():
    choice = dict(selected='hexstrike.sqlmap_scan', reason='eligible_external_preferred',
                  policy='external_preferred', cost=300,
                  considered=[dict(tool_id=f'tool{i}', provider='hexstrike',
                                   blockers=['b1', 'b2', 'b3', 'b4']) for i in range(10)])
    compact = _compact_choice(choice)
    assert compact['selected'] == 'hexstrike.sqlmap_scan'
    assert compact['cost'] == 300
    assert len(compact['blocked']) == 2
    assert all(len(item['blockers']) == 3 for item in compact['blocked'])
    assert json.dumps(compact)


def test_planner_tool_context_filters_and_stays_bounded():
    choices = {f'a{i}': dict(selected='hexstrike.sqlmap_scan', cost=300, considered=[])
               for i in range(60)}
    choices['b1'] = dict(selected='builtin.sql_error', cost=3, considered=[])
    view = planner_tool_context(choices, {f'a{i}' for i in range(20)} | {'b1'}, 'external_preferred')
    assert set(view['external']) == {f'a{i}' for i in range(20)}
    assert view['builtin'] == ['b1']
    assert view['compact'] is True and 'choices' not in view
    assert len(json.dumps(view)) < 2_000
