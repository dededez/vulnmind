import hashlib
import json
import pytest
from vulnmind.workbench.access_control import AccessCheck,actions,requests_for,evaluate
from vulnmind.workbench.browser_checks import actions as browser_actions
from vulnmind.workbench.browser import evaluate_browser
from vulnmind.workbench.detectors import file_followups
from test_workbench_delivery import job


def check():
    return dict(credential_a='a',credential_b='b',resource_a='http://local/records/red',resource_b='http://local/records/blue',
        identity_path=['record','owner'],identity_a='alice',identity_b='bob',expected_policy='owner_only',
        ownership_basis='Two operator-owned private records created under separate identities')


def response(owner,status=200):
    body=json.dumps({'record':{'owner':owner}})
    return dict(body=body,status_code=status,truncated=False,sha256=hashlib.sha256(body.encode()).hexdigest())


def test_generic_defaults_do_not_enable_lab_protocol():
    assert job().target_adapter=='generic'
    with pytest.raises(ValueError): job(auth_probe=True)
    with pytest.raises(ValueError): job(detectors=['weak_password'])
    assert job(target_adapter='juice_shop',auth_probe=True).auth_probe


def test_access_matrix_requires_both_owner_baselines_and_anonymous_controls():
    action=actions([check()])[0]
    assert [s['credential_override'] for s in requests_for(action)]==['a','b','a','b',None,None]
    results=[response('alice'),response('bob'),response('bob'),response('alice'),response(None,403),response(None,403)]
    assert evaluate(action,results)['behavior']=='cross_account_read'
    results[0]=response('wrong-owner')
    assert evaluate(action,results)['verdict']=='inconclusive'
    results[0]=response('alice');results[4]=response('alice')
    assert evaluate(action,results)['behavior']=='anonymous_private_resource_read'
    results[4]=response(None,403);results[2]=response(None,403);results[3]=response(None,403)
    assert evaluate(action,results)['verdict']=='inconclusive'


def test_duplicate_credentials_and_missing_policy_are_rejected():
    with pytest.raises(ValueError): AccessCheck(**{**check(),'credential_b':'a'})
    with pytest.raises(ValueError): AccessCheck(**{**check(),'expected_policy':'public'})


def test_browser_markers_require_control_and_repeat_and_follow_discovered_routes():
    mapping=dict(routes=[dict(id='r',method='GET',url='http://local/catalog/find',parameters=['term'],executable=True)])
    action=browser_actions(mapping)[0]
    assert '/catalog/find?term=' in action['url'] and '/#/search' not in action['url']
    run=lambda message:dict(dialogs=[dict(type='alert',message=message)],blocked=[],status_code=200)
    outcome=dict(dialogs=run('1')['dialogs'],html='',requests=3,sha256='0'*64,causal_runs=[run('1'),run('1'),run('1')])
    assert evaluate_browser(action,outcome)['verdict']=='inconclusive'
    outcome['causal_runs']=[run('normal'),run(action['marker']),run(action['marker'])]
    assert evaluate_browser(action,outcome)['behavior']=='script_execution'
    outcome['causal_runs'][0]=run(action['marker'])
    assert evaluate_browser(action,outcome)['verdict']=='inconclusive'


def test_file_followup_uses_actual_directory():
    found=file_followups('http://local','["readme.md", "../escape.json"]',base_url='http://local/downloads')
    assert len(found)==1 and found[0]['url']=='http://local/downloads/readme.md'
    assert not file_followups('http://local','["x.md"]',base_url='http://other/files')
