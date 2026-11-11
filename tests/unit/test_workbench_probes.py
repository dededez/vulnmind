import hashlib
import json

import pytest

from vulnmind.workbench.detectors import CATALOG, requests_for, evaluate, synthetic_actions
from vulnmind.workbench.knowledge import QUERIES
from vulnmind.workbench.redaction import redact_tokens


def test_every_detector_category_has_a_retrieval_query():
    # A missing query made the knowledge stage fail with KeyError on a real run.
    assert {value[0] for value in CATALOG.values()} <= set(QUERIES)


def action(kind, url='http://127.0.0.1:3000/rest/user/login'):
    return dict(id='probe', kind=kind, category=CATALOG[kind][0], detector_version='2.1.0',
                method='POST' if kind in {'sql_login', 'weak_password'} else 'GET',
                url=url, parameter='', parameters=[], source={})


def response(body, status=200, truncated=False):
    return dict(body=body, headers={'content-type': 'application/json'}, status_code=status,
                truncated=truncated, sha256=hashlib.sha256(body.encode()).hexdigest())


def login_body(email):
    return json.dumps({'authentication': {'token': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl', 'umail': email}})


def test_route_actions_never_attach_probe_kinds():
    # Probe kinds target fixed endpoints; attaching them to source routes sent
    # login probes to /rest/products/search on the first real run.
    from vulnmind.workbench.detectors import actions_for
    route = dict(id='r', method='GET', url='http://127.0.0.1:3000/rest/products/search',
                 parameters=['q'], signals=['dynamic_sql'], source_link_verified=True, executable=True)
    actions = actions_for(dict(routes=[route]), list(CATALOG))
    assert {a['kind'] for a in actions}.isdisjoint({'sql_login', 'weak_password', 'config_exposure', 'well_known_exposure'})
    assert all(a['url'].endswith('/rest/products/search') for a in actions)


def test_synthetic_actions_are_bounded_and_gated():
    origin = 'http://127.0.0.1:3000'
    disabled = synthetic_actions(origin, list(CATALOG), auth_probe=False)
    assert not any(a['kind'] == 'sql_login' for a in disabled)
    assert {a['kind'] for a in disabled} == {'config_exposure', 'well_known_exposure', 'browser_xss'}
    enabled = synthetic_actions(origin, list(CATALOG), auth_probe=True)
    kinds = [a['kind'] for a in enabled]
    assert kinds.count('sql_login') == 1 and kinds.count('weak_password') == 1
    assert kinds.count('well_known_exposure') == 3
    assert kinds.count('browser_xss') == 1
    assert len({a['id'] for a in enabled}) == len(enabled)
    # An action already derived from source (same kind+method+url) is not duplicated.
    existing = [dict(kind='sql_login', method='POST', url=origin + '/rest/user/login')]
    again = synthetic_actions(origin, ['sql_login'], auth_probe=True, existing=existing)
    assert again == []


@pytest.mark.parametrize('kind', [k for k in CATALOG if k not in {'browser_xss', 'auth_idor'}])
def test_request_and_response_counts_match_declared_cost(kind):
    url = 'http://127.0.0.1:3000/ftp/' if kind == 'well_known_exposure' else 'http://127.0.0.1:3000/rest/user/login'
    requests = requests_for(action(kind, url))
    assert len(requests) == CATALOG[kind][2]
    assert all(r['url'].startswith(url.split('?')[0]) or r['url'].startswith('http') for r in requests)


def test_login_probe_requires_control_failure():
    probe = action('sql_login')
    bypass = [response('{}', 401), response(login_body('admin@juice-sh.op')), response('{}', 401)]
    result = evaluate(probe, bypass)
    assert result['verdict'] == 'candidate' and result['behavior'] == 'authentication_bypass'
    assert 'token' not in json.dumps(result)
    confounded = [response(login_body('someone@juice-sh.op')), response(login_body('admin@juice-sh.op')), response('{}', 401)]
    assert evaluate(probe, confounded)['verdict'] == 'inconclusive'


def test_weak_password_probe():
    probe = action('weak_password')
    result = evaluate(probe, [response('{}', 401), response(login_body('admin@juice-sh.op'))])
    assert result['verdict'] == 'candidate' and result['behavior'] == 'default_credentials'
    assert evaluate(probe, [response('{}', 401), response('{}', 401)])['verdict'] == 'inconclusive'


def test_config_exposure_probe():
    probe = action('config_exposure', 'http://127.0.0.1:3000/rest/admin/application-configuration')
    assert evaluate(probe, [response('{"config":{"server":{"port":3000}}}')] * 2)['verdict'] == 'candidate'
    assert evaluate(probe, [response('{"config":{}}')] * 2)['verdict'] == 'inconclusive'
    assert evaluate(probe, [response('{"config":{"a":1}}', 500)] * 2)['verdict'] == 'inconclusive'


@pytest.mark.parametrize('url,body,behavior', [
    ('http://127.0.0.1:3000/metrics', '# HELP process_cpu_seconds_total\n# TYPE counter\n', 'anonymous_metrics'),
    ('http://127.0.0.1:3000/support/logs', '<a href="access.log">access.log</a>', 'log_directory_exposed'),
    ('http://127.0.0.1:3000/ftp/', '<a href="package.json.bak">package.json.bak</a>', 'static_directory_listing'),
])
def test_well_known_exposure_classification(url, body, behavior):
    probe = action('well_known_exposure', url)
    result = evaluate(probe, [response(body)] * 2)
    assert result['verdict'] == 'candidate' and result['behavior'] == behavior
    assert evaluate(probe, [response(body), response('different')])['verdict'] == 'inconclusive'


def test_metrics_accepts_changing_counter_values():
    probe = action('well_known_exposure', 'http://127.0.0.1:3000/metrics')
    first = '# HELP juiceshop_llm_input_tokens_total x\n# TYPE counter\njuiceshop_llm_input_tokens_total 1\n'
    second = '# HELP juiceshop_llm_input_tokens_total x\n# TYPE counter\njuiceshop_llm_input_tokens_total 2\n'
    assert evaluate(probe, [response(first), response(second)])['verdict'] == 'candidate'


def test_redaction_removes_tokens_without_touching_plain_text():
    text = '{"authentication":{"token":"abc.def.ghi","umail":"a@b.c"}} Authorization: Bearer abcdefghijklmnop'
    redacted, changed = redact_tokens(text)
    assert changed and 'abc.def.ghi' not in redacted and 'abcdefghijklmnop' not in redacted
    assert 'a@b.c' in redacted
    same, unchanged = redact_tokens('{"status":"ok","count":3}')
    assert same == '{"status":"ok","count":3}' and unchanged is False
