import hashlib
import json

from vulnmind.workbench.detectors import CATALOG, evaluate_idor, synthetic_actions

ORIGIN = 'http://127.0.0.1:3000'


def action():
    return dict(id='idor1', kind='auth_idor', url=ORIGIN + '/rest/basket/0', category=CATALOG['auth_idor'][0],
                detector_version='2.3.0')


def response(body, status=200, truncated=False):
    return dict(body=body, headers={}, status_code=status, truncated=truncated,
                sha256=hashlib.sha256(body.encode()).hexdigest())


def basket(bid):
    return json.dumps({'status': 'success', 'data': {'id': bid, 'UserId': bid, 'Products': []}})


def test_cross_account_basket_read_is_a_candidate():
    result = evaluate_idor(action(), [response(basket(7)), response(basket(8)), response(basket(9))], 7)
    assert result['verdict'] == 'candidate' and result['behavior'] == 'cross_account_read'
    assert result['source'] == {}
    assert '8' in result['detail'] and '9' in result['detail']


def test_rejected_or_same_basket_is_inconclusive():
    rejected = evaluate_idor(action(), [response(basket(7)), response('{}', 401), response('{}', 403)], 7)
    assert rejected['verdict'] == 'inconclusive' and '401' in rejected['detail']
    same = evaluate_idor(action(), [response(basket(7)), response(basket(7)), response(basket(7))], 7)
    assert same['verdict'] == 'inconclusive'


def test_missing_baseline_does_not_claim_idor():
    result = evaluate_idor(action(), [response('{}', 401), response(basket(8)), response(basket(9))], 7)
    assert result['verdict'] == 'inconclusive' and '基线' in result['detail']


def test_idor_probe_requires_the_test_account():
    without = synthetic_actions(ORIGIN, list(CATALOG), account=False)
    assert 'auth_idor' not in {item['kind'] for item in without}
    with_account = synthetic_actions(ORIGIN, list(CATALOG), account=True)
    assert 'auth_idor' in {item['kind'] for item in with_account}
