import json
from types import SimpleNamespace

from vulnmind.workbench.engine import UnifiedInvestigation, upstream_status_code

ACTION = dict(id='a1', kind='sql_error', url='http://172.19.160.1:3000/rest/products/search?q=1',
              method='GET', parameter='q', source={}, category='sql_injection',
              detector_version='2.0.0')


def response(stdout='', upstream=None, blocked=0, exhausted=False, exceptions=None, requests_used=16):
    histogram = upstream or {}
    codes = sorted(int(code) for code in histogram if str(code).isdigit()) or [502]
    raw = dict(success=False, return_code=0, stdout=stdout, stderr='', truncated=False,
               requests_used=requests_used, blocked_requests=blocked, budget_exhausted=exhausted,
               upstream_status=histogram, exceptions=exceptions or {})
    return dict(tool_id='hexstrike.sqlmap_scan', execution_id='e1', result_sha256='r1',
                sha256='s1', requests_used=requests_used, status_code=codes[-1],
                statuses=codes, body=json.dumps(raw))


def evaluate(payload):
    return UnifiedInvestigation.evaluate_external(SimpleNamespace(), ACTION, payload)


def test_failed_juice_shop_run_is_unreachable_not_candidate():
    # Raw output of the 2026-11-11 run: proxy 502 x16, 429 x16, no upstream 2xx.
    stdout = ("[02:42:43] [WARNING] HTTP error codes detected during run:\n"
              "502 (Bad Gateway) - 16 times, 429 (Too Many Requests) - 16 times\n"
              "[02:42:43] [INFO] all tested parameters do not appear to be injectable\n")
    result = evaluate(response(stdout=stdout, upstream={}, blocked=16, exhausted=True,
                               exceptions={'ConnectionRefusedError': 16}))
    assert result['verdict'] == 'inconclusive'
    assert result['tool_state'] == 'tool_unreachable'
    assert result['behavior'] is None


def test_reachable_negative_sqlmap_is_negative_not_candidate():
    stdout = ("[INFO] testing if GET parameter 'q' is dynamic\n"
              "[INFO] GET parameter 'q' does not appear to be injectable\n"
              "[WARNING] all tested parameters do not appear to be injectable\n")
    result = evaluate(response(stdout=stdout, upstream={'200': 8}))
    assert result['verdict'] == 'inconclusive'
    assert result['tool_state'] == 'negative'


def test_only_parameter_and_type_summary_is_a_candidate():
    stdout = ("[INFO] testing if GET parameter 'q' is dynamic\n"
              "Parameter: q (GET)\n"
              "    Type: boolean-based blind\n"
              "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
              "    Payload: q=1 AND 1=1\n")
    result = evaluate(response(stdout=stdout, upstream={'200': 20}))
    assert result['verdict'] == 'candidate'
    assert result['tool_state'] == 'candidate'
    assert result['statuses'] == [200]


def test_parameter_word_alone_never_promotes_to_candidate():
    stdout = "[INFO] testing if GET parameter 'q' is dynamic\n"
    result = evaluate(response(stdout=stdout, upstream={'200': 4}))
    assert result['verdict'] == 'inconclusive'
    assert result['tool_state'] == 'inconclusive'


def test_unreachable_overrides_a_summary_like_line():
    # Even if a summary-looking line appears, blocked/exhausted runs stay unreachable.
    stdout = "Parameter: q (GET)\n    Type: time-based blind\n"
    result = evaluate(response(stdout=stdout, upstream={}, blocked=3, exhausted=True))
    assert result['verdict'] == 'inconclusive'
    assert result['tool_state'] == 'tool_unreachable'


def test_upstream_status_code_uses_real_histogram():
    assert upstream_status_code({'upstream_status': {'200': 2, '404': 1}}) == (200, [200, 404])
    assert upstream_status_code({'upstream_status': {}}) == (0, [])
    assert upstream_status_code({'upstream_status': {}, 'blocked_requests': 2}) == (502, [502])
    assert upstream_status_code({'upstream_status': {}, 'exceptions': {'TimeoutError': 1}}) == (502, [502])
