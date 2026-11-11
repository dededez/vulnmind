import pytest

from vulnmind.workbench.browser import BrowserRunner, BrowserUnavailable, evaluate_browser

ORIGIN = 'http://127.0.0.1:3000'


def action():
    return dict(id='b1', kind='browser_xss', url=ORIGIN + '/#/search?q=%3Ciframe%3E', category='xss',
                parameter='q', detector_version='2.2.0')


def outcome(dialogs=(), html='<html>ok</html>'):
    import hashlib
    return dict(status_code=200, requests=12, blocked=[], dialogs=list(dialogs), title='t', elapsed_ms=900,
                html=html, sha256=hashlib.sha256(html.encode()).hexdigest())


def test_alert_dialog_is_execution_evidence():
    result = evaluate_browser(action(), outcome([dict(type='alert', message='1')]))
    assert result['verdict'] == 'candidate' and result['behavior'] == 'script_execution'
    assert result['browser']['dialogs'][0]['type'] == 'alert'
    assert result['source'] == {}
    assert result['response_hashes']


def test_dom_reflection_without_dialog_is_not_execution():
    result = evaluate_browser(action(), outcome(html='<html>vm-probe</html>'))
    assert result['verdict'] == 'inconclusive' and result['behavior'] is None


def test_absent_marker_stays_inconclusive():
    assert evaluate_browser(action(), outcome())['verdict'] == 'inconclusive'


def test_scope_is_enforced_before_playwright_is_used():
    runner = BrowserRunner(None, ORIGIN)
    with pytest.raises(ValueError, match='outside the authorized origin'):
        runner.run('http://evil.example/')
    with pytest.raises(ValueError):
        runner.run('https://127.0.0.1:3000/#/search')


@pytest.mark.skipif(__import__('os').environ.get('VULNMIND_BROWSER_LIVE') != '1',
                    reason='live browser test requires VULNMIND_BROWSER_LIVE=1')
def test_live_browser_counts_requests_and_bounds_redirects():
    runner = BrowserRunner(None, ORIGIN, max_requests=25, timeout_ms=8000)
    try:
        result = runner.run(ORIGIN + '/#/search?q=vm-probe')
    except BrowserUnavailable as exc:
        pytest.skip(str(exc))
    assert result['requests'] <= 25
    assert all(request.startswith(ORIGIN) for request in result['request_paths'])
