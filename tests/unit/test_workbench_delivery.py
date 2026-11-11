from pathlib import Path

from vulnmind.workbench.service import JobInput

STATIC = Path(__file__).resolve().parents[2] / 'src' / 'vulnmind' / 'workbench' / 'static'


def job(**overrides):
    base = dict(name='交付自检', repository=r'C:\repo', origin='http://127.0.0.1:3000',
                deployment_version='local', binding_confirmed=True,
                authorization_source='VulnMind 自有本机演示环境',
                allowed_ip_networks=['127.0.0.1/32'])
    base.update(overrides)
    return JobInput(**base)


def test_new_jobs_default_to_v6_with_conservative_detectors():
    value = job()
    assert value.pipeline_version == 6
    assert value.rounds == 2 and value.request_budget == 18
    assert value.auth_probe is False and value.account_profile is None
    assert value.detectors == ['sql_boolean', 'sql_error', 'xss_context', 'template_expression',
                               'reflection', 'cors', 'security_headers']
    assert 'sql_login' not in value.detectors


def test_new_detectors_are_accepted():
    value = job(detectors=['exposed_file', 'well_known_exposure', 'config_exposure', 'browser_xss', 'auth_idor'])
    assert len(value.detectors) == 5
    for kind in ('exposed_file', 'browser_xss', 'auth_idor'):
        assert kind in value.detectors


def test_ui_exposes_version_probes_and_browser_options():
    html = (STATIC / 'index.html').read_text(encoding='utf-8')
    for marker in ('name="pipeline_version"', 'name="auth_probe"', 'name="account"',
                   'value="browser_xss"', 'value="auth_idor"', 'value="exposed_file"',
                   'value="well_known_exposure"'):
        assert marker in html, marker
    script = (STATIC / 'app.js').read_text(encoding='utf-8')
    for marker in ('pipeline_version', 'auth_probe', 'account_profile', "/api/accounts", 'root_causes'):
        assert marker in script, marker
