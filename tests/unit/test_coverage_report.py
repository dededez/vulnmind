from vulnmind.workbench.coverage import build_report, markdown, roots_for


def test_roots_for_known_behaviors():
    assert roots_for(dict(kind='sql_login', behavior='authentication_bypass')) == ['RC-SQLI-LOGIN']
    assert roots_for(dict(kind='weak_password')) == ['RC-WEAK-PASSWORD']
    assert roots_for(dict(kind='sql_error')) == ['RC-SQLI-SEARCH']
    assert roots_for(dict(kind='well_known_exposure', url='http://x/metrics')) == ['RC-METRICS']
    assert roots_for(dict(kind='well_known_exposure', url='http://x/support/logs')) == ['RC-ACCESS-LOG']
    assert roots_for(dict(kind='exposed_file')) == ['RC-STATIC-FILE-EXPOSURE']
    assert roots_for(dict(kind='browser_xss')) == ['RC-DOM-XSS']
    assert roots_for(dict(kind='auth_idor')) == ['RC-IDOR-BASKET']
    assert roots_for(dict(kind='cors')) == []


def test_report_counts_only_candidates_and_separates_denominators():
    truth = dict(summary={}, entries=[
        dict(challenge_key='a', root_cause_id='RC-SQLI-SEARCH', mode='anon', note=''),
        dict(challenge_key='b', root_cause_id='RC-IDOR-BASKET', mode='auth', note=''),
        dict(challenge_key='c', root_cause_id='RC-WEAK-PASSWORD', mode='anon', note=''),
        dict(challenge_key='d', root_cause_id='RC-VULN-LIB', mode='static', note=''),
    ])
    result = dict(job_id='j1', status='finished', requests_used=10, stop_reason='max_rounds', observations=[
        dict(kind='sql_error', verdict='candidate', url='http://x/rest/products/search'),
        dict(kind='weak_password', verdict='inconclusive', url='http://x/rest/user/login'),
        dict(kind='cors', verdict='candidate', url='http://x/'),
    ])
    report, entries, covered = build_report(truth, result, 'test')
    assert report['denominators'] == {'dynamic': 3, 'eligible': 2, 'static': 1}
    assert report['covered']['dynamic'] == ['RC-SQLI-SEARCH']
    assert report['coverage']['overall_dynamic'] == round(1 / 3, 3)
    assert report['coverage']['eligible_dynamic'] == round(1 / 2, 3)
    assert report['targets'] == {'overall_gt_50': False, 'eligible_ge_70': False}
    text = markdown(report, entries, covered)
    assert '| a | eligible | RC-SQLI-SEARCH | covered |' in text
    assert 'RC-WEAK-PASSWORD' in text and 'RC-IDOR-BASKET' in text


def test_verified_behavior_is_reported_separately():
    truth = dict(summary={}, entries=[dict(challenge_key='a', root_cause_id='RC-DOM-XSS', mode='browser', note='')])
    result = dict(observations=[dict(kind='browser_xss', verdict='verified_behavior', behavior='script_execution',
                                     url='http://x/#/search')])
    report, _, _ = build_report(truth, result, 't')
    assert report['covered']['confirmed'] == ['RC-DOM-XSS']
    assert report['covered']['dynamic'] == ['RC-DOM-XSS']
