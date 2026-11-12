from vulnmind.workbench.coverage import build_report, markdown, roots_for


def test_mapping_requires_exact_surface_and_signal():
    assert roots_for(dict(kind='sql_error',url='http://x/rest/products/search',parameter='q'))==['RC-SQLI-SEARCH']
    assert roots_for(dict(kind='sql_error',url='http://x/orders',parameter='q'))==[]
    assert roots_for(dict(kind='sql_error'))==[]
    assert roots_for(dict(kind='well_known_exposure',url='http://x/metrics',behavior='anonymous_metrics'))==['RC-METRICS']
    assert roots_for(dict(kind='well_known_exposure',url='http://x/not/metrics',behavior='anonymous_metrics'))==[]
    assert roots_for(dict(kind='auth_idor',url='http://x/documents/1',behavior='cross_account_read'))==[]


def test_candidates_and_behavior_never_become_confirmed_coverage():
    truth=dict(entries=[dict(challenge_key='a',root_cause_id='RC-SQLI-SEARCH',mode='anon',note='')])
    for verdict in ['candidate','verified_behavior']:
        result=dict(observations=[dict(kind='sql_error',verdict=verdict,url='http://x/rest/products/search',parameter='q')])
        report,entries,covered=build_report(truth,result,'test')
        assert report['covered']['candidates']==['RC-SQLI-SEARCH']
        assert report['coverage']['overall_dynamic']==0
        assert report['candidate_coverage']['overall']==1
        assert not report['targets']['overall_gt_50']
        assert not covered and not report['covered']['confirmed']
        assert 'not_covered' in markdown(report,entries,covered)


def test_mismatched_target_cannot_use_lab_denominator(tmp_path):
    import pytest
    truth=dict(source={'repository':str(tmp_path/'lab')},entries=[])
    with pytest.raises(ValueError,match='不匹配'): build_report(truth,{},'test',config={'repository':str(tmp_path/'other')})
    with pytest.raises(ValueError,match='通用任务'): build_report(truth,{},'test',config={'repository':str(tmp_path/'lab'),'pipeline_version':7,'target_adapter':'generic'})
