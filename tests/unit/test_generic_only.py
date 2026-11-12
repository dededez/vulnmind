from pathlib import Path
from types import SimpleNamespace
import pytest
from vulnmind.workbench.service import Workbench
from vulnmind.workbench.generic_coverage import build_report


def test_current_creation_has_no_target_specific_escape():
    saved=[]
    service=SimpleNamespace(create=lambda data:saved.append(data) or data)
    for override in [dict(target_adapter='juice_shop'),dict(pipeline_version=6),dict(auth_probe=True),dict(account_profile='old')]:
        with pytest.raises(ValueError): Workbench.create_current(service,override)
    assert not saved
    result=Workbench.create_current(service,{'name':'arbitrary app'})
    assert result['target_adapter']=='generic' and result['pipeline_version']==7


def test_ui_has_no_adapter_or_fixed_probe_controls():
    root=Path(__file__).resolve().parents[2]/'src/vulnmind/workbench/static'
    html=(root/'index.html').read_text(encoding='utf-8');js=(root/'app.js').read_text(encoding='utf-8')
    for marker in ['name="target_adapter"','name="pipeline_version"','name="auth_probe"','value="sql_login"','value="weak_password"','value="well_known_exposure"','value="config_exposure"','Juice Shop']:
        assert marker not in html
    assert 'syncAdapter' not in js and "get('target_adapter')" not in js


def test_generic_truth_binds_application_version_and_exact_interface(tmp_path):
    binding=dict(origin='http://local:3000',repository=str(tmp_path),source_snapshot='a'*64)
    truth=dict(schema_version='coverage-truth-2',target=binding,roots=[dict(id='private-search',eligible=True,method='GET',path='/catalog/find',parameter='term',kinds=['sql_error'])])
    result=dict(origin=binding['origin'],source_snapshot=binding['source_snapshot'],observations=[dict(method='GET',kind='sql_error',parameter='term',url=binding['origin']+'/catalog/find',verdict='candidate')])
    report,_,_=build_report(truth,result,'test',config=binding)
    assert report['covered']['candidates']==['private-search'] and report['coverage']['overall_dynamic']==0
    result['observations'][0]['url']=binding['origin']+'/other'
    assert not build_report(truth,result,'test',config=binding)[0]['covered']['candidates']
    with pytest.raises(ValueError): build_report(truth,{**result,'source_snapshot':'b'*64},'test',config=binding)
    with pytest.raises(ValueError): build_report({'schema_version':'juice-shop-truth-1'},result,'test',config=binding)
