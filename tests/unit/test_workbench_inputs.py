from datetime import datetime,timedelta,timezone
import json
import os
import pytest
from vulnmind.schemas import Authorization
from vulnmind.workbench.routes import snapshot,verify_snapshot,imported_routes
from vulnmind.workbench.investigation import correlate,evaluate,requests_for
from vulnmind.workbench.secrets import Vault
from vulnmind.analysis.http_broker_worker import validate


def scope(root):
    now=datetime.now(timezone.utc)
    return Authorization(authorization_source='test',approved_by='test',starts_at=now-timedelta(minutes=1),expires_at=now+timedelta(hours=1),repository_roots=[str(root)],web_origins=['http://127.0.0.1:1234'],allowed_ip_networks=['127.0.0.1/32'])

def test_static_routes_never_execute_and_mapping_cannot_forge_handler(tmp_path):
    (tmp_path/'app.py').write_text("raise Exception('must not execute')\n@app.get('/search')\ndef search(q):\n return q\n@app.post('/item/{id}')\ndef item(name):\n return name\n")
    auth=scope(tmp_path);saved=snapshot(tmp_path,auth)
    imported=imported_routes([dict(path='/search',file='app.py',handler='invented')],'http://127.0.0.1:1234')
    mapped=correlate(saved,imported,dict(origin='http://127.0.0.1:1234',binding_confirmed=True,deployment_version='test'),auth)
    assert not mapped['routes'][0]['source_link_verified']
    assert not mapped['routes'][1]['executable']
    (tmp_path/'app.py').write_text('changed')
    with pytest.raises(ValueError): verify_snapshot(saved)

def test_har_discards_credentials_and_values_and_foreign_origin():
    req=dict(method='POST',url='http://127.0.0.1:1234/api',headers=[dict(name='Authorization',value='secret')],postData=dict(mimeType='application/json',text='{"q":"private"}'))
    result=imported_routes(dict(log=dict(entries=[dict(request=req),dict(request={**req,'url':'http://other.test/api'})])),'http://127.0.0.1:1234')
    assert len(result)==1 and result[0]['parameters']==['q']
    assert 'private' not in json.dumps(result) and 'secret' not in json.dumps(result)

@pytest.mark.parametrize('bodies,status,truncated,expected',[
    (['baseline','13889','18929'],200,False,'verified_behavior'),
    (['13889','13889','18929'],200,False,'inconclusive'),
    (['baseline','13889 18929','18929'],200,False,'inconclusive'),
    (['baseline','13889','18929'],403,False,'inconclusive'),
    (['baseline','13889','18929'],200,True,'inconclusive'),
])
def test_differential_false_positive_controls(bodies,status,truncated,expected):
    action=dict(id='x',kind='template_expression',method='GET',url='http://127.0.0.1/',parameter='q',source={})
    result=evaluate(action,[dict(body=b,status_code=status,truncated=truncated,sha256='x') for b in bodies])
    assert result['verdict']==expected


@pytest.mark.parametrize('kind,bodies,codes',[
    ('sql_error',['baseline','syntax error at or near','control'],[200,403,200]),
    ('reflection',['vm_reflect_c31','vm_reflect_b19','vm_reflect_c31'],[200,200,200]),
    ('reflection',['baseline','vm_reflect_b19 vm_reflect_c31','vm_reflect_c31'],[200,200,200]),
])
def test_refused_auth_and_static_markers_never_become_candidates(kind,bodies,codes):
    action=dict(id='x',kind=kind,method='GET',url='http://127.0.0.1/',parameter='q',source={})
    result=evaluate(action,[dict(body=b,status_code=c,truncated=False,sha256='x') for b,c in zip(bodies,codes)])
    assert result['verdict']=='inconclusive'

@pytest.mark.skipif(os.name!='nt',reason='Windows DPAPI')
def test_dpapi_and_origin_binding(tmp_path):
    vault=Vault(tmp_path);profile=vault.save('https://example.test','bearer','private-sentinel-value')
    assert b'private-sentinel-value' not in (tmp_path/(profile+'.bin')).read_bytes()
    assert vault.load(profile,'https://example.test')=={'Authorization':'Bearer private-sentinel-value'}
    with pytest.raises(ValueError):vault.load(profile,'https://other.test')

@pytest.mark.parametrize('change',[{},dict(api_profile=None),dict(body='x'*64001),dict(headers={'Content-Type':'text/plain'}),dict(headers={'Content-Type':'application/json','Authorization':'a\r\nb'}),dict(api_profile=dict(version=1,origin='http://other.test',approval_digest='a'*64))])
def test_api_broker_profile(tmp_path,change):
    data=dict(scope=scope(tmp_path).model_dump(mode='json'),url='http://127.0.0.1:1234/api',addresses=['127.0.0.1'],method='POST',body='{"q":"a"}',headers={'Content-Type':'application/json','Authorization':'Bearer owned'},max_body=1000,timeout=2,api_profile=dict(version=1,origin='http://127.0.0.1:1234',approval_digest='a'*64))
    if not change: assert validate(data)[0][1]=='127.0.0.1'
    else:
        with pytest.raises(ValueError): validate({**data,**change})
