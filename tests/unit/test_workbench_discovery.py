from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
from urllib.parse import parse_qs, urlsplit

from vulnmind.workbench.discovery import extend_snapshot, discovered_routes, price_actions
from vulnmind.workbench.detectors import requests_for, evaluate
from vulnmind.workbench.engine import UnifiedInvestigation


def test_express_imports_parameters_and_snapshot_changes(tmp_path):
    (tmp_path/'server.ts').write_text("import { search } from './search'\napp.get('/search', search())\napp.get('/orders/:id', order())\n")
    handler=tmp_path/'search.ts'
    handler.write_text('export function search() { const q=req.query.q; db.query(`SELECT ${q}`) }')
    def read(): return extend_snapshot(dict(root=str(tmp_path),files={},routes=[],truncated=False))
    first=read()
    route=first['routes'][0]
    assert route['parameters']==['q'] and route['signals']==['dynamic_sql']
    assert route['handler_file']=='search.ts'
    handler.write_text(handler.read_text()+'\n// new revision')
    assert read()['digest']!=first['digest']


def test_discovery_filters_origin_assets_and_discards_values():
    routes=discovered_routes(['http://local/search?q=secret','http://local.evil/search?q=x',
        'http://local/main.js','http://local/%7B%7Bhref%7D%7D'], 'http://local')
    assert len(routes)==1 and routes[0]['parameters']==['q']
    assert 'secret' not in str(routes)


def test_provider_cost_and_context_are_real():
    def route(budget,**kwargs):
        a=dict(id='a',kind='sql_error',method='GET',cost=3)
        r={'choices':{'a':{'selected':'hexstrike.sqlmap_scan'}}}
        return price_actions([a],r,budget,**kwargs)[0]
    assert route(18)['execution_tool']=='builtin.sql_error'
    assert route(400)['cost']==300
    assert route(400,authenticated=True)['execution_tool']=='builtin.sql_error'


def test_repeated_boolean_closures_distinguish_true_and_false():
    a=dict(id='a',kind='sql_boolean',boolean_closures=True,method='GET',url='http://local/search',
           parameter='q',parameters=['q'],encoding='json',source={},category='sql_injection',detector_version='2.0.0')
    requests=requests_for(a)
    assert len(requests)==18
    responses=[]
    for req in requests:
        q=parse_qs(urlsplit(req['url']).query,keep_blank_values=True)['q'][0]
        good=not q or q.startswith("'))")
        body='baseline products' if not q else 'all products' if '1=1' in q else 'empty'
        responses.append(dict(status_code=200 if good else 500,body=body,truncated=False,
                              sha256=hashlib.sha256(body.encode()).hexdigest()))
    assert evaluate(a,responses)['verdict']=='candidate'
    for response in responses: response.update(status_code=200,body='same')
    assert evaluate(a,responses)['verdict']=='inconclusive'


def test_exhausted_sqlmap_with_valid_baseline_is_not_negative():
    a=dict(id='a',kind='sql_error',url='http://local',method='GET',parameter='q',source={},category='sql_injection',detector_version='2')
    raw=dict(stdout='all tested parameters do not appear to be injectable',upstream_status={'200':2},budget_exhausted=True)
    response=dict(tool_id='hexstrike.sqlmap_scan',body=json.dumps(raw),requests_used=2,sha256='s',status_code=200,
                  execution_id='e',result_sha256='r')
    result=UnifiedInvestigation.evaluate_external(SimpleNamespace(),a,response)
    assert result['tool_state']=='inconclusive'


def test_iac_excludes_dependencies(tmp_path):
    from vulnmind.analysis.repo_analyzers import McpCheckovAnalyzer
    (tmp_path/'node_modules'/'vendor').mkdir(parents=True)
    (tmp_path/'node_modules'/'vendor'/'unrelated.yml').write_text('not my app')
    (tmp_path/'Dockerfile').write_text('FROM alpine:3.20')
    assert McpCheckovAnalyzer(target_id='fixture')._collect_iac_files(tmp_path)==[('Dockerfile','FROM alpine:3.20')]


def test_stale_first_runtime_does_not_hide_valid_receipt(tmp_path,monkeypatch):
    from vulnmind.workbench.external import validated_service
    primary=tmp_path/'workbench'/'external'
    good=tmp_path/'bench'/'external'
    for root,env in ((primary,'old'),(good,'new')):
        root.mkdir(parents=True)
        (root/'validation.json').write_text(json.dumps(dict(environment_sha256=env)))
    class Runtime:
        def __init__(self,root,**kwargs): self.root=root;self.environment=None
        def refresh(self): self.environment='new'
    monkeypatch.setattr('vulnmind.workbench.external.ExternalWorkbench',Runtime)
    assert validated_service(primary,distro='fixture').root==good


def test_external_negative_can_get_one_source_supported_builtin_review():
    from vulnmind.workbench.discovery import independent_followup
    action=dict(id='a',kind='sql_boolean',builtin_cost=18,cost=300,source={'signals':['dynamic_sql']})
    result=dict(external_tool='hexstrike.sqlmap_scan',verdict='inconclusive')
    followup=independent_followup(action,result)
    assert followup['cost']==18 and followup['execution_tool']=='builtin.sql_boolean'
    assert independent_followup(followup,result) is None
    assert independent_followup({**action,'source':{}},result) is None
