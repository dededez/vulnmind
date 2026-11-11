import hashlib
import html
import sqlite3
from urllib.parse import parse_qs,urlsplit

import pytest
from vulnmind.workbench.detectors import CATALOG,requests_for,evaluate,actions_for,classify
from vulnmind.workbench.knowledge import ROOT,validate_references
from vulnmind.knowledge.skills import SkillLoader


def action(kind):
    return dict(id='test',kind=kind,category=CATALOG[kind][0],detector_version='2.0.0',method='GET',
                url='http://127.0.0.1/item',parameter='q',parameters=['q'],source={})


def response(body,headers=None,status=200,truncated=False):
    return dict(body=body,headers=headers or {},status_code=status,truncated=truncated,
                sha256=hashlib.sha256(body.encode()).hexdigest())


@pytest.mark.parametrize('parameterized',[False,True])
def test_sql_boolean_actual_sqlite_and_parameterization(parameterized):
    db=sqlite3.connect(':memory:');db.executescript("create table items(id text);insert into items values('1');")
    responses=[]
    for request in requests_for(action('sql_boolean')):
        value=parse_qs(urlsplit(request['url']).query)['q'][0]
        rows=db.execute('select id from items where id=?',(value,)).fetchall() if parameterized else db.execute("select id from items where id='"+value+"'").fetchall()
        responses.append(response(str(rows)))
    result=evaluate(action('sql_boolean'),responses)
    assert result['verdict']==('inconclusive' if parameterized else 'candidate')
    db.close()


@pytest.mark.parametrize('change',['unstable','reflected','denied','truncated'])
def test_sql_boolean_rejects_confounded_results(change):
    responses=[response(v) for v in ['match','match','empty','match','empty','match']]
    if change=='unstable':responses[3]=response('different')
    if change=='reflected':responses=[response("AND '1'= reflected "+r['body']) for r in responses]
    if change=='denied':responses[2]['status_code']=403
    if change=='truncated':responses[2]['truncated']=True
    assert evaluate(action('sql_boolean'),responses)['verdict']=='inconclusive'


@pytest.mark.parametrize('context,expected',[
    ('html','candidate'),('encoded','inconclusive'),('textarea','inconclusive'),
    ('script','inconclusive'),('attribute','inconclusive'),('json','inconclusive'),('static','inconclusive'),
])
def test_html_context_is_not_generic_reflection(context,expected):
    responses=[]
    for req in requests_for(action('xss_context')):
        value=parse_qs(urlsplit(req['url']).query)['q'][0]
        body=html.escape(value) if context=='encoded' else '<textarea>'+value+'</textarea>' if context=='textarea' else '<script>'+value+'</script>' if context=='script' else "<div title='"+value+"'></div>" if context=='attribute' else value
        if context=='static':body='<vm-probe data-id="b19"></vm-probe><vm-probe data-id="c31"></vm-probe>'
        responses.append(response(body,{'content-type':'application/json' if context=='json' else 'text/html'}))
    assert evaluate(action('xss_context'),responses)['verdict']==expected


@pytest.mark.parametrize('wildcard,credentials,expected',[(False,True,'candidate'),(True,True,'inconclusive'),(False,False,'inconclusive')])
def test_cors_requires_two_origins_and_credentials(wildcard,credentials,expected):
    responses=[response('public')]+[response('public',{'access-control-allow-origin':'*' if wildcard else f'https://vm-origin-{i}.invalid',
                'access-control-allow-credentials':'true' if credentials else 'false'}) for i in (1,2)]
    assert evaluate(action('cors'),responses)['verdict']==expected


def test_header_checks_apply_to_html_and_are_not_vulnerability_confirmation():
    assert evaluate(action('security_headers'),[response('{}',{'content-type':'application/json'})]*3)['verdict']=='inconclusive'
    assert evaluate(action('security_headers'),[response('<p>Hello</p>',{'content-type':'text/html'})]*3)['verdict']=='candidate'


def test_skill_manifest_covers_actual_tools_and_rejects_fabricated_refs():
    loader=SkillLoader(ROOT/'skills');skills=[loader.load(m.skill_id).model_dump() for m in loader.available()]
    # Every detector category must be backed by a skill; skills may cover extra
    # categories that have no executable detector yet.
    assert len({s['skill_id'] for s in skills})==len(skills)
    assert set(CATALOG)<={t for s in skills for t in s['tools']}
    assert {value[0] for value in CATALOG.values()}<={s['vuln_type'] for s in skills}
    with pytest.raises(ValueError,match='unknown knowledge'):validate_references(['rag:invented'],dict(skills=skills,chunks=[]))


def test_static_categories_do_not_become_executable_detectors():
    route=dict(id='a',method='GET',url='http://127.0.0.1/',parameters=[],signals=['outbound_request'],source_link_verified=True,executable=True)
    mapping=dict(routes=[route]);coverage=classify(mapping)
    assert next(c for c in coverage if c['category']=='ssrf')['status']=='needs_context'
    assert {a['kind'] for a in actions_for(mapping,list(CATALOG))}=={'cors','security_headers'}
    # Exposure checks stay available where the source shows a disclosure surface.
    static=dict(route,id='b',url='http://127.0.0.1/ftp',signals=['static_directory'])
    kinds={a['kind'] for a in actions_for(dict(routes=[static]),list(CATALOG))}
    assert 'response_disclosure' in kinds and 'redirect_location' not in kinds
