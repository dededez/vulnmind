"""Real local HTTP, distinct resource schemas, and full durable v7 execution."""
import hashlib
import json
import threading
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID
import pytest
from sqlalchemy.orm import Session
from test_workbench import workbench,settled
from test_durable_flow import flow
from vulnmind.workbench.engine import UnifiedInvestigation
from vulnmind.knowledge.skills import SkillLoader
from vulnmind.workbench.knowledge import ROOT
from vulnmind.persistence.models import WorkbenchJob


@pytest.mark.parametrize('resource,field',[('documents','owner'),('invoices','tenant')])
@pytest.mark.parametrize('vulnerable',[False,True])
def test_changed_application_access_control_and_replay(workbench,resource,field,vulnerable):
    service,data,_=workbench;calls=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            owner='A' if self.path.endswith('/red') else 'B'
            actor=self.headers.get('Authorization','').removeprefix('Bearer fixture-token-')
            allowed=actor in {'A','B'} and (vulnerable or actor==owner)
            self.send_response(200 if allowed else 403);self.end_headers()
            self.wfile.write(json.dumps({'payload':{field:owner}} if allowed else {}).encode())
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    origin='http://127.0.0.1:'+str(server.server_port)
    def http(**kw):
        calls.append((kw['url'],kw['headers'].get('Authorization')))
        req=urllib.request.Request(kw['url'],headers=kw['headers'])
        try: r=urllib.request.urlopen(req,timeout=3)
        except urllib.error.HTTPError as e:r=e
        with r:return SimpleNamespace(status_code=r.code,body=r.read(),headers=dict(r.headers),truncated=False)
    def knowledge(*args):
        loader=SkillLoader(ROOT/'skills');skill=loader.load('workbench.broken_access_control').model_dump()
        return dict(schema_version='knowledge-1',mode='keyword',skills=[skill],chunks=[],retrievals=[])
    service.vault.load=lambda key,site: {'Authorization':'Bearer fixture-token-'+key}
    service.runner=lambda *a:UnifiedInvestigation(*a,http=http,knowledge_provider=knowledge)
    data.update(pipeline_version=7,target_adapter='generic',origin=origin,allow_post=False,detectors=['auth_idor'],rounds=1,
        request_budget=18,access_checks=[dict(credential_a='A',credential_b='B',resource_a=origin+'/'+resource+'/red',
            resource_b=origin+'/'+resource+'/blue',identity_path=['payload',field],identity_a='A',identity_b='B',
            expected_policy='owner_only',ownership_basis='Controlled fixture: two separately owned private resources')])
    try:
        identifier=service.create(data)['id'];service.start(identifier);pending=settled(service,identifier)
        assert pending['status']=='waiting_approval',pending['result']
        assert len(pending['result']['plan']['auth_actions'][0]['requests'])==6
        assert not calls
        service.decide(identifier,pending['result']['approval_id'],True);done=settled(service,identifier)
        assert done['status']=='finished',done['result']
        observations=done['result']['observations']
        assert len(observations)==1
        assert observations[0]['verdict']==('candidate' if vulnerable else 'inconclusive')
        assert done['result']['requests_used']==6 and len(calls)==6
        assert calls[-1][1] is None and calls[-2][1] is None
        assert service.verify(identifier)['status']=='verified'
        with Session(service.engine) as session:
            row=session.get(WorkbenchJob,UUID(identifier))
            runner=UnifiedInvestigation(service.engine,row,service.settings,service.vault,
                http=lambda **kw:pytest.fail('replay sent HTTP'),knowledge_provider=lambda *a:pytest.fail('replay retrieved knowledge'))
            assert runner.run()['status']=='finished'
    finally:
        server.shutdown();server.server_close();thread.join(timeout=3)


def test_browser_only_round_gap_unknown_retry_and_budget(workbench,monkeypatch):
    """Skipped first round must not break evidence links; uncertain runs keep their hold."""
    from vulnmind.workbench import browser
    from urllib.parse import unquote
    import re
    service,data,_=workbench;calls=[];fail=[True]
    class Runner:
        def __init__(self,*a,**kw): pass
        def run(self,url):
            calls.append(url)
            if fail[0]: raise browser.BrowserUnavailable('simulated uncertain run')
            marker=re.search(r"alert\('([^']+)'\)",unquote(url))
            return dict(html='<html>bounded</html>',requests=1,status_code=200,blocked=[],request_paths=[url],
                dialogs=[dict(type='alert',message=marker.group(1))] if marker else [],title='',elapsed_ms=1)
    monkeypatch.setattr(browser,'BrowserRunner',Runner)
    def knowledge(*args):
        skill=SkillLoader(ROOT/'skills').load('workbench.xss').model_dump()
        return dict(schema_version='knowledge-1',mode='keyword',skills=[skill],chunks=[],retrievals=[])
    service.runner=lambda *a:UnifiedInvestigation(*a,knowledge_provider=knowledge)
    data.update(pipeline_version=7,target_adapter='generic',detectors=['browser_xss'],allow_post=False,
        rounds=2,request_budget=300,routes=[dict(method='GET',path='/display',parameters=['phrase'])])
    identifier=service.create(data)['id'];service.start(identifier);pending=settled(service,identifier)
    assert pending['status']=='waiting_approval',pending['result']
    assert pending['result']['round']==2
    assert pending['result']['plan']['browser_actions'][0]['baseline_url']
    service.decide(identifier,pending['result']['approval_id'],True);unknown=settled(service,identifier)
    assert unknown['status']=='unknown'
    stage=next(s['stage'] for s in unknown['stages'] if s['stage'].startswith('browser_'))
    fail[0]=False
    service.recover(identifier,dict(stage=stage,action='retry',reason='controlled fixture retry',acknowledged=True))
    done=settled(service,identifier)
    assert done['status']=='finished',done['result']
    assert done['result']['requests_used']==123
    assert done['result']['knowledge_round_numbers']==[1]
    assert done['result']['observations'][0]['behavior']=='script_execution'
    assert service.verify(identifier)['status']=='verified'
    assert len(calls)==4


@pytest.mark.parametrize('vulnerable',[False,True])
def test_real_sqlite_search_renamed_route_and_parameter(workbench,vulnerable):
    """Actual SQLite behavior, no Juice Shop route, fixture labels or known answers."""
    import sqlite3
    from urllib.parse import parse_qs,urlsplit
    service,data,_=workbench;calls=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            q=parse_qs(urlsplit(self.path).query,keep_blank_values=True).get('needle',[''])[0]
            with sqlite3.connect(':memory:') as db:
                db.execute('create table items (name text)')
                db.executemany('insert into items values (?)',[('apple',),('orange',)])
                try:
                    rows=db.execute("select name from items where name like '%"+q+"%'" if vulnerable else 'select name from items where name like ?',
                        () if vulnerable else ('%'+q+'%',)).fetchall()
                    status=200;body=json.dumps(rows)
                except sqlite3.Error:
                    status=500;body='SQLITE_ERROR: invalid query'
            self.send_response(status);self.end_headers();self.wfile.write(body.encode())
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    origin='http://127.0.0.1:'+str(server.server_port)
    def http(**kw):
        calls.append(kw['url'])
        try:r=urllib.request.urlopen(kw['url'],timeout=3)
        except urllib.error.HTTPError as e:r=e
        with r:return SimpleNamespace(status_code=r.code,body=r.read(),headers=dict(r.headers),truncated=False)
    def knowledge(*args):
        skill=SkillLoader(ROOT/'skills').load('workbench.sql_injection').model_dump()
        return dict(schema_version='knowledge-1',mode='keyword',skills=[skill],chunks=[],retrievals=[])
    service.runner=lambda *a:UnifiedInvestigation(*a,http=http,knowledge_provider=knowledge)
    data.update(pipeline_version=7,target_adapter='generic',origin=origin,allow_post=False,detectors=['sql_boolean','sql_error'],
        request_budget=30,rounds=2,routes=[dict(method='GET',path='/inventory/find',parameters=['needle'])])
    try:
        identifier=service.create(data)['id'];service.start(identifier);pending=settled(service,identifier)
        assert pending['status']=='waiting_approval',pending['result']
        assert all('/inventory/find?' in r['url'] for r in pending['result']['plan']['requests'])
        service.decide(identifier,pending['result']['approval_id'],True);done=settled(service,identifier)
        if done['status']=='waiting_approval':
            service.decide(identifier,done['result']['approval_id'],True);done=settled(service,identifier)
        assert done['status']=='finished',done['result']
        results=done['result']['observations']
        assert len(results)==2 and len(calls)==21
        assert all(o['verdict']==('candidate' if vulnerable else 'inconclusive') for o in results)
        assert service.verify(identifier)['status']=='verified'
    finally:
        server.shutdown();server.server_close();thread.join(timeout=3)


def test_explicit_lab_account_password_never_enters_plan_or_journal(workbench):
    from sqlalchemy import select
    from vulnmind.persistence.models import DurableStep
    service,data,_=workbench;secret='temporary-private-password-791'
    service.vault.load_account=lambda *a:dict(email='owned@example.invalid',password=secret)
    service.vault.load_session=lambda *a:None
    saved_sessions=[];service.vault.save_session=lambda *args:saved_sessions.append(args)
    def http(**kw):
        if kw['method']=='POST':
            assert json.loads(kw['body'])['password']==secret
            body=json.dumps({'authentication':{'token':'fixture-long-session-token','umail':'owned@example.invalid','bid':7}})
        else:body=json.dumps({'config':{'public':True}})
        return SimpleNamespace(status_code=200,body=body.encode(),headers={},truncated=False)
    def knowledge(*args):
        skill=SkillLoader(ROOT/'skills').load('workbench.information_disclosure').model_dump()
        return dict(schema_version='knowledge-1',mode='keyword',skills=[skill],chunks=[],retrievals=[])
    service.runner=lambda *a:UnifiedInvestigation(*a,http=http,knowledge_provider=knowledge)
    data.update(pipeline_version=7,target_adapter='juice_shop',account_profile='fixture-profile',
        detectors=['config_exposure'],rounds=1,request_budget=18)
    identifier=service.create(data)['id'];service.start(identifier);pending=settled(service,identifier)
    assert pending['status']=='waiting_approval',pending['result']
    assert secret not in json.dumps(pending)
    assert pending['result']['plan']['account_requests'][0]['body_sha256']
    service.decide(identifier,pending['result']['approval_id'],True);done=settled(service,identifier)
    assert done['status']=='finished',done['result']
    assert saved_sessions and secret not in json.dumps(done)
    with Session(service.engine) as session:
        steps=session.scalars(select(DurableStep).where(DurableStep.workflow_id==UUID(identifier))).all()
        assert all(secret not in json.dumps(s.payload) for s in steps)
    assert service.verify(identifier)['status']=='verified'
