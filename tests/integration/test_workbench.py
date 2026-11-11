import hashlib
import json
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID
from urllib.parse import parse_qs,urlsplit

import pytest
from sqlalchemy.orm import Session
from sqlalchemy import select
from test_durable_flow import flow
from vulnmind.config import Settings
from vulnmind.persistence.models import WorkbenchJob,DurableStep
from vulnmind.workbench.service import Workbench
from vulnmind.workbench.engine import UnifiedInvestigation
from vulnmind.workbench.routes import snapshot,verify_snapshot,imported_routes
from vulnmind.workbench.investigation import correlate,actions_for,requests_for,evaluate


@pytest.fixture
def workbench(flow,tmp_path):
    settings=Settings(_env_file=None,report_root=str(tmp_path/'reports'),evidence_root=str(tmp_path/'evidence'),approval_secret='a'*64)
    calls=[]
    def http(**kw):
        calls.append(kw)
        value=json.loads(kw['body'])['name'] if kw['body'] else parse_qs(urlsplit(kw['url']).query).get('name',[''])[0]
        body={'{{731*19}}':'13889','{{823*23}}':'18929'}.get(value,value)
        return SimpleNamespace(status_code=200,body=body.encode(),truncated=False)
    service=Workbench(flow.engine,settings,tmp_path/'bench',runner=lambda *a:UnifiedInvestigation(*a,http=http))
    root=Path(flow.target.locator)
    (root/'app.py').write_text("@app.post('/render')\ndef render():\n    return render_template_string(request.json.get('name',''))\n")
    data=dict(pipeline_version=1,name='owned test',repository=str(root),origin='http://127.0.0.1:12345',deployment_version='test-v1',binding_confirmed=True,
        allowed_ip_networks=['127.0.0.1/32'],authorization_source='owned fixture',allow_post=True,rounds=2,request_budget=9)
    yield service,data,calls
    service.pool.shutdown(wait=True);service.close()


def settled(service,job):
    future=service.active.get(UUID(job))
    if future: future.result(timeout=60)
    return service.detail(job)


def test_approved_resume_and_exact_evidence(workbench):
    service,data,calls=workbench
    job=service.create(data);identifier=job['id']
    service.start(identifier);first=settled(service,identifier)
    assert first['status']=='waiting_approval',first['result']
    assert not calls
    assert first['result']['mapping']['routes'][0]['source_link_verified']
    service.start(identifier);assert settled(service,identifier)['result']==first['result']
    for _ in range(3):
        current=service.detail(identifier)
        if current['status']!='waiting_approval': break
        service.decide(identifier,current['result']['approval_id'],True);settled(service,identifier)
    done=service.detail(identifier)
    assert done['status']=='finished',done['result']
    assert len(calls)==9
    proof=service.verify(identifier)
    assert proof['audit_valid'] and proof['evidence_count']==3
    assert any(o['verdict']=='verified_behavior' for o in done['result']['observations'])
    assert len({r['sha256'] for r in [s['preview'] for s in done['stages'] if s['stage'].startswith('http_')]})>=4
    service.start(identifier);assert len(calls)==9
    with Session(service.engine) as s:
        job=s.get(WorkbenchJob,UUID(identifier));runner=UnifiedInvestigation(service.engine,job,service.settings,service.vault,http=lambda **kw:pytest.fail('completed request repeated'))
        assert runner.run()['status']=='finished'


def test_report_download_rejects_modified_http_receipt(workbench):
    service,data,_=workbench;data.update(rounds=1,request_budget=3)
    job=service.create(data)['id'];service.start(job);pending=settled(service,job)
    service.decide(job,pending['result']['approval_id'],True);assert settled(service,job)['status']=='finished'
    assert service.verify(job)['status']=='verified'
    with Session(service.engine) as s,s.begin():
        step=s.scalar(select(DurableStep).where(DurableStep.workflow_id==UUID(job),DurableStep.stage.like('http_%')))
        step.payload={**step.payload,'body':'tampered'}
    with pytest.raises(ValueError,match='receipt'):service.verify(job)


def test_nested_repository_stage_can_be_recovered(workbench,monkeypatch):
    from vulnmind.graph.durable_repository import RepositoryFlow
    service,data,_=workbench
    compute=RepositoryFlow.compute
    def fail(self,stage,prior,audit):
        if stage=='plan':raise RuntimeError('interrupted child')
        return compute(self,stage,prior,audit)
    monkeypatch.setattr(RepositoryFlow,'compute',fail)
    job=service.create(data)['id'];service.start(job);failed=settled(service,job)
    child=next(s for s in failed['child_stages'] if s['status']=='running')
    monkeypatch.setattr(RepositoryFlow,'compute',compute)
    service.recover(job,dict(stage=child['stage'],workflow_id=child['workflow_id'],action='retry',reason='reviewed local child',acknowledged=True))
    assert settled(service,job)['status']=='waiting_approval'


def test_unknown_external_call_requires_explicit_recovery(workbench):
    service,data,calls=workbench
    original=service.runner
    counter=[]
    def lost_response(**kw):
        counter.append(kw);raise RuntimeError('connection lost after request')
    service.runner=lambda *a:UnifiedInvestigation(*a,http=lost_response)
    job=service.create(data)['id'];service.start(job);pending=settled(service,job)
    service.decide(job,pending['result']['approval_id'],True);failed=settled(service,job)
    assert failed['status']=='unknown' and len(counter)==1
    service.start(job);settled(service,job);assert len(counter)==1
    stage=next(s['stage'] for s in failed['stages'] if s['status']=='running')
    with pytest.raises(ValueError): service.recover(job,dict(stage=stage,action='retry',reason='inspected'))
    service.runner=original
    service.recover(job,dict(stage=stage,action='retry',reason='owned fixture, accept repeat',acknowledged=True))
    recovered=settled(service,job)
    assert recovered['status']=='waiting_approval',recovered['result']
    assert len(calls)==6


def test_source_change_blocks_approved_requests(workbench):
    service,data,calls=workbench
    job=service.create(data)['id'];service.start(job);pending=settled(service,job)
    (Path(data['repository'])/'app.py').write_text('# changed')
    service.decide(job,pending['result']['approval_id'],True);result=settled(service,job)
    assert result['status']=='unknown' and 'changed' in result['result']['message']
    assert not calls


def test_local_server_session_origin_csrf(workbench):
    import threading,urllib.request,urllib.error,http.cookiejar
    from vulnmind.workbench.server import make_server
    service,_,_=workbench
    server=make_server(service,0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    base='http://127.0.0.1:'+str(server.server_port)
    client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    try:
        with pytest.raises(urllib.error.HTTPError) as denied: client.open(base+'/api/state')
        assert denied.value.code==403
        assert b'VulnMind' in client.open(base).read()
        state=json.load(client.open(base+'/api/state'))
        req=urllib.request.Request(base+'/api/jobs',data=b'{}',headers={'Content-Type':'application/json','Origin':'http://evil.invalid','X-CSRF-Token':state['csrf']})
        with pytest.raises(urllib.error.HTTPError) as denied: client.open(req)
        assert denied.value.code==403
        req=urllib.request.Request(base+'/api/jobs',data=b'{}',headers={'Content-Type':'application/json'})
        with pytest.raises(urllib.error.HTTPError) as denied: client.open(req)
        assert denied.value.code==403
        req=urllib.request.Request(base+'/api/jobs',data=b'{}',headers={'Content-Type':'text/plain','X-CSRF-Token':state['csrf']})
        with pytest.raises(urllib.error.HTTPError) as denied: client.open(req)
        assert denied.value.code==400
    finally: server.shutdown();server.server_close();thread.join()


def test_download_is_verified_json_attachment(workbench):
    import threading,urllib.request,http.cookiejar
    from vulnmind.workbench.server import make_server
    service,data,_=workbench;data.update(rounds=1,request_budget=3)
    job=service.create(data)['id'];service.start(job);pending=settled(service,job)
    service.decide(job,pending['result']['approval_id'],True);assert settled(service,job)['status']=='finished'
    server=make_server(service,0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    base='http://127.0.0.1:'+str(server.server_port)
    client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    try:
        client.open(base).read()
        response=client.open(base+'/api/jobs/'+job+'/report')
        assert response.headers['Content-Disposition']=='attachment; filename="vulnmind-report.json"'
        assert json.load(response)['job_id']==job
    finally:server.shutdown();server.server_close();thread.join()


def test_model_planner_consumes_critic_feedback(workbench):
    from vulnmind.agents.model import ModelResponse
    import html,re
    service,data,_=workbench
    job=service.create(data)['id']
    class Model:
        def __init__(self): self.prompts=[]
        def complete(self,request):
            text='\n'.join(m.content for m in request.messages);self.prompts.append(text)
            if 'disputed_action_ids' in text and 'Select at most' not in text:
                return ModelResponse(text=json.dumps(dict(continue_investigation=True,disputed_action_ids=[],summary='Need complementary reflection evidence')))
            candidates=json.loads(html.unescape(re.search(r'<reference ref="candidates"[^>]*>\n(.*?)\n</reference>',text,re.S)[1]))
            return ModelResponse(text=json.dumps(dict(action_ids=[candidates[0]['id']],rationale='Follow source and critic')))
    model=Model()
    class Audit:
        def record(self,event): pass
    with Session(service.engine) as s:
        row=s.get(WorkbenchJob,UUID(job));row.config={**row.config,'agents':True}
        runner=UnifiedInvestigation(service.engine,row,service.settings,service.vault,model=model)
        action=dict(id='action1',kind='reflection');first=runner.plan(Audit(),[action],[],[])
        critic=runner.critique(Audit(),[dict(action_id='action1',verdict='candidate')],[action])
        runner.plan(Audit(),[action],[],[critic])
        assert first['mode']=='model' and 'complementary reflection' in model.prompts[-1]


def test_v5_context_shadow_is_recorded_and_v4_is_unchanged(workbench):
    from vulnmind.agents.model import ModelResponse
    import html,re
    service,data,_=workbench
    job=service.create(data)['id']
    class Model:
        def complete(self,request):
            text='\n'.join(m.content for m in request.messages)
            if 'disputed_action_ids' in text:
                return ModelResponse(text=json.dumps(dict(continue_investigation=False,disputed_action_ids=[],summary='ok')))
            candidates=json.loads(html.unescape(re.search(r'<reference ref="candidates"[^>]*>\n(.*?)\n</reference>',text,re.S)[1]))
            return ModelResponse(text=json.dumps(dict(action_ids=[candidates[0]['id']],rationale='ok')))
    class Audit:
        def record(self,event): pass
    action=dict(id='action1',kind='reflection')
    with Session(service.engine) as s:
        row=s.get(WorkbenchJob,UUID(job))
        row.config={**row.config,'agents':True,'pipeline_version':5}
        runner=UnifiedInvestigation(service.engine,row,service.settings,service.vault,model=Model())
        result=runner.plan(Audit(),[action],[],[])
        assert result['mode']=='model'
        shadow=result['context_shadow']
        assert shadow['profile']=='planner' and shadow['budget']==24_000 and shadow['unit']=='tokens'
        assert shadow['used_tokens']>0 and shadow['selected_count']>=2 and shadow['overflow'] is None
        manifest=result['context_manifest']
        assert manifest['budget']==24_000 and manifest['unit']=='tokens'
        assert any(row['ref']=='candidates' and row['selected'] for row in manifest['items'])
        assert any(row['ref']=='system' and row['selected'] for row in manifest['items'])
        critic=runner.critique(Audit(),[dict(action_id='action1',verdict='candidate',kind='reflection')],[action])
        assert critic['mode']=='model' and critic['context_manifest']['budget']==24_000
        assert critic['context_shadow']['profile']=='critic'
        row.config={**row.config,'pipeline_version':4}
        legacy=UnifiedInvestigation(service.engine,row,service.settings,service.vault,model=Model())
        assert 'context_shadow' not in legacy.plan(Audit(),[action],[],[])
