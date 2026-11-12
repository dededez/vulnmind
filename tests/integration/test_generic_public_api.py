import http.cookiejar
import json
import threading
import urllib.request
import urllib.error
import pytest
from test_durable_flow import flow
from test_workbench import workbench
from vulnmind.workbench.server import make_server


def test_only_generic_jobs_can_be_created_or_started_from_public_api(workbench,monkeypatch):
    service,data,calls=workbench
    monkeypatch.delenv('VULNMIND_COVERAGE_TRUTH',raising=False)
    legacy=service.create(data)['id']
    server=make_server(service,port=0)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    base='http://127.0.0.1:'+str(server.server_port)
    opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def api(path,payload=None):
        req=urllib.request.Request(base+path,data=None if payload is None else json.dumps(payload).encode(),
            headers={'Content-Type':'application/json','Origin':base,'X-CSRF-Token':csrf})
        return json.load(opener.open(req,timeout=5))
    try:
        opener.open(base+'/').read();csrf=json.load(opener.open(base+'/api/state'))['csrf']
        generic={k:v for k,v in data.items() if k!='pipeline_version'}
        created=api('/api/jobs',generic)
        assert created['config']['target_adapter']=='generic' and created['config']['pipeline_version']==7
        for path,payload in [('/api/jobs',{**generic,'target_adapter':'juice_shop'}),('/api/jobs',data),
                ('/api/accounts',{'origin':data['origin']}),('/api/jobs/'+legacy+'/start',{})]:
            with pytest.raises(urllib.error.HTTPError) as e:api(path,payload)
            assert e.value.code==400
        with pytest.raises(urllib.error.HTTPError) as e:api('/api/jobs/'+created['id']+'/coverage')
        assert e.value.code==400
        assert not calls and service.detail(legacy)['status']=='draft'
    finally:
        server.shutdown();server.server_close();thread.join(timeout=3)
