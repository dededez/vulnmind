"""Only the bundled owned WSL fixture, never public targets."""
import os
import pytest
from datetime import datetime,timedelta,timezone
from types import SimpleNamespace
from vulnmind.workbench.demo import configuration
from vulnmind.workbench.secrets import Vault
from vulnmind.config import Settings
from vulnmind.analysis.http_broker import IsolatedHttpBroker
from vulnmind.schemas import Authorization


@pytest.mark.skipif(os.getenv('VULNMIND_RUN_HTTP_LIVE')!='1',reason='owned WSL lab opt-in')
def test_authenticated_json_and_form_through_isolated_broker(tmp_path):
    service=SimpleNamespace(root=tmp_path,settings=Settings(_env_file=None),vault=Vault(tmp_path/'credentials'))
    config=configuration(service);now=datetime.now(timezone.utc)
    scope=Authorization(authorization_source='owned WSL fixture',approved_by='test',starts_at=now-timedelta(minutes=1),expires_at=now+timedelta(hours=1),web_origins=[config['origin']],allowed_ip_networks=['127.0.0.1/32'])
    broker=IsolatedHttpBroker(scope);auth=service.vault.load(config['credential_profile'],config['origin'])
    try:
        for path,body,media,expected in [('/api/template','{"name":"{{731*19}}"}','application/json',b'13889'),('/form','q=owned-form','application/x-www-form-urlencoded',b'Form: owned-form')]:
            response=broker.request_api(method='POST',url=config['origin']+path,headers={**auth,'Content-Type':media},body=body,addresses=['127.0.0.1'],approval_digest='a'*64,auth_origin=config['origin'])
            assert response.status_code==200 and response.body==expected
        response=broker.request_api(method='POST',url=config['origin']+'/api/template',headers={'Content-Type':'application/json'},body='{}',addresses=['127.0.0.1'],approval_digest='a'*64,auth_origin=config['origin'])
        assert response.status_code==401
    finally:service.demo_process.communicate(input='stop\n',timeout=10)


@pytest.mark.skipif(os.getenv('VULNMIND_RUN_HTTP_LIVE')!='1',reason='owned WSL lab opt-in')
def test_v2_sql_html_cors_and_headers_through_real_isolation(tmp_path):
    import hashlib
    from vulnmind.workbench.detectors import requests_for,evaluate,CATALOG
    service=SimpleNamespace(root=tmp_path,settings=Settings(_env_file=None),vault=Vault(tmp_path/'credentials'))
    config=configuration(service);now=datetime.now(timezone.utc)
    scope=Authorization(authorization_source='owned WSL fixture',approved_by='test',starts_at=now-timedelta(minutes=1),expires_at=now+timedelta(hours=1),web_origins=[config['origin']],allowed_ip_networks=['127.0.0.1/32'])
    broker=IsolatedHttpBroker(scope)
    try:
        for kind in ('sql_boolean','sql_error','xss_context','cors','security_headers'):
            action=dict(id=kind,kind=kind,category=CATALOG[kind][0],detector_version='2.0.0',method='GET',
                        url=config['origin']+('/sql' if kind.startswith('sql') else '/search'),
                        parameter='' if kind in {'cors','security_headers'} else 'q',parameters=['q'],source={})
            responses=[]
            for spec in requests_for(action):
                r=broker.request_api(**{k:spec[k] for k in ('method','url','headers','body')},addresses=['127.0.0.1'],approval_digest='a'*64,auth_origin=config['origin'])
                body=r.body.decode();responses.append(dict(status_code=r.status_code,body=body,headers=r.headers,truncated=r.truncated,sha256=hashlib.sha256(body.encode()).hexdigest()))
            assert evaluate(action,responses)['verdict']=='candidate',kind
    finally:service.demo_process.communicate(input='stop\n',timeout=10)
