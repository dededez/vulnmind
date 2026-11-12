"""Opt-in real Edge verification against an ephemeral owned HTTP application."""
import os
import html
import threading
import urllib.request
from urllib.parse import urlsplit,parse_qs
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from datetime import datetime,timedelta,timezone
from types import SimpleNamespace
import pytest
from vulnmind.schemas import Authorization,Target
from vulnmind.security.scope import check_target,check_resolved_addresses
from vulnmind.workbench.browser import BrowserRunner,evaluate_browser
from vulnmind.workbench.browser_checks import actions


@pytest.mark.skipif(os.getenv('VULNMIND_GENERIC_BROWSER_LIVE')!='1',reason='real Edge opt-in')
@pytest.mark.parametrize('vulnerable',[False,True])
def test_real_browser_changed_endpoint_and_normal_alert(vulnerable):
    calls=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            value=parse_qs(urlsplit(self.path).query).get('phrase',[''])[0]
            text=value if vulnerable else html.escape(value)
            self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers()
            self.wfile.write(('<html><body><script>alert("ordinary-page-dialog")</script>'+text+'</body></html>').encode())
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    origin='http://127.0.0.1:'+str(server.server_port)
    now=datetime.now(timezone.utc)
    scope=Authorization(authorization_source='owned transient test app',approved_by='test',starts_at=now-timedelta(minutes=1),
        expires_at=now+timedelta(minutes=5),web_origins=[origin],allowed_ip_networks=['127.0.0.1/32'])
    def transport(method,url):
        check_target(Target(type='web',locator=url),scope)
        check_resolved_addresses(Target(type='web',locator=url),scope,['127.0.0.1'])
        calls.append(url)
        with urllib.request.urlopen(urllib.request.Request(url,method=method),timeout=3) as r:
            return SimpleNamespace(status_code=r.code,body=r.read(),headers=dict(r.headers),truncated=False)
    action=actions(dict(routes=[dict(id='r',url=origin+'/catalog/render',method='GET',parameters=['phrase'],executable=True)]))[0]
    try:
        runner=BrowserRunner(scope,origin,max_requests=40,transport=transport)
        runs=[runner.run(url,wait_ms=100) for url in [action['baseline_url'],action['url'],action['url']]]
        outcome={**runs[-1],'causal_runs':runs,'requests':sum(r['requests'] for r in runs)}
        result=evaluate_browser(action,outcome)
        assert result['verdict']==('candidate' if vulnerable else 'inconclusive')
        assert len(calls)==outcome['requests'] and 3<=len(calls)<=120
        assert all('/catalog/render?' in u for u in calls)
    finally:
        server.shutdown();server.server_close();thread.join(timeout=3)
