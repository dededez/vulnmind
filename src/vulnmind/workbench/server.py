"""Loopback-only UI server with exact Host/Origin checks and session CSRF token."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from http.cookies import SimpleCookie
import hmac
import json
import os
from pathlib import Path
import secrets
from urllib.parse import urlsplit


def make_server(service,port=8765):
    session_token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
    static=Path(__file__).with_name('static')
    import threading
    external_service=None
    external_lock=threading.Lock()
    def external():
        nonlocal external_service
        with external_lock:
            if external_service is None:
                from vulnmind.workbench.external import validated_service
                external_service=validated_service(service.root/'external',distro=service.settings.http_broker_distro)
        return external_service
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def reply(self,status,value,content_type='application/json; charset=utf-8',cookie=False,download=False):
            body=json.dumps(value,ensure_ascii=False).encode() if isinstance(value,(dict,list)) else value
            self.send_response(status)
            self.send_header('Content-Type',content_type);self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
            if download: self.send_header('Content-Disposition','attachment; filename="vulnmind-report.json"')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            if cookie: self.send_header('Set-Cookie','vm_session='+session_token+'; HttpOnly; SameSite=Strict; Path=/')
            self.end_headers();self.wfile.write(body)

        def allowed(self,write=False):
            host='127.0.0.1:'+str(self.server.server_port)
            if self.headers.get('Host')!=host: return False
            origin=self.headers.get('Origin')
            if origin and origin!='http://'+host: return False
            if self.headers.get('Sec-Fetch-Site')=='cross-site': return False
            if self.path in {'/','/app.js','/tools.js','/style.css'} and not write: return True
            cookies=SimpleCookie()
            try: cookies.load(self.headers.get('Cookie',''))
            except Exception: return False
            token=cookies.get('vm_session')
            if not token or not hmac.compare_digest(token.value,session_token): return False
            return not write or hmac.compare_digest(self.headers.get('X-CSRF-Token',''),csrf)

        def do_GET(self):
            if not self.allowed(): return self.reply(403,dict(error='本机会话校验失败，请使用 127.0.0.1 地址打开页面'))
            path=urlsplit(self.path).path
            if path in {'/','/app.js','/tools.js','/style.css'}:
                filename={'/':'index.html','/app.js':'app.js','/tools.js':'tools.js','/style.css':'style.css'}[path]
                kind={'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/tools.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}[path]
                return self.reply(200,(static/filename).read_bytes(),kind,cookie=path=='/')
            try:
                if path=='/api/state': return self.reply(200,{**service.list(),'csrf':csrf})
                if path=='/api/tools': return self.reply(200,external().catalog())
                if path.startswith('/api/jobs/'):
                    parts=path.split('/');detail=service.detail(parts[3])
                    if len(parts)==5 and parts[4]=='report':
                        service.verify(parts[3])
                        from vulnmind.reports.store import ReportStore
                        uri=(detail['result'] or {}).get('report_uri')
                        if not uri: raise ValueError('报告尚未生成')
                        return self.reply(200,ReportStore(Path(service.settings.report_root)).read(uri).encode(),download=True)
                    if len(parts)==5 and parts[4]=='verify': return self.reply(200,service.verify(parts[3]))
                    if len(parts)==5 and parts[4]=='coverage':
                        # Explicit operator action: offline evaluation against a frozen
                        # truth file. The engine never reads this data.
                        from vulnmind.workbench.generic_coverage import build_report
                        truth_setting=os.environ.get('VULNMIND_COVERAGE_TRUTH')
                        if not truth_setting: raise ValueError('尚未配置与当前目标匹配的通用评估基准；不会套用其他应用的漏洞清单')
                        truth_path=Path(truth_setting)
                        if not truth_path.is_file(): raise ValueError('未找到离线真值文件，请设置 VULNMIND_COVERAGE_TRUTH')
                        if detail['status']!='finished': raise ValueError('任务尚未完成，无法生成覆盖率')
                        truth=json.loads(truth_path.read_text(encoding='utf-8'))
                        report,_,_=build_report(truth,detail['result'] or {},'ui',config=detail['config'])
                        return self.reply(200,report)
                    return self.reply(200,detail)
                self.reply(404,dict(error='not found'))
            except ValueError as exc: self.reply(400,dict(error=str(exc)[:300]))
            except Exception: self.reply(500,dict(error='无法读取本机数据，请检查服务与数据库配置'))

        def do_POST(self):
            if not self.allowed(True): return self.reply(403,dict(error='请求来源或会话令牌不匹配'))
            path=urlsplit(self.path).path
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=1_000_000 or self.headers.get_content_type()!='application/json': raise ValueError('请求应为不超过 1 MB 的 JSON')
                data=json.loads(self.rfile.read(length));path=urlsplit(self.path).path
                if not isinstance(data,dict): raise ValueError('invalid object')
                if path=='/api/tools/refresh': result=external().refresh()
                elif path=='/api/tools/prepare': result=external().prepare(data)
                elif path=='/api/tools/execute': result=external().execute(data['execution_id'],data['digest'])
                elif path=='/api/tools/reconcile': result=external().reconcile(data['execution_id'])
                elif path=='/api/demo':
                    from vulnmind.workbench.demo import configuration
                    result=configuration(service)
                elif path=='/api/jobs': result=service.create_current(data)
                elif path=='/api/credentials':
                    result=dict(id=service.vault.save(data['origin'].rstrip('/'),data['kind'],data['value']))
                elif path=='/api/accounts': raise ValueError('请通过通用凭据接口配置已有测试身份')
                elif path.startswith('/api/jobs/'):
                    parts=path.split('/');identifier,action=parts[3],parts[4]
                    current=service.detail(identifier)
                    cfg=current['config']
                    if action in {'start','approve','recover'} and current['status']!='finished' and (cfg.get('pipeline_version',1)!=7 or cfg.get('target_adapter','generic')!='generic'):
                        raise ValueError('旧专用流程仅保留记录；请按实际接口和凭据新建通用调查')
                    if action=='start': result=service.start(identifier)
                    elif action=='approve': result=service.decide(identifier,data['approval_id'],data['approved'])
                    elif action=='recover': result=service.recover(identifier,data)
                    else: raise ValueError('unknown action')
                else: return self.reply(404,dict(error='not found'))
                self.reply(200,result)
            except (ValueError,KeyError,IndexError) as exc:
                # Validation errors can include inputs; never serialize credential values.
                message='请检查输入字段、授权范围与关联任务' if path in {'/api/credentials','/api/accounts'} or type(exc).__name__=='ValidationError' else str(exc)[:300]
                self.reply(400,dict(error=message))
            except Exception: self.reply(500,dict(error='操作未完成，请刷新任务查看持久状态'))
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    server.daemon_threads=True
    return server


def serve(port=8765):
    from sqlalchemy import create_engine,text
    from vulnmind.config import Settings
    from vulnmind.workbench.service import Workbench
    settings=Settings()
    if not settings.database_url or not settings.report_root or not settings.evidence_root:
        raise ValueError('请先配置数据库与报告/证据目录')
    engine=create_engine(settings.database_url)
    with engine.connect() as conn:
        if conn.execute(text('SELECT version_num FROM alembic_version')).scalar_one()!='0019_durable_step_failed':
            raise ValueError('请先备份并升级数据库至 0019_durable_step_failed')
    root=Path(settings.report_root).resolve().parent/'workbench'
    service=Workbench(engine,settings,root)
    server=make_server(service,port)
    print('VulnMind 工作台：http://127.0.0.1:'+str(server.server_port),flush=True)
    try: server.serve_forever()
    finally:
        server.server_close();service.close();engine.dispose()
