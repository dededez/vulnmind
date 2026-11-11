"""Explicitly requested, owned loopback fixture; no general expression evaluator."""
import hashlib
import json
import subprocess
import threading

SOURCE = '''import json, re, sys, threading, sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs
from types import SimpleNamespace
class App:
    def get(self, path): return lambda fn: fn
    def post(self, path): return lambda fn: fn
app=App()
request=SimpleNamespace(args={},json={},form={})

@app.get('/sql')
def sql():
    q=request.args.get('q','1')
    with sqlite3.connect(':memory:') as db:
        db.executescript("create table items(id text);insert into items values('1');")
        try: return json.dumps(db.execute(f"select id from items where id='{q}'").fetchall())
        except sqlite3.Error: return 'SQLSTATE[42000]: demo SQL syntax error'
def render_template_string(value):
    # Owned demo: multiply two bounded integers only; never eval target input.
    return re.sub(r"\\{\\{([0-9]{1,4})\\*([0-9]{1,4})\\}\\}",lambda m:str(int(m[1])*int(m[2])),value)
@app.get('/search')
def search():
    return 'Search: '+request.args.get('q','')
@app.post('/api/template')
def template():
    return render_template_string(request.json.get('name',''))
@app.post('/form')
def form():
    return 'Form: '+request.form.get('q','')
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self): self.respond()
    def do_POST(self): self.respond()
    def respond(self):
        path=urlsplit(self.path).path
        request.args={k:v[0] for k,v in parse_qs(urlsplit(self.path).query).items()}
        status=200
        if self.command=='POST':
            raw=self.rfile.read(min(int(self.headers.get('Content-Length',0)),64000)).decode()
            if self.headers.get('Authorization')!='Bearer vulnmind-owned-demo': status=401;body='Authentication required'
            elif path=='/api/template':
                request.json=json.loads(raw);body=template()
            elif path=='/form':
                request.form={k:v[0] for k,v in parse_qs(raw).items()};body=form()
            else: status=404;body='not found'
        elif path=='/search': body=search()
        elif path=='/sql': body=sql()
        else: status=404;body='not found'
        data=body.encode();self.send_response(status)
        self.send_header('Content-Type','text/html; charset=utf-8' if path=='/search' else 'text/plain; charset=utf-8')
        if path=='/search' and self.headers.get('Origin'):
            self.send_header('Access-Control-Allow-Origin',self.headers['Origin'])
            self.send_header('Access-Control-Allow-Credentials','true')
        self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
if __name__=='__main__':
    server=HTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    print(json.dumps({'port':server.server_port}),flush=True)
    sys.stdin.readline()
    server.shutdown()
'''

_lock=threading.Lock()

def configuration(service):
    with _lock:
        if hasattr(service,'demo_config') and service.demo_process.poll() is None:
            return service.demo_config
        repo=service.root/'demo-v3'/'repository';repo.mkdir(parents=True,exist_ok=True)
        (repo/'app.py').write_text(SOURCE,encoding='utf-8')
        process=subprocess.Popen(['wsl.exe','-d',service.settings.http_broker_distro,'--','python3','-u','-c',SOURCE],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',errors='replace',
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        # Bound startup even if the WSL distro cannot launch.
        from concurrent.futures import ThreadPoolExecutor
        reader=ThreadPoolExecutor(1)
        try:
            line=reader.submit(process.stdout.readline).result(timeout=20)
            port=json.loads(line)['port']
        except Exception:
            process.kill();process.communicate();raise ValueError('本地演示启动失败，请检查 VulnMindLab WSL')
        finally: reader.shutdown(wait=False)
        origin='http://127.0.0.1:'+str(port)
        profile=service.vault.save(origin,'bearer','vulnmind-owned-demo')
        service.demo_process=process
        service.demo_config=dict(name='本地演示 · 源码与 API 联合调查',repository=str(repo),origin=origin,
            path_prefix='',deployment_version='owned-demo-'+hashlib.sha256(SOURCE.encode()).hexdigest()[:12],
            binding_confirmed=True,allowed_ip_networks=['127.0.0.1/32'],authorization_source='VulnMind 自有本机演示环境',
            agents=False,rounds=3,request_budget=30,allow_post=True,credential_profile=profile,
            routes=[dict(method='POST',path='/form',parameters=['q'],encoding='form')])
        return service.demo_config
