"""Explicit local WSL target only; never uses public network targets."""
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Project, Scan, Approval, DurableStep
from vulnmind.analysis.validation import plan_probes, plan_digest

pytestmark = pytest.mark.skipif(os.getenv("VULNMIND_RUN_HTTP_LIVE") != "1", reason="local WSL HTTP lab opt-in")
ROOT = Path(__file__).resolve().parents[2]

SERVER = r'''
import json, ssl, subprocess, tempfile, pathlib, threading, sys, shutil
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlsplit, unquote
root = pathlib.Path(tempfile.mkdtemp(prefix="vulnmind-product-http-"))
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-keyout", str(root/"key"), "-out", str(root/"cert"), "-subj", "/CN=127.0.0.1",
    "-addext", "subjectAltName=IP:127.0.0.1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
counts = {}
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        path = urlsplit(self.path).path
        if path != "/count": counts[path] = counts.get(path, 0) + 1
        if path == "/count": body = json.dumps(counts).encode()
        elif path == "/": body = b'<a href="/page">page</a><a href="/denied">denied</a>'
        elif path == "/large": body = b'x' * 50000
        else: body = unquote(self.path).encode()
        self.send_response(302 if path == "/redirect" else 200)
        if path == "/redirect": self.send_header("Location", "/denied")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try: self.wfile.write(body)
        except OSError: pass
plain = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
secure = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(root/"cert", root/"key")
secure.socket = context.wrap_socket(secure.socket, server_side=True)
for server in (plain, secure): threading.Thread(target=server.serve_forever, daemon=True).start()
print(json.dumps({"http": plain.server_port, "https": secure.server_port, "ca": (root/"cert").read_text()}), flush=True)
try: sys.stdin.read()
finally:
    for server in (plain, secure): server.shutdown(); server.server_close()
    if root.parent == pathlib.Path(tempfile.gettempdir()) and root.name.startswith("vulnmind-product-http-"):
        shutil.rmtree(root)
'''


@pytest.fixture(scope="module")
def target():
    proc = subprocess.Popen(["wsl.exe", "-d", "VulnMindLab", "-u", "root", "--", "python3", "-u", "-c", SERVER],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        config = json.loads(proc.stdout.readline())
        yield config
    finally:
        proc.communicate(timeout=20)


@pytest.fixture
def setup(tmp_path, target):
    db = tmp_path / "http.db"
    engine = create_engine(f"sqlite:///{db.as_posix()}")
    Base.metadata.create_all(engine)
    project, scan = uuid4(), uuid4()
    with Session(engine) as session, session.begin():
        session.add(Project(id=project, name="owned local lab"))
        session.flush()
        session.add(Scan(id=scan, project_id=project, mode="crawl", status="finished"))
    now = datetime.now(timezone.utc)
    origins = [f"{protocol}://127.0.0.1:{target[protocol]}" for protocol in ("http", "https")]
    scope = {"authorization_source": "owned temporary local test server", "approved_by": "test",
             "starts_at": (now-timedelta(minutes=1)).isoformat(), "expires_at": (now+timedelta(hours=1)).isoformat(),
             "web_origins": origins, "allowed_ip_networks": ["127.0.0.1/32"],
             "denied_web_paths": {origin: ["/denied"] for origin in origins}}
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(scope))
    ca = tmp_path / "ca.pem"
    ca.write_text(target["ca"])
    env = {**os.environ, "VULNMIND_DATABASE_URL": str(engine.url), "VULNMIND_HTTP_CA_FILE": str(ca),
           "VULNMIND_APPROVAL_SECRET": "local-http-test-only-owner-secret-123456789",
           "VULNMIND_APPROVAL_ALLOWED_SIGNERS": "",
           "VULNMIND_HTTP_BROKER_DISTRO": "VulnMindLab", "PYTHONIOENCODING": "utf-8",
           "PYTHONPATH": str(ROOT / "src"), "HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1"}
    yield dict(engine=engine, project=project, scan=scan, scope=scope_file, origins=origins, env=env)
    engine.dispose()


def cli(setup, command, *args):
    result = subprocess.run([sys.executable, "-m", "vulnmind", command, "--scope-file", str(setup["scope"]),
                             *map(str, args)], cwd=ROOT, env=setup["env"], capture_output=True, encoding="utf-8", timeout=45)
    assert result.stdout, result.stderr
    return result.returncode, json.loads(result.stdout)


def counts(setup):
    code, payload = cli(setup, "fetch", "--url", setup["origins"][0] + "/count")
    assert code == 0, payload
    return json.loads(payload["body"])


def test_public_fetch_https_pinning_proxy_redirect_scope_and_replay(setup):
    before = counts(setup)
    operation = uuid4()
    url = setup["origins"][1] + "/page"
    code, first = cli(setup, "fetch", "--url", url, "--operation-id", operation)
    assert code == 0 and first["body"] == "/page", first
    assert cli(setup, "fetch", "--url", url, "--operation-id", operation) == (code, first)
    assert cli(setup, "fetch", "--url", setup["origins"][0] + "/changed", "--operation-id", operation)[0] == 2
    after = counts(setup)
    assert after.get("/page", 0) == before.get("/page", 0) + 1
    assert cli(setup, "fetch", "--url", setup["origins"][0] + "/denied")[0] == 2
    assert cli(setup, "fetch", "--url", "http://127.0.0.1:1/page")[0] == 2
    code, redirect = cli(setup, "fetch", "--url", setup["origins"][0] + "/redirect")
    assert code == 0 and redirect["status_code"] == 302
    assert counts(setup).get("/denied", 0) == before.get("/denied", 0)
    code, large = cli(setup, "fetch", "--url", setup["origins"][0] + "/large", "--max-bytes", 100)
    assert code == 0 and large["body_bytes"] == 100 and large["truncated"]


def test_public_crawl_and_validation_resume_without_duplicate_requests(setup):
    operation = uuid4()
    args = ("--start", setup["origins"][0] + "/", "--store", "--project-id", setup["project"], "--operation-id", operation)
    code, result = cli(setup, "crawl", *args)
    assert code == 0 and result["endpoint_count"] == 1 and len(result["pages"]) == 2, result
    before = counts(setup)
    assert cli(setup, "crawl", *args) == (code, result)
    assert counts(setup) == before
    url = setup["origins"][0] + "/search?q=x"
    probes = plan_probes([url])
    def approval_cli(*arguments):
        result = subprocess.run([sys.executable, "-m", "vulnmind", *map(str, arguments)], cwd=ROOT,
            env=setup["env"], capture_output=True, encoding="utf-8", timeout=20)
        assert result.returncode == 0, result.stdout + result.stderr
        return json.loads(result.stdout)
    from uuid import UUID
    requested = approval_cli("validate-request", "--scan-id", setup["scan"], "--url", url)
    approval_id = UUID(requested["approval_id"])
    assert approval_cli("approvals", "decide", "--id", approval_id, "--approver", "local-test-owner",
                        "--local-owner")["status"] == "approved"
    args = ("--scan-id", setup["scan"], "--url", url, "--approval-token", approval_id)
    code, result = cli(setup, "validate-run", *args)
    assert code == 0 and result["candidates"] >= 1, result
    before = counts(setup)
    assert cli(setup, "validate-run", *args) == (code, result)
    assert counts(setup) == before
    with Session(setup["engine"]) as session:
        assert session.get(Approval, approval_id).status == "consumed"


def test_tls_untrusted_ca_and_unknown_request_never_replayed(setup):
    setup["env"]["VULNMIND_HTTP_CA_FILE"] = ""
    operation = uuid4()
    args = ("--url", setup["origins"][1] + "/page", "--operation-id", operation)
    code, result = cli(setup, "fetch", *args)
    assert code == 2 and result["status"] == "unknown"
    with Session(setup["engine"]) as session:
        row = session.scalar(select(DurableStep).where(DurableStep.workflow_id == operation, DurableStep.stage != "http_binding"))
        assert row.attempt == 1 and row.status == "running"
    assert cli(setup, "fetch", *args)[0] == 2
    with Session(setup["engine"]) as session:
        assert session.scalar(select(DurableStep).where(DurableStep.workflow_id == operation, DurableStep.stage != "http_binding")).attempt == 1


def test_public_web_loop_approval_evidence_report_and_replay(setup, tmp_path):
    setup['env'].update(VULNMIND_REPORT_ROOT=str(tmp_path/'reports'), VULNMIND_EVIDENCE_ROOT=str(tmp_path/'evidence'))
    args = ('--workflow-id', uuid4(), '--project-id', setup['project'], '--start', setup['origins'][1]+'/search?q=x')
    code, waiting = cli(setup, 'workflow-web', *args)
    assert code == 0 and waiting['status'] == 'waiting_approval', waiting
    assert cli(setup, 'workflow-web', *args) == (code, waiting)
    result = subprocess.run([sys.executable, '-m', 'vulnmind', 'approvals', 'decide', '--id', waiting['approval_id'],
        '--approver', 'test', '--local-owner'], cwd=ROOT, env=setup['env'], capture_output=True, timeout=20)
    assert result.returncode == 0, result.stdout
    code, done = cli(setup, 'workflow-web', *args)
    assert code == 0 and done['status'] == 'finished', done
    before = counts(setup)
    assert cli(setup, 'workflow-web', *args) == (code, done)
    assert counts(setup) == before
    report = json.loads((tmp_path/'reports'/done['report_uri']).read_text(encoding='utf-8'))
    assert report['scan_id'] == done['scan_id']
    assert report['validation_performed'] is True


def test_empty_namespace_blocks_noncooperative_process(target):
    from vulnmind.analysis import http_broker_worker
    source = Path(http_broker_worker.__file__).read_text()
    source = source[:source.index('if __name__ == "__main__":')]
    source += '\n' + f'''
isolate()
assert not os.path.exists('/proc') and not os.path.exists('/run') and os.listdir('/') == []
for family, address in [(socket.AF_INET, ('127.0.0.1', {target['http']})), (socket.AF_INET, ('1.1.1.1', 443)), (socket.AF_INET6, ('::1', 443))]:
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(.2)
    try:
        sock.connect(address)
        raise RuntimeError("unexpected network escape")
    except OSError: pass
    finally: sock.close()
libc = ctypes.CDLL(None, use_errno=True)
assert libc.unshare(0x40000000) != 0
print("isolated")
'''
    result = subprocess.run(["wsl.exe", "-d", "VulnMindLab", "-u", "root", "--", "python3", "-I", "-c", source],
        capture_output=True, timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert result.returncode == 0 and result.stdout.strip() == b"isolated"


def test_process_death_after_http_response_never_resends_unknown_request(setup):
    operation = uuid4()
    url = setup["origins"][0] + "/crash"
    args = ["vulnmind", "fetch", "--url", url, "--scope-file", str(setup["scope"]), "--operation-id", str(operation)]
    driver = '''import os,sys
from vulnmind.analysis.http_broker import IsolatedHttpBroker
original = IsolatedHttpBroker.__call__
def send(self, **kwargs):
    response = original(self, **kwargs)
    os._exit(74)
IsolatedHttpBroker.__call__ = send
from vulnmind.__main__ import main
sys.argv = ARGS
raise SystemExit(main())
'''.replace("ARGS", repr(args))
    before = counts(setup).get("/crash", 0)
    result = subprocess.run([sys.executable, "-c", driver], cwd=ROOT, env=setup["env"], capture_output=True, timeout=30)
    assert result.returncode == 74, result.stdout + result.stderr
    assert counts(setup).get("/crash", 0) == before + 1
    code, result = cli(setup, "fetch", "--url", url, "--operation-id", operation)
    assert code == 2 and result["status"] == "unknown"
    assert counts(setup).get("/crash", 0) == before + 1
