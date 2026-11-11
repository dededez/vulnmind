"""Real MCP + owned offline & local loopback fixture validation; no third-party target requests.

Covers all 23 reviewed controlled executors across health, binary sample analysis,
workspace file/payload/data/IaC operations, 9 egress-enforced Web tools, and
netns/nftables-isolated nmap. A new MCP process must return the identical
execution receipt (same ID and digest) and reconciliation must not repeat work.
"""
import argparse
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

from vulnmind.integrations.hexstrike.catalog import IMPLEMENTED
from vulnmind.workbench.external import ExternalWorkbench

OWNED_HTTP_SERVER = r"""
import http.server, socketserver, sys

class OwnedFixtureHandler(http.server.BaseHTTPRequestHandler):
    server_version = "VulnMindOwnedFixture/1.0"
    def log_message(self, fmt, *args):
        return
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Powered-By", "VulnMind-Lab")
        self.end_headers()
    def do_GET(self):
        if self.path.startswith("/.env"):
            body = b"APP_ENV=local\nDB_HOST=127.0.0.1\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        elif self.path.startswith("/admin") or self.path.startswith("/api") or self.path.startswith("/health"):
            body = b'{"status":"ok","owned_fixture":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        else:
            body = (
                b"<html><head><title>VulnMind Owned Target</title></head>"
                b"<body><a href='/admin'>Admin</a>"
                b"<form action='/item' method='GET'><input name='id' value='1'></form>"
                b"<div>Item: " + self.path.encode("utf-8", errors="ignore") + b"</div></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Powered-By", "VulnMind-Lab")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        self.do_GET()

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 0), OwnedFixtureHandler) as httpd:
    print(httpd.server_address[1], flush=True)
    httpd.serve_forever()
"""


def start_owned_wsl_target(distro='VulnMindLab'):
    proc = subprocess.Popen(
        ['wsl.exe', '-d', distro, '-u', 'root', '--', '/usr/bin/python3', '-u', '-c', OWNED_HTTP_SERVER],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
    )
    port_line = proc.stdout.readline().decode('ascii', errors='replace').strip()
    if not port_line.isdecimal():
        proc.kill()
        raise RuntimeError('failed to start owned loopback target in WSL')
    return proc, int(port_line)


def read_elf_sample(distro='VulnMindLab'):
    res = subprocess.run(
        ['wsl.exe', '-d', distro, '-u', 'root', '--', '/usr/bin/python3', '-c',
         'import sys, pathlib; sys.stdout.buffer.write(pathlib.Path("/mnt/d/\u65b0\u5efa\u6587\u4ef6\u5939/ai-workspace/projects/vulnmind/.devtools/hexstrike-tools/alpine/usr/bin/file").read_bytes()[:40000])'],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
    )
    return res.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    service = ExternalWorkbench(args.root)
    service.refresh()
    records = []
    validation = {}
    fixture = b'\x00\x01VULNMIND_OWNED_OFFLINE_FIXTURE\x00no-network-no-execution\xff'
    elf_fixture = (Path(__file__).resolve().parents[1] / '.devtools/hexstrike-tools/alpine/usr/bin/file').read_bytes()

    def run(name, arguments, *, workspace=None, sample=None, scope=None, budget=None):
        data = dict(tool_id='hexstrike.' + name, arguments=arguments)
        if workspace:
            data['workspace_job_id'] = workspace
        if sample is not None:
            data['sample_base64'] = base64.b64encode(sample).decode()
        if scope is not None:
            data['scope'] = scope
        if budget is not None:
            data['budget'] = budget
        prepared = service.prepare(data)
        plan = prepared['plan']
        result = service.execute(plan['execution_id'], prepared['digest'])
        if result['execution']['status'] != 'succeeded':
            raise RuntimeError(f"{name} failed: {json.dumps(result, ensure_ascii=True)}")
        # A new MCP process, same execution ID: identical receipt, no second worker.
        replay = service.execute(plan['execution_id'], prepared['digest'])
        if replay['execution'] != result['execution']:
            raise ValueError(f'{name}: execution was repeated')
        reconciled = service.reconcile(plan['execution_id'])
        if reconciled['payload'] != result['execution']:
            raise ValueError(f'{name}: reconciliation changed receipt')
        validation[plan['tool_id']] = dict(
            status='passed',
            schema_sha256=plan['schema_sha256'],
            profile_sha256=plan['profile_sha256'],
            skill_sha256=plan['skill_sha256'],
            execution_id=plan['execution_id'],
            result_sha256=result['execution']['result_sha256'],
        )
        records.append(dict(
            tool=plan['tool_id'],
            execution=result['execution'],
            restart_replay_equal=True,
            reconciliation_equal=True,
        ))
        print(name + ': passed; restart replay and reconciliation unchanged', flush=True)
        return plan, result

    # 1. Health & Sample tools (4 tools)
    _, health = run('server_health', {})
    if health['execution']['result'].get('total_tools_available') != len(IMPLEMENTED):
        raise ValueError('health tool count mismatch')
    _, strings = run('strings_extract', {}, sample=fixture)
    if 'VULNMIND_OWNED_OFFLINE_FIXTURE' not in strings['execution']['result']['stdout']:
        raise ValueError('strings result mismatch')
    _, xxd = run('xxd_hexdump', {}, sample=fixture)
    if '5655 4c4e' not in xxd['execution']['result']['stdout']:
        raise ValueError('xxd result mismatch')
    _, objdump = run('objdump_analyze', {'disassemble': False}, sample=elf_fixture)
    if 'file format elf64-x86-64' not in objdump['execution']['result']['stdout']:
        raise ValueError('objdump result mismatch')

    # 2. Workspace File, Payload, Data & IaC tools (9 tools)
    create, _ = run('create_file', {
        'filename': 'Dockerfile',
        'content': 'FROM alpine:latest\nRUN echo VULNMIND_WORKSPACE_FIXTURE\n',
    })
    workspace = create['scope']['workspace']
    _, listing = run('list_files', {'directory': '.'}, workspace=workspace)
    if [entry['name'] for entry in listing['execution']['result'].get('files', [])] != ['Dockerfile']:
        raise ValueError('workspace listing mismatch')
    _, modified = run(
        'modify_file',
        {'filename': 'Dockerfile', 'content': '# appended\n', 'append': True},
        workspace=workspace,
    )
    if modified['execution']['result'].get('size') <= 20:
        raise ValueError('workspace modify mismatch')
    _, generated = run(
        'generate_payload',
        {'payload_type': 'cyclic', 'size': 32, 'filename': 'p.bin'},
        workspace=workspace,
    )
    if generated['execution']['result'].get('size') != 32:
        raise ValueError('payload generation mismatch')
    _, anew = run(
        'anew_data_processing',
        {'input_data': 'alpha\nbeta\nalpha\n', 'output_file': 'urls.txt'},
        workspace=workspace,
    )
    if anew['execution']['result'].get('added_lines') != ['alpha', 'beta']:
        raise ValueError('anew deduplication mismatch')
    _, qsr = run(
        'qsreplace_parameter_replacement',
        {'urls': 'http://127.0.0.1/item?id=1&sort=asc\n', 'replacement': 'FUZZ'},
        workspace=workspace,
    )
    if 'FUZZ' not in (qsr['execution']['result'].get('stdout') or ''):
        raise ValueError('qsreplace output mismatch')
    _, uro = run(
        'uro_url_filtering',
        {'urls': 'http://127.0.0.1/item?id=1\nhttp://127.0.0.1/item?id=2\n'},
        workspace=workspace,
    )
    if uro['execution']['result'].get('count') != 1:
        raise ValueError('uro filtering mismatch')
    _, checkov = run(
        'checkov_iac_scan',
        {'directory': '.', 'framework': 'dockerfile', 'output_format': 'json'},
        workspace=workspace,
    )
    if checkov['execution']['result']['summary']['failed'] < 1:
        raise ValueError('checkov static audit mismatch')
    _, deleted = run('delete_file', {'filename': 'Dockerfile'}, workspace=workspace)
    if deleted['execution']['result'].get('message') != 'deleted':
        raise ValueError('workspace delete mismatch')

    # 3. Egress-enforced Web tools (9 tools) & netns nmap (1 tool) against owned WSL loopback target
    target_proc, port = start_owned_wsl_target()
    try:
        origin = f'http://127.0.0.1:{port}'
        web_scope = {'origins': [origin], 'networks': ['127.0.0.1/32']}
        run('httpx_probe', {'target': f'{origin}/', 'status_code': True, 'title': True},
            scope=web_scope, budget={'requests': 5, 'connections': 5, 'seconds': 25})
        run('katana_crawl', {'url': f'{origin}/', 'depth': 1, 'output_format': 'json'},
            scope=web_scope, budget={'requests': 8, 'connections': 8, 'seconds': 25})
        run('nuclei_scan', {'target': f'{origin}/', 'template': 'http/technologies'},
            scope=web_scope, budget={'requests': 8, 'connections': 8, 'seconds': 30})
        run('dalfox_xss_scan', {'url': f'{origin}/item?id=1'},
            scope=web_scope, budget={'requests': 45, 'connections': 45, 'seconds': 35})
        run('ffuf_scan', {'url': f'{origin}/FUZZ'},
            scope=web_scope, budget={'requests': 5, 'connections': 5, 'seconds': 25})
        run('wafw00f_scan', {'target': f'{origin}/'},
            scope=web_scope, budget={'requests': 12, 'connections': 12, 'seconds': 25})
        run('arjun_parameter_discovery', {'url': f'{origin}/item', 'method': 'GET'},
            scope=web_scope, budget={'requests': 10, 'connections': 10, 'seconds': 25})
        run('arjun_scan', {'url': f'{origin}/item', 'method': 'GET'},
            scope=web_scope, budget={'requests': 10, 'connections': 10, 'seconds': 25})
        run('sqlmap_scan', {'url': f'{origin}/item?id=1'},
            scope=web_scope, budget={'requests': 45, 'connections': 45, 'seconds': 35})
        _, nmap_res = run(
            'nmap_scan',
            {'target': '127.0.0.1', 'ports': str(port), 'scan_type': '-sV'},
            scope={'networks': ['127.0.0.1/32'], 'ports': [port]},
            budget={'requests': 2, 'connections': 2, 'seconds': 25},
        )
        if f'{port}/tcp' not in nmap_res['execution']['result']['stdout']:
            raise ValueError('nmap output missing expected open port')
    finally:
        target_proc.kill()

    manifest = dict(
        recorded_at=datetime.now(timezone.utc).isoformat(),
        environment_sha256=service.environment,
        tools=validation,
    )
    (service.root / 'validation.json').write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )
    totals = service.catalog()['totals']
    if totals.get('validated') != len(IMPLEMENTED) or totals.get('eligible') != len(IMPLEMENTED):
        raise ValueError(f'unexpected validation totals: {totals}')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(dict(**manifest, records=records, totals=totals), ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )
    print(json.dumps(totals))


if __name__ == '__main__':
    main()
