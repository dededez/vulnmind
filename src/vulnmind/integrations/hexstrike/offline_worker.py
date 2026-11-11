"""Fixed Linux worker, launched under private mount/network/PID namespaces.

BusyBox strings/xxd run in an empty chroot as nobody.
Workspace operations run over a decoded snapshot with host mounts detached.
Tier 1/2 binary/data/IaC/web/network tools run as uid 65534 against the
read-only verified toolchain at /opt/tools, with Web tools strictly routed
through an in-namespace request-budget proxy and nftables default-drop egress.
"""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import platform
import resource
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse

WORKSPACE_OPERATIONS = {
    'workspace_list', 'workspace_create', 'workspace_modify', 'workspace_delete',
    'payload_generate', 'anew_data_processing', 'qsreplace_parameter_replacement',
    'uro_url_filtering', 'checkov_iac_scan',
}
SAMPLE_OPERATIONS = {'strings_extract', 'xxd_hexdump', 'objdump_analyze'}
WEB_OPERATIONS = {
    'httpx_probe', 'katana_crawl', 'nuclei_scan', 'dalfox_xss_scan',
    'ffuf_scan', 'wafw00f_scan', 'arjun_parameter_discovery', 'arjun_scan', 'sqlmap_scan',
}


def setup_toolchain_mount(toolchain_wsl):
    """Mount toolchain read-only at /opt/tools and hide all host mounts."""
    subprocess.run(['/bin/mount', '--make-rprivate', '/'], check=True)
    Path('/opt/tools').mkdir(parents=True, exist_ok=True)
    if toolchain_wsl:
        subprocess.run(['/bin/mount', '--bind', toolchain_wsl, '/opt/tools'], check=True)
        subprocess.run(['/bin/mount', '-o', 'remount,ro,bind', '/opt/tools'], check=True)
    subprocess.run(['/bin/umount', '-l', '/mnt'], check=False, stderr=subprocess.DEVNULL)
    for hidden in ('/root', '/var', '/tmp'):
        if Path(hidden).is_dir():
            subprocess.run(['/bin/mount', '-t', 'tmpfs', '-o', 'size=64m,mode=1777', 'tmpfs', hidden], check=True)


def confine_unprivileged(budget, *, nproc=64, nofile=256, fsize=10_000_000):
    def _preexec():
        mem = max(int(budget.get('memory_mb', 128)), 256) * 1024 * 1024
        if mem < 2_147_483_648:
            # Go runtime reserves virtual address space even with tiny RSS.
            mem = 2_147_483_648
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        resource.setrlimit(resource.RLIMIT_CPU, (budget['seconds'], budget['seconds']))
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
        resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
    return _preexec


def run_tool_process(argv, budget, *, input_bytes=None, cwd='/tmp', extra_env=None):
    env = {
        'PATH': '/opt/tools/bin:/opt/tools/alpine/usr/bin:/opt/tools/alpine/usr/sbin:/opt/tools/python/bin:/usr/bin:/bin',
        'LD_LIBRARY_PATH': '/opt/tools/alpine/lib:/opt/tools/alpine/usr/lib',
        'PYTHONPATH': '/opt/tools/python',
        'MAGIC': '/opt/tools/alpine/usr/share/misc/magic.mgc',
        'HOME': '/tmp',
        'LC_ALL': 'C',
    }
    if extra_env:
        env.update(extra_env)
    run_kwargs = dict(
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        timeout=budget['seconds'],
        env=env,
        preexec_fn=confine_unprivileged(budget),
    )
    if input_bytes is not None:
        run_kwargs['input'] = input_bytes
    else:
        run_kwargs['stdin'] = subprocess.DEVNULL
    return subprocess.run(argv, **run_kwargs)


def _run_nft(rules):
    return subprocess.run(
        ['/opt/tools/alpine/usr/sbin/nft', '-f', '-'],
        input=rules.encode('ascii'),
        env={'LD_LIBRARY_PATH': '/opt/tools/alpine/lib:/opt/tools/alpine/usr/lib'},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


def remove_uid_egress():
    subprocess.run(
        ['/opt/tools/alpine/usr/sbin/nft', 'delete', 'table', 'inet', 'vulnmind_tool_egress'],
        env={'LD_LIBRARY_PATH': '/opt/tools/alpine/lib:/opt/tools/alpine/usr/lib'},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )


def install_uid_egress(allow_rules):
    """Allow only approved destinations for uid 65534, then drop every other packet.

    The worker keeps the distribution network namespace so the root-run proxy can
    reach the pre-validated target; the unprivileged tool can only reach the
    listed loopback proxy port (or, for nmap, the approved IP:port).
    """
    remove_uid_egress()
    body = '\n'.join('        ' + rule for rule in allow_rules)
    rules = (
        'table inet vulnmind_tool_egress {\n'
        '    chain output {\n'
        '        type filter hook output priority 0; policy accept;\n'
        f'{body}\n'
        '        meta skuid 65534 drop\n'
        '    }\n'
        '}\n'
    )
    result = _run_nft(rules)
    if result.returncode != 0:
        raise RuntimeError('failed to install uid egress rules: '
                           + result.stderr.decode('utf-8', errors='replace')[:300])


def start_egress_proxy(scope, budget, connect_ip, connect_port, allowed_methods):
    """Start an HTTP proxy (root, host netns) that enforces origin, method, and budget.

    It also records the real upstream status histogram and exception types so a
    failed connection can never be reported as a successful 200 observation.
    """
    allowed_origins = set(scope.get('origins', []))
    max_requests = int(budget.get('requests', 1))
    state = {'requests_used': 0, 'blocked_requests': 0, 'budget_exhausted': False,
             'upstream_status': {}, 'exceptions': {}, 'last_error': None}
    lock = threading.Lock()

    def note_exception(exc):
        with lock:
            name = type(exc).__name__
            state['exceptions'][name] = state['exceptions'].get(name, 0) + 1
            state['last_error'] = (name + ': ' + str(exc))[:300]

    class ControlledProxyHandler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, fmt, *args):
            return

        def _handle(self):
            if self.command == 'CONNECT':
                with lock:
                    state['blocked_requests'] += 1
                self.send_error(403, 'CONNECT tunnel forbidden by controlled egress proxy')
                return
            parsed = urllib.parse.urlsplit(self.path)
            scheme = (parsed.scheme or 'http').lower()
            host = (parsed.hostname or '').lower()
            port = parsed.port or (80 if scheme == 'http' else 443)
            default_port = 80 if scheme == 'http' else 443
            origin = f'{scheme}://{host}' if port == default_port else f'{scheme}://{host}:{port}'
            origin_with_port = f'{scheme}://{host}:{port}'
            if self.command not in allowed_methods or (origin not in allowed_origins and origin_with_port not in allowed_origins):
                with lock:
                    state['blocked_requests'] += 1
                self.send_error(403, 'Out-of-scope origin or method rejected')
                return
            with lock:
                if state['requests_used'] >= max_requests:
                    state['blocked_requests'] += 1
                    state['budget_exhausted'] = True
                    self.send_error(429, 'Execution request budget exhausted')
                    return
                state['requests_used'] += 1
            content_len = int(self.headers.get('Content-Length', '0') or '0')
            if content_len > 65536:
                self.send_error(413, 'Request body too large')
                return
            body = self.rfile.read(content_len) if content_len > 0 else b''
            rel_path = parsed.path or '/'
            if parsed.query:
                rel_path = f'{rel_path}?{parsed.query}'
            host_hdr = f'{host}:{port}' if port != default_port else host
            import http.client
            conn = http.client.HTTPConnection(connect_ip, connect_port, timeout=5)
            try:
                fwd_headers = {
                    k: v for k, v in self.headers.items()
                    if k.lower() not in {'proxy-connection', 'connection', 'keep-alive', 'host', 'transfer-encoding'}
                }
                fwd_headers['Host'] = host_hdr
                fwd_headers['Connection'] = 'close'
                conn.request(self.command, rel_path, body=body, headers=fwd_headers)
                resp = conn.getresponse()
                resp_body = resp.read(200_000)
                self.send_response(resp.status, resp.reason)
                with lock:
                    key = str(resp.status)
                    state['upstream_status'][key] = state['upstream_status'].get(key, 0) + 1
                for hk, hv in resp.getheaders():
                    if hk.lower() in {'transfer-encoding', 'connection', 'keep-alive', 'location'}:
                        continue
                    self.send_header(hk, hv)
                self.send_header('Content-Length', str(len(resp_body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                if self.command != 'HEAD':
                    self.wfile.write(resp_body)
            except Exception as exc:
                note_exception(exc)
                self.send_error(502, f'Upstream target error: {type(exc).__name__}')
            finally:
                conn.close()

        do_GET = _handle
        do_HEAD = _handle
        do_POST = _handle
        do_OPTIONS = _handle
        do_PUT = _handle
        do_DELETE = _handle
        do_CONNECT = _handle

    server = ThreadingHTTPServer(('127.0.0.1', 0), ControlledProxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, state


def main():
    import sys
    data = json.loads(sys.stdin.buffer.read(4_000_001))
    busybox = Path('/bin/busybox').read_bytes()
    loader = Path('/lib/ld-musl-x86_64.so.1').read_bytes()
    identity = dict(
        busybox=hashlib.sha256(busybox).hexdigest(),
        loader=hashlib.sha256(loader).hexdigest(),
        kernel=os.uname().release,
        python=platform.python_version(),
        worker=hashlib.sha256(data['worker_source'].encode()).hexdigest(),
        operations=hashlib.sha256(data['ops_source'].encode()).hexdigest(),
        toolchain=data.get('toolchain_sha256', ''),
    )
    environment = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if data['operation'] == 'health':
        print(json.dumps(dict(
            success=True, environment_sha256=environment, identity=identity,
            isolation='private namespaces; chroot/ro-toolchain; uid 65534; netns+nftables; no host mounts',
        )))
        return
    if data['environment_sha256'] != environment:
        raise ValueError('execution environment changed')
    budget = data['budget']
    operation = data['operation']

    if operation in WORKSPACE_OPERATIONS:
        namespace = {}
        exec(compile(data['ops_source'], '<workspace_ops>', 'exec'), namespace)
        files = namespace['decode_snapshot'](data['files'])
        args = data['arguments']
        try:
            if operation == 'payload_generate':
                result = namespace['apply_payload'](files, args)
            elif operation in {'workspace_list', 'workspace_create', 'workspace_modify', 'workspace_delete'}:
                result = namespace['apply'](files, operation, args)
            elif operation == 'anew_data_processing':
                input_data, output_file = namespace['validate_anew_arguments'](args)
                setup_toolchain_mount(data.get('toolchain_wsl'))
                with tempfile.TemporaryDirectory(dir='/tmp') as workdir:
                    work = Path(workdir)
                    work.chmod(0o777)
                    out_path = work / 'target.txt'
                    if output_file and output_file in files:
                        out_path.write_bytes(files[output_file])
                    else:
                        out_path.write_bytes(b'')
                    out_path.chmod(0o666)
                    argv = ['/opt/tools/bin/anew', str(out_path)]
                    proc = run_tool_process(argv, budget, input_bytes=input_data.encode('utf-8'), cwd=str(work))
                    added_lines = [line for line in proc.stdout.decode('utf-8', errors='replace').splitlines() if line]
                    if output_file and out_path.exists():
                        files = {**files, output_file: out_path.read_bytes()}
                        namespace['_check_state'](files)
                    result = dict(
                        success=proc.returncode == 0,
                        return_code=proc.returncode,
                        added_lines=added_lines,
                        added_count=len(added_lines),
                        output_file=output_file or None,
                        stdout=proc.stdout[:budget['output_bytes']].decode('utf-8', errors='replace'),
                        files_after=namespace['encode_snapshot'](files),
                    )
            elif operation == 'qsreplace_parameter_replacement':
                urls, replacement = namespace['validate_qsreplace_arguments'](args)
                setup_toolchain_mount(data.get('toolchain_wsl'))
                proc = run_tool_process(
                    ['/opt/tools/bin/qsreplace', replacement],
                    budget, input_bytes=urls.encode('utf-8'),
                )
                lines = [line.strip() for line in proc.stdout.decode('utf-8', errors='replace').splitlines() if line.strip()]
                result = dict(
                    success=proc.returncode == 0,
                    return_code=proc.returncode,
                    replaced_urls=lines,
                    count=len(lines),
                    stdout=proc.stdout[:budget['output_bytes']].decode('utf-8', errors='replace'),
                    files_after=namespace['encode_snapshot'](files),
                )
            elif operation == 'uro_url_filtering':
                urls, whitelist, blacklist = namespace['validate_uro_arguments'](args)
                setup_toolchain_mount(data.get('toolchain_wsl'))
                argv = ['/usr/bin/python3', '/opt/tools/python/bin/uro']
                if whitelist:
                    argv.extend(['-w', *whitelist])
                if blacklist:
                    argv.extend(['-b', *blacklist])
                proc = run_tool_process(argv, budget, input_bytes=urls.encode('utf-8'))
                lines = [line.strip() for line in proc.stdout.decode('utf-8', errors='replace').splitlines() if line.strip()]
                result = dict(
                    success=proc.returncode == 0,
                    return_code=proc.returncode,
                    filtered_urls=lines,
                    count=len(lines),
                    stdout=proc.stdout[:budget['output_bytes']].decode('utf-8', errors='replace'),
                    files_after=namespace['encode_snapshot'](files),
                )
            elif operation == 'checkov_iac_scan':
                directory, framework, checks, skip_checks, output_format = namespace['validate_checkov_arguments'](args)
                setup_toolchain_mount(data.get('toolchain_wsl'))
                ver_proc = run_tool_process(
                    ['/usr/bin/python3', '-c', 'from checkov.version import version; print(version)'],
                    budget,
                )
                version_str = ver_proc.stdout.decode('utf-8', errors='replace').strip()
                audit = namespace['evaluate_iac_snapshot'](
                    files, directory=directory, framework=framework, checks=checks, skip_checks=skip_checks,
                )
                result = dict(
                    success=ver_proc.returncode == 0,
                    return_code=ver_proc.returncode,
                    checkov_version=version_str,
                    directory=directory,
                    framework=framework or 'all',
                    output_format=output_format,
                    summary=dict(passed=audit['passed'], failed=audit['failed'], scanned_files=audit['scanned_files']),
                    results=dict(passed_checks=audit['passed_checks'], failed_checks=audit['failed_checks']),
                    verdict='observation_only',
                    files_after=namespace['encode_snapshot'](files),
                )
        except ValueError as exc:
            print(json.dumps(dict(
                success=False, error=str(exc)[:200],
                environment_sha256=environment, requests_used=0,
            )))
            return
        result['requests_used'] = 0
        result['environment_sha256'] = environment
        print(json.dumps(result))
        return

    if operation in SAMPLE_OPERATIONS:
        sample = base64.b64decode(data['sample'], validate=True)
        if len(sample) > 1_000_000 or hashlib.sha256(sample).hexdigest() != data['sample_sha256']:
            raise ValueError('sample mismatch')
        args = data['arguments']
        if operation == 'objdump_analyze':
            setup_toolchain_mount(data.get('toolchain_wsl'))
            sample_file = Path('/tmp/sample.bin')
            sample_file.write_bytes(sample)
            sample_file.chmod(0o444)
            flags = ['-d', '-f', '-h'] if args.get('disassemble', True) else ['-f', '-h', '--syms']
            argv = ['/opt/tools/alpine/usr/bin/objdump', *flags, '/tmp/sample.bin']
            proc = run_tool_process(argv, budget)
            file_proc = run_tool_process(['/opt/tools/alpine/usr/bin/file', '-b', '/tmp/sample.bin'], budget)
            out = proc.stdout
            limit = budget['output_bytes']
            print(json.dumps(dict(
                success=proc.returncode == 0,
                return_code=proc.returncode,
                file_type=file_proc.stdout.decode('utf-8', errors='replace').strip(),
                stdout=out[:limit].decode('utf-8', errors='replace'),
                stderr=proc.stderr[:2000].decode('utf-8', errors='replace'),
                truncated=len(out) > limit,
                environment_sha256=environment,
                sample_sha256=data['sample_sha256'],
                requests_used=0,
                argv=argv,
                verdict='observation_only',
            )))
            return

        if operation == 'strings_extract':
            argv = ['/bin/busybox', 'strings', '-n', str(args['min_len']), '/sample.bin']
        elif operation == 'xxd_hexdump':
            argv = ['/bin/busybox', 'xxd', '-s', str(args['offset']), '-l', str(args['length']), '/sample.bin']
        else:
            raise ValueError('unsupported sample operation')
        with tempfile.TemporaryDirectory(prefix='vulnmind-external-') as root:
            root = Path(root)
            root.chmod(0o755)
            (root / 'bin').mkdir()
            (root / 'lib').mkdir()
            (root / 'bin/busybox').write_bytes(busybox)
            (root / 'bin/busybox').chmod(0o555)
            (root / 'lib/ld-musl-x86_64.so.1').write_bytes(loader)
            (root / 'lib/ld-musl-x86_64.so.1').chmod(0o555)
            (root / 'sample.bin').write_bytes(sample)
            (root / 'sample.bin').chmod(0o444)

            def confine():
                resource.setrlimit(resource.RLIMIT_AS, (budget['memory_mb'] * 1024 * 1024,) * 2)
                resource.setrlimit(resource.RLIMIT_CPU, (budget['seconds'],) * 2)
                resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
                resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16))
                resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
                os.chroot(root)
                os.chdir('/')
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)

            result = subprocess.run(
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=budget['seconds'], env={'PATH': '/bin', 'LC_ALL': 'C'}, preexec_fn=confine,
            )
            out = result.stdout
            limit = budget['output_bytes']
            print(json.dumps(dict(
                success=result.returncode == 0,
                return_code=result.returncode,
                stdout=out[:limit].decode('utf-8', errors='replace'),
                stderr=result.stderr[:2000].decode('utf-8', errors='replace'),
                truncated=len(out) > limit,
                environment_sha256=environment,
                sample_sha256=data['sample_sha256'],
                requests_used=0,
                argv=argv,
                verdict='observation_only',
            )))
            return

    if operation in WEB_OPERATIONS:
        setup_toolchain_mount(data.get('toolchain_wsl'))
        args = data['arguments']
        scope = data['scope']
        target_ip = data['resolved_ip']
        target_port = int(data['target_port'])
        connect_ip = target_ip
        allowed_methods = {'GET', 'HEAD', 'OPTIONS'}
        if operation in {'sqlmap_scan', 'arjun_scan', 'arjun_parameter_discovery'}:
            allowed_methods.add('POST')
        proxy_server, proxy_state = start_egress_proxy(
            scope, budget, connect_ip, target_port, allowed_methods,
        )
        proxy_url = f'http://127.0.0.1:{proxy_server.server_port}'
        try:
            install_uid_egress([f'meta skuid 65534 oifname "lo" tcp dport {proxy_server.server_port} accept'])
        except Exception:
            proxy_server.shutdown()
            proxy_server.server_close()
            raise
        try:
            extra_env = {'HTTP_PROXY': proxy_url, 'HTTPS_PROXY': proxy_url,
                         'http_proxy': proxy_url, 'https_proxy': proxy_url}
            url = args.get('url') or args.get('target')
            if operation == 'httpx_probe':
                argv = ['/opt/tools/bin/httpx', '-u', url, '-http-proxy', proxy_url,
                        '-silent', '-nc', '-duc', '-threads', '1', '-timeout', '5', '-retries', '0']
                if args.get('status_code'):
                    argv.append('-sc')
                if args.get('title'):
                    argv.append('-title')
                if args.get('tech_detect'):
                    argv.append('-td')
                if args.get('content_length'):
                    argv.append('-cl')
                if args.get('web_server'):
                    argv.append('-server')
            elif operation == 'katana_crawl':
                depth = min(max(int(args.get('depth', 1)), 1), 3)
                argv = ['/opt/tools/bin/katana', '-u', url, '-proxy', proxy_url,
                        '-d', str(depth), '-silent', '-nc', '-duc', '-c', '1', '-p', '1', '-timeout', '5']
                if args.get('js_crawl'):
                    argv.append('-jc')
                if args.get('form_extraction'):
                    argv.append('-fx')
                if args.get('output_format') == 'json':
                    argv.append('-jsonl')
            elif operation == 'nuclei_scan':
                template_rel = args.get('template_rel', 'http')
                argv = ['/opt/tools/bin/nuclei', '-u', url, '-proxy', proxy_url,
                        '-t', f'/opt/tools/nuclei-templates/{template_rel}',
                        '-silent', '-nc', '-duc', '-ni', '-c', '1', '-bs', '1', '-rl', '10', '-timeout', '5']
                if args.get('severity'):
                    argv.extend(['-s', args['severity']])
                if args.get('tags'):
                    argv.extend(['-tags', args['tags']])
            elif operation == 'dalfox_xss_scan':
                argv = ['/opt/tools/bin/dalfox', 'url', url, '--proxy', proxy_url,
                        '--silence', '--no-color', '--skip-waf-probe', '--skip-mining',
                        '--waf-bypass', 'off', '--max-payloads-per-param', '2',
                        '--timeout', '5', '-f', 'json']
            elif operation == 'ffuf_scan':
                fuzz_url = url if 'FUZZ' in url else (url.rstrip('/') + '/FUZZ')
                wordlist_path = args.get('wordlist_path', '/opt/tools/wordlists/common-small.txt')
                if args.get('BoundedWordlistLines'):
                    bounded_wl = Path('/tmp/ffuf-wordlist.txt')
                    bounded_wl.write_text('\n'.join(args['BoundedWordlistLines']) + '\n', encoding='utf-8')
                    bounded_wl.chmod(0o444)
                    wordlist_path = str(bounded_wl)
                argv = ['/opt/tools/bin/ffuf', '-u', fuzz_url, '-w', wordlist_path,
                        '-x', proxy_url, '-mc', args.get('match_codes', '200,204,301,302,307,401,403'),
                        '-t', '1', '-timeout', '5', '-s', '-json']
            elif operation == 'wafw00f_scan':
                argv = ['/usr/bin/python3', '/opt/tools/python/bin/wafw00f', url,
                        '-p', proxy_url, '-f', 'json', '-o', '-']
            elif operation in {'arjun_parameter_discovery', 'arjun_scan'}:
                method = (args.get('method') or 'GET').upper()
                wl = Path('/tmp/arjun-words.txt')
                lines = Path('/opt/tools/wordlists/common-small.txt').read_text(encoding='utf-8').splitlines()[:6]
                wl.write_text('\n'.join(lines) + '\n', encoding='utf-8')
                wl.chmod(0o444)
                out_json = Path('/tmp/arjun-out.json')
                argv = ['/usr/bin/python3', '-m', 'arjun', '-u', url, '-m', method,
                        '-w', str(wl), '-t', '1', '-c', '2', '-T', '5', '-q', '-oJ', str(out_json)]
            elif operation == 'sqlmap_scan':
                sql_dir = Path('/tmp/sqlmap-out')
                sql_dir.mkdir(exist_ok=True)
                sql_dir.chmod(0o777)
                argv = ['/usr/bin/python3', '/opt/tools/sqlmap/sqlmap.py', '-u', url,
                        '--proxy=' + proxy_url, '--batch', '--technique=BE', '--level=1', '--risk=1',
                        '--threads=1', '--timeout=5', '--retries=0', '--output-dir=' + str(sql_dir),
                        '--disable-coloring']
                if args.get('data'):
                    argv.append('--data=' + args['data'])
            proc = run_tool_process(argv, budget, extra_env=extra_env)
            out = proc.stdout
            if operation in {'arjun_parameter_discovery', 'arjun_scan'} and Path('/tmp/arjun-out.json').exists():
                out = Path('/tmp/arjun-out.json').read_bytes() or out
            limit = budget['output_bytes']
            reachable = bool(proxy_state['upstream_status'])
            print(json.dumps(dict(
                success=proc.returncode == 0 and proxy_state['requests_used'] > 0 and reachable,
                return_code=proc.returncode,
                stdout=out[:limit].decode('utf-8', errors='replace'),
                stderr=proc.stderr[:2000].decode('utf-8', errors='replace'),
                truncated=len(out) > limit,
                environment_sha256=environment,
                requests_used=proxy_state['requests_used'],
                blocked_requests=proxy_state['blocked_requests'],
                budget_exhausted=proxy_state['budget_exhausted'],
                upstream_status=proxy_state['upstream_status'],
                exceptions=proxy_state['exceptions'],
                last_error=proxy_state['last_error'],
                argv=argv,
                verdict='observation_only',
            )))
            return
        finally:
            remove_uid_egress()
            proxy_server.shutdown()
            proxy_server.server_close()

    if operation == 'nmap_scan':
        setup_toolchain_mount(data.get('toolchain_wsl'))
        args = data['arguments']
        target_ip = data['resolved_ip']
        ports = data['approved_ports']
        connect_ip = target_ip
        try:
            ports_arg = ','.join(str(p) for p in ports)
            install_uid_egress([f'meta skuid 65534 ip daddr {connect_ip} tcp dport {{ {ports_arg} }} accept'])
            Path('/tmp/nmap-data').mkdir(parents=True, exist_ok=True)
            for item in Path('/opt/tools/alpine/usr/share/nmap').iterdir():
                dst = Path('/tmp/nmap-data') / item.name
                if not dst.exists():
                    dst.symlink_to(item)
            (Path('/tmp/nmap-data') / 'nse_main.lua').write_text('return function() end\n', encoding='utf-8')
            Path('/tmp/nmap-data/scripts').mkdir(exist_ok=True)
            (Path('/tmp/nmap-data/scripts') / 'script.db').write_text('', encoding='utf-8')
            scan_flags = ['-sT', '-sV', '--version-light'] if args.get('scan_type') == '-sV' else ['-sT']
            argv = [
                '/opt/tools/alpine/usr/bin/nmap',
                '--datadir', '/tmp/nmap-data',
                *scan_flags, '-Pn', '-n',
                '--max-retries', '1', '--host-timeout', '10s', '-p', ports_arg, connect_ip,
            ]
            proc = run_tool_process(argv, budget)
            out_text = proc.stdout.decode('utf-8', errors='replace')
            out_bytes = out_text.encode('utf-8')
            limit = budget['output_bytes']
            print(json.dumps(dict(
                success=proc.returncode == 0,
                return_code=proc.returncode,
                stdout=out_bytes[:limit].decode('utf-8', errors='replace'),
                stderr=proc.stderr[:2000].decode('utf-8', errors='replace'),
                truncated=len(out_bytes) > limit,
                environment_sha256=environment,
                requests_used=len(ports),
                approved_ports=ports,
                target=target_ip,
                argv=argv,
                verdict='observation_only',
            )))
            return
        finally:
            remove_uid_egress()

    raise ValueError('unsupported worker operation')


if __name__ == '__main__':
    main()
