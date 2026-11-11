"""Controlled replacement for the upstream HTTP executor; no shell commands."""
import base64
import hashlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
import shutil
import socket
import subprocess
import urllib.parse
from uuid import uuid4

from vulnmind.integrations.hexstrike.catalog import IMPLEMENTED, PROBE_PROGRAMS
from vulnmind.integrations.hexstrike.workspace_ops import (
    decode_snapshot, encode_snapshot, normalize_name,
    validate_anew_arguments, validate_checkov_arguments,
    validate_payload_arguments, validate_qsreplace_arguments,
    validate_uro_arguments,
)

WORKSPACE_ENDPOINTS = {
    'hexstrike.create_file': 'api/files/create',
    'hexstrike.modify_file': 'api/files/modify',
    'hexstrike.delete_file': 'api/files/delete',
    'hexstrike.list_files': 'api/files/list',
    'hexstrike.generate_payload': 'api/payloads/generate',
    'hexstrike.anew_data_processing': 'api/tools/anew',
    'hexstrike.qsreplace_parameter_replacement': 'api/tools/qsreplace',
    'hexstrike.uro_url_filtering': 'api/tools/uro',
    'hexstrike.checkov_iac_scan': 'api/tools/checkov',
}
WORKSPACE_OPERATIONS = {
    'hexstrike.create_file': 'workspace_create',
    'hexstrike.modify_file': 'workspace_modify',
    'hexstrike.delete_file': 'workspace_delete',
    'hexstrike.list_files': 'workspace_list',
    'hexstrike.generate_payload': 'payload_generate',
    'hexstrike.anew_data_processing': 'anew_data_processing',
    'hexstrike.qsreplace_parameter_replacement': 'qsreplace_parameter_replacement',
    'hexstrike.uro_url_filtering': 'uro_url_filtering',
    'hexstrike.checkov_iac_scan': 'checkov_iac_scan',
}
WORKSPACE_ARGUMENTS = {
    'hexstrike.create_file': {'filename', 'content', 'binary'},
    'hexstrike.modify_file': {'filename', 'content', 'append'},
    'hexstrike.delete_file': {'filename'},
    'hexstrike.list_files': {'directory'},
    'hexstrike.generate_payload': {'type', 'size', 'pattern', 'filename'},
    'hexstrike.anew_data_processing': {'input_data', 'output_file', 'additional_args'},
    'hexstrike.qsreplace_parameter_replacement': {'urls', 'replacement', 'additional_args'},
    'hexstrike.uro_url_filtering': {'urls', 'whitelist', 'blacklist', 'additional_args'},
    'hexstrike.checkov_iac_scan': {'directory', 'framework', 'check', 'skip_check', 'output_format', 'additional_args'},
}
SAMPLE_ENDPOINTS = {
    'hexstrike.strings_extract': 'api/tools/strings',
    'hexstrike.xxd_hexdump': 'api/tools/xxd',
    'hexstrike.objdump_analyze': 'api/tools/objdump',
}
WEB_ENDPOINTS = {
    'hexstrike.httpx_probe': 'api/tools/httpx',
    'hexstrike.katana_crawl': 'api/tools/katana',
    'hexstrike.nuclei_scan': 'api/tools/nuclei',
    'hexstrike.dalfox_xss_scan': 'api/tools/dalfox',
    'hexstrike.ffuf_scan': 'api/tools/ffuf',
    'hexstrike.wafw00f_scan': 'api/tools/wafw00f',
    'hexstrike.arjun_parameter_discovery': 'api/tools/arjun',
    'hexstrike.arjun_scan': 'api/tools/arjun',
    'hexstrike.sqlmap_scan': 'api/tools/sqlmap',
}
NETWORK_ENDPOINTS = {
    'hexstrike.nmap_scan': 'api/tools/nmap',
}
WEB_OPERATIONS = frozenset(tool.removeprefix('hexstrike.') for tool in WEB_ENDPOINTS)
PINNED_TEMPLATES = frozenset({
    'http',
    'http/technologies',
    'http/technologies/tech-detect.yaml',
    'http/misconfiguration',
    'http/misconfiguration/missing-security-headers.yaml',
    'http/exposures/configs',
    'http/exposures/configs/dotenv-exposure.yaml',
})


def default_toolchain_root():
    candidate = Path(__file__).resolve().parents[4] / '.devtools' / 'hexstrike-tools'
    if (candidate / 'manifest.json').is_file():
        return candidate
    return None


def to_wsl_path(win_path):
    resolved = Path(win_path).resolve()
    return '/mnt/' + resolved.drive[0].lower() + '/' + PurePosixPath(*resolved.parts[1:]).as_posix()


def verify_toolchain(toolchain_root=None, required_entrypoints=()):
    root = Path(toolchain_root or default_toolchain_root() or '')
    manifest_file = root / 'manifest.json'
    if not manifest_file.is_file():
        raise ValueError('hexstrike toolchain manifest is missing')
    raw = manifest_file.read_bytes()
    manifest = json.loads(raw.decode('utf-8'))
    entrypoints = manifest.get('entrypoints', {})
    for name in required_entrypoints:
        info = entrypoints.get(name)
        if not info:
            raise ValueError(f'required toolchain entrypoint not declared: {name}')
        target = (root / info['path']).resolve()
        if not target.is_relative_to(root.resolve()) or not target.is_file():
            raise ValueError(f'toolchain entrypoint missing on disk: {name}')
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if digest != info.get('sha256'):
            raise ValueError(f'toolchain entrypoint integrity mismatch: {name}')
    return root, hashlib.sha256(raw).hexdigest(), manifest


def validate_web_target(url, scope):
    if not isinstance(url, str) or not 1 <= len(url) <= 2048 or any(ord(c) < 33 or ord(c) >= 127 for c in url):
        raise ValueError('target URL must be bounded printable ASCII without whitespace')
    parsed = urllib.parse.urlsplit(url)
    scheme = (parsed.scheme or '').lower()
    if scheme not in {'http', 'https'} or not parsed.hostname:
        raise ValueError('target URL must use http or https with an explicit host')
    if parsed.username or parsed.password:
        raise ValueError('target URL must not embed credentials')
    host = parsed.hostname.lower()
    port = parsed.port or (80 if scheme == 'http' else 443)
    default_port = 80 if scheme == 'http' else 443
    origin = f'{scheme}://{host}' if port == default_port else f'{scheme}://{host}:{port}'
    origin_with_port = f'{scheme}://{host}:{port}'
    allowed_origins = {o.rstrip('/') for o in (scope.origins or [])}
    if not allowed_origins or (origin not in allowed_origins and origin_with_port not in allowed_origins):
        raise ValueError('target URL origin is outside approved ResourceScope.origins')
    if not scope.networks:
        raise ValueError('Web ResourceScope requires explicit CIDR networks')
    networks = [ipaddress.ip_network(net, strict=False) for net in scope.networks]
    try:
        resolved_ips = [ipaddress.ip_address(host)]
    except ValueError:
        if host in {'localhost', 'localhost.localdomain'}:
            resolved_ips = [ipaddress.ip_address('127.0.0.1')]
        else:
            infos = socket.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
            resolved_ips = [ipaddress.ip_address(item[4][0]) for item in infos]
    if not resolved_ips:
        raise ValueError('unable to resolve target host')
    for ip_val in resolved_ips:
        if not any(ip_val in net for net in networks):
            raise ValueError(f'resolved IP {ip_val} is outside approved ResourceScope.networks')
    return str(resolved_ips[0]), port


def validate_network_target(target, ports_raw, scan_type, scope):
    if not isinstance(target, str) or not 1 <= len(target) <= 255:
        raise ValueError('invalid network target')
    if scan_type not in {'-sT', '-sV'}:
        raise ValueError('only unprivileged TCP connect/service scans (-sT, -sV) are permitted')
    if not scope.networks or not scope.ports:
        raise ValueError('network ResourceScope requires explicit networks and ports')
    networks = [ipaddress.ip_network(net, strict=False) for net in scope.networks]
    try:
        ip_val = ipaddress.ip_address(target.strip())
    except ValueError:
        if target.strip().lower() == 'localhost':
            ip_val = ipaddress.ip_address('127.0.0.1')
        else:
            raise ValueError('network target must be an explicit IPv4 address') from None
    if not any(ip_val in net for net in networks):
        raise ValueError('network target IP is outside approved ResourceScope.networks')
    approved_set = {int(p) for p in scope.ports if 1 <= int(p) <= 65535}
    if not approved_set or len(approved_set) > 32:
        raise ValueError('network ResourceScope.ports must contain 1..32 valid TCP ports')
    if ports_raw:
        if not isinstance(ports_raw, str):
            raise ValueError('ports must be a comma-separated string')
        requested = []
        for token in ports_raw.split(','):
            token = token.strip()
            if not token.isdecimal() or not 1 <= int(token) <= 65535:
                raise ValueError('ports must be explicit port numbers (no arbitrary ranges)')
            requested.append(int(token))
        if not requested or not set(requested) <= approved_set:
            raise ValueError('requested ports exceed approved ResourceScope.ports')
        ports = sorted(set(requested))
    else:
        ports = sorted(approved_set)
    return str(ip_val), ports


def worker(data, *, distro='VulnMindLab'):
    here = Path(__file__).parent
    source = (here / 'offline_worker.py').read_text(encoding='utf-8')
    operations = (here / 'workspace_ops.py').read_text(encoding='utf-8')
    tc_root = default_toolchain_root()
    tc_sha = hashlib.sha256((tc_root / 'manifest.json').read_bytes()).hexdigest() if tc_root else ''
    tc_wsl = to_wsl_path(tc_root) if tc_root else ''
    payload = {
        **data,
        'worker_source': source,
        'ops_source': operations,
        'toolchain_sha256': tc_sha,
        'toolchain_wsl': tc_wsl,
    }
    seconds = data.get('budget', {}).get('seconds', 20)
    # Web/network tools need the distribution network namespace: the root-run
    # proxy (or nmap allowlist) reaches the validated target, while uid 65534 is
    # restricted by nftables. Sample/workspace operations keep a private netns.
    operation = data.get('operation')
    egress_tools = WEB_OPERATIONS | {'nmap_scan'}
    unshare_flags = ['--mount', '--pid', '--fork'] if operation in egress_tools \
        else ['--mount', '--net', '--pid', '--fork']
    command = [
        'wsl.exe', '-d', distro, '-u', 'root', '--', '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin:/sbin',
        '/usr/bin/timeout', '-s', 'KILL', str(seconds + 10),
        '/usr/bin/unshare', *unshare_flags,
        '/usr/bin/python3', '-I', '-c', source,
    ]
    result = subprocess.run(
        command, input=json.dumps(payload).encode(), stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=seconds + 20,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
    )
    if result.returncode or len(result.stdout) > 4_000_000:
        raise RuntimeError('isolated external worker failed')
    return json.loads(result.stdout)


def probe(*, distro='VulnMindLab', programs=None, runner=None, toolchain_root=None):
    """Read-only PATH/fingerprint probe; the probe script never executes a program."""
    source = Path(__file__).with_name('environment_probe.py').read_text(encoding='utf-8')
    names = list(programs or PROBE_PROGRAMS)
    path_env = '/usr/bin:/bin'
    if toolchain_root is None:
        toolchain_root = default_toolchain_root()
    if toolchain_root is not None:
        wsl_base = to_wsl_path(toolchain_root)
        path_env = f'{wsl_base}/bin:{wsl_base}/alpine/usr/bin:{wsl_base}/alpine/usr/sbin:{wsl_base}/python/bin:{path_env}'
    command = [
        'wsl.exe', '-d', distro, '-u', 'root', '--', '/usr/bin/env', '-i', 'PATH=' + path_env,
        '/usr/bin/timeout', '-s', 'KILL', '60', '/usr/bin/unshare', '--net', '--fork',
        '/usr/bin/python3', '-I', '-c', source,
    ]
    payload = json.dumps({'programs': names}).encode()

    def invoke(cmd, data):
        return subprocess.run(
            cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=90, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )

    result = (runner or invoke)(command, payload)
    if result.returncode or len(result.stdout) > 2_000_000:
        raise RuntimeError('environment probe failed')
    report = json.loads(result.stdout)
    if not isinstance(report.get('programs'), dict):
        raise RuntimeError('environment probe returned an invalid report')
    return report


class ControlledClient:
    """Only these reviewed upstream endpoints are executable. Everything else fails closed."""
    def __init__(self, root, plan, *, distro='VulnMindLab', runner=worker, toolchain_root=None):
        self.root = Path(root).resolve()
        self.plan = plan
        self.distro = distro
        self.runner = runner
        self.toolchain_root = toolchain_root

    def check_health(self):
        if self.plan.tool_id != 'hexstrike.server_health' or self.plan.scope.kind != 'execution':
            raise ValueError('health scope mismatch')
        result = self.runner(dict(operation='health'), distro=self.distro)
        if result['environment_sha256'] != self.plan.environment_sha256:
            raise ValueError('environment changed')
        return dict(
            **result, status='healthy', total_tools_available=len(IMPLEMENTED),
            note='controlled Tier-1/Tier-2 profiles with uid egress filtering and request-budget proxy',
        )

    def safe_get(self, endpoint, params=None):
        if self.plan.tool_id != 'hexstrike.list_files':
            raise ValueError('unadapted endpoint')
        return self._workspace_call(endpoint, dict(params or {}))

    def safe_post(self, endpoint, json_data):
        data = dict(json_data or {})
        if self.plan.tool_id in WORKSPACE_ENDPOINTS:
            return self._workspace_call(endpoint, data)
        if self.plan.tool_id in SAMPLE_ENDPOINTS:
            return self._sample_call(endpoint, data)
        if self.plan.tool_id in WEB_ENDPOINTS:
            return self._web_call(endpoint, data)
        if self.plan.tool_id in NETWORK_ENDPOINTS:
            return self._network_call(endpoint, data)
        raise ValueError('unadapted or mismatched endpoint')

    def _sample_call(self, endpoint, json_data):
        if SAMPLE_ENDPOINTS.get(self.plan.tool_id) != endpoint:
            raise ValueError('unadapted or mismatched endpoint')
        if self.plan.scope.kind != 'sample' or not self.plan.scope.sample_sha256:
            raise ValueError('sample scope required')
        if self.plan.budget.requests or self.plan.budget.connections:
            raise ValueError('offline budget required')
        if json_data.get('additional_args', ''):
            raise ValueError('additional_args are not allowed')
        if self.plan.tool_id == 'hexstrike.objdump_analyze':
            if json_data.get('binary') != 'sample.bin':
                raise ValueError('only staged sample.bin is allowed')
            disassemble = json_data.get('disassemble', True)
            if not isinstance(disassemble, bool):
                raise ValueError('disassemble must be boolean')
            if self.runner is worker:
                verify_toolchain(self.toolchain_root, ('objdump', 'file'))
            args = dict(disassemble=disassemble)
        else:
            if json_data.get('file_path') != 'sample.bin':
                raise ValueError('only staged sample.bin and fixed arguments are allowed')
            if self.plan.tool_id.endswith('strings_extract'):
                minimum = json_data.get('min_len', 4)
                if type(minimum) is not int or not 4 <= minimum <= 32:
                    raise ValueError('min_len must be 4..32')
                args = dict(min_len=minimum)
            else:
                def integer(key, default, limit):
                    raw = str(json_data.get(key, '') or default)
                    if not raw.isascii() or not raw.isdecimal() or not 0 <= int(raw) <= limit:
                        raise ValueError('invalid bounded numeric parameter')
                    return int(raw)
                args = dict(offset=integer('offset', 0, 1_000_000), length=integer('length', 4096, 65536))
        path = self.root / 'samples' / str(self.plan.job_id) / (self.plan.scope.sample_sha256 + '.bin')
        if path.is_symlink() or path.resolve().parent != (self.root / 'samples' / str(self.plan.job_id)).resolve():
            raise ValueError('invalid sample path')
        if not path.resolve().is_relative_to(self.root):
            raise ValueError('sample escapes execution root')
        with path.open('rb') as stream:
            sample = stream.read(1_000_001)
        if len(sample) > 1_000_000 or hashlib.sha256(sample).hexdigest() != self.plan.scope.sample_sha256:
            raise ValueError('sample content changed')
        result = self.runner(dict(
            operation=self.plan.tool_id.removeprefix('hexstrike.'),
            arguments=args,
            sample=base64.b64encode(sample).decode(),
            sample_sha256=self.plan.scope.sample_sha256,
            environment_sha256=self.plan.environment_sha256,
            budget=self.plan.budget.model_dump(),
        ), distro=self.distro)
        if result.get('environment_sha256') != self.plan.environment_sha256:
            raise ValueError('execution environment changed')
        return result

    def _workspace_call(self, endpoint, arguments):
        tool = self.plan.tool_id
        if WORKSPACE_ENDPOINTS.get(tool) != endpoint:
            raise ValueError('unadapted or mismatched endpoint')
        if self.plan.scope.kind != 'workspace' or self.plan.scope.workspace != str(self.plan.job_id):
            raise ValueError('workspace scope must match the execution job')
        if self.plan.budget.requests or self.plan.budget.connections:
            raise ValueError('workspace budget must not permit network access')
        if set(arguments) - WORKSPACE_ARGUMENTS[tool]:
            raise ValueError('undeclared workspace arguments')
        if arguments.get('additional_args', ''):
            raise ValueError('additional_args are not allowed')
        if 'filename' in arguments and arguments['filename']:
            normalize_name(arguments['filename'])
        if arguments.get('directory') not in (None, '', '.'):
            normalize_name(arguments['directory'])
        if tool == 'hexstrike.generate_payload':
            validate_payload_arguments(arguments)
        elif tool == 'hexstrike.anew_data_processing':
            validate_anew_arguments(arguments)
            if self.runner is worker:
                verify_toolchain(self.toolchain_root, ('anew',))
        elif tool == 'hexstrike.qsreplace_parameter_replacement':
            validate_qsreplace_arguments(arguments)
            if self.runner is worker:
                verify_toolchain(self.toolchain_root, ('qsreplace',))
        elif tool == 'hexstrike.uro_url_filtering':
            validate_uro_arguments(arguments)
            if self.runner is worker:
                verify_toolchain(self.toolchain_root, ('uro',))
        elif tool == 'hexstrike.checkov_iac_scan':
            validate_checkov_arguments(arguments)
            if self.runner is worker:
                verify_toolchain(self.toolchain_root, ('checkov',))
        folder = self.root / 'workspaces' / str(self.plan.job_id)
        files = self._read_workspace(folder)
        payload = dict(
            operation=WORKSPACE_OPERATIONS[tool],
            arguments=arguments,
            files=encode_snapshot(files),
            environment_sha256=self.plan.environment_sha256,
            budget=self.plan.budget.model_dump(),
        )
        result = self.runner(payload, distro=self.distro)
        if result.get('environment_sha256') != self.plan.environment_sha256:
            raise ValueError('execution environment changed')
        if result.get('success') is not True:
            return result
        after = result.pop('files_after', None)
        if not isinstance(after, list):
            raise ValueError('workspace result is incomplete')
        if 'files' in result and not isinstance(result['files'], list):
            raise ValueError('workspace listing is malformed')
        self._write_workspace(folder, decode_snapshot(after))
        return result

    def _web_call(self, endpoint, arguments):
        tool = self.plan.tool_id
        if WEB_ENDPOINTS.get(tool) != endpoint:
            raise ValueError('unadapted or mismatched endpoint')
        if self.plan.scope.kind != 'web' or not self.plan.scope.origins or not self.plan.scope.networks:
            raise ValueError('Web ResourceScope with explicit origins and networks is required')
        if self.plan.budget.requests < 1 or self.plan.budget.connections < 1:
            raise ValueError('Web execution requires positive request and connection budgets')
        if arguments.get('additional_args', ''):
            raise ValueError('additional_args are not allowed')
        name = tool.removeprefix('hexstrike.')
        url = arguments.get('url') or arguments.get('target')
        resolved_ip, target_port = validate_web_target(url, self.plan.scope)
        clean_args = dict(arguments)
        entry_map = {
            'httpx_probe': 'httpx',
            'katana_crawl': 'katana',
            'nuclei_scan': 'nuclei',
            'dalfox_xss_scan': 'dalfox',
            'ffuf_scan': 'ffuf',
            'wafw00f_scan': 'wafw00f',
            'arjun_parameter_discovery': 'arjun',
            'arjun_scan': 'arjun',
            'sqlmap_scan': 'sqlmap',
        }
        if self.runner is worker:
            verify_toolchain(self.toolchain_root, (entry_map[name], 'nft'))

        if name == 'httpx_probe':
            threads = clean_args.get('threads', 50)
            if type(threads) is not int or not 1 <= threads <= 50:
                raise ValueError('httpx threads must be 1..50')
        elif name == 'katana_crawl':
            depth = clean_args.get('depth', 3)
            if type(depth) is not int or not 1 <= depth <= 3:
                raise ValueError('katana depth must be 1..3')
            if clean_args.get('output_format', 'json') not in {'json', 'text'}:
                raise ValueError('katana output_format must be json or text')
        elif name == 'nuclei_scan':
            template = (clean_args.get('template') or '').strip().strip('/')
            if template and template not in PINNED_TEMPLATES:
                raise ValueError('only pinned local nuclei template paths are permitted')
            clean_args['template_rel'] = template or 'http'
            for field in ('severity', 'tags'):
                val = clean_args.get(field, '') or ''
                if not isinstance(val, str) or len(val) > 64 or any(not (c.isalnum() or c in {',', '-', '_'}) for c in val):
                    raise ValueError(f'invalid nuclei {field} filter')
        elif name == 'dalfox_xss_scan':
            if clean_args.get('blind') or clean_args.get('custom_payload') or clean_args.get('pipe_mode'):
                raise ValueError('dalfox blind callbacks, custom payloads, and pipe mode are disabled')
        elif name == 'ffuf_scan':
            wl = clean_args.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
            if wl not in {'/usr/share/wordlists/dirb/common.txt', 'common-small.txt', ''}:
                raise ValueError('only the pinned bounded wordlist is permitted for ffuf_scan')
            if clean_args.get('mode', 'directory') not in {'directory', 'parameter'}:
                raise ValueError('unsupported ffuf mode')
            mc = clean_args.get('match_codes', '200,204,301,302,307,401,403')
            if not isinstance(mc, str) or any(not (p.isdecimal() and 100 <= int(p) <= 599) for p in mc.split(',') if p):
                raise ValueError('invalid ffuf match_codes')
            max_words = max(1, min(self.plan.budget.requests, 20))
            tc_root = Path(self.toolchain_root or default_toolchain_root() or '')
            if (tc_root / 'wordlists/common-small.txt').is_file():
                words = (tc_root / 'wordlists/common-small.txt').read_text(encoding='utf-8').splitlines()[:max_words]
            else:
                words = ['admin', 'login', 'api', 'health', 'robots.txt'][:max_words]
            clean_args['BoundedWordlistLines'] = words
        elif name in {'arjun_parameter_discovery', 'arjun_scan'}:
            method = (clean_args.get('method') or 'GET').upper()
            if method not in {'GET', 'POST'}:
                raise ValueError('arjun method must be GET or POST')
            if clean_args.get('wordlist') not in {None, '', 'common-small.txt'}:
                raise ValueError('only the pinned bounded wordlist is permitted for arjun')
            if clean_args.get('headers') or clean_args.get('output_file'):
                raise ValueError('custom headers and host output_file are not allowed in arjun')
        elif name == 'sqlmap_scan':
            data_str = clean_args.get('data', '') or ''
            if not isinstance(data_str, str) or len(data_str) > 1024 or any(ord(c) < 32 or ord(c) >= 127 for c in data_str):
                raise ValueError('sqlmap data parameter must be bounded printable ASCII')

        result = self.runner(dict(
            operation=name,
            arguments=clean_args,
            scope=self.plan.scope.model_dump(mode='json'),
            resolved_ip=resolved_ip,
            target_port=target_port,
            environment_sha256=self.plan.environment_sha256,
            budget=self.plan.budget.model_dump(),
        ), distro=self.distro)
        if result.get('environment_sha256') != self.plan.environment_sha256:
            raise ValueError('execution environment changed')
        if result.get('requests_used', 0) > self.plan.budget.requests:
            raise ValueError('worker exceeded approved request budget')
        return result

    def _network_call(self, endpoint, arguments):
        if NETWORK_ENDPOINTS.get(self.plan.tool_id) != endpoint:
            raise ValueError('unadapted or mismatched endpoint')
        if self.plan.scope.kind != 'network':
            raise ValueError('network ResourceScope required')
        if self.plan.budget.connections < 1:
            raise ValueError('network scan requires positive connection budget')
        if arguments.get('additional_args', ''):
            raise ValueError('additional_args are not allowed')
        scan_type = arguments.get('scan_type', '-sV') or '-sV'
        resolved_ip, approved_ports = validate_network_target(
            arguments.get('target', ''), arguments.get('ports', ''), scan_type, self.plan.scope,
        )
        if len(approved_ports) > self.plan.budget.connections:
            raise ValueError('approved port count exceeds connection budget')
        if self.runner is worker:
            verify_toolchain(self.toolchain_root, ('nmap', 'slirp4netns', 'nft'))
        result = self.runner(dict(
            operation='nmap_scan',
            arguments={'target': resolved_ip, 'scan_type': scan_type, 'ports': ','.join(str(p) for p in approved_ports)},
            scope=self.plan.scope.model_dump(mode='json'),
            resolved_ip=resolved_ip,
            approved_ports=approved_ports,
            environment_sha256=self.plan.environment_sha256,
            budget=self.plan.budget.model_dump(),
        ), distro=self.distro)
        if result.get('environment_sha256') != self.plan.environment_sha256:
            raise ValueError('execution environment changed')
        return result

    def _read_workspace(self, folder):
        if not folder.exists():
            return {}
        if not folder.is_dir():
            raise ValueError('workspace root is not a directory')
        entries = []
        for path in sorted(folder.rglob('*')):
            if path.is_symlink():
                raise ValueError('workspace symlink rejected')
            if path.is_dir():
                continue
            if not path.is_file():
                raise ValueError('workspace entry is not a regular file')
            data = path.read_bytes()
            entries.append(dict(
                name=path.relative_to(folder).as_posix(),
                content_base64=base64.b64encode(data).decode(),
                sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),
            ))
        return decode_snapshot(entries)

    def _write_workspace(self, folder, files):
        folder.parent.mkdir(parents=True, exist_ok=True)
        temp = folder.with_name('.tmp-' + uuid4().hex)
        temp.mkdir()
        try:
            for name, data in files.items():
                target = temp.joinpath(*name.split('/'))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            if folder.exists():
                shutil.rmtree(folder)
            temp.rename(folder)
        except BaseException:
            shutil.rmtree(temp, ignore_errors=True)
            raise
