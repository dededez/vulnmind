"""Local operator interface to signed, scoped external executions."""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import secrets
import sys
import threading
import urllib.parse
from uuid import UUID, uuid4

from vulnmind.integrations.hexstrike.catalog import EGRESS_ENFORCED_WEB, IMPLEMENTED, ROOT, directory, get_tool
from vulnmind.integrations.hexstrike.execution import Budget, ExecutionLedger, ExecutionPlan, ResourceScope, sign_plan
from vulnmind.integrations.hexstrike.backend import (
    PINNED_TEMPLATES, validate_network_target, validate_web_target, worker,
)
from vulnmind.integrations.hexstrike.workspace_ops import (
    normalize_name, validate_anew_arguments, validate_checkov_arguments,
    validate_payload_arguments, validate_qsreplace_arguments, validate_uro_arguments,
)
from vulnmind.integrations.mcp.client import call_once, stdio_session, validate_arguments
from vulnmind.knowledge.skills import SkillLoader

SAMPLE_TOOLS = {'strings_extract', 'xxd_hexdump', 'objdump_analyze'}
WORKSPACE_TOOLS = {
    'create_file', 'modify_file', 'delete_file', 'list_files', 'generate_payload',
    'anew_data_processing', 'qsreplace_parameter_replacement', 'uro_url_filtering', 'checkov_iac_scan',
}


class ExternalWorkbench:
    def __init__(self, root, *, upstream=None, distro='VulnMindLab'):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.upstream = Path(
            upstream or Path(__file__).resolve().parents[3] / '.devtools/research/hexstrike-ai-20261110/hexstrike_mcp.py'
        )
        self.distro = distro
        self.ledger = ExecutionLedger(self.root / 'executions.sqlite3')
        self.key_file = self.root / 'approval.key'
        try:
            with self.key_file.open('xb') as stream:
                stream.write(secrets.token_bytes(32))
        except FileExistsError:
            pass
        self.key = self.key_file.read_bytes()
        if len(self.key) != 32:
            raise ValueError('invalid execution approval key')
        self.environment = None
        self.programs = None
        self.probe_error = None
        self.lock = threading.Lock()

    def refresh(self):
        from vulnmind.integrations.hexstrike.inventory_server import load_upstream
        from vulnmind.integrations.hexstrike.backend import probe
        load_upstream(self.upstream)
        self.environment = worker(dict(operation='health'), distro=self.distro)['environment_sha256']
        try:
            self.programs = probe(distro=self.distro)['programs']
            self.probe_error = None
        except Exception:
            self.programs = None
            self.probe_error = 'environment probe unavailable'
        return self.catalog()

    def catalog(self):
        validation = {}
        path = self.root / 'validation.json'
        if path.exists() and self.environment:
            saved = json.loads(path.read_text(encoding='utf-8'))
            if saved.get('environment_sha256') == self.environment:
                validation = saved.get('tools', {})
        return dict(
            **directory(validation, environment=self.programs),
            environment_sha256=self.environment,
            connection='checked' if self.environment else 'not_checked',
            probe_error=self.probe_error,
            executions=self.recent(),
        )

    def recent(self):
        with self.ledger.connect() as conn:
            rows = conn.execute('SELECT id,job_id FROM executions ORDER BY updated DESC LIMIT 30').fetchall()
        return [self.ledger.get(r['id'], job_id=r['job_id']) for r in rows]

    def prepare(self, data):
        allowed = {'tool_id', 'sample_base64', 'arguments', 'workspace_job_id', 'scope', 'budget'}
        if set(data) - allowed:
            raise ValueError('unknown external execution fields')
        tool_id = data.get('tool_id')
        name = str(tool_id or '').removeprefix('hexstrike.')
        if name not in IMPLEMENTED:
            raise ValueError('该工具的受控执行适配尚未完成')
        if not self.environment:
            self.refresh()
        tool = get_tool(tool_id)
        args = dict(data.get('arguments', {}))
        budget = Budget()

        if name in SAMPLE_TOOLS:
            if 'workspace_job_id' in data or 'scope' in data:
                raise ValueError('样本工具不接受工作区或外部范围标识')
            try:
                sample = base64.b64decode(data.get('sample_base64', ''), validate=True)
            except (ValueError, TypeError):
                raise ValueError('样本编码无效') from None
            if not 0 < len(sample) <= 500000:
                raise ValueError('样本须为 1–500000 字节')
            sample_hash = hashlib.sha256(sample).hexdigest()
            job = uuid4()
            folder = self.root / 'samples' / str(job)
            folder.mkdir(parents=True)
            (folder / (sample_hash + '.bin')).write_bytes(sample)
            if name == 'objdump_analyze':
                args = {**args, 'binary': 'sample.bin'}
                budget = Budget(seconds=25, memory_mb=256)
            else:
                args = {**args, 'file_path': 'sample.bin'}
            scope = ResourceScope(kind='sample', sample_sha256=sample_hash)

        elif name in WORKSPACE_TOOLS:
            if 'sample_base64' in data or 'scope' in data:
                raise ValueError('工作区工具不接受样本内容或网络范围')
            if data.get('workspace_job_id'):
                try:
                    job = UUID(str(data['workspace_job_id']))
                except ValueError:
                    raise ValueError('工作区标识无效') from None
                folder = self.root / 'workspaces' / str(job)
                if folder.is_symlink() or not folder.is_dir():
                    raise ValueError('工作区不存在')
            else:
                job = uuid4()
                folder = self.root / 'workspaces' / str(job)
                folder.mkdir(parents=True)
            scope = ResourceScope(kind='workspace', workspace=str(job))
            if name in {'anew_data_processing', 'qsreplace_parameter_replacement', 'uro_url_filtering', 'checkov_iac_scan'}:
                budget = Budget(seconds=25, memory_mb=256)

        elif name in EGRESS_ENFORCED_WEB:
            if 'sample_base64' in data or 'workspace_job_id' in data:
                raise ValueError('Web 工具不接受样本或工作区标识')
            url = args.get('url') or args.get('target')
            if not isinstance(url, str) or not url.strip():
                raise ValueError('Web 工具需要提供目标 URL')
            raw_scope = dict(data.get('scope') or {})
            parsed = urllib.parse.urlsplit(url)
            scheme = (parsed.scheme or 'http').lower()
            host = (parsed.hostname or '').lower()
            port = parsed.port or (80 if scheme == 'http' else 443)
            default_origin = f'{scheme}://{host}' if port in {80, 443} else f'{scheme}://{host}:{port}'
            origins = raw_scope.get('origins') or [default_origin]
            networks = raw_scope.get('networks')
            if not networks:
                raise ValueError('Web 执行计划必须显式声明允许的 CIDR 网络范围 (scope.networks)')
            scope = ResourceScope(kind='web', origins=origins, networks=networks)
            validate_web_target(url, scope)
            raw_budget = dict(data.get('budget') or {})
            req_default = 45 if name in {'dalfox_xss_scan', 'sqlmap_scan'} else 12
            requests_cap = int(raw_budget.get('requests', req_default))
            connections_cap = int(raw_budget.get('connections', requests_cap))
            seconds_cap = int(raw_budget.get('seconds', 35))
            if requests_cap < 1 or connections_cap < 1:
                raise ValueError('Web 执行计划必须具有正数的请求与连接预算')
            budget = Budget(seconds=seconds_cap, requests=requests_cap, connections=connections_cap, memory_mb=256)
            job = uuid4()

        elif name == 'nmap_scan':
            if 'sample_base64' in data or 'workspace_job_id' in data:
                raise ValueError('网络扫描工具不接受样本或工作区标识')
            raw_scope = dict(data.get('scope') or {})
            networks = raw_scope.get('networks')
            ports = raw_scope.get('ports')
            if not networks or not ports:
                raise ValueError('网络扫描计划必须显式声明允许的 CIDR 网段 (scope.networks) 与端口列表 (scope.ports)')
            scope = ResourceScope(kind='network', networks=networks, ports=ports)
            scan_type = args.get('scan_type', '-sV') or '-sV'
            _, approved_ports = validate_network_target(args.get('target', ''), args.get('ports', ''), scan_type, scope)
            raw_budget = dict(data.get('budget') or {})
            conn_cap = int(raw_budget.get('connections', max(len(approved_ports), 1)))
            if conn_cap < len(approved_ports):
                raise ValueError('连接预算小于授权扫描端口数')
            budget = Budget(
                seconds=int(raw_budget.get('seconds', 30)),
                requests=int(raw_budget.get('requests', len(approved_ports))),
                connections=conn_cap,
                memory_mb=256,
            )
            job = uuid4()

        else:
            if 'workspace_job_id' in data or 'sample_base64' in data or 'scope' in data:
                raise ValueError('该工具不接受工作区、样本或网络范围标识')
            job = uuid4()
            scope = ResourceScope(kind='execution')

        try:
            validate_arguments(tool['inputSchema'], args)
        except Exception:
            raise ValueError('参数不符合工具 Schema') from None
        if args.get('additional_args'):
            raise ValueError('不接受任意附加命令参数')

        if name in {'create_file', 'modify_file', 'delete_file', 'list_files', 'generate_payload'}:
            if 'filename' in args and args['filename']:
                normalize_name(args['filename'])
            if args.get('directory') not in (None, '', '.'):
                normalize_name(args['directory'])
        if name == 'generate_payload':
            check = dict(args)
            if 'payload_type' in check:
                check['type'] = check.pop('payload_type')
            validate_payload_arguments(check)
        elif name == 'anew_data_processing':
            validate_anew_arguments(args)
        elif name == 'qsreplace_parameter_replacement':
            validate_qsreplace_arguments(args)
        elif name == 'uro_url_filtering':
            validate_uro_arguments(args)
        elif name == 'checkov_iac_scan':
            validate_checkov_arguments(args)
        elif name == 'nuclei_scan':
            tpl = (args.get('template') or '').strip().strip('/')
            if tpl and tpl not in PINNED_TEMPLATES:
                raise ValueError('仅允许受控固定模板路径')
        elif name == 'dalfox_xss_scan':
            if args.get('blind') or args.get('custom_payload') or args.get('pipe_mode'):
                raise ValueError('受控模式禁用盲打回调、自定义载荷与管道模式')

        skill = SkillLoader(ROOT / 'skills').load(tool['skill_id'])
        plan = ExecutionPlan(
            execution_id=uuid4(),
            job_id=job,
            tool_id=tool_id,
            arguments=args,
            scope=scope,
            budget=budget,
            schema_sha256=tool['schema_sha256'],
            profile_sha256=tool['profile_sha256'],
            skill_sha256=skill.sha256,
            environment_sha256=self.environment,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        folder = self.root / 'plans'
        folder.mkdir(exist_ok=True)
        with (folder / (str(plan.execution_id) + '.json')).open('x', encoding='utf-8') as stream:
            json.dump(plan.value(), stream, ensure_ascii=False)
        return dict(plan=plan.value(), digest=plan.digest(), status='waiting_approval', skill=skill.model_dump())

    def read_plan(self, identifier):
        identifier = UUID(str(identifier))
        return ExecutionPlan.model_validate_json((self.root / 'plans' / (str(identifier) + '.json')).read_text(encoding='utf-8'))

    async def invoke(self, plan, *, reconcile=False):
        signature = sign_plan(plan, self.key)
        args = [
            '-m', 'vulnmind.integrations.hexstrike.server',
            '--root', str(self.root),
            '--upstream', str(self.upstream),
            '--key-file', str(self.key_file),
            '--distro', self.distro,
        ]
        async with stdio_session(
            sys.executable, args, timeout=plan.budget.seconds + 25, error_log=self.root / 'mcp.log',
        ) as session:
            return await call_once(
                session,
                'vulnmind_execution_status' if reconcile else plan.tool_id.removeprefix('hexstrike.'),
                {} if reconcile else plan.arguments,
                schema={'type': 'object', 'properties': {}} if reconcile else get_tool(plan.tool_id)['inputSchema'],
                timeout=plan.budget.seconds + 20,
                meta={'vulnmind': dict(plan=plan.value(), signature=signature)},
            )

    def execute(self, identifier, expected_digest):
        plan = self.read_plan(identifier)
        if plan.digest() != expected_digest:
            raise ValueError('计划摘要变化，请重新核对')
        with self.lock:
            result = asyncio.run(self.invoke(plan))
        return dict(transport=result, execution=self.ledger.get(plan.execution_id, job_id=plan.job_id))

    def reconcile(self, identifier):
        plan = self.read_plan(identifier)
        return asyncio.run(self.invoke(plan, reconcile=True))


def validated_service(primary, *, distro):
    """Prefer a locally validated runtime, never merely the first receipt file."""
    primary=Path(primary)
    candidates=[primary, primary.parent.parent/'bench'/'external',
                Path(__file__).resolve().parents[3]/'.vulnmind-workbench'/'external']
    fallback=None
    for root in dict.fromkeys(candidates):
        if root!=primary and not (root/'validation.json').is_file(): continue
        service=ExternalWorkbench(root,distro=distro)
        service.refresh()
        if fallback is None: fallback=service
        try:
            saved=json.loads((root/'validation.json').read_text(encoding='utf-8'))
        except (OSError,ValueError): continue
        if service.environment and saved.get('environment_sha256')==service.environment:
            return service
    return fallback
