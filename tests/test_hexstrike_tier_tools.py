import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from uuid import uuid4

import pytest

from vulnmind.integrations.hexstrike.backend import (
    ControlledClient, validate_network_target, validate_web_target, verify_toolchain,
)
from vulnmind.integrations.hexstrike.catalog import EGRESS_ENFORCED_WEB, IMPLEMENTED, directory
from vulnmind.integrations.hexstrike.execution import Budget, ExecutionPlan, ResourceScope
from vulnmind.integrations.hexstrike.workspace_ops import (
    WorkspaceError, encode_snapshot, evaluate_iac_snapshot,
    validate_anew_arguments, validate_checkov_arguments,
    validate_qsreplace_arguments, validate_uro_arguments,
)
from vulnmind.workbench.external import ExternalWorkbench


def make_plan(tool_id, arguments, scope, *, budget=None, env='5' * 64):
    return ExecutionPlan(
        execution_id=uuid4(),
        job_id=uuid4() if scope.kind != 'workspace' else scope.workspace,
        tool_id=tool_id,
        arguments=arguments,
        scope=scope,
        budget=budget or Budget(),
        schema_sha256='2' * 64,
        profile_sha256='3' * 64,
        skill_sha256='4' * 64,
        environment_sha256=env,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


def test_tier12_catalog_and_eligibility_rules():
    saved = directory()
    assert len(IMPLEMENTED) == 23
    assert saved['totals']['adapters'] == 23
    by_name = {t['name']: t for t in saved['tools']}
    for name in EGRESS_ENFORCED_WEB:
        row = by_name[name]
        assert row['adapter_implemented'] is True
        assert 'request_budget_and_egress_enforcement_required' not in row['blockers']
        # When validated in current environment, no blockers remain.
        receipt = {
            row['tool_id']: dict(
                status='passed',
                schema_sha256=row['schema_sha256'],
                profile_sha256=row['profile_sha256'],
                skill_sha256=row['skill_sha256'],
            )
        }
        checked = next(t for t in directory(receipt)['tools'] if t['name'] == name)
        assert checked['validated'] is True and checked['eligible'] is True
    # Unadapted web scanner still retains the egress blocker.
    assert 'request_budget_and_egress_enforcement_required' in by_name['gobuster_scan']['blockers']
    # checkov_iac_scan is workspace-scoped and eligible when validated; trivy_scan remains cluster-blocked.
    assert by_name['checkov_iac_scan']['resource_scope'] == 'workspace'
    assert 'dedicated_resource_scope_required' not in by_name['checkov_iac_scan']['blockers']
    assert 'dedicated_resource_scope_required' in by_name['trivy_scan']['blockers']


def test_toolchain_manifest_verification_and_tamper_rejection(tmp_path):
    # Real workspace toolchain must pass verification for all 18 entrypoints.
    root, sha, manifest = verify_toolchain(
        required_entrypoints=(
            'httpx', 'katana', 'nuclei', 'dalfox', 'ffuf', 'sqlmap',
            'anew', 'qsreplace', 'uro', 'arjun', 'wafw00f',
            'checkov', 'objdump', 'readelf', 'file', 'nmap', 'slirp4netns', 'nft',
        )
    )
    assert len(sha) == 64 and len(manifest['entrypoints']) == 18

    # Synthetic tampered manifest must fail closed.
    fake = tmp_path / 'tools'
    (fake / 'bin').mkdir(parents=True)
    binary = fake / 'bin/anew'
    binary.write_bytes(b'binary-content')
    bad_manifest = {
        'version': 1,
        'entrypoints': {
            'anew': {'path': 'bin/anew', 'sha256': '0' * 64, 'size': 14},
        },
    }
    (fake / 'manifest.json').write_text(json.dumps(bad_manifest), encoding='utf-8')
    with pytest.raises(ValueError, match='integrity mismatch'):
        verify_toolchain(fake, ('anew',))
    with pytest.raises(ValueError, match='not declared'):
        verify_toolchain(fake, ('missing_tool',))


def test_data_and_iac_argument_validators():
    assert validate_anew_arguments({'input_data': 'a\nb\n', 'output_file': 'out.txt'}) == ('a\nb\n', 'out.txt')
    with pytest.raises(WorkspaceError):
        validate_anew_arguments({'input_data': 'a', 'output_file': '../escape.txt'})
    with pytest.raises(WorkspaceError):
        validate_anew_arguments({'input_data': 'a', 'additional_args': '-q'})

    assert validate_qsreplace_arguments({'urls': 'http://a/?x=1', 'replacement': 'FUZZ'}) == ('http://a/?x=1', 'FUZZ')
    with pytest.raises(WorkspaceError):
        validate_qsreplace_arguments({'urls': '', 'replacement': 'FUZZ'})
    with pytest.raises(WorkspaceError):
        validate_qsreplace_arguments({'urls': 'http://a/?x=1', 'replacement': 'bad\nchar'})

    assert validate_uro_arguments({'urls': 'http://a/index.php?id=1', 'whitelist': 'php,html', 'blacklist': 'png'}) == (
        'http://a/index.php?id=1', ['php', 'html'], ['png'],
    )
    with pytest.raises(WorkspaceError):
        validate_uro_arguments({'urls': 'http://a/', 'whitelist': '../bad'})

    assert validate_checkov_arguments({'directory': 'iac', 'framework': 'dockerfile', 'check': 'CKV_DOCKER_2'}) == (
        'iac', 'dockerfile', ['CKV_DOCKER_2'], [], 'json',
    )
    with pytest.raises(WorkspaceError):
        validate_checkov_arguments({'directory': '.', 'framework': 'unknown_fw'})
    with pytest.raises(WorkspaceError):
        validate_checkov_arguments({'directory': '.', 'check': 'BAD-DASH;'})


def test_iac_static_evaluation_rules():
    files = {
        'Dockerfile': b'FROM alpine:latest\nRUN echo hi\n',
        'k8s/pod.yaml': b'apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n  - securityContext:\n      privileged: true\n',
        'main.tf': b'resource "aws_security_group" "sg" {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n',
    }
    report = evaluate_iac_snapshot(files)
    assert report['scanned_files'] == 3
    failed_ids = {item['check_id'] for item in report['failed_checks']}
    assert {'CKV_DOCKER_2', 'CKV_DOCKER_3', 'CKV_DOCKER_7', 'CKV_K8S_16', 'CKV_K8S_19', 'CKV_AWS_24'} <= failed_ids


def test_web_and_network_scope_validation_and_rejections(tmp_path):
    web_scope = ResourceScope(kind='web', origins=['http://127.0.0.1:18080'], networks=['127.0.0.1/32'])
    assert validate_web_target('http://127.0.0.1:18080/items?id=1', web_scope) == ('127.0.0.1', 18080)

    for bad_url in (
        'http://127.0.0.1:9999/items',
        'http://10.0.0.1:18080/items',
        'ftp://127.0.0.1:18080/items',
        'http://user:pass@127.0.0.1:18080/',
    ):
        with pytest.raises(ValueError):
            validate_web_target(bad_url, web_scope)

    net_scope = ResourceScope(kind='network', networks=['127.0.0.1/32'], ports=[80, 18080])
    assert validate_network_target('127.0.0.1', '18080', '-sV', net_scope) == ('127.0.0.1', [18080])
    with pytest.raises(ValueError):
        validate_network_target('127.0.0.1', '22', '-sV', net_scope)
    with pytest.raises(ValueError):
        validate_network_target('192.168.1.1', '80', '-sV', net_scope)
    with pytest.raises(ValueError):
        validate_network_target('127.0.0.1', '80', '-sS', net_scope)


def test_controlled_client_web_network_objdump_and_data_calls(tmp_path):
    # 1. objdump_analyze sample call
    sample = b'\x7fELF-owned-sample'
    sample_sha = hashlib.sha256(sample).hexdigest()
    plan_obj = make_plan(
        'hexstrike.objdump_analyze',
        {'binary': 'sample.bin', 'disassemble': True},
        ResourceScope(kind='sample', sample_sha256=sample_sha),
    )
    sdir = tmp_path / 'samples' / str(plan_obj.job_id)
    sdir.mkdir(parents=True)
    (sdir / f'{sample_sha}.bin').write_bytes(sample)
    res = ControlledClient(
        tmp_path, plan_obj,
        runner=lambda payload, **kw: {'success': True, 'stdout': 'elf', 'environment_sha256': '5' * 64},
    ).safe_post('api/tools/objdump', {'binary': 'sample.bin', 'disassemble': True})
    assert res['success'] is True

    # Reject non-sample.bin path in objdump
    with pytest.raises(ValueError):
        ControlledClient(tmp_path, plan_obj, runner=lambda *a, **kw: pytest.fail()).safe_post(
            'api/tools/objdump', {'binary': '/etc/passwd'},
        )

    # 2. Web tool call with budget & scope enforcement
    web_plan = make_plan(
        'hexstrike.nuclei_scan',
        {'target': 'http://127.0.0.1:18080'},
        ResourceScope(kind='web', origins=['http://127.0.0.1:18080'], networks=['127.0.0.1/32']),
        budget=Budget(requests=10, connections=10),
    )
    res_web = ControlledClient(
        tmp_path, web_plan,
        runner=lambda payload, **kw: {'success': True, 'requests_used': 3, 'environment_sha256': '5' * 64},
    ).safe_post('api/tools/nuclei', {'target': 'http://127.0.0.1:18080', 'template': 'http/technologies'})
    assert res_web['requests_used'] == 3

    # Reject unpinned nuclei template
    with pytest.raises(ValueError, match='pinned'):
        ControlledClient(tmp_path, web_plan, runner=lambda *a, **kw: pytest.fail()).safe_post(
            'api/tools/nuclei', {'target': 'http://127.0.0.1:18080', 'template': '/etc/passwd'},
        )
    # Reject worker exceeding budget
    with pytest.raises(ValueError, match='budget'):
        ControlledClient(
            tmp_path, web_plan,
            runner=lambda payload, **kw: {'success': True, 'requests_used': 11, 'environment_sha256': '5' * 64},
        ).safe_post('api/tools/nuclei', {'target': 'http://127.0.0.1:18080'})

    # 3. Network tool call
    net_plan = make_plan(
        'hexstrike.nmap_scan',
        {'target': '127.0.0.1', 'ports': '18080', 'scan_type': '-sV'},
        ResourceScope(kind='network', networks=['127.0.0.1/32'], ports=[18080]),
        budget=Budget(requests=2, connections=2),
    )
    res_net = ControlledClient(
        tmp_path, net_plan,
        runner=lambda payload, **kw: {'success': True, 'requests_used': 1, 'environment_sha256': '5' * 64},
    ).safe_post('api/tools/nmap', {'target': '127.0.0.1', 'ports': '18080', 'scan_type': '-sV'})
    assert res_net['success'] is True


def test_external_workbench_prepare_for_all_new_categories(tmp_path):
    service = ExternalWorkbench(tmp_path / 'ext')
    service.environment = 'e' * 64

    # Sample: objdump_analyze
    obj = service.prepare({
        'tool_id': 'hexstrike.objdump_analyze',
        'sample_base64': base64.b64encode(b'\x7fELF').decode(),
        'arguments': {'disassemble': False},
    })
    assert obj['plan']['scope']['kind'] == 'sample'
    assert obj['plan']['arguments']['binary'] == 'sample.bin'

    # Workspace: anew, qsreplace, uro, checkov
    anew = service.prepare({
        'tool_id': 'hexstrike.anew_data_processing',
        'arguments': {'input_data': 'one\ntwo\n', 'output_file': 'lines.txt'},
    })
    ws_id = anew['plan']['scope']['workspace']
    qsr = service.prepare({
        'tool_id': 'hexstrike.qsreplace_parameter_replacement',
        'workspace_job_id': ws_id,
        'arguments': {'urls': 'http://127.0.0.1/?a=1', 'replacement': 'TEST'},
    })
    assert qsr['plan']['scope']['workspace'] == ws_id
    chk = service.prepare({
        'tool_id': 'hexstrike.checkov_iac_scan',
        'workspace_job_id': ws_id,
        'arguments': {'directory': '.', 'framework': 'dockerfile'},
    })
    assert chk['plan']['scope']['kind'] == 'workspace'

    # Web: httpx_probe
    httpx_plan = service.prepare({
        'tool_id': 'hexstrike.httpx_probe',
        'arguments': {'target': 'http://127.0.0.1:18080'},
        'scope': {'networks': ['127.0.0.1/32']},
        'budget': {'requests': 5, 'connections': 5},
    })
    assert httpx_plan['plan']['scope']['kind'] == 'web'
    assert httpx_plan['plan']['scope']['origins'] == ['http://127.0.0.1:18080']
    assert httpx_plan['plan']['budget']['requests'] == 5

    # Network: nmap_scan
    nmap_plan = service.prepare({
        'tool_id': 'hexstrike.nmap_scan',
        'arguments': {'target': '127.0.0.1', 'ports': '18080', 'scan_type': '-sV'},
        'scope': {'networks': ['127.0.0.1/32'], 'ports': [18080]},
    })
    assert nmap_plan['plan']['scope']['kind'] == 'network'
    assert nmap_plan['plan']['scope']['ports'] == [18080]
