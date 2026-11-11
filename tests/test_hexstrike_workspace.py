import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from vulnmind.integrations.hexstrike.backend import ControlledClient
from vulnmind.integrations.hexstrike.execution import ExecutionPlan, ResourceScope
from vulnmind.integrations.hexstrike.workspace_ops import (MAX_CONTENT, MAX_FILES, WorkspaceError,
                                                           apply, apply_payload, decode_snapshot,
                                                           encode_snapshot, normalize_name)
from vulnmind.workbench.external import ExternalWorkbench


def workspace_plan(tool='hexstrike.create_file', arguments=None, **changes):
    job = uuid4()
    values = dict(execution_id=uuid4(), job_id=job, tool_id=tool,
                  arguments=arguments or {'filename': 'a.txt', 'content': 'hi'},
                  scope=ResourceScope(kind='workspace', workspace=str(job)),
                  schema_sha256='2'*64, profile_sha256='3'*64, skill_sha256='4'*64,
                  environment_sha256='5'*64,
                  expires_at=datetime.now(timezone.utc)+timedelta(hours=1))
    values.update(changes)
    return ExecutionPlan(**values)


def encoded(files):
    return encode_snapshot(files)


def runner_returning(value):
    calls = []
    def runner(payload, *, distro=None):
        calls.append(payload)
        return dict(value)
    return runner, calls


def failing_runner(payload, *, distro=None):
    pytest.fail('the runner must not be called for a rejected request')


def test_workspace_names_are_relative_and_conservative():
    assert normalize_name('a.txt') == 'a.txt'
    assert normalize_name('dir/sub/a.bin') == 'dir/sub/a.bin'
    assert normalize_name('.hidden') == '.hidden'
    for name in ('/abs', '../x', 'a/../b', 'a/./b', 'a//b', 'a\\b', 'a\x00b', '', '.', '..',
                 'CON', 'con.txt', 'a:b', 'a*b', 'a?b', 'a b', 'a.'):
        with pytest.raises(WorkspaceError):
            normalize_name(name)
    with pytest.raises(WorkspaceError):
        normalize_name('a'*201)
    with pytest.raises(WorkspaceError):
        normalize_name('/'.join(['d']*9))


def test_snapshot_roundtrip_and_tamper_detection():
    files = {'a.txt': b'hi', 'dir/b.bin': b'\x00\xff'}
    assert decode_snapshot(encode_snapshot(files)) == files
    entry = encode_snapshot(files)[0]
    for broken in (dict(entry, sha256='0'*64), dict(entry, size=99), dict(entry, extra='x'),
                   dict(entry, content_base64='not base64')):
        with pytest.raises(WorkspaceError):
            decode_snapshot([broken])
    with pytest.raises(WorkspaceError):
        decode_snapshot([entry, entry])


def test_create_list_modify_delete_semantics():
    result = apply({}, 'workspace_create', {'filename': 'note.txt', 'content': 'hello'})
    files = decode_snapshot(result['files_after'])
    assert files == {'note.txt': b'hello'} and result['message'] == 'created'
    with pytest.raises(WorkspaceError):
        apply(files, 'workspace_create', {'filename': 'note.txt', 'content': 'again'})
    listed = apply(files, 'workspace_list', {'directory': '.'})
    assert [entry['name'] for entry in listed['files']] == ['note.txt']
    assert listed['files'][0]['type'] == 'file' and listed['files'][0]['size'] == 5
    appended = apply(files, 'workspace_modify', {'filename': 'note.txt', 'content': '!', 'append': True})
    assert decode_snapshot(appended['files_after']) == {'note.txt': b'hello!'}
    replaced = apply(files, 'workspace_modify', {'filename': 'note.txt', 'content': 'new'})
    assert decode_snapshot(replaced['files_after']) == {'note.txt': b'new'}
    deleted = apply(files, 'workspace_delete', {'filename': 'note.txt'})
    assert decode_snapshot(deleted['files_after']) == {}
    with pytest.raises(WorkspaceError):
        apply(files, 'workspace_delete', {'filename': 'missing.txt'})
    with pytest.raises(WorkspaceError):
        apply(files, 'workspace_modify', {'filename': 'missing.txt', 'content': 'x'})


def test_workspace_rejects_undeclared_arguments_and_limits():
    with pytest.raises(WorkspaceError):
        apply({}, 'workspace_create', {'filename': 'a.txt', 'content': 'x', 'command': 'sh'})
    with pytest.raises(WorkspaceError):
        apply({}, 'workspace_list', {'directory': '.', 'recursive': True})
    with pytest.raises(WorkspaceError):
        apply({}, 'workspace_create', {'filename': 'a.txt', 'content': 'x'*(MAX_CONTENT+1)})
    with pytest.raises(WorkspaceError):
        apply({}, 'workspace_create', {'filename': 'a.bin', 'content': 'not base64', 'binary': True})
    packed = apply({}, 'workspace_create', {'filename': 'a.bin', 'content': base64.b64encode(b'\x00\x01').decode(),
                                            'binary': True})
    assert decode_snapshot(packed['files_after']) == {'a.bin': b'\x00\x01'}
    files = {f'f{i}.txt': b'x' for i in range(MAX_FILES)}
    with pytest.raises(WorkspaceError):
        apply(files, 'workspace_create', {'filename': 'extra.txt', 'content': 'x'})


def test_list_directory_only_shows_direct_children():
    files = {'top.txt': b'1', 'dir/a.txt': b'2', 'dir/sub/b.txt': b'3'}
    listed = apply(files, 'workspace_list', {'directory': '.'})
    assert [(entry['name'], entry['type']) for entry in listed['files']] == [
        ('dir', 'directory'), ('top.txt', 'file')]
    nested = apply(files, 'workspace_list', {'directory': 'dir'})
    assert [(entry['name'], entry['type']) for entry in nested['files']] == [
        ('sub', 'directory'), ('a.txt', 'file')]


def test_controlled_client_rejects_scope_endpoint_and_argument_escapes(tmp_path):
    wrong_scope = workspace_plan(scope=ResourceScope(kind='sample', sample_sha256='a'*64))
    with pytest.raises(ValueError):
        ControlledClient(tmp_path, wrong_scope, runner=failing_runner).safe_post('api/files/create',
                                                                                 {'filename': 'a.txt', 'content': 'x'})
    other_job = workspace_plan(scope=ResourceScope(kind='workspace', workspace=str(uuid4())))
    with pytest.raises(ValueError):
        ControlledClient(tmp_path, other_job, runner=failing_runner).safe_post('api/files/create',
                                                                               {'filename': 'a.txt', 'content': 'x'})
    plan = workspace_plan()
    with pytest.raises(ValueError):
        ControlledClient(tmp_path, plan, runner=failing_runner).safe_post('api/command', {})
    with pytest.raises(ValueError):
        ControlledClient(tmp_path, plan, runner=failing_runner).safe_post('api/files/create',
                                                                          {'filename': 'a.txt', 'content': 'x', 'extra': 1})
    with pytest.raises(ValueError):
        ControlledClient(tmp_path, plan, runner=failing_runner).safe_post('api/files/create',
                                                                          {'filename': '../escape.txt', 'content': 'x'})
    network_plan = workspace_plan(budget=dict(seconds=20, output_bytes=1000, requests=5, connections=0, memory_mb=64))
    with pytest.raises(ValueError):
        ControlledClient(tmp_path, network_plan, runner=failing_runner).safe_post('api/files/create',
                                                                                  {'filename': 'a.txt', 'content': 'x'})
    with pytest.raises(ValueError):
        ControlledClient(tmp_path, workspace_plan(tool='hexstrike.list_files',
                                                  arguments={'directory': '.'}),
                         runner=failing_runner).safe_post('api/files/other', {'directory': '.'})


def test_controlled_client_applies_and_writes_back_verified_snapshot(tmp_path):
    plan = workspace_plan(environment_sha256='5'*64)
    payload = {'success': True, 'message': 'created', 'filename': 'a.txt', 'size': 2,
               'sha256': '0'*64, 'environment_sha256': '5'*64,
               'files_after': encoded({'a.txt': b'hi'})}
    runner, calls = runner_returning(payload)
    client = ControlledClient(tmp_path, plan, runner=runner)
    result = client.safe_post('api/files/create', {'filename': 'a.txt', 'content': 'hi'})
    assert 'files_after' not in result and calls and calls[0]['operation'] == 'workspace_create'
    assert (tmp_path/'workspaces'/str(plan.job_id)/'a.txt').read_bytes() == b'hi'
    assert calls[0]['files'] == []
    # A second call sees the written snapshot.
    payload2 = dict(payload, files_after=encoded({'a.txt': b'hi', 'b.txt': b'bye'}))
    runner2, calls2 = runner_returning(payload2)
    ControlledClient(tmp_path, plan, runner=runner2).safe_post('api/files/create',
                                                               {'filename': 'b.txt', 'content': 'bye'})
    assert [entry['name'] for entry in calls2[0]['files']] == ['a.txt']
    assert (tmp_path/'workspaces'/str(plan.job_id)/'b.txt').read_bytes() == b'bye'


def test_controlled_client_returns_business_failure_without_writing(tmp_path):
    plan = workspace_plan(tool='hexstrike.modify_file', arguments={'filename': 'a.txt', 'content': 'x'})
    runner, _ = runner_returning({'success': False, 'error': 'file does not exist',
                                  'environment_sha256': '5'*64, 'requests_used': 0})
    result = ControlledClient(tmp_path, plan, runner=runner).safe_post('api/files/modify',
                                                                       {'filename': 'a.txt', 'content': 'x'})
    assert result['success'] is False and not (tmp_path/'workspaces'/str(plan.job_id)).exists()


def test_controlled_client_rejects_changed_environment_and_tampered_snapshot(tmp_path):
    plan = workspace_plan()
    bad_env = {'success': True, 'environment_sha256': '6'*64, 'files_after': encoded({})}
    with pytest.raises(ValueError):
        ControlledClient(tmp_path, plan, runner=lambda *a, **k: bad_env).safe_post(
            'api/files/create', {'filename': 'a.txt', 'content': 'x'})
    tampered = encoded({'a.txt': b'hi'})
    tampered[0]['sha256'] = '0'*64
    bad_snapshot = {'success': True, 'environment_sha256': '5'*64, 'files_after': tampered}
    with pytest.raises(WorkspaceError):
        ControlledClient(tmp_path, plan, runner=lambda *a, **k: bad_snapshot).safe_post(
            'api/files/create', {'filename': 'a.txt', 'content': 'x'})


def test_prepare_builds_workspace_scope_and_reuses_it(tmp_path):
    service = ExternalWorkbench(tmp_path/'external')
    service.environment = 'e'*64
    prepared = service.prepare(dict(tool_id='hexstrike.create_file',
                                    arguments={'filename': 'a.txt', 'content': 'hi'}))
    plan = prepared['plan']
    assert plan['scope']['kind'] == 'workspace' and plan['job_id'] == plan['scope']['workspace']
    assert (tmp_path/'external'/'workspaces'/plan['job_id']).is_dir()
    reused = service.prepare(dict(tool_id='hexstrike.list_files', arguments={'directory': '.'},
                                  workspace_job_id=plan['job_id']))
    assert reused['plan']['scope']['workspace'] == plan['job_id']
    assert reused['plan']['job_id'] == plan['job_id']
    payload = service.prepare(dict(tool_id='hexstrike.generate_payload',
                                   arguments={'payload_type': 'cyclic', 'size': 16}))
    assert payload['plan']['scope']['kind'] == 'workspace'


def test_prepare_rejects_mixed_inputs_unknown_tools_and_escapes(tmp_path):
    service = ExternalWorkbench(tmp_path/'external')
    service.environment = 'e'*64
    cases = [
        dict(tool_id='hexstrike.create_file', arguments={'filename': 'a.txt', 'content': 'x'},
             sample_base64='aGk='),
        dict(tool_id='hexstrike.strings_extract', arguments={}, sample_base64='aGk=', workspace_job_id=str(uuid4())),
        dict(tool_id='hexstrike.nmap_scan', arguments={}),
        dict(tool_id='hexstrike.create_file', arguments={'filename': '../x', 'content': 'x'}),
        dict(tool_id='hexstrike.list_files', arguments={'directory': '../x'}),
        dict(tool_id='hexstrike.create_file', arguments={'filename': 'a.txt'}),
        dict(tool_id='hexstrike.create_file', arguments={'filename': 'a.txt', 'content': 'x', 'binary': 'yes'}),
        dict(tool_id='hexstrike.generate_payload', arguments={'type': 'shellcode'}),
        dict(tool_id='hexstrike.generate_payload', arguments={'size': 300_000}),
        dict(tool_id='hexstrike.create_file', arguments={'filename': 'a.txt', 'content': 'x'}, unexpected=True),
    ]
    for case in cases:
        with pytest.raises(ValueError):
            service.prepare(case)


def test_payload_generation_is_exact_and_bounded():
    buffer = apply_payload({}, {'type': 'buffer', 'size': 5, 'pattern': 'AB', 'filename': 'a.bin'})
    assert decode_snapshot(buffer['files_after']) == {'a.bin': b'ABABA'}
    assert buffer['size'] == 5 and buffer['payload_info']['type'] == 'buffer'
    cyclic = apply_payload({}, {'type': 'cyclic', 'size': 28, 'filename': 'c.bin'})
    assert decode_snapshot(cyclic['files_after'])['c.bin'] == b'ABCDEFGHIJKLMNOPQRSTUVWXYZAB'
    random = apply_payload({}, {'type': 'random', 'size': 64, 'filename': 'r.bin'})
    value = decode_snapshot(random['files_after'])['r.bin']
    assert len(value) == 64 and value.decode('ascii').isalnum()
    default = apply_payload({}, {'type': 'cyclic', 'size': 4})
    name = next(iter(decode_snapshot(default['files_after'])))
    assert name.startswith('payload_') and len(default['files_after']) == 1
    with pytest.raises(WorkspaceError):
        apply_payload({'r.bin': b'x'}, {'type': 'buffer', 'size': 4, 'filename': 'r.bin'})
    for arguments in ({'type': 'shellcode', 'size': 4},
                      {'type': 'buffer', 'size': 0},
                      {'type': 'buffer', 'size': MAX_CONTENT+1},
                      {'type': 'buffer', 'size': 4, 'pattern': ''},
                      {'type': 'buffer', 'size': 4, 'pattern': 'A'*65},
                      {'type': 'buffer', 'size': 4, 'pattern': 'A\n'},
                      {'type': 'buffer', 'size': 4, 'filename': '../x'},
                      {'type': 'buffer', 'size': 4, 'extra': 1},
                      {'type': 'buffer', 'size': '4'}):
        with pytest.raises(WorkspaceError):
            apply_payload({}, arguments)


def test_payload_endpoint_is_scoped_and_validated(tmp_path):
    plan = workspace_plan(tool='hexstrike.generate_payload', arguments={'type': 'cyclic', 'size': 8})
    payload = {'success': True, 'filename': 'p.bin', 'size': 8, 'sha256': '0'*64,
               'environment_sha256': '5'*64, 'files_after': encoded({'p.bin': b'ABCDEFGH'})}
    runner, calls = runner_returning(payload)
    result = ControlledClient(tmp_path, plan, runner=runner).safe_post('api/payloads/generate',
                                                                       {'type': 'cyclic', 'size': 8})
    assert result['filename'] == 'p.bin' and calls[0]['operation'] == 'payload_generate'
    assert (tmp_path/'workspaces'/str(plan.job_id)/'p.bin').read_bytes() == b'ABCDEFGH'
    for arguments in ({'type': 'cyclic', 'size': 200_001}, {'type': 'cyclic', 'size': 8, 'pattern': 'x'*65},
                      {'type': 'cyclic', 'size': 8, 'extra': 1}):
        with pytest.raises(ValueError):
            ControlledClient(tmp_path, plan, runner=failing_runner).safe_post('api/payloads/generate', arguments)
    with pytest.raises(ValueError):
        ControlledClient(tmp_path, plan, runner=failing_runner).safe_post('api/files/create',
                                                                          {'filename': 'a.txt', 'content': 'x'})


def test_prepare_keeps_sample_and_health_profiles(tmp_path):
    service = ExternalWorkbench(tmp_path/'external')
    service.environment = 'e'*64
    sample = service.prepare(dict(tool_id='hexstrike.strings_extract', arguments={},
                                  sample_base64=base64.b64encode(b'abc').decode()))
    assert sample['plan']['scope']['kind'] == 'sample'
    health = service.prepare(dict(tool_id='hexstrike.server_health', arguments={}))
    assert health['plan']['scope']['kind'] == 'execution'
