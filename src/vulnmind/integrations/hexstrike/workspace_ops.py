"""Bounded, pure workspace file operations for the controlled external worker.

The module never touches the host filesystem: it receives a decoded workspace
snapshot, applies one reviewed operation, and returns the new snapshot. The
host re-validates names and hashes before writing anything back.

Safety rules (all enforced here, not in the caller):
* names are relative POSIX paths with a conservative ASCII charset,
* no absolute paths, traversal segments, backslashes, control characters or
  Windows-reserved characters/names,
* bounded file count, per-file content and total workspace size,
* no directory entries, symlinks or metadata in the snapshot.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
import string
import time

MAX_FILES = 100
MAX_BYTES = 1_000_000
MAX_CONTENT = 200_000
MAX_NAME = 200
MAX_DEPTH = 8
ALLOWED = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-')
RESERVED = frozenset({
    'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10)),
})


class WorkspaceError(ValueError):
    """A workspace operation was rejected; the message is safe to log."""


def normalize_name(name):
    """Validate a relative workspace path and return it in POSIX form."""
    if not isinstance(name, str):
        raise WorkspaceError('filename must be text')
    if not name or len(name) > MAX_NAME:
        raise WorkspaceError('filename length is not allowed')
    if name.startswith('/') or '\\' in name or '\x00' in name:
        raise WorkspaceError('filename must be a relative POSIX path')
    parts = name.split('/')
    if len(parts) > MAX_DEPTH:
        raise WorkspaceError('filename nesting is too deep')
    for part in parts:
        if part in {'', '.', '..'}:
            raise WorkspaceError('filename must not contain empty, current or parent segments')
        if part.endswith((' ', '.')):
            raise WorkspaceError('filename segment must not end with a space or dot')
        if not set(part) <= ALLOWED:
            raise WorkspaceError('filename contains characters outside the allowed set')
        if part.split('.')[0].upper() in RESERVED:
            raise WorkspaceError('filename uses a reserved device name')
    return '/'.join(parts)


def _content(arguments, *, binary):
    value = arguments.get('content')
    if not isinstance(value, str):
        raise WorkspaceError('content must be text')
    if binary:
        try:
            data = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise WorkspaceError('binary content must be strict base64') from None
    else:
        data = value.encode('utf-8')
    if len(data) > MAX_CONTENT:
        raise WorkspaceError('content exceeds the per-file limit')
    return data


def _check_state(files):
    if len(files) > MAX_FILES:
        raise WorkspaceError('workspace file limit exceeded')
    total = 0
    for name, data in files.items():
        if normalize_name(name) != name:
            raise WorkspaceError('workspace name is not normalized')
        if not isinstance(data, (bytes, bytearray)):
            raise WorkspaceError('workspace content must be bytes')
        total += len(data)
    if total > MAX_BYTES:
        raise WorkspaceError('workspace byte limit exceeded')


def encode_snapshot(files):
    """Serialize a name->bytes map into the bounded transfer format."""
    return [dict(name=name, content_base64=base64.b64encode(data).decode(),
                 sha256=hashlib.sha256(data).hexdigest(), size=len(data))
            for name, data in sorted(files.items())]


def decode_snapshot(entries):
    """Host/worker boundary: decode an untrusted snapshot into a name->bytes map."""
    if not isinstance(entries, list) or len(entries) > MAX_FILES:
        raise WorkspaceError('workspace snapshot must be a bounded list')
    files, seen = {}, set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) - {'name', 'content_base64', 'sha256', 'size'}:
            raise WorkspaceError('invalid workspace entry')
        name = normalize_name(entry.get('name'))
        if name in seen:
            raise WorkspaceError('duplicate workspace entry')
        seen.add(name)
        try:
            data = base64.b64decode(entry.get('content_base64', ''), validate=True)
        except (binascii.Error, ValueError):
            raise WorkspaceError('workspace entry is not strict base64') from None
        if entry.get('size') != len(data):
            raise WorkspaceError('workspace entry size mismatch')
        if entry.get('sha256') != hashlib.sha256(data).hexdigest():
            raise WorkspaceError('workspace entry hash mismatch')
        files[name] = data
    _check_state(files)
    return files


def _direct_children(files, directory):
    directory = normalize_name(directory) if directory not in ('', '.') else ''
    prefix = directory + '/' if directory else ''
    entries, directories = [], set()
    for name in sorted(files):
        if prefix and not name.startswith(prefix):
            continue
        rest = name[len(prefix):]
        if '/' in rest:
            directories.add(rest.split('/', 1)[0])
            continue
        entries.append(dict(name=rest, type='file', size=len(files[name])))
    entries.extend(dict(name=name, type='directory') for name in sorted(directories))
    entries.sort(key=lambda entry: (entry['type'] != 'directory', entry['name']))
    return directory or '.', entries


def apply(files, operation, arguments):
    """Apply one operation to a decoded snapshot and return the new state.

    ``arguments`` keys are validated against the reviewed operation allowlist;
    undeclared or misplaced keys are rejected instead of being ignored.
    """
    if not isinstance(arguments, dict):
        raise WorkspaceError('arguments must be an object')
    if operation == 'workspace_list':
        if set(arguments) - {'directory'}:
            raise WorkspaceError('undeclared list arguments')
        directory, entries = _direct_children(files, arguments.get('directory', '.'))
        return dict(success=True, directory=directory, files=entries[:MAX_FILES],
                    truncated=len(entries) > MAX_FILES, files_after=encode_snapshot(files))

    if operation == 'workspace_create':
        if set(arguments) - {'filename', 'content', 'binary'}:
            raise WorkspaceError('undeclared create arguments')
        if 'filename' not in arguments or 'content' not in arguments:
            raise WorkspaceError('filename and content are required')
        filename = normalize_name(arguments['filename'])
        if filename in files:
            raise WorkspaceError('file already exists; use modify_file')
        data = _content(arguments, binary=bool(arguments.get('binary', False)))
        files = {**files, filename: data}
        _check_state(files)
        return dict(success=True, message='created', filename=filename, size=len(data),
                    sha256=hashlib.sha256(data).hexdigest(), files_after=encode_snapshot(files))

    if operation == 'workspace_modify':
        if set(arguments) - {'filename', 'content', 'append'}:
            raise WorkspaceError('undeclared modify arguments')
        if 'filename' not in arguments or 'content' not in arguments:
            raise WorkspaceError('filename and content are required')
        filename = normalize_name(arguments['filename'])
        if filename not in files:
            raise WorkspaceError('file does not exist')
        data = _content(arguments, binary=False)
        merged = files[filename] + data if arguments.get('append') else data
        if len(merged) > MAX_CONTENT:
            raise WorkspaceError('content exceeds the per-file limit')
        files = {**files, filename: merged}
        _check_state(files)
        return dict(success=True, message='modified', filename=filename, size=len(merged),
                    sha256=hashlib.sha256(merged).hexdigest(), files_after=encode_snapshot(files))

    if operation == 'workspace_delete':
        if set(arguments) - {'filename'}:
            raise WorkspaceError('undeclared delete arguments')
        filename = normalize_name(arguments.get('filename'))
        if filename not in files:
            raise WorkspaceError('file does not exist')
        files = {name: data for name, data in files.items() if name != filename}
        return dict(success=True, message='deleted', filename=filename, files_after=encode_snapshot(files))

    raise WorkspaceError('unsupported workspace operation')


def validate_payload_arguments(arguments):
    """Validate payload parameters without generating content."""
    if not isinstance(arguments, dict) or set(arguments) - {'type', 'size', 'pattern', 'filename'}:
        raise WorkspaceError('undeclared payload arguments')
    payload_type = arguments.get('type', 'buffer')
    if payload_type not in {'buffer', 'cyclic', 'random'}:
        raise WorkspaceError('unsupported payload type')
    size = arguments.get('size', 1024)
    if type(size) is not int or not 1 <= size <= MAX_CONTENT:
        raise WorkspaceError('payload size must be 1..%d bytes' % MAX_CONTENT)
    pattern = arguments.get('pattern', 'A')
    if (not isinstance(pattern, str) or not 1 <= len(pattern) <= 64
            or any(not 32 <= ord(char) < 127 for char in pattern)):
        raise WorkspaceError('pattern must be 1..64 printable ASCII characters')
    return payload_type, size, pattern


def _payload_bytes(arguments):
    """Bounded, deterministic byte generation matching the reviewed semantics."""
    payload_type, size, pattern = validate_payload_arguments(arguments)
    if payload_type == 'buffer':
        # Exactly `size` bytes; the upstream pattern * (size // len) may fall short.
        data = (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size].encode('ascii')
    elif payload_type == 'cyclic':
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        data = (alphabet * ((size + 25) // 26))[:size].encode('ascii')
    else:
        alphabet = string.ascii_letters + string.digits
        data = ''.join(secrets.choice(alphabet) for _ in range(size)).encode('ascii')
    return payload_type, data


def apply_payload(files, arguments):
    """Generate a test payload as a new workspace file; content never leaves the worker."""
    payload_type, data = _payload_bytes(arguments)
    filename = arguments.get('filename') or f'payload_{int(time.time())}'
    filename = normalize_name(filename)
    if filename in files:
        raise WorkspaceError('file already exists; choose another filename')
    files = {**files, filename: data}
    _check_state(files)
    return dict(success=True, filename=filename, size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                payload_info=dict(type=payload_type, size=len(data), pattern=arguments.get('pattern', 'A')),
                files_after=encode_snapshot(files))


def validate_anew_arguments(arguments):
    if not isinstance(arguments, dict) or set(arguments) - {'input_data', 'output_file', 'additional_args'}:
        raise WorkspaceError('undeclared anew arguments')
    if arguments.get('additional_args', ''):
        raise WorkspaceError('additional_args are not allowed')
    data = arguments.get('input_data')
    if not isinstance(data, str) or len(data.encode('utf-8')) > MAX_CONTENT:
        raise WorkspaceError('input_data must be bounded UTF-8 text')
    output_file = arguments.get('output_file') or ''
    if not isinstance(output_file, str):
        raise WorkspaceError('output_file must be text')
    if output_file:
        output_file = normalize_name(output_file)
    return data, output_file


def validate_qsreplace_arguments(arguments):
    if not isinstance(arguments, dict) or set(arguments) - {'urls', 'replacement', 'additional_args'}:
        raise WorkspaceError('undeclared qsreplace arguments')
    if arguments.get('additional_args', ''):
        raise WorkspaceError('additional_args are not allowed')
    urls = arguments.get('urls')
    if not isinstance(urls, str) or not urls.strip() or len(urls.encode('utf-8')) > MAX_CONTENT:
        raise WorkspaceError('urls must be non-empty bounded UTF-8 text')
    replacement = arguments.get('replacement', 'FUZZ')
    if (not isinstance(replacement, str) or not 1 <= len(replacement) <= 128
            or any(not 32 <= ord(ch) < 127 for ch in replacement)):
        raise WorkspaceError('replacement must be 1..128 printable ASCII characters')
    return urls, replacement


def _parse_ext_list(raw, label):
    if not isinstance(raw, str):
        raise WorkspaceError(f'{label} must be text')
    tokens = [part.strip().lstrip('.') for part in raw.replace(',', ' ').split() if part.strip()]
    if len(tokens) > 32:
        raise WorkspaceError(f'{label} has too many extensions')
    for token in tokens:
        if not 1 <= len(token) <= 16 or not token.isalnum():
            raise WorkspaceError(f'{label} contains an invalid extension token')
    return tokens


def validate_uro_arguments(arguments):
    if not isinstance(arguments, dict) or set(arguments) - {'urls', 'whitelist', 'blacklist', 'additional_args'}:
        raise WorkspaceError('undeclared uro arguments')
    if arguments.get('additional_args', ''):
        raise WorkspaceError('additional_args are not allowed')
    urls = arguments.get('urls')
    if not isinstance(urls, str) or not urls.strip() or len(urls.encode('utf-8')) > MAX_CONTENT:
        raise WorkspaceError('urls must be non-empty bounded UTF-8 text')
    whitelist = _parse_ext_list(arguments.get('whitelist', ''), 'whitelist')
    blacklist = _parse_ext_list(arguments.get('blacklist', ''), 'blacklist')
    return urls, whitelist, blacklist


def _parse_check_list(raw, label):
    if not isinstance(raw, str):
        raise WorkspaceError(f'{label} must be text')
    tokens = [part.strip() for part in raw.split(',') if part.strip()]
    if len(tokens) > 32:
        raise WorkspaceError(f'{label} has too many check identifiers')
    for token in tokens:
        if not 1 <= len(token) <= 48 or not all(ch.isalnum() or ch in {'_'} for ch in token):
            raise WorkspaceError(f'{label} contains an invalid check identifier')
    return tokens


def validate_checkov_arguments(arguments):
    allowed = {'directory', 'framework', 'check', 'skip_check', 'output_format', 'additional_args'}
    if not isinstance(arguments, dict) or set(arguments) - allowed:
        raise WorkspaceError('undeclared checkov arguments')
    if arguments.get('additional_args', ''):
        raise WorkspaceError('additional_args are not allowed')
    directory = arguments.get('directory', '.') or '.'
    if directory not in {'.', ''}:
        directory = normalize_name(directory)
    else:
        directory = '.'
    framework = (arguments.get('framework') or '').strip().lower()
    if framework and framework not in {'dockerfile', 'kubernetes', 'terraform', 'json', 'yaml', 'all'}:
        raise WorkspaceError('unsupported checkov framework')
    output_format = (arguments.get('output_format') or 'json').strip().lower()
    if output_format not in {'json', 'cli'}:
        raise WorkspaceError('output_format must be json or cli')
    checks = _parse_check_list(arguments.get('check', ''), 'check')
    skip_checks = _parse_check_list(arguments.get('skip_check', ''), 'skip_check')
    return directory, framework, checks, skip_checks, output_format


def evaluate_iac_snapshot(files, directory='.', framework='', checks=(), skip_checks=()):
    """Deterministic static IaC rules over a workspace snapshot."""
    prefix = '' if directory in {'', '.'} else directory + '/'
    checks_set = set(checks)
    skip_set = set(skip_checks)

    def include(rule_id):
        if rule_id in skip_set:
            return False
        return not checks_set or rule_id in checks_set

    passed, failed = [], []
    scanned = 0
    for name, raw in sorted(files.items()):
        if prefix and not (name == directory or name.startswith(prefix)):
            continue
        text = raw.decode('utf-8', errors='replace')
        lower_name = name.lower()
        base = lower_name.rsplit('/', 1)[-1]
        is_docker = base == 'dockerfile' or base.startswith('dockerfile.') or lower_name.endswith('.dockerfile')
        is_k8s = lower_name.endswith(('.yaml', '.yml')) and ('apiVersion:' in text and 'kind:' in text)
        is_tf = lower_name.endswith('.tf')
        if framework == 'dockerfile' and not is_docker:
            continue
        if framework == 'kubernetes' and not is_k8s:
            continue
        if framework == 'terraform' and not is_tf:
            continue
        if not (is_docker or is_k8s or is_tf):
            continue
        scanned += 1
        if is_docker:
            has_user = any(line.strip().upper().startswith('USER ') and 'root' not in line.lower()
                           for line in text.splitlines())
            has_health = any(line.strip().upper().startswith('HEALTHCHECK ') for line in text.splitlines())
            uses_latest = any(line.strip().upper().startswith('FROM ') and ':latest' in line.lower()
                              for line in text.splitlines())
            for rule_id, title, ok in (
                ('CKV_DOCKER_2', 'Ensure that HEALTHCHECK instructions have been added to container images', has_health),
                ('CKV_DOCKER_3', 'Ensure that a user for the container has been created', has_user),
                ('CKV_DOCKER_7', 'Ensure the base image uses a non-latest version tag', not uses_latest),
            ):
                if include(rule_id):
                    (passed if ok else failed).append(dict(check_id=rule_id, check_name=title,
                                                           file_path=name, framework='dockerfile'))
        if is_k8s:
            privileged = 'privileged: true' in text.lower()
            host_net = 'hostnetwork: true' in text.lower()
            for rule_id, title, ok in (
                ('CKV_K8S_16', 'Container should not be privileged', not privileged),
                ('CKV_K8S_19', 'Pod should not share host network namespace', not host_net),
            ):
                if include(rule_id):
                    (passed if ok else failed).append(dict(check_id=rule_id, check_name=title,
                                                           file_path=name, framework='kubernetes'))
        if is_tf:
            open_cidr = '0.0.0.0/0' in text
            for rule_id, title, ok in (
                ('CKV_AWS_24', 'Ensure no security groups allow ingress from 0.0.0.0:0', not open_cidr),
            ):
                if include(rule_id):
                    (passed if ok else failed).append(dict(check_id=rule_id, check_name=title,
                                                           file_path=name, framework='terraform'))
    return dict(scanned_files=scanned, passed=len(passed), failed=len(failed),
                passed_checks=passed, failed_checks=failed)
