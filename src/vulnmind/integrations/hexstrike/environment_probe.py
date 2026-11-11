"""Read-only tool-environment probe for the sandbox distribution.

This script never executes a probed program. It resolves names through the
fixed PATH with ``shutil.which`` and records a bounded local fingerprint
(path, size, SHA-256 of the first 8 MB) for each found binary.

Names are restricted to plain executable basenames; path separators, traversal,
control characters and shell metacharacters are rejected. The report is an
observation, not proof of installation integrity or a version check.
"""
import hashlib
import json
import os
import re
import shutil
import sys

NAME = re.compile(r'^[a-z0-9][a-z0-9._-]{0,63}$')
MAX_PROGRAMS = 128


def main():
    data = json.loads(sys.stdin.buffer.read(65536))
    programs = data.get('programs')
    if not isinstance(programs, list) or not programs or len(programs) > MAX_PROGRAMS:
        raise ValueError('invalid probe program list')
    report = {}
    for name in programs:
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ValueError('invalid probe program name')
        path = shutil.which(name)
        if not path:
            report[name] = {'found': False}
            continue
        try:
            size = os.stat(path).st_size
            digest = hashlib.sha256()
            remaining = min(size, 8_000_000)
            with open(path, 'rb') as stream:
                while remaining:
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        break
                    digest.update(chunk)
                    remaining -= len(chunk)
        except OSError:
            report[name] = {'found': True, 'path': path, 'readable': False}
            continue
        report[name] = {'found': True, 'path': path, 'size': size, 'readable': True,
                        'sha256_prefix': digest.hexdigest(),
                        'fingerprint_bytes': min(size, 8_000_000)}
    print(json.dumps(dict(programs=report, python=sys.version.split()[0],
                          note='PATH lookup and local fingerprints only; no execution, no version check')))


if __name__ == '__main__': main()
