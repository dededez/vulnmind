"""Fingerprint locally cached embedding files; no network and no DB writes.

This records what is present now, not what created any existing database vector.
"""
import hashlib
import json
from pathlib import Path
from huggingface_hub import snapshot_download

MODEL='Qwen/Qwen3-Embedding-0.6B'
MAX_FILES=128
MAX_FILE_BYTES=4_000_000_000

def fingerprint():
    snapshot=Path(snapshot_download(MODEL,local_files_only=True))
    files=sorted(p for p in snapshot.rglob('*') if p.is_file())
    if not files or len(files)>MAX_FILES:
        raise ValueError('unexpected number of model files')
    hashes={}
    for path in files:
        before=path.stat()
        if before.st_size>MAX_FILE_BYTES: raise ValueError('model file too large')
        digest=hashlib.sha256()
        with path.open('rb') as f:
            while data:=f.read(1024*1024): digest.update(data)
        after=path.stat()
        if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):
            raise ValueError('model file changed during fingerprinting')
        hashes[path.relative_to(snapshot).as_posix()]={'sha256':digest.hexdigest(),'bytes':before.st_size}
    return {'model':MODEL,'cached_revision':snapshot.name,'files':hashes,
            'note':'Current local cache only; no signature or historical database vector provenance verified.'}


def model_identity(manifest):
    encoded = json.dumps(manifest['files'], sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    return {'model': manifest['model'], 'revision': manifest['cached_revision'],
            'files_sha256': hashlib.sha256(encoded.encode('utf-8')).hexdigest()}

if __name__=='__main__': print(json.dumps(fingerprint(),ensure_ascii=False))
