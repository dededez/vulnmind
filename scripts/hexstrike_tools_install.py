"""Install the tier-1/tier-2 HexStrike toolchain next to the workspace.

Everything lands in ``.devtools/hexstrike-tools`` (Windows filesystem, visible in
WSL under /mnt/<drive>/...). The VulnMindLab root filesystem is not modified:
Alpine packages are fetched with ``apk fetch`` and unpacked into the toolchain
directory, Python tools are installed with ``--target``.

Downloads with a published checksum are verified against it. Downloads without
one (anew, qsreplace, sqlmap, pip zipapp, nuclei-templates source) are recorded
trust-on-first-use; a later run fails if the bytes differ from the manifest.

The manifest (``manifest.json``) is what the isolated worker hashes into the
execution environment fingerprint. Re-running the installer with different
bytes changes the fingerprint and invalidates earlier validation receipts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import urllib.request

PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = PROJECT/'.devtools'/'hexstrike-tools'
DISTRO = 'VulnMindLab'

GO_TOOLS = {
    # name: (version, asset url, checksum file url or None, binary name inside archive)
    'httpx': ('1.12.0', 'https://github.com/projectdiscovery/httpx/releases/download/v1.12.0/httpx_1.12.0_linux_amd64.zip',
              'https://github.com/projectdiscovery/httpx/releases/download/v1.12.0/httpx_1.12.0_checksums.txt', 'httpx'),
    'katana': ('1.8.0', 'https://github.com/projectdiscovery/katana/releases/download/v1.8.0/katana_1.8.0_linux_amd64.zip',
               'https://github.com/projectdiscovery/katana/releases/download/v1.8.0/katana-1.8.0-checksums.txt', 'katana'),
    'nuclei': ('3.11.1', 'https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip',
               'https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_checksums.txt', 'nuclei'),
    'dalfox': ('3.3.0', 'https://github.com/hahwul/dalfox/releases/download/v3.3.0/dalfox-v3.3.0-linux-x86_64-musl.tar.gz',
               'https://github.com/hahwul/dalfox/releases/download/v3.3.0/dalfox-v3.3.0-linux-x86_64-musl.tar.gz.sha256', 'dalfox'),
    'ffuf': ('2.3.0', 'https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_linux_amd64.tar.gz',
             'https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_checksums.txt', 'ffuf'),
    'anew': ('0.1.1', 'https://github.com/tomnomnom/anew/releases/download/v0.1.1/anew-linux-amd64-0.1.1.tgz', None, 'anew'),
    'qsreplace': ('0.0.3', 'https://github.com/tomnomnom/qsreplace/releases/download/v0.0.3/qsreplace-linux-amd64-0.0.3.tgz',
                  None, 'qsreplace'),
}
SOURCES = {
    'sqlmap': ('1.10', 'https://github.com/sqlmapproject/sqlmap/archive/refs/tags/1.10.tar.gz'),
    'pip': ('25.3', 'https://bootstrap.pypa.io/pip/zipapp/pip-25.3.pyz'),
}
# Pinned non-destructive template subset (technologies, misconfiguration, exposures/configs).
TEMPLATE_DIRS = ('http/technologies', 'http/misconfiguration', 'http/exposures/configs')
PINNED_TEMPLATES = {
    'http/technologies/tech-detect.yaml': '''id: tech-detect

info:
  name: Technology Detection (Pinned Subset)
  author: vulnmind-pinned
  severity: info
  description: Non-destructive server and header technology fingerprint.
  tags: tech,discovery

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers-condition: or
    matchers:
      - type: regex
        part: header
        name: server-header
        regex:
          - "(?i)^server:\\\\s*(nginx|apache|werkzeug|uvicorn|gunicorn|caddy|cloudflare|iis)"
      - type: regex
        part: header
        name: powered-by
        regex:
          - "(?i)^x-powered-by:\\\\s*(.+)"

    extractors:
      - type: kval
        part: header
        kval:
          - server
          - x_powered_by
''',
    'http/misconfiguration/missing-security-headers.yaml': '''id: missing-security-headers

info:
  name: Missing HTTP Security Headers
  author: vulnmind-pinned
  severity: info
  description: Checks for missing X-Frame-Options or Content-Security-Policy headers on the base response.
  tags: misconfig,headers,generic

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: header
        words:
          - "x-frame-options"
          - "content-security-policy"
        condition: or
        negative: true
''',
    'http/exposures/configs/dotenv-exposure.yaml': '''id: dotenv-exposure

info:
  name: Dotenv Configuration Exposure
  author: vulnmind-pinned
  severity: medium
  description: Checks whether a .env file is publicly readable with key=value content.
  tags: exposure,config,files

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: regex
        part: body
        regex:
          - "^[A-Z0-9_]{2,40}="
''',
}
PYTHON_PACKAGES = ('arjun==2.2.7', 'wafw00f==2.4.2', 'uro==1.0.2')
PYTHON_NO_DEPS_PACKAGES = ('checkov==3.4.3',)
APK_PACKAGES = ('nmap', 'binutils', 'file', 'slirp4netns', 'nftables')
# Entry points the worker hashes before each run (relative to the toolchain root).
ENTRYPOINTS = {
    'httpx': 'bin/httpx', 'katana': 'bin/katana', 'nuclei': 'bin/nuclei', 'dalfox': 'bin/dalfox',
    'ffuf': 'bin/ffuf', 'anew': 'bin/anew', 'qsreplace': 'bin/qsreplace',
    'sqlmap': 'sqlmap/sqlmap.py', 'nmap': 'alpine/usr/bin/nmap', 'objdump': 'alpine/usr/bin/objdump',
    'readelf': 'alpine/usr/bin/readelf', 'file': 'alpine/usr/bin/file',
    'slirp4netns': 'alpine/usr/bin/slirp4netns', 'nft': 'alpine/usr/sbin/nft',
    'arjun': 'python/arjun/__main__.py', 'wafw00f': 'python/wafw00f/main.py', 'uro': 'python/uro/uro.py',
    'checkov': 'python/checkov/main.py',
}
WORDLIST = '''admin
administrator
api
api/v1
api/v2
app
assets
backup
backups
bin
cgi-bin
config
console
css
dashboard
data
db
debug
dev
docs
download
downloads
env
error
files
health
healthz
help
home
images
img
include
includes
index
info
js
json
lib
log
login
logout
logs
manage
manager
media
metrics
old
panel
phpinfo
private
public
register
robots.txt
search
server-status
service
services
settings
setup
signin
signup
sitemap.xml
static
status
swagger
swagger.json
swagger-ui
temp
test
tmp
upload
uploads
user
users
v1
v2
version
web
.env
.git
.git/HEAD
.well-known/security.txt
openapi.json
graphql
actuator
actuator/health
'''


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def fetch(url, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        return target
    temp = target.with_suffix(target.suffix+'.part')
    request = urllib.request.Request(url, headers={'User-Agent': 'vulnmind-toolchain-installer'})
    with urllib.request.urlopen(request, timeout=120) as response, temp.open('wb') as stream:
        while block := response.read(1 << 20):
            stream.write(block)
    temp.replace(target)
    return target


def published_checksum(url, asset_name, cache):
    text = fetch(url, cache/(asset_name+'.checksums')).read_text(encoding='utf-8')
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip('*') == asset_name:
            return parts[0].lower()
        if len(parts) == 1 and len(parts[0]) == 64:
            return parts[0].lower()
    raise ValueError('checksum not published for '+asset_name)


def wsl_path(path):
    path = Path(path).resolve()
    return '/mnt/' + path.drive[0].lower() + '/' + PurePosixPath(*path.parts[1:]).as_posix() + '/'


def wsl(script, *, distro=DISTRO, timeout=1800):
    result = subprocess.run(['wsl.exe', '-d', distro, '-u', 'root', '--', '/bin/sh', '-eu'],
                            input=script.encode('utf-8'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    output = result.stdout.decode('utf-8', errors='replace')
    if result.returncode:
        err = result.stderr.decode('utf-8', errors='replace')
        raise RuntimeError('WSL step failed:\n'+(output+'\n'+err)[-4000:])
    return output


def quote(value):
    return "'"+str(value).replace("'", "'\\''")+"'"


def tree_digest(root):
    digest = hashlib.sha256()
    count = 0
    candidates = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for fname in sorted(filenames):
            path = Path(dirpath)/fname
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                candidates.append(path)
            except OSError:
                continue
    for path in sorted(candidates):
        digest.update(path.relative_to(root).as_posix().encode()+b'\0'+sha256(path).encode()+b'\n')
        count += 1
    return digest.hexdigest(), count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    parser.add_argument('--skip-python', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    downloads = root/'downloads'
    previous = {}
    if (root/'manifest.json').exists():
        previous = json.loads((root/'manifest.json').read_text(encoding='utf-8')).get('downloads', {})
    records = {}

    def record(name, version, url, path, checksum_source):
        actual = sha256(path)
        old = previous.get(name)
        if old and old['sha256'] != actual:
            raise ValueError(f'{name}: download differs from the recorded manifest')
        records[name] = dict(version=version, url=url, sha256=actual, checksum_source=checksum_source)

    for name, (version, url, checksum_url, _binary) in GO_TOOLS.items():
        asset = url.rsplit('/', 1)[1]
        path = fetch(url, downloads/asset)
        if checksum_url:
            expected = published_checksum(checksum_url, asset, downloads)
            if sha256(path) != expected:
                raise ValueError(f'{name}: checksum mismatch')
            record(name, version, url, path, 'published')
        else:
            record(name, version, url, path, 'trust_on_first_use')
        print(f'downloaded {name} {version}', flush=True)
    for name, (version, url) in SOURCES.items():
        path = fetch(url, downloads/(name+'-'+version+('.pyz' if name == 'pip' else '.tar.gz')))
        record(name, version, url, path, 'trust_on_first_use')
        print(f'downloaded {name} {version}', flush=True)
    (root/'wordlists').mkdir(parents=True, exist_ok=True)
    (root/'wordlists'/'common-small.txt').write_text(WORDLIST, encoding='utf-8', newline='\n')
    for rel, content in PINNED_TEMPLATES.items():
        target = root/'nuclei-templates'/rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding='utf-8', newline='\n')

    base = wsl_path(root)
    dl = base+'downloads/'
    steps = ['cd '+quote(base), 'mkdir -p bin', 'T=$(mktemp -d)']
    for name, (_v, url, _c, binary) in GO_TOOLS.items():
        asset = url.rsplit('/', 1)[1]
        unpack = f'unzip -oq {quote(dl+asset)} -d "$T/{name}"' if asset.endswith('.zip') else \
            f'mkdir -p "$T/{name}" && tar -xzf {quote(dl+asset)} -C "$T/{name}"'
        steps += [unpack, f'cp "$(find "$T/{name}" -type f -name {binary} | head -1)" bin/{binary}', f'chmod 0555 bin/{binary}']
    steps += ['rm -rf sqlmap && mkdir sqlmap', f'tar -xzf {quote(dl+"sqlmap-1.10.tar.gz")} -C sqlmap --strip-components=1',
              'printf "#!/bin/sh\\nexec /usr/bin/python3 \\"$(dirname \\"$0\\")/../sqlmap/sqlmap.py\\" \\"\\$@\\"\\n" > bin/sqlmap && chmod 0555 bin/sqlmap',
              'printf "#!/usr/bin/env python3\\nimport sys, checkov.main\\nsys.exit(checkov.main.Checkov().run() if hasattr(checkov.main, \'Checkov\') else 0)\\n" > bin/checkov && chmod 0555 bin/checkov',
              'rm -rf "$T"']
    print(wsl('\n'.join(steps)), flush=True)
    print('unpacked Go tools, sqlmap and pinned templates', flush=True)

    # Alpine packages: fetched with their dependency closure, unpacked here only.
    apk = ['cd '+quote(base), 'rm -rf alpine apk && mkdir -p alpine apk', 'apk update -q',
           'apk fetch -q -R -o apk '+' '.join(APK_PACKAGES),
           'for f in apk/*.apk; do tar -xzf "$f" -C alpine 2>/dev/null || true; done',
           'rm -f alpine/.PKGINFO alpine/.SIGN.* alpine/.pre-* alpine/.post-* alpine/.trigger',
           'ls apk']
    packages = wsl('\n'.join(apk)).split()
    print('unpacked apk closure: '+' '.join(packages), flush=True)

    if not args.skip_python and not all((root/ENTRYPOINTS[k]).is_file() for k in ('arjun', 'wafw00f', 'uro', 'checkov')):
        py = ['cd '+quote(base), 'rm -rf python && mkdir python && T=$(mktemp -d)',
              f'/usr/bin/python3 {quote(dl+"pip-25.3.pyz")} install --disable-pip-version-check --no-compile -q '
              '--target "$T" '+' '.join(PYTHON_PACKAGES),
              f'/usr/bin/python3 {quote(dl+"pip-25.3.pyz")} install --disable-pip-version-check --no-compile -q '
              '--no-deps --upgrade --target "$T" '+' '.join(PYTHON_NO_DEPS_PACKAGES),
              'cp -r "$T"/* python/ && rm -rf "$T"']
        print(wsl('\n'.join(py), timeout=3600)[-2000:], flush=True)
        print('installed Python tools', flush=True)

    entry = {}
    for name, rel in ENTRYPOINTS.items():
        path = root/rel
        if path.is_file():
            entry[name] = dict(path=rel, sha256=sha256(path), size=path.stat().st_size)
        else:
            entry[name] = dict(path=rel, missing=True)
    trees = {}
    for part in ('bin', 'sqlmap', 'nuclei-templates', 'alpine', 'python', 'wordlists'):
        if (root/part).exists():
            digest, count = tree_digest(root/part)
            trees[part] = dict(sha256=digest, files=count)
    manifest = dict(version=1, downloads=records, apk_packages=sorted(packages),
                    python_packages=list(PYTHON_PACKAGES + PYTHON_NO_DEPS_PACKAGES),
                    template_dirs=list(TEMPLATE_DIRS), entrypoints=entry, trees=trees)
    (root/'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n', encoding='utf-8', newline='\n')
    missing = [k for k, v in entry.items() if v.get('missing')]
    print(json.dumps(dict(root=str(root), entrypoints=len(entry), missing=missing, trees=trees), indent=2))
    return 1 if missing else 0


if __name__ == '__main__':
    sys.exit(main())
