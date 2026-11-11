"""Regenerate the offline AST inventory for the authorized local Juice Shop copy.

Read-only against the repository; writes one JSON artifact. Not used at runtime.
"""
import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from vulnmind.schemas import Authorization
from vulnmind.workbench.ast_discovery import extend_ast_snapshot
from vulnmind.workbench.discovery import extend_snapshot
from vulnmind.workbench.routes import snapshot


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--origin', default='http://172.19.160.1:3000')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source='VulnMind 自有本机演示环境', approved_by='本机操作者',
                          starts_at=now - timedelta(minutes=1), expires_at=now + timedelta(hours=2),
                          repository_roots=[str(args.repo)], web_origins=[args.origin],
                          allowed_ip_networks=['172.19.160.1/32', '127.0.0.1/32'])
    saved = extend_ast_snapshot(extend_snapshot(snapshot(args.repo, scope, extended=True), scope), scope)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(saved, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    print(json.dumps(dict(output=str(args.output), files=len(saved['files']), routes=len(saved['routes']),
                          client_endpoints=len(saved['client_endpoints']),
                          duplicates_removed=saved['indexing']['duplicates_removed'],
                          client_duplicates_removed=saved.get('client_duplicates_removed'),
                          excluded=saved['indexing']['excluded'], parser=saved['indexing']['parser'],
                          digest=saved['digest'], legacy_digest=saved['legacy_digest']), ensure_ascii=False))


if __name__ == '__main__':
    main()
