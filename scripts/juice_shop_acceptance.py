"""Fixed-config acceptance run: model planning, 300 requests, at most three rounds.

--mode fixed    : no account, no browser (the user's original fixed configuration)
--mode extended : one registered account + browser verification (explicit extra)
"""
import argparse
import http.cookiejar
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

FIXED = ["sql_error", "sql_boolean", "response_disclosure", "well_known_exposure", "config_exposure",
         "redirect_location", "sql_login", "weak_password", "exposed_file"]
EXTENDED = FIXED + ["browser_xss", "auth_idor"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', default='http://127.0.0.1:8765')
    parser.add_argument('--origin', default='http://172.19.160.1:3000')
    parser.add_argument('--repository', default=os.environ.get('JUICE_SHOP_REPO'))
    parser.add_argument('--mode', choices=['fixed', 'extended'], default='fixed')
    parser.add_argument('--budget', type=int, default=300)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--external', action='store_true')
    parser.add_argument('--model', action='store_true', default=True)
    parser.add_argument('--wait', type=int, default=2400)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.repository:
        parser.error('--repository or JUICE_SHOP_REPO is required')

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    opener.open(args.base + '/').read()
    csrf = json.load(opener.open(args.base + '/api/state'))['csrf']

    def api(path, data=None):
        request = urllib.request.Request(args.base + path,
                                         data=None if data is None else json.dumps(data).encode(),
                                         headers={'Content-Type': 'application/json',
                                                  'X-CSRF-Token': csrf, 'Origin': args.base})
        return json.load(opener.open(request, timeout=300))

    account_profile = None
    detectors = list(EXTENDED if args.mode == 'extended' else FIXED)
    if args.mode == 'extended':
        from vulnmind.config import Settings
        from vulnmind.workbench.account import random_account
        from vulnmind.workbench.secrets import Vault
        vault = Vault(Path(Settings().report_root).resolve().parent / 'workbench' / 'credentials')
        account_profile = vault.save_account(args.origin, **random_account())

    config = dict(
        name=f'Juice Shop v6 {args.mode} 验收', repository=args.repository, origin=args.origin,
        deployment_version='juice-shop-master-local', binding_confirmed=True,
        authorization_source='VulnMind 自有本机演示环境',
        allowed_ip_networks=['172.19.160.1/32', '127.0.0.1/32'],
        pipeline_version=6, agents=True, rounds=args.rounds, request_budget=args.budget,
        external_execution=args.external, external_recon=bool(args.external),
        tool_policy='external_preferred' if args.external else 'builtin_only',
        repository_iac=False, knowledge_mode='keyword', detectors=detectors,
        allow_post=False, auth_probe=True,
        **(dict(account_profile=account_profile) if account_profile else {}),
    )
    job = api('/api/jobs', config)['id']
    print('job=' + job, flush=True)
    api('/api/jobs/' + job + '/start', {})
    deadline = time.monotonic() + args.wait
    approvals = []
    detail = None
    while time.monotonic() < deadline:
        detail = api('/api/jobs/' + job)
        if detail['status'] == 'waiting_approval':
            plan = detail['result']['plan']
            summary = dict(round=len(approvals) + 1, requests=len(plan.get('requests', [])),
                           actions=len(plan.get('actions', [])),
                           browser=len(plan.get('browser_actions', []) or []),
                           auth=len(plan.get('auth_actions', []) or []),
                           kinds=sorted({a.get('kind') for a in plan.get('actions', [])}))
            print(json.dumps(summary, ensure_ascii=False), flush=True)
            approvals.append(detail['result']['digest'])
            api('/api/jobs/' + job + '/approve',
                dict(approval_id=detail['result']['approval_id'], approved=True))
        elif detail['status'] not in {'queued', 'running'}:
            break
        time.sleep(3)
    record = dict(job_id=job, label=args.mode, config=config, status=detail['status'],
                  result=detail['result'], approval_digests=approvals)
    if detail['status'] == 'finished':
        record['integrity'] = api('/api/jobs/' + job + '/verify')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    result = detail['result'] or {}
    print(json.dumps(dict(job_id=job, status=detail['status'], used=result.get('requests_used'),
                          stop=result.get('stop_reason'), observations=len(result.get('observations', [])),
                          roots=len(result.get('root_causes', [])), approvals=len(approvals),
                          integrity=record.get('integrity'), output=str(args.output)), ensure_ascii=False), flush=True)
    if detail['status'] != 'finished':
        raise SystemExit('acceptance run did not finish: ' + str(detail['status']))


if __name__ == '__main__':
    main()
