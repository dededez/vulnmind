"""Bounded v6 smoke run against the authorized local Juice Shop lab.

Creates one workbench job through the local API, approves each round exactly
once, then records the result and integrity check. No model calls when
--model is absent.
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

DETECTORS = ["sql_error", "sql_boolean", "response_disclosure", "redirect_location",
             "well_known_exposure", "config_exposure", "sql_login", "weak_password", "browser_xss",
             "auth_idor", "exposed_file"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8765")
    parser.add_argument("--origin", default="http://172.19.160.1:3000")
    parser.add_argument("--repository", default=os.environ.get("JUICE_SHOP_REPO"))
    parser.add_argument("--budget", type=int, default=60)
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--external", action="store_true")
    parser.add_argument("--model", action="store_true")
    parser.add_argument("--account", action="store_true", help="register one random test account and use its session")
    parser.add_argument("--wait", type=int, default=900)
    parser.add_argument("--output", type=Path, default=Path("evaluation/juice_shop_v6_smoke.json"))
    args = parser.parse_args()
    if not args.repository:
        parser.error('--repository or JUICE_SHOP_REPO is required')

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    opener.open(args.base + "/").read()
    csrf = json.load(opener.open(args.base + "/api/state"))["csrf"]

    def api(path, data=None):
        request = urllib.request.Request(args.base + path,
                                         data=None if data is None else json.dumps(data).encode(),
                                         headers={"Content-Type": "application/json",
                                                  "X-CSRF-Token": csrf, "Origin": args.base})
        return json.load(opener.open(request, timeout=120))

    account_profile = None
    if args.account:
        from vulnmind.config import Settings
        from vulnmind.workbench.account import random_account
        from vulnmind.workbench.secrets import Vault
        settings = Settings()
        vault = Vault(Path(settings.report_root).resolve().parent / 'workbench' / 'credentials')
        account_profile = vault.save_account(args.origin, **random_account())

    config = dict(
        name="Juice Shop v6 冒烟 · " + ("外部" if args.external else "内置") + (" · 模型" if args.model else " · 规则"),
        repository=args.repository, origin=args.origin, deployment_version="juice-shop-master-local",
        binding_confirmed=True, authorization_source="VulnMind 自有本机演示环境",
        allowed_ip_networks=["172.19.160.1/32", "127.0.0.1/32"],
        pipeline_version=6, agents=args.model, rounds=args.rounds, request_budget=args.budget,
        external_execution=args.external,
        external_recon=bool(args.external), tool_policy="external_preferred" if args.external else "builtin_only",
        repository_iac=False, knowledge_mode="keyword", detectors=DETECTORS,
        allow_post=False, auth_probe=True,
        **(dict(account_profile=account_profile) if account_profile else {}),
    )
    job = api("/api/jobs", config)["id"]
    print("job=" + job, flush=True)
    api("/api/jobs/" + job + "/start", {})
    deadline = time.monotonic() + args.wait
    approvals = []
    detail = None
    while time.monotonic() < deadline:
        detail = api("/api/jobs/" + job)
        if detail["status"] == "waiting_approval":
            plan = detail["result"]["plan"]
            print(json.dumps(dict(round=len(approvals) + 1, digest=detail["result"]["digest"],
                                  requests=len(plan["requests"]),
                                  actions=[{k: a.get(k) for k in ("kind", "url", "cost", "execution_tool")}
                                           for a in plan["actions"]]), ensure_ascii=False), flush=True)
            approvals.append(detail["result"]["digest"])
            api("/api/jobs/" + job + "/approve",
                dict(approval_id=detail["result"]["approval_id"], approved=True))
        elif detail["status"] not in {"queued", "running"}:
            break
        time.sleep(2)
    record = dict(job_id=job, status=detail["status"], config=config, result=detail["result"],
                  approval_digests=approvals)
    if detail["status"] == "finished":
        record["integrity"] = api("/api/jobs/" + job + "/verify")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    result = detail["result"] or {}
    print(json.dumps(dict(job_id=job, status=detail["status"], requests_used=result.get("requests_used"),
                          stop_reason=result.get("stop_reason"), observations=len(result.get("observations", [])),
                          account=result.get("account"),
                          verdicts=[{k: o.get(k) for k in ("kind", "url", "verdict", "behavior")}
                                    for o in result.get("observations", [])],
                          integrity=record.get("integrity"), output=str(args.output)),
                     ensure_ascii=False), flush=True)
    if detail["status"] != "finished":
        raise SystemExit("job did not finish: " + detail["status"])


if __name__ == "__main__":
    main()
