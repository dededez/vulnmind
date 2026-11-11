"""Explicitly authorized local Juice Shop regression. Fixed target, no data dumping."""
import argparse
import http.cookiejar
import json
import os
import time
import urllib.request
from pathlib import Path


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--external',action='store_true')
    p.add_argument('--model',action='store_true')
    args=p.parse_args()
    base='http://127.0.0.1:8766'
    origin='http://172.19.160.1:3000'
    opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    opener.open(base+'/').read()
    csrf=json.load(opener.open(base+'/api/state'))['csrf']
    def api(path,data=None):
        req=urllib.request.Request(base+path,data=None if data is None else json.dumps(data).encode(),
            headers={'Content-Type':'application/json','X-CSRF-Token':csrf,'Origin':base})
        return json.load(opener.open(req,timeout=60))
    config=dict(name='Juice Shop v4 回归 · '+('SQLMap' if args.external else '内置重复差分'),
        repository=os.environ.get('JUICE_SHOP_REPO',r'C:\\path\\to\\juice-shop-master'),origin=origin,
        deployment_version='juice-shop-master-local',binding_confirmed=True,
        authorization_source='用户授权的本机 Juice Shop 修复后复测',allowed_ip_networks=['172.19.160.1/32','127.0.0.1/32'],
        pipeline_version=4,agents=args.model,rounds=2 if args.external else 1,request_budget=330 if args.external else 30,
        external_execution=args.external,external_recon=False,tool_policy='external_preferred' if args.external else 'builtin_only',
        knowledge_mode='hybrid',detectors=['sql_boolean'] if args.external else ['sql_boolean','sql_error'],allow_post=False)
    job=api('/api/jobs',config)['id']
    print('job='+job,flush=True)
    api('/api/jobs/'+job+'/start',{})
    deadline=time.monotonic()+600
    approvals=[]
    while time.monotonic()<deadline:
        detail=api('/api/jobs/'+job)
        if detail['status']=='waiting_approval':
            plan=detail['result']['plan']
            assert all(req['url'].startswith(origin+'/') and req['method']=='GET' for req in plan['requests'])
            # Review and log exact plan before approving only this script-created task.
            print(json.dumps(dict(actions=[{k:a.get(k) for k in ('kind','url','parameter','cost','execution_tool')} for a in plan['actions']],
                                  requests=len(plan['requests'])),ensure_ascii=False),flush=True)
            approvals.append(detail['result']['digest'])
            api('/api/jobs/'+job+'/approve',dict(approval_id=detail['result']['approval_id'],approved=True))
        elif detail['status'] not in {'queued','running'}:
            break
        time.sleep(2)
    record=dict(job_id=job,status=detail['status'],config=config,result=detail['result'],approval_digests=approvals)
    if detail['status']=='finished': record['integrity']=api('/api/jobs/'+job+'/verify')
    out=Path('evaluation')/('juice_shop_v4_external.json' if args.external else 'juice_shop_v4_model.json' if args.model else 'juice_shop_v4_builtin.json')
    out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(job_id=job,status=detail['status'],requests_used=(detail['result'] or {}).get('requests_used'),
        observations=[{k:o.get(k) for k in ('kind','url','parameter','verdict','behavior','tool_state','detail')} for o in (detail['result'] or {}).get('observations',[])],
        integrity=record.get('integrity'),output=str(out)),ensure_ascii=False),flush=True)
    if detail['status']!='finished': raise RuntimeError(str(detail['result']))


if __name__=='__main__': main()
