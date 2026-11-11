"""Owned-fixture smoke, optionally real configured model; never accepts a target URL."""
import argparse
import json
from pathlib import Path
from uuid import UUID
from sqlalchemy import create_engine
from vulnmind.config import Settings
from vulnmind.workbench.service import Workbench
from vulnmind.workbench.demo import configuration


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--model',action='store_true');parser.add_argument('--output',type=Path);parser.add_argument('--pipeline-version',type=int,choices=[1,2,3],default=3);args=parser.parse_args()
    settings=Settings();engine=create_engine(settings.database_url)
    service=Workbench(engine,settings,Path(settings.report_root).resolve().parent/'workbench')
    try:
        config=configuration(service);config.update(name='开发回归 · '+('真实模型联合调查' if args.model else '规则联合调查'),agents=args.model,pipeline_version=args.pipeline_version)
        job=service.create(config)['id'];service.start(job)
        decisions=[]
        for _ in range(5):
            service.active[UUID(job)].result(timeout=300)
            detail=service.detail(job)
            if detail['status']!='waiting_approval':break
            # Only this script-created, bundled loopback target; exact current plan.
            decisions.append(detail['result']['digest'])
            service.decide(job,detail['result']['approval_id'],True)
        if detail['status']!='finished': raise RuntimeError(json.dumps(detail['result'],ensure_ascii=False))
        proof=service.verify(job)
        record=dict(job_id=job,mode='real_model' if args.model else 'rules',status=detail['status'],
            pipeline_version=detail['config'].get('pipeline_version',1),
            knowledge=[dict(mode=k['mode'],skills=len(k['skills']),chunks=len(k['chunks']),retrievals=k['retrievals']) for k in detail['result'].get('knowledge',[])],
            request_count=detail['result']['requests_used'],approval_digests=decisions,
            observations=[dict(kind=o['kind'],verdict=o['verdict']) for o in detail['result']['observations']],
            agents=[dict(stage=s['stage'],mode=s['preview'].get('mode'),knowledge_refs=s['preview'].get('knowledge_refs',[])) for s in detail['stages'] if s['stage'].startswith(('plan_','critic_'))],
            integrity=proof,report_uri=detail['result']['report_uri'])
        # Completed jobs are not queued again. Also verify final receipts directly.
        from sqlalchemy.orm import Session
        from vulnmind.persistence.models import WorkbenchJob
        from vulnmind.workbench.engine import UnifiedInvestigation
        class NoReplay:
            def complete(self,*a,**kw):raise AssertionError('model repeated')
        def no_http(**kw):raise AssertionError('request repeated')
        with Session(engine) as session:
            row=session.get(WorkbenchJob,UUID(job))
            assert UnifiedInvestigation(engine,row,settings,service.vault,http=no_http,model=NoReplay(),knowledge_provider=no_http).run()['status']=='finished'
        record['replay_without_model_or_http']=True
        out=args.output or Path('evaluation')/('workbench_v'+str(args.pipeline_version)+('_model' if args.model else '')+'_smoke_20261110.json')
        out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(record,ensure_ascii=False))
    finally:service.pool.shutdown(wait=True);service.close();engine.dispose()


if __name__=='__main__':main()
