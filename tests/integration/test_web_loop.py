from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
import pytest

from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session

from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Project, Approval, Evidence, Report, Finding
from vulnmind.graph.web_loop import WebLoop
from vulnmind.schemas import Authorization
from test_durable_flow import flow


@pytest.mark.parametrize('signal', [False, True])
def test_approval_wait_resume_evidence_report_and_no_repeat(tmp_path, signal, flow):
    engine, project = flow.engine, flow.project_id
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source='owned fixture', approved_by='test', starts_at=now-timedelta(minutes=1),
        expires_at=now+timedelta(hours=1), web_origins=['https://example.test'])
    calls = []
    def http(args, **kw):
        calls.append(args.command)
        if args.command == 'crawl':
            from vulnmind.analysis.crawl_store import store_crawl_result
            with Session(engine) as s, s.begin():
                row = store_crawl_result(session=s, project_id=project, actor='test', endpoints=[])
                return dict(status='ok', scan_id=str(row.id), findings=[dict(title='Missing header',vulnerability_type='missing_header',
                    target_id='web',location='https://example.test/',source_tool='builtin.passive_checks')])
        return dict(status='completed', candidates=int(signal), results=[dict(kind=p.kind,url=p.url,verdict='candidate' if signal else 'inconclusive',detail='fixture observation') for p in kw['planned_probes']])
    options = dict(actor='test', start='https://example.test/?q=a&name=b', rounds=3, max_pages=2,max_bytes=1000,
        scope_file='unused',report_root=str(tmp_path/'reports'), evidence_root=str(tmp_path/'evidence'))
    flow = WebLoop(engine, uuid4(), project, scope, options, http=http)
    first = flow.run()
    assert first['status'] == 'waiting_approval'
    assert flow.run() == first
    assert calls == ['crawl']
    with Session(engine) as s,s.begin():
        s.get(Approval, UUID(first['approval_id'])).status='approved'
    done = flow.run()
    if signal:
        assert done['status']=='waiting_approval' and done['round']==1
        assert set(p['url'] for p in done['probes']).isdisjoint(p['url'] for p in first['probes'])
        with Session(engine) as s,s.begin():
            s.get(Approval,UUID(done['approval_id'])).status='approved'
        done=flow.run()
    assert done['status']=='finished'
    assert flow.run()==done
    assert calls == ['crawl',*(['validate-run']*(2 if signal else 1))]
    with Session(engine) as s:
        assert s.scalar(select(func.count()).select_from(Evidence))==(8 if signal else 5)
        assert s.scalar(select(func.count()).select_from(Finding))==(9 if signal else 6)
        assert s.scalar(select(func.count()).select_from(Report))==(3 if signal else 2)
    engine.dispose()
