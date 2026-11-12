from pathlib import Path
from uuid import UUID, uuid4
import json
import pytest
from sqlalchemy.orm import Session
from test_durable_flow import flow
from test_workbench import workbench,settled
from vulnmind.knowledge.ingestion import ingest_document
from vulnmind.persistence.models import WorkbenchJob, Approval, Finding
from vulnmind.workbench.engine import UnifiedInvestigation
from vulnmind.workbench.external import ExternalWorkbench
from vulnmind.integrations.hexstrike.catalog import directory
from vulnmind.graph.durable_repository import RepositoryFlow
from vulnmind.graph.web_loop import WebLoop
from vulnmind.schemas import Authorization, Target
from vulnmind.security.approvals import ApprovalService
from vulnmind.security.approval_tokens import ApprovalTokenSigner


def _fake_external(tmp_path):
    import hashlib
    ext_root = tmp_path / 'bench' / 'external'
    ext_root.mkdir(parents=True, exist_ok=True)
    tools = directory()['tools']
    tools_val = {
        t['tool_id']: dict(
            status='passed',
            schema_sha256=t['schema_sha256'],
            profile_sha256=t['profile_sha256'],
            skill_sha256=t['skill_sha256'],
            checked_at='2026-11-10T00:00:00Z',
            execution_id=str(uuid4()),
            result_sha256='a' * 64,
        )
        for t in tools if t['adapter_implemented']
    }
    calls = []

    class FakeExternal(ExternalWorkbench):
        def refresh(self):
            self.environment = 'e' * 64
            self.programs = {t['name']: dict(present=True) for t in tools if t['adapter_implemented']}
            self.probe_error = None
            return self.catalog()

        def execute(self, identifier, expected_digest):
            plan = self.read_plan(identifier)
            if plan.digest() != expected_digest:
                raise ValueError('plan digest mismatch')
            name = plan.tool_id.removeprefix('hexstrike.')
            calls.append((name, plan.arguments))
            if name == 'checkov_iac_scan':
                res = dict(
                    status='succeeded',
                    tool_name=name,
                    requests_used=0,
                    results=dict(
                        passed_checks=[],
                        failed_checks=[dict(
                            check_id='CKV_DOCKER_7',
                            check_name='Ensure base image is not latest',
                            file_path='/Dockerfile',
                            file_line_range=[1, 1],
                        )],
                    ),
                )
            elif name == 'sqlmap_scan':
                res = dict(
                    status='succeeded',
                    tool_name=name,
                    requests_used=2,
                    stdout=("Parameter: name (GET)\n"
                            "    Type: boolean-based blind\n"
                            "    Payload: name=1' OR '1'='1\n"),
                    stderr='',
                    truncated=False,
                    upstream_status={'200': 2},
                    exceptions={},
                    blocked_requests=0,
                    budget_exhausted=False,
                )
            elif name == 'dalfox_xss_scan':
                res = dict(
                    status='succeeded',
                    tool_name=name,
                    requests_used=2,
                    stdout='{"type":"R","poc":"http://127.0.0.1:12345/render?name=%3Cvulnmind%3E","message_str":"Reflected"}',
                    stderr='',
                    truncated=False,
                    upstream_status={'200': 2},
                    exceptions={},
                )
            elif name == 'nuclei_scan':
                res = dict(
                    status='succeeded',
                    tool_name=name,
                    requests_used=1,
                    stdout='[missing-security-headers] [http] [info] http://127.0.0.1:12345/render',
                    stderr='',
                    truncated=False,
                    upstream_status={'200': 1},
                    exceptions={},
                )
            elif name == 'httpx_probe':
                res = dict(status='succeeded', tool_name=name, requests_used=1, stdout='{"url":"http://127.0.0.1:12345/","status_code":200}\n', stderr='', truncated=False)
            elif name == 'katana_crawl':
                res = dict(status='succeeded', tool_name=name, requests_used=2, stdout='{"request":{"endpoint":"http://127.0.0.1:12345/render?name=1"}}\n', stderr='', truncated=False)
            elif name == 'uro_url_filtering':
                res = dict(status='succeeded', tool_name=name, requests_used=0, filtered_urls=['http://127.0.0.1:12345/', 'http://127.0.0.1:12345/render?name=1'], stdout='http://127.0.0.1:12345/\n', stderr='', truncated=False)
            elif name == 'anew_data_processing':
                res = dict(status='succeeded', tool_name=name, requests_used=0, added_lines=['http://127.0.0.1:12345/', 'http://127.0.0.1:12345/render?name=1'], stdout='http://127.0.0.1:12345/\n', stderr='', truncated=False)
            else:
                res = dict(status='succeeded', tool_name=name, requests_used=0, filename=plan.arguments.get('filename', 'file'), stdout='ok', stderr='', truncated=False)
            result_sha = hashlib.sha256(json.dumps(res, sort_keys=True).encode()).hexdigest()
            return dict(
                transport=res,
                execution=dict(
                    id=str(plan.execution_id),
                    job_id=str(plan.job_id),
                    tool_id=plan.tool_id,
                    status='succeeded',
                    result=res,
                    result_sha256=result_sha,
                ),
            )

    ext = FakeExternal(ext_root)
    ext.refresh()
    (ext_root / 'validation.json').write_text(json.dumps(dict(
        version=1,
        environment_sha256=ext.environment,
        tools=tools_val,
    )), encoding='utf-8')
    return ext, calls


def test_v3_routes_and_knowledge_are_frozen_and_old_replay_is_unchanged(workbench,monkeypatch):
    service,data,calls=workbench
    if service.engine.dialect.name!='postgresql': pytest.skip('real PostgreSQL retrieval')
    data.update(pipeline_version=3,knowledge_mode='keyword',detectors=['sql_error'],rounds=1,request_budget=3)
    with Session(service.engine) as session,session.begin():
        ingest_document(session,title='External sqlmap reference',content='sqlmap SQL injection: fixed parameter and budget, no data extraction.',source_type='test')
    identifier=service.create(data)['id'];service.start(identifier);pending=settled(service,identifier)
    assert pending['status']=='waiting_approval',pending['result']
    routing=pending['result']['plan']['tool_routing']
    assert all(c['selected']=='builtin.sql_error' for c in routing['choices'].values())
    assert any(c['tool_id']=='hexstrike.sqlmap_scan' and c['blockers'] for r in routing['choices'].values() for c in r['considered'])
    saved=pending['result']['knowledge'][0]
    assert any(s['skill_id']=='hexstrike-sql_injection-1' for s in saved['skills'])
    assert any(r['query']=='sqlmap' and r['chunk_ids'] for r in saved['retrievals'])
    service.decide(identifier,pending['result']['approval_id'],True);done=settled(service,identifier)
    assert done['status']=='finished',done['result']
    assert done['result']['schema_version']=='workbench-3'
    assert done['result']['tool_routing']==routing
    assert service.verify(identifier)['status']=='verified'
    def forbidden(*args,**kw): pytest.fail('completed tool selection, knowledge or HTTP operation repeated')
    monkeypatch.setattr('vulnmind.integrations.hexstrike.router.workbench_snapshot',forbidden)
    monkeypatch.setattr('vulnmind.integrations.hexstrike.knowledge.extend_context',forbidden)
    with Session(service.engine) as session:
        row=session.get(WorkbenchJob,UUID(identifier))
        assert UnifiedInvestigation(service.engine,row,service.settings,service.vault,http=forbidden,knowledge_provider=forbidden).run()['status']=='finished'


def test_new_jobs_default_v7_and_explicit_legacy_is_preserved(workbench):
    service,data,_=workbench
    legacy=service.create(data)
    assert legacy['config']['pipeline_version']==1
    del data['pipeline_version']
    created=service.create(data)
    assert created['config']['pipeline_version']==7
    assert created['config']['tool_policy']=='external_preferred'


def test_v3_external_execution_and_recon_in_unified_investigation(workbench, tmp_path):
    service, data, http_calls = workbench
    if service.engine.dialect.name != 'postgresql':
        pytest.skip('real PostgreSQL retrieval')
    ext, mcp_calls = _fake_external(tmp_path)
    repo_root = Path(data['repository'])
    (repo_root / 'Dockerfile').write_text('FROM alpine:latest\nRUN echo hello\n', encoding='utf-8')
    service.runner = lambda *a: UnifiedInvestigation(*a, http=lambda **kw: pytest.fail('builtin HTTP should not be called when external MCP tool is selected'), external=ext)
    data.update(
        pipeline_version=3,
        knowledge_mode='keyword',
        external_execution=True,
        external_recon=True,
        detectors=['sql_error', 'xss_context'],
        rounds=1,
        request_budget=24,
    )
    identifier = service.create(data)['id']
    service.start(identifier)
    pending = settled(service, identifier)
    assert pending['status'] == 'waiting_approval', pending['result']
    assert pending['result']['external_recon']['discovered_urls']
    routing = pending['result']['plan']['tool_routing']
    selected_tools = {c['selected'] for c in routing['choices'].values()}
    assert 'hexstrike.sqlmap_scan' in selected_tools
    assert 'hexstrike.dalfox_xss_scan' in selected_tools
    assert pending['result']['plan'].get('external_plans')
    service.decide(identifier, pending['result']['approval_id'], True)
    done = settled(service, identifier)
    assert done['status'] == 'finished', done['result']
    obs = done['result']['observations']
    assert len(obs) == 2
    assert {o['external_tool'] for o in obs} == {'hexstrike.sqlmap_scan', 'hexstrike.dalfox_xss_scan'}
    assert all(o['verdict'] == 'candidate' for o in obs)
    assert all(o['mcp_execution_id'] and o['mcp_result_sha256'] for o in obs)
    assert any(name == 'checkov_iac_scan' for name, _ in mcp_calls)
    assert any(name == 'httpx_probe' for name, _ in mcp_calls)
    assert any(name == 'katana_crawl' for name, _ in mcp_calls)
    assert any(name == 'sqlmap_scan' for name, _ in mcp_calls)
    assert any(name == 'dalfox_xss_scan' for name, _ in mcp_calls)
    assert not http_calls
    proof = service.verify(identifier)
    assert proof['status'] == 'verified'
    call_count_before_replay = len(mcp_calls)
    with Session(service.engine) as session:
        row = session.get(WorkbenchJob, UUID(identifier))
        replayed = UnifiedInvestigation(
            service.engine, row, service.settings, service.vault,
            http=lambda **kw: pytest.fail('replay must not call HTTP'),
            external=ext,
        ).run()
        assert replayed['status'] == 'finished'
    assert len(mcp_calls) == call_count_before_replay


def test_v4_no_actions_is_explicit_and_verifiable(workbench):
    service,data,_=workbench
    data.update(pipeline_version=4,allow_post=False,detectors=['sql_error'])
    identifier=service.create(data)['id'];service.start(identifier)
    done=settled(service,identifier)
    assert done['status']=='finished',done['result']
    assert done['result']['assessment']=='not_tested'
    assert done['result']['requests_used']==0
    assert service.verify(identifier)['status']=='verified'


def test_v4_recon_creates_actions_and_reserves_provider_budget(workbench,tmp_path):
    service,data,_=workbench
    if service.engine.dialect.name!='postgresql': pytest.skip('real PostgreSQL retrieval')
    ext,calls=_fake_external(tmp_path)
    service.runner=lambda *a:UnifiedInvestigation(*a,external=ext)
    # Existing source only contains a POST route. Crawl adds GET with query parameter.
    data.update(pipeline_version=4,allow_post=False,knowledge_mode='keyword',external_execution=True,
                external_recon=True,detectors=['sql_error','sql_boolean'],rounds=1,request_budget=400)
    identifier=service.create(data)['id'];service.start(identifier)
    pending=settled(service,identifier)
    assert pending['status']=='waiting_approval',pending['result']
    plan=pending['result']['plan']
    assert len(plan['actions'])==1  # two SQLMap jobs would need 600, not the builtin 3+18
    assert plan['actions'][0]['method']=='GET'
    assert sum(p['budget']['requests'] for p in plan['external_plans'].values())==300
    service.decide(identifier,pending['result']['approval_id'],True)
    done=settled(service,identifier)
    assert done['status']=='finished',done['result']
    assert done['result']['requests_used']<=400
    assert service.verify(identifier)['status']=='verified'
    before=len(calls)
    with Session(service.engine) as session:
        row=session.get(WorkbenchJob,UUID(identifier))
        assert UnifiedInvestigation(service.engine,row,service.settings,service.vault,external=ext).run()['status']=='finished'
    assert len(calls)==before


def test_v4_external_negative_gets_approved_builtin_review(workbench,tmp_path):
    from types import SimpleNamespace
    import hashlib
    service,data,_=workbench
    if service.engine.dialect.name!='postgresql': pytest.skip('real PostgreSQL retrieval')
    (Path(data['repository'])/'app.py').write_text("@app.get('/search')\ndef search(name):\n    execute(f'SELECT {name}')\n")
    ext,calls=_fake_external(tmp_path)
    execute=ext.execute
    def negative(identifier,expected_digest):
        out=execute(identifier,expected_digest)
        if out['execution']['tool_id']=='hexstrike.sqlmap_scan':
            out['execution']['result']['stdout']='all tested parameters do not appear to be injectable'
            out['execution']['result_sha256']=hashlib.sha256(json.dumps(out['execution']['result'],sort_keys=True).encode()).hexdigest()
        return out
    ext.execute=negative
    builtin=[]
    def http(**kw):
        builtin.append(kw)
        return SimpleNamespace(status_code=200,body=b'{}',truncated=False)
    service.runner=lambda *a:UnifiedInvestigation(*a,external=ext,http=http)
    data.update(pipeline_version=4,knowledge_mode='keyword',external_execution=True,
                detectors=['sql_boolean'],rounds=2,request_budget=330)
    identifier=service.create(data)['id'];service.start(identifier)
    pending=settled(service,identifier)
    assert pending['status']=='waiting_approval',pending['result']
    assert pending['result']['plan']['external_plans']
    service.decide(identifier,pending['result']['approval_id'],True)
    pending=settled(service,identifier)
    assert pending['status']=='waiting_approval',pending['result']
    assert len(pending['result']['plan']['requests'])==18
    assert pending['result']['plan']['actions'][0]['followup_of']
    service.decide(identifier,pending['result']['approval_id'],True)
    done=settled(service,identifier)
    assert done['status']=='finished',done['result']
    assert len(builtin)==18 and done['result']['requests_used']==20
    assert service.verify(identifier)['status']=='verified'


def test_repository_flow_langgraph_executes_checkov_mcp(flow, tmp_path):
    ext, mcp_calls = _fake_external(tmp_path)
    repo_root = Path(flow.target.locator)
    (repo_root / 'Dockerfile').write_text('FROM alpine:latest\n', encoding='utf-8')
    opts = {**flow.options, 'tools': ['checkov_mcp'], 'external_root': str(ext.root)}
    repo_flow = RepositoryFlow(
        flow.engine, uuid4(), flow.project_id, flow.target, flow.scope, opts, external=ext,
    )
    res = repo_flow.run()
    assert res['status'] == 'finished'
    assert any(name == 'checkov_iac_scan' for name, _ in mcp_calls)
    with Session(flow.engine) as session:
        findings = list(session.query(Finding).filter(Finding.scan_id == repo_flow.scan_id))
        assert any(f.vuln_type == 'iac_misconfiguration' and 'CKV_DOCKER_7' in f.title for f in findings)


def test_web_loop_executes_external_mcp_probes(flow, tmp_path):
    ext, mcp_calls = _fake_external(tmp_path)
    scope_data = flow.scope.model_dump(mode='json')
    scope_data['web_origins'] = ['http://127.0.0.1:12345']
    scope_data['allowed_ip_networks'] = ['127.0.0.1/32']
    scope = Authorization.model_validate(scope_data)
    scope_file = tmp_path / 'scope.json'
    scope_file.write_text(json.dumps(scope_data), encoding='utf-8')
    scan_id = uuid4()

    def fake_http(args, emit=False, planned_probes=None):
        if args.command == 'crawl':
            from vulnmind.persistence.models import Scan, WebEndpoint
            from datetime import datetime, timezone
            with Session(flow.engine) as session, session.begin():
                session.add(Scan(id=scan_id, project_id=flow.project_id, mode='web', status='completed', started_at=datetime.now(timezone.utc)))
                session.add(WebEndpoint(id=uuid4(), scan_id=scan_id, project_id=flow.project_id, url='http://127.0.0.1:12345/render?name=1', source_url='http://127.0.0.1:12345/', method='GET'))
            return dict(status='ok', scan_id=str(scan_id), findings=[], finding_count=0)
        raise AssertionError('validate-run should be handled by ExternalWorkbench when external_tools=True')

    options = dict(
        actor='tester',
        start='http://127.0.0.1:12345/render?name=1',
        rounds=1,
        max_pages=5,
        max_bytes=200000,
        agent_plan=False,
        external_tools=True,
        scope_file=str(scope_file),
        report_root=flow.options['report_root'],
        evidence_root=flow.options['evidence_root'],
    )
    wf_id = uuid4()
    loop = WebLoop(flow.engine, wf_id, flow.project_id, scope, options, http=fake_http, external=ext)
    waiting = loop.run()
    assert waiting['status'] == 'waiting_approval'
    signer = ApprovalTokenSigner('a' * 64)
    with Session(flow.engine) as session, session.begin():
        row = session.get(Approval, UUID(waiting['approval_id']))
        token = signer.sign(
            approval_id=row.id, scan_id=row.scan_id, action=row.action,
            target=row.target, expires_at=row.expires_at,
            operation_hash=row.operation_hash, approved=True,
        )
        ApprovalService(session, signer=signer).decide(row.id, approver='tester', approved=True, credential=token)
    done = loop.run()
    assert done['status'] == 'finished'
    assert any(name in {'sqlmap_scan', 'dalfox_xss_scan', 'nuclei_scan'} for name, _ in mcp_calls)

