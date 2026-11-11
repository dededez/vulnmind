import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from vulnmind.integrations.mcp.client import list_all_tools,validate_arguments,fingerprint,normalize_result,call_once
from vulnmind.integrations.hexstrike.catalog import directory,get_tool,ROOT
from vulnmind.integrations.hexstrike.execution import ExecutionPlan,ResourceScope,ExecutionLedger,sign_plan,verify_approval
from vulnmind.integrations.hexstrike.router import select_tool


def plan(**changes):
    values=dict(execution_id=uuid4(),job_id=uuid4(),tool_id='hexstrike.strings_extract',arguments={'file_path':'sample.bin'},
                scope=ResourceScope(kind='sample',sample_sha256='1'*64),schema_sha256='2'*64,profile_sha256='3'*64,
                skill_sha256='4'*64,environment_sha256='5'*64,expires_at=datetime.now(timezone.utc)+timedelta(hours=1))
    values.update(changes)
    return ExecutionPlan(**values)


def test_full_runtime_catalog_and_skill_coverage():
    saved=directory()
    assert saved['totals']==dict(catalog=150,schemas=150,adapters=23,skills=150,validated=0,eligible=0)
    assert len({t['tool_id'] for t in saved['tools']})==150
    duplicate=get_tool('hexstrike.httpx_probe')
    assert duplicate['duplicate_declaration']
    assert len(duplicate['source_declarations'])==2
    assert 'probe' in duplicate['inputSchema']['properties']


def test_validation_receipts_bind_all_revisions():
    row=next(t for t in directory()['tools'] if t['name']=='strings_extract')
    receipt=dict(status='passed',**{k:row[k] for k in ('schema_sha256','profile_sha256','skill_sha256')})
    assert directory({row['tool_id']:receipt})['totals']['validated']==1
    receipt['skill_sha256']='f'*64
    assert directory({row['tool_id']:receipt})['totals']['validated']==0


def test_exact_schema_and_no_network_schema_resolution():
    schema=get_tool('hexstrike.strings_extract')['inputSchema']
    validate_arguments(schema,{'file_path':'sample.bin'})
    with pytest.raises(ValueError): validate_arguments(schema,{'file_path':'sample.bin','command':'sh'})
    with pytest.raises(ValueError): validate_arguments({'$ref':'https://example.invalid/schema'}, {})
    with pytest.raises(Exception): validate_arguments(schema,{'file_path':'sample.bin','min_len':'4'})


def test_ledger_concurrent_duplicate_and_replay(tmp_path):
    ledger=ExecutionLedger(tmp_path/'ledger.db');p=plan()
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(lambda _:ledger.accept(p),range(16)))==1
    ledger.start(p.execution_id)
    with pytest.raises(ValueError): ledger.start(p.execution_id)
    ledger.finish(p.execution_id,'succeeded',{'stdout':'fixture'})
    saved=ledger.get(p.execution_id,job_id=p.job_id)
    assert not ledger.accept(p)
    assert ExecutionLedger(tmp_path/'ledger.db').get(p.execution_id,job_id=p.job_id)==saved
    with pytest.raises(ValueError): ledger.finish(p.execution_id,'tool_failed',{})
    assert ledger.get(p.execution_id,job_id=uuid4())=={'status':'not_found'}
    with pytest.raises(ValueError): ledger.accept(p.model_copy(update={'arguments':{'file_path':'different'}}))


def test_unknown_registration_gap_never_reexecutes(tmp_path):
    ledger=ExecutionLedger(tmp_path/'ledger.db');p=plan();ledger.accept(p)
    with ledger.connect() as conn: conn.execute('UPDATE executions SET updated=0')
    assert ledger.get(p.execution_id,job_id=p.job_id)['status']=='unknown'
    assert not ledger.accept(p)


def test_ledger_tamper_detection(tmp_path):
    ledger=ExecutionLedger(tmp_path/'ledger.db');p=plan();ledger.accept(p);ledger.start(p.execution_id)
    ledger.finish(p.execution_id,'succeeded',{'value':1})
    with ledger.connect() as conn: conn.execute("UPDATE executions SET result='{}'")
    with pytest.raises(ValueError): ledger.get(p.execution_id,job_id=p.job_id)


def test_approval_covers_scope_parameters_environment_and_expiry():
    p=plan();key=b'k'*32;signature=sign_plan(p,key);verify_approval(p,signature,key)
    for field,value in [('arguments',{}),('environment_sha256','a'*64),('job_id',uuid4())]:
        with pytest.raises(ValueError): verify_approval(p.model_copy(update={field:value}),signature,key)
    old=plan(expires_at=datetime.now(timezone.utc)-timedelta(seconds=1))
    with pytest.raises(ValueError): verify_approval(old,sign_plan(old,key),key)


def test_external_preference_is_after_eligibility_and_pinning():
    builtin=dict(tool_id='builtin.sql_error',provider='builtin',capabilities=['sql_error'],eligible=True,blockers=[])
    external=dict(tool_id='hexstrike.sqlmap_scan',provider='hexstrike',capabilities=['sql_error'],eligible=True,blockers=[])
    assert select_tool('sql_error',[builtin,external])['selected']==external['tool_id']
    assert select_tool('sql_error',[builtin,external],pinned=builtin['tool_id'])['selected']==builtin['tool_id']
    external['blockers']=['budget_too_small']
    result=select_tool('sql_error',[builtin,external])
    assert result['selected']==builtin['tool_id'] and result['reason']=='explicit_builtin_fallback'
    assert select_tool('sql_error',[builtin,external],pinned=external['tool_id'])['selected'] is None
    assert select_tool('sql_error',[builtin,external],unknown_execution=True)['reason']=='reconciliation_required'


def test_mcp_pagination_and_repeated_cursor():
    class Tool:
        def __init__(self,name): self.name=name
        def model_dump(self,**kw): return dict(name=self.name,inputSchema={'type':'object','properties':{}})
    class Session:
        async def list_tools(self,cursor=None):
            return SimpleNamespace(tools=[Tool('one' if cursor is None else 'two')],nextCursor='next' if cursor is None else None)
    assert len(asyncio.run(list_all_tools(Session())))==2
    class Loop:
        async def list_tools(self,cursor=None): return SimpleNamespace(tools=[],nextCursor='same')
    with pytest.raises(ValueError): asyncio.run(list_all_tools(Loop()))


def test_mcp_errors_not_confused_with_negative_findings():
    pytest.importorskip('mcp')
    from mcp.types import CallToolResult,TextContent
    assert normalize_result(CallToolResult(content=[TextContent(type='text',text='bad')],isError=True))['status']=='protocol_error'
    assert normalize_result(CallToolResult(content=[TextContent(type='text',text='unparseable')]))['status']=='parse_failed'
    assert normalize_result(CallToolResult(content=[],structuredContent={'success':False}))['status']=='tool_failed'
    assert normalize_result(CallToolResult(content=[],structuredContent={'success':True,'findings':[]}))['status']=='succeeded'
    class Broken:
        count=0
        async def call_tool(self,*args,**kw): self.count+=1;raise TimeoutError()
    session=Broken()
    result=asyncio.run(call_once(session,'tool',{},schema={'type':'object','properties':{}}))
    assert result['status']=='unknown' and session.count==1


def test_controlled_backend_denies_escape_extra_args_and_unknown_endpoints(tmp_path):
    from vulnmind.integrations.hexstrike.backend import ControlledClient
    client=ControlledClient(tmp_path,plan(),runner=lambda *a,**kw:pytest.fail('must not execute'))
    for data in ({'file_path':'../../secret'},{'file_path':'sample.bin','additional_args':'; curl x'},
                 {'file_path':'sample.bin','min_len':100}):
        with pytest.raises(ValueError): client.safe_post('api/tools/strings',data)
    with pytest.raises(ValueError): client.safe_post('api/command',{})


def test_reviewed_guides_have_unique_content_and_attribution():
    cards=json.loads((ROOT/'corpus.json').read_text(encoding='utf-8'))
    assert len(cards)==len({c['content_sha256'] for c in cards})==18
    assert all(c['source_url'].endswith(directory()['upstream_commit']) for c in cards)
