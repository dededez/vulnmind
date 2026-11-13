import hashlib
import pytest
from vulnmind.workbench.detectors import evaluate
from vulnmind.workbench.batches import effective_stop_reason


def response(body, status=401, truncated=False):
    return dict(body=body, status_code=status, truncated=truncated,
                sha256=hashlib.sha256(body.encode()).hexdigest(), headers={})


@pytest.mark.parametrize('case,expected',[
    ('sql', 'candidate'), ('generic500', 'inconclusive'),
    ('component', 'inconclusive'), ('forbidden', 'inconclusive'),
    ('truncated', 'inconclusive'), ('drift', 'inconclusive'),
    ('preexisting', 'inconclusive'), ('denied_probe', 'inconclusive'),
])
def test_rejected_baseline_sql_difference(case, expected):
    a=dict(id='a',kind='sql_error',category='sql_injection',detector_version='2',
           url='http://127.0.0.1/session',method='POST',parameter='user',source={})
    rs=[response('Invalid credentials'),response('SQLITE_ERROR: syntax error',500),response('Invalid credentials')]
    if case=='generic500': rs[1]=response('Internal server error',500)
    if case=='component': rs[1]=response('Sequelize MongoDB connection error',500)
    if case=='forbidden': rs[0]=rs[2]=response('Forbidden',403)
    if case=='truncated': rs[1]['truncated']=True
    if case=='drift': rs[2]=response('Different session')
    if case=='preexisting': rs[0]=rs[2]=response('SQLITE_ERROR: syntax error')
    if case=='denied_probe': rs[1]['status_code']=403
    result=evaluate(a,rs)
    assert result['verdict']==expected
    assert result['behavior'] is None
    assert result['statuses']==[r['status_code'] for r in rs]


@pytest.mark.parametrize('reason,available,expected',[
    ('max_rounds',0,'budget_exhausted'),('critic_stop',0,'budget_exhausted'),
    ('critic_stop',6,'critic_stop'),(None,6,'max_rounds'),
    ('budget_exhausted',2,'budget_exhausted'),
])
def test_final_stop_reason(reason,available,expected):
    assert effective_stop_reason(reason,dict(available=available))==expected


@pytest.mark.parametrize('parameterized',[False,True])
def test_sqlite_login_with_rejected_baseline(parameterized):
    import sqlite3
    db=sqlite3.connect(':memory:')
    db.execute('create table users(name text)')
    responses=[]
    for value in ['control', "control'", 'control']:
        try:
            if parameterized:
                db.execute('select name from users where name=?',(value,)).fetchall()
            else:
                db.execute("select name from users where name='"+value+"'").fetchall()
            responses.append(response('Invalid credentials'))
        except sqlite3.OperationalError as exc:
            responses.append(response('sqlite3.OperationalError: '+str(exc),500))
    db.close()
    a=dict(id='sqlite',kind='sql_error',category='sql_injection',detector_version='2',
           url='http://127.0.0.1/authenticate',method='POST',parameter='name',source={})
    assert evaluate(a,responses)['verdict']==('inconclusive' if parameterized else 'candidate')


@pytest.mark.parametrize('outcome',['succeeded','unknown'])
def test_external_execution_reuses_outer_hold(tmp_path,monkeypatch,outcome):
    from types import SimpleNamespace
    from datetime import datetime,timedelta,timezone
    from uuid import uuid4
    from vulnmind.workbench import engine as module
    from vulnmind.workbench.budget import BudgetLedger
    ledger=BudgetLedger(tmp_path/'budget.sqlite',60)
    ledger.reserve('act:0:probe',60)
    class Session:
        def __init__(self,*args): pass
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def get(self,*args):
            return SimpleNamespace(status='consumed',expires_at=datetime.now(timezone.utc)+timedelta(hours=1),operation_hash='approved')
    monkeypatch.setattr(module,'Session',Session)
    monkeypatch.setattr(module,'verify_snapshot',lambda _:None)
    called=[]
    def execute(*args):
        called.append(args)
        return {'execution':dict(status=outcome,result={'requests_used':17,'upstream_status':{'200':17}},result_sha256='hash')}
    runner=object.__new__(module.UnifiedInvestigation)
    runner.version=7;runner.budget=ledger;runner.engine=None
    runner.settings=SimpleNamespace(enabled_http_commands=['validate-run'])
    runner.external_service=lambda:SimpleNamespace(execute=execute)
    binding=dict(execution_id='external',digest='plan',tool_id='hexstrike.sqlmap_scan',budget={'requests':60})
    approval=dict(approval_id=str(uuid4()),digest='approved')
    if outcome=='unknown':
        with pytest.raises(module.StepUnknown): runner.execute_external_action(binding,approval,{},'act:0:probe')
        assert ledger.snapshot()['charged']==60
    else:
        result=runner.execute_external_action(binding,approval,{},'act:0:probe')
        ledger.settle('act:0:probe',result['requests_used'])
        assert ledger.snapshot()['charged']==17
    assert len(called)==1
    assert len(ledger.snapshot()['reservations'])==1
