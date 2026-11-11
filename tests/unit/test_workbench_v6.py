import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
from pathlib import Path
import pytest
from vulnmind.schemas import Authorization
from vulnmind.workbench.budget import BudgetLedger,BudgetExceeded,affordable
from vulnmind.workbench.ast_discovery import extend_ast_snapshot,ROOT
from vulnmind.workbench.routes import snapshot
from vulnmind.workbench.investigation import correlate
from vulnmind.workbench.batches import deduplicated_findings,batch_limit
from vulnmind.workbench.context_calls import batch_index,assemble,observation_index
from vulnmind.workbench.engine import BatchPlan,BatchCritique
from vulnmind.context.builder import ContextItem
from vulnmind.agents.runtime import AgentSpec


def test_budget_exhaustion_is_reported_not_raised(tmp_path):
    # The engine asks before spending, so the cap produces a reported gap instead of a failed job.
    ledger=BudgetLedger(tmp_path/'budget.sqlite',10)
    assert ledger.try_reserve('a',6) is True
    assert affordable(ledger,5) is False
    assert affordable(ledger,4) is True
    assert ledger.try_reserve('b',4) is True
    assert ledger.snapshot()['stop_reason']=='budget_exhausted'
    assert ledger.snapshot()['available']==0
    assert ledger.try_reserve('c',1) is False
    ledger.settle('a',3)
    assert ledger.snapshot()['available']==3
    assert ledger.snapshot()['stop_reason'] is None
    with pytest.raises(ValueError): ledger.try_reserve('d',-1)


def test_concurrent_budget_and_unknown_reservation(tmp_path):
    ledger=BudgetLedger(tmp_path/'budget.sqlite',12)
    def reserve(i):
        try: ledger.reserve(str(i),3);return True
        except BudgetExceeded: return False
    with ThreadPoolExecutor(max_workers=8) as pool: accepted=list(pool.map(reserve,range(8)))
    assert sum(accepted)==4
    assert ledger.snapshot()['charged']==12
    first=ledger.snapshot()['reservations'][0]['id']
    ledger.reserve(first,3)
    ledger.settle(first,1)
    ledger.reserve('recovery-new-attempt',2)
    with pytest.raises(BudgetExceeded): ledger.reserve('over-cap',1)
    with pytest.raises(ValueError): ledger.settle(first,2)
    with pytest.raises(ValueError): BudgetLedger(ledger.path,13)
    with pytest.raises(ValueError,match='missing'): BudgetLedger(tmp_path/'lost',12,must_exist=True)


def test_ast_import_mount_destructuring_and_nonrouter_middleware(tmp_path):
    if not (ROOT/'.devtools/ast-parser/node_modules/typescript/lib/typescript.js').is_file(): pytest.skip('pinned compiler not installed')
    (tmp_path/'server.ts').write_text('''import router from './router';
function logs(req,res,next){next()}
app.use('/logs', logs);
app.use('/api', router);
app.get('/health', (req,res)=>res.json({ok:true}));
app.get('/mutate', (req,res)=>db.update(req.query.value));
''')
    (tmp_path/'router.ts').write_text('''import { handler } from './handler';
const router=Router();
router.get('/find', handler());
export default router;
''')
    (tmp_path/'handler.ts').write_text('''export function handler(){return ({query},res)=>db.query(`select * from t where x='${query.q}'`)}''')
    now=datetime.now(timezone.utc)
    scope=Authorization(authorization_source='fixture',approved_by='test',starts_at=now-timedelta(minutes=1),expires_at=now+timedelta(hours=1),repository_roots=[str(tmp_path)],web_origins=['http://127.0.0.1:3000'],allowed_ip_networks=['127.0.0.1/32'])
    saved=extend_ast_snapshot(snapshot(str(tmp_path),scope,extended=True),scope)
    routes={r['path']:r for r in saved['routes']}
    assert '/health' in routes and '/logs/health' not in routes
    assert routes['/api/find']['parameters']==['q']
    assert routes['/api/find']['handler_file']=='handler.ts'
    assert routes['/api/find']['signals']==['dynamic_sql']
    config=dict(origin='http://127.0.0.1:3000',binding_confirmed=True,deployment_version='test',pipeline_version=6)
    mapped=correlate(saved,[],config,scope)
    assert not next(r for r in mapped['routes'] if r['path']=='/mutate')['executable']


def test_large_batch_and_critic_index_fit():
    spec=AgentSpec(name='fixture',role='planner',system_prompt='test')
    actions=[dict(id=hashlib.sha256(str(i).encode()).hexdigest()[:20],kind='sql_error',method='GET',url='http://local/'+('path/'*100)+str(i),parameter='q',cost=3) for i in range(240)]
    index=batch_index(actions)
    items=[ContextItem(ref='system',kind='system',text='test'),ContextItem(ref='task',kind='task',text='test'),ContextItem(ref='candidates',kind='execution',text=index,required=True,budget_group='candidates')]
    selected,manifest=assemble(items,'planner',spec,'test',BatchPlan)
    assert len(json.loads(next(i.text for i in selected if i.ref=='candidates'))['actions'])==240
    assert manifest['rendered_chars']<=37000
    observations=[dict(action_id=a['id'],response_hashes=['a'*64]*18,statuses=[200]*18,detail='bounded detail') for a in actions[:24]]
    items[-1]=ContextItem(ref='observations',kind='evidence',text=observation_index(observations),required=True,budget_group='evidence')
    assert assemble(items,'critic',spec,'test',BatchCritique)[1]['rendered_chars']<=37000


def test_sql_methods_deduplicate_without_promoting_candidates():
    observations=[dict(method='GET',url='http://local/search',parameter='q',kind=k,verdict='candidate') for k in ['sql_boolean','sql_error']]
    results=deduplicated_findings(observations)
    assert len(results)==1 and not results[0]['counts_as_confirmed_vulnerability']
    assert [batch_limit(i,u,300) for i,u in enumerate([9,60,210])]==[51,150,90]
