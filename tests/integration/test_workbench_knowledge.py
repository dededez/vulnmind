import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from test_durable_flow import flow
from test_workbench import workbench,settled
from vulnmind.workbench.engine import UnifiedInvestigation
from vulnmind.workbench.knowledge import snapshot
from vulnmind.knowledge.ingestion import ingest_document
from vulnmind.persistence.models import WorkbenchJob


def test_workbench_v2_real_keyword_snapshot_budget_and_no_retrieval_on_replay(workbench):
    service,data,calls=workbench
    if service.engine.dialect.name!='postgresql': pytest.skip('real sparse retrieval requires PostgreSQL')
    data.update(pipeline_version=2,knowledge_mode='keyword',detectors=['template_expression','sql_boolean'],request_budget=6,rounds=2)
    with Session(service.engine) as s,s.begin():
        ingest_document(s,title='Template guidance',content='template injection: use two independent controls and do not assume code execution.',source_type='test',version='test-1')
    identifier=service.create(data)['id'];service.start(identifier);pending=settled(service,identifier)
    assert pending['status']=='waiting_approval',pending['result']
    knowledge=pending['result']['knowledge'][0]
    assert knowledge['chunks'] and knowledge['skills'] and knowledge['mode']=='keyword'
    assert len(pending['result']['plan']['requests'])<=6
    while pending['status']=='waiting_approval':
        service.decide(identifier,pending['result']['approval_id'],True);pending=settled(service,identifier)
    assert pending['status']=='finished',pending['result']
    assert pending['result']['requests_used']==3  # six-request SQL action cannot fit remaining budget
    assert pending['result']['untested_action_count']==1
    assert service.verify(identifier)['status']=='verified'
    def forbidden(*a,**kw):pytest.fail('completed external operation repeated')
    with Session(service.engine) as s:
        job=s.get(WorkbenchJob,UUID(identifier))
        assert UnifiedInvestigation(service.engine,job,service.settings,service.vault,http=forbidden,knowledge_provider=forbidden).run()['status']=='finished'


def test_workbench_v2_failure_is_visible_not_silent_knowledge_downgrade(workbench):
    service,data,calls=workbench;data.update(pipeline_version=2)
    def unavailable(*a):raise ValueError('knowledge unavailable')
    service.runner=lambda *a:UnifiedInvestigation(*a,knowledge_provider=unavailable)
    identifier=service.create(data)['id'];service.start(identifier);result=settled(service,identifier)
    assert result['status']=='unknown' and not calls
    assert not any(s['stage'].startswith('plan_') for s in result['stages'])


def test_workbench_models_receive_skill_and_rag_and_validate_citations(workbench):
    service,data,_=workbench;data.update(pipeline_version=2,agents=True,knowledge_mode='keyword',detectors=['template_expression'],rounds=1,request_budget=3)
    if service.engine.dialect.name!='postgresql': pytest.skip('real sparse retrieval requires PostgreSQL')
    with Session(service.engine) as s,s.begin():
        ingest_document(s,title='Template reference',content='template injection requires independent arithmetic controls.',source_type='test')
    prompts=[]
    from vulnmind.agents.model import ModelResponse,ModelUsage
    class Model:
        def complete(self,request):
            text=request.messages[-1].content;prompts.append(text)
            assert 'kind="skill"' in text and 'kind="rag"' in text
            import re,html
            refs=re.findall(r'<reference ref="(skill:[^"]+|rag:[^"]+)"',text)
            if 'Select at most two' in text:
                candidates=html.unescape(re.search(r'<reference ref="candidates"[^>]*>\s*(.*?)\s*</reference>',text,re.S)[1])
                value=dict(action_ids=[json.loads(candidates)[0]['id']],rationale='use independent controls',knowledge_refs=refs)
            else:value=dict(continue_investigation=False,disputed_action_ids=[],summary='behavior only',knowledge_refs=refs)
            return ModelResponse(text=json.dumps(value),usage=ModelUsage())
    def http(**kw):return SimpleNamespace(status_code=200,body={'{"name": "{{731*19}}"}':b'13889','{"name": "{{823*23}}"}':b'18929'}.get(kw['body'],b'baseline'),truncated=False,headers={})
    service.runner=lambda *a:UnifiedInvestigation(*a,model=Model(),http=http)
    identifier=service.create(data)['id'];service.start(identifier);pending=settled(service,identifier)
    assert pending['status']=='waiting_approval',pending['result']
    service.decide(identifier,pending['result']['approval_id'],True);done=settled(service,identifier)
    assert done['status']=='finished',done['result']
    assert len(prompts)==2 and service.verify(identifier)['status']=='verified'
