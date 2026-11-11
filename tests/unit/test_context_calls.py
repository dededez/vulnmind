import json
from types import SimpleNamespace
import pytest
from vulnmind.agents.model import ModelUsage
from vulnmind.agents.runtime import AgentSpec, build_prompt
from vulnmind.workbench.engine import UnifiedInvestigation, PlanDecision
from vulnmind.workbench.context_calls import action_index, assemble, validate_manifest
from vulnmind.context.builder import ContextItem


def test_v4_receives_actual_knowledge():
    sent=[]
    def runtime(_):
        def run(spec,**kw):
            sent.extend(i.ref for i in kw['context'])
            return SimpleNamespace(usage=ModelUsage(),data=kw['schema'].model_validate(dict(action_ids=['a'],rationale='ok',knowledge_refs=['skill:s'])))
        return SimpleNamespace(run=run)
    runner=SimpleNamespace(config={'agents':True},version=4,actor='test',
        knowledge={'skills':[{'skill_id':'s','content':'specific guidance'}],'chunks':[{'ref':'rag:r','content':'evidence guidance'}]},runtime=runtime)
    UnifiedInvestigation.plan(runner,None,[{'id':'a'}],[],[])
    assert {'candidates','previous','skill:s','rag:r'}.issubset(sent)


def test_full_index_survives_and_rendered_optional_context_is_trimmed():
    spec=AgentSpec(name='test',role='test',system_prompt='test')
    actions=[dict(id=str(i),url='http://local/'+('path/'*180),source={'file':'long/'*300}) for i in range(60)]
    items=[ContextItem(ref='system',kind='system',text='test',required=True),
           ContextItem(ref='task',kind='task',text='test',required=True),
           ContextItem(ref='candidates',kind='execution',text=action_index(actions),budget_group='candidates',required=True),
           ContextItem(ref='optional',kind='evidence',text='"'*20000)]
    selected,manifest=assemble(items,'planner',spec,'test',PlanDecision)
    index=next(i for i in selected if i.ref=='candidates')
    assert {a['id'] for a in json.loads(index.text)}=={str(i) for i in range(60)}
    assert manifest['rendered_chars']<=37000
    assert sum(len(m.content) for m in build_prompt(spec,'test',[i for i in selected if i.kind not in {'task','system'}],PlanDecision))<=37000


def test_manifest_rejects_deleted_required_index_and_unsent_citation():
    value=dict(knowledge_refs=[],context_manifest={'policy_version':'rendered-context-1','items':[]})
    with pytest.raises(ValueError,match='required context'): validate_manifest(value,{'skills':[],'chunks':[]},'plan_0')
    value['knowledge_refs']=['skill:fake']
    with pytest.raises(ValueError,match='unsent'): validate_manifest(value,{'skills':[],'chunks':[]},'plan_0')
