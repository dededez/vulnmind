"""Unified journaled coordinator: source, mapping, planning, validation, critique."""
import hashlib
import json
import re
import socket
import time
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urlencode,urlsplit
from uuid import UUID,uuid5

from pydantic import BaseModel,Field,ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnmind.persistence.durable import Journal,workflow_lock,digest,StepUnknown
from vulnmind.persistence.models import Scan,Approval,Finding,Evidence,Report
from vulnmind.schemas import Authorization,Target
from vulnmind.security.scope import check_target,check_resolved_addresses
from vulnmind.security.approvals import ApprovalService
from vulnmind.workbench.routes import snapshot,verify_snapshot,imported_routes
from vulnmind.workbench.investigation import correlate,actions_for,requests_for,evaluate

EXTERNAL_WEB_ADAPTERS = frozenset({
    'hexstrike.sqlmap_scan',
    'hexstrike.dalfox_xss_scan',
    'hexstrike.nuclei_scan',
})
BROWSER_KINDS = frozenset({'browser_xss'})
AUTH_KINDS = frozenset({'auth_idor'})


class PlanDecision(BaseModel):
    model_config=ConfigDict(extra='forbid')
    action_ids:list[str]=Field(max_length=2)
    rationale:str=Field(min_length=1,max_length=1200)


class Critique(BaseModel):
    model_config=ConfigDict(extra='forbid')
    continue_investigation:bool
    disputed_action_ids:list[str]=Field(default_factory=list,max_length=6)
    summary:str=Field(min_length=1,max_length=1200)


class KnowledgePlan(PlanDecision):
    knowledge_refs:list[str]=Field(min_length=1,max_length=12)


class BatchPlan(PlanDecision):
    action_ids:list[str]=Field(max_length=24)
    knowledge_refs:list[str]=Field(default_factory=list,max_length=12)


class BatchCritique(Critique):
    disputed_action_ids:list[str]=Field(default_factory=list,max_length=24)
    knowledge_refs:list[str]=Field(default_factory=list,max_length=12)


class KnowledgeCritique(Critique):
    knowledge_refs:list[str]=Field(min_length=1,max_length=12)


def upstream_status_code(result):
    """Return the most frequent real upstream status, or 502/0 for failed runs."""
    histogram = (result or {}).get('upstream_status') or {}
    codes = sorted(int(code) for code in histogram if str(code).isdigit())
    if codes:
        return max(codes, key=lambda code: (histogram.get(str(code), 0), code)), codes
    if (result or {}).get('blocked_requests') or (result or {}).get('exceptions'):
        return 502, [502]
    return 0, []


class UnifiedInvestigation:
    def __init__(self,engine,job,settings,vault,*,http=None,model=None,knowledge_provider=None,external=None):
        self.engine,self.job,self.settings,self.vault=engine,job,settings,vault
        self.config=job.config; self.scope=Authorization.model_validate(self.config['scope'])
        self.actor=self.config['actor']; self.scan=uuid5(job.id,'unified-scan')
        self.version=self.config.get('pipeline_version',1)
        self.adapter=self.config.get('target_adapter','generic') if self.version>=7 else 'juice_shop'
        self.knowledge_provider=knowledge_provider
        self.knowledge=None
        self.journal=Journal(engine,job.id,dict(version=self.version,project=str(job.project_id),config=self.config),self.actor,'web')
        self.http,self.model=http,model
        self.external=external
        self.last_request=0
        self.stop_reason=None
        self.skipped_for_budget=0
        self.account=self.vault.load_account(self.config['account_profile'],self.config['origin']) if self.config.get('account_profile') else None
        self.session_headers={}
        self.account_bid=None
        self._captured_bodies=[]
        if self.account:
            restored=self.vault.load_session(self.job.id,self.config['origin'])
            if restored:
                self.session_headers={'Authorization':'Bearer '+restored['token']}
                self.account_bid=restored.get('bid')
        self.account_status=None

    def external_service(self):
        if self.external is not None:
            return self.external
        from vulnmind.workbench.external import ExternalWorkbench,validated_service
        if self.version>=4:
            self.external=validated_service(Path(self.settings.report_root).resolve().parent/'workbench'/'external',distro=self.settings.http_broker_distro)
            return self.external
        candidates=[
            Path(self.settings.report_root).resolve().parent/'workbench'/'external',
            Path(self.settings.report_root).resolve().parent/'bench'/'external',
            Path(__file__).resolve().parents[3]/'.vulnmind-workbench'/'external',
        ]
        ext_root=candidates[0]
        for c in candidates:
            if (c/'validation.json').is_file():
                ext_root=c
                break
        self.external=ExternalWorkbench(ext_root,distro=self.settings.http_broker_distro)
        return self.external

    def load_external_validation(self):
        if not self.config.get('external_execution'):
            return None
        service=self.external_service()
        if not service.environment:
            service.refresh()
        path=service.root/'validation.json'
        if path.is_file():
            saved=json.loads(path.read_text(encoding='utf-8'))
            if saved.get('environment_sha256')==service.environment:
                return saved.get('tools',{})
        return None

    def stage(self,name,inputs,compute,*,persist=None,safe=False):
        check_target(Target(type='web',locator=self.config['origin']+'/'),self.scope)
        return self.journal.run(name,inputs,compute,persist=persist,replay_safe=safe)

    def runtime(self,audit):
        from vulnmind.agents.runtime import AgentRuntime
        from vulnmind.agents.deepseek import DeepSeekClient
        from vulnmind.agents.audit import AgentAuditBridge
        return AgentRuntime(self.model or DeepSeekClient(),AgentAuditBridge(audit,target_type='web'))

    def plan(self,audit,remaining,previous,critique):
        from vulnmind.workbench.knowledge import context,filter_references
        extra=context(self.knowledge) if self.knowledge else []
        if not self.config.get('agents'):
            return dict(action_ids=[a['id'] for a in remaining[:24 if self.version>=6 else 2]],rationale='规则模式：按剩余候选顺序调查；保留请求预算和逐轮审批',mode='rules',
                        **(dict(knowledge_refs=[i.ref for i in extra if i.kind=='skill'],knowledge_usage='method_reference_no_model') if self.knowledge else {}))
        from vulnmind.agents.prompts import PLANNER
        from vulnmind.context.builder import ContextItem
        candidates_text=json.dumps(remaining,ensure_ascii=False)
        if self.version>=5:
            from vulnmind.workbench.context_calls import action_index
            candidates_text=action_index(remaining)
        if self.version>=6:
            from vulnmind.workbench.context_calls import batch_index
            candidates_text=batch_index(remaining)
        if self.version>=5:
            from vulnmind.workbench.digest import build_digest
            previous_text=json.dumps(build_digest(previous,remaining,critique),ensure_ascii=False)
        else:
            previous_text=json.dumps(dict(results=previous,critic=critique),ensure_ascii=False)
        base_refs=[ContextItem(ref='candidates',kind='execution',text=candidates_text[:22000]),
            ContextItem(ref='previous',kind='execution',text=previous_text[:16000])]
        task_text=('Select at most two remaining action_ids. Use prior observations and independent critic feedback to replan or return an empty list to stop. Only provided action IDs are valid. Do not assume exploitability. '+
            ('Consult supplied skill methods and RAG references for applicability and false positives; cite 1 to 6 relevant exact skill:/rag: reference IDs in knowledge_refs, not every reference. Keep rationale under 400 characters. Knowledge is not target evidence.' if self.knowledge else ''))
        plan_schema=BatchPlan if self.version>=6 else KnowledgePlan if self.knowledge else PlanDecision
        if self.version>=6:
            task_text=task_text.replace('at most two','up to 24').replace('Only provided','Cover diverse vulnerability categories within supplied per-action costs; do not stop just because one tool was negative. Only provided')
            task_text+=f' This round has {self.round_budget} requests. Select as many useful distinct checks as fit, with at most 2 header-hardening checks. Prioritize source-supported hypotheses and independent followups. Empty means no useful affordable check remains. Do not reserve a whole round for a single expensive scan if cheaper checks can cover more categories.'
        manifest=None;shadow=None
        if self.version>=5:
            from vulnmind.workbench.context_calls import assemble
            from vulnmind.context.profiles import budget_for
            from vulnmind.workbench.context_shadow import manifest_summary
            grouped=[item.model_copy(update={'budget_group':{'skill':'skills','rag':'rag'}.get(item.kind,'routing')})
                     for item in extra]
            items=[ContextItem(ref='system',kind='system',text=PLANNER.system_prompt,required=True,budget_group='system_task'),
                   ContextItem(ref='task',kind='task',text=task_text,required=True,budget_group='system_task'),
                   ContextItem(ref='candidates',kind='execution',text=candidates_text,budget_group='candidates',required=True),
                   ContextItem(ref='previous',kind='execution',text=previous_text,budget_group='previous'),
                   *grouped]
            selected,manifest=assemble(items,'planner',PLANNER,task_text,plan_schema)
            refs=[item for item in selected if item.kind not in {'system','task'}]
            shadow=manifest_summary('planner',manifest,selected)
        else:
            refs=base_refs+extra
        call=self.runtime(audit).run(PLANNER,actor=self.actor,schema=plan_schema,context=refs,
            task=task_text)
        decision=call.data
        ids=list(dict.fromkeys(decision.action_ids))
        if any(i not in {a['id'] for a in remaining} for i in ids): raise ValueError('planner selected an unknown action')
        knowledge_refs=[];dropped_refs=[]
        if self.knowledge:
            allowed=({item.ref for item in refs if item.kind in {'skill','rag'}} if self.version>=5
                     else {'skill:'+s['skill_id'] for s in self.knowledge['skills']}|{c['ref'] for c in self.knowledge['chunks']})
            knowledge_refs,dropped_refs=filter_references(decision.knowledge_refs,allowed)
        return dict(action_ids=ids,rationale=decision.rationale,mode='model',model_usage=call.usage.model_dump(),
                    **(dict(knowledge_refs=knowledge_refs) if self.knowledge else {}),
                    **(dict(knowledge_refs_dropped=dropped_refs) if dropped_refs else {}),
                    **(dict(context_shadow=shadow) if shadow else {}),
                    **(dict(context_manifest=manifest) if manifest else {}))

    def critique(self,audit,observations,remaining):
        from vulnmind.workbench.knowledge import context,filter_references
        extra=context(self.knowledge) if self.knowledge else []
        if not self.config.get('agents'):
            return dict(continue_investigation=bool(remaining),disputed_action_ids=[],summary='规则复核：保留证据等级，继续检查剩余候选；不会将候选提升为漏洞确认',mode='rules',
                        **(dict(knowledge_refs=[i.ref for i in extra if i.kind=='skill'],knowledge_usage='method_reference_no_model') if self.knowledge else {}))
        from vulnmind.agents.runtime import AgentSpec
        from vulnmind.context.builder import ContextItem
        spec=AgentSpec(name='independent-critic',role='triage',system_prompt='Independently challenge supplied observations. Distinguish behavior from exploitability. Never create evidence or expand scope.')
        if self.version>=5:
            from vulnmind.workbench.digest import build_digest
            from vulnmind.workbench.context_calls import observation_index
            observations_text=observation_index(observations)
        else:
            observations_text=json.dumps(observations,ensure_ascii=False)
        remaining_text=json.dumps([dict(id=a['id'],kind=a['kind']) for a in remaining])
        task_text=('Review results. Identify action IDs whose conclusion is unsupported. Decide whether remaining candidates merit another approved round. Use only provided IDs.'+
            (' Apply supplied skill false-positive and evidence criteria and RAG knowledge; cite 1 to 6 relevant exact skill:/rag: IDs in knowledge_refs, not every reference. Keep summary under 400 characters. Knowledge is not evidence.' if self.knowledge else ''))
        base_refs=[ContextItem(ref='observations',kind='evidence',text=observations_text),
            ContextItem(ref='remaining',kind='execution',text=remaining_text)]
        critic_schema=BatchCritique if self.version>=6 else KnowledgeCritique if self.knowledge else Critique
        manifest=None;shadow=None
        if self.version>=5:
            from vulnmind.workbench.context_calls import assemble
            from vulnmind.context.profiles import budget_for
            from vulnmind.workbench.context_shadow import manifest_summary
            grouped=[item.model_copy(update={'budget_group':{'skill':'skills','rag':'rag'}.get(item.kind,'routing')})
                     for item in extra]
            items=[ContextItem(ref='system',kind='system',text=spec.system_prompt,required=True,budget_group='system_task'),
                   ContextItem(ref='task',kind='task',text=task_text,required=True,budget_group='system_task'),
                   ContextItem(ref='observations',kind='evidence',text=observations_text,budget_group='evidence',required=True),
                   ContextItem(ref='remaining',kind='execution',text=remaining_text,budget_group='candidates'),
                   *grouped]
            selected,manifest=assemble(items,'critic',spec,task_text,critic_schema)
            refs=[item for item in selected if item.kind not in {'system','task'}]
            shadow=manifest_summary('critic',manifest,selected)
        else:
            refs=base_refs+extra
        call=self.runtime(audit).run(spec,actor=self.actor,schema=critic_schema,
            task=task_text,context=refs)
        result=call.data
        if any(i not in {a['action_id'] for a in observations} for i in result.disputed_action_ids): raise ValueError('critic referenced unknown action')
        knowledge_refs=[];dropped_refs=[]
        if self.knowledge:
            allowed=({item.ref for item in refs if item.kind in {'skill','rag'}} if self.version>=5
                     else {'skill:'+s['skill_id'] for s in self.knowledge['skills']}|{c['ref'] for c in self.knowledge['chunks']})
            knowledge_refs,dropped_refs=filter_references(result.knowledge_refs,allowed)
        return {**result.model_dump(), 'mode':'model', 'model_usage':call.usage.model_dump(),
                **(dict(knowledge_refs=knowledge_refs) if self.knowledge else {}),
                **(dict(knowledge_refs_dropped=dropped_refs) if dropped_refs else {}),
                **(dict(context_shadow=shadow) if shadow else {}),
                **(dict(context_manifest=manifest) if manifest else {})}

    def budget_attempt(self,audit,prefix):
        from vulnmind.persistence.models import DurableStep
        with Session(self.engine) as session:
            step=session.get(DurableStep,audit.parent)
            return prefix+':'+str(step.id)+':'+str(step.attempt)

    def recon_budgeted(self,mapped,audit):
        if self.version<6: return self.run_external_recon(mapped)
        key=self.budget_attempt(audit,'recon')
        self.budget.reserve(key,9)
        out=self.run_external_recon(mapped)
        self.budget.settle(key,out['requests_used'])
        return out

    def run_external_recon(self,mapped):
        """Bounded MCP reconnaissance chain: httpx + katana + uro + anew."""
        service=self.external_service()
        origin=self.config['origin']
        web_scope=dict(origins=[origin],networks=list(self.scope.allowed_ip_networks))
        probe_prep=service.prepare(dict(
            tool_id='hexstrike.httpx_probe',
            arguments=dict(target=origin+'/',status_code=True,title=True),
            scope=web_scope,
            budget=dict(requests=3,connections=3,seconds=20),
        ))
        probe_res=service.execute(probe_prep['plan']['execution_id'],probe_prep['digest'])['execution']
        crawl_prep=service.prepare(dict(
            tool_id='hexstrike.katana_crawl',
            arguments=dict(url=origin+'/',depth=1,output_format='json'),
            scope=web_scope,
            budget=dict(requests=6,connections=6,seconds=25),
        ))
        crawl_res=service.execute(crawl_prep['plan']['execution_id'],crawl_prep['digest'])['execution']
        raw_urls=[origin+'/']
        for line in (crawl_res.get('result') or {}).get('stdout','').splitlines():
            line=line.strip()
            if not line: continue
            try:
                obj=json.loads(line)
                u=obj.get('request',{}).get('endpoint') or obj.get('endpoint') or ''
                if u.startswith(origin): raw_urls.append(u)
            except Exception:
                if line.startswith(origin): raw_urls.append(line)
        uro_prep=service.prepare(dict(
            tool_id='hexstrike.uro_url_filtering',
            arguments=dict(urls='\n'.join(raw_urls)+'\n'),
        ))
        uro_res=service.execute(uro_prep['plan']['execution_id'],uro_prep['digest'])['execution']
        filtered=(uro_res.get('result') or {}).get('filtered_urls') or raw_urls
        ws_id=uro_prep['plan']['scope']['workspace']
        anew_prep=service.prepare(dict(
            tool_id='hexstrike.anew_data_processing',
            workspace_job_id=ws_id,
            arguments=dict(input_data='\n'.join(filtered)+'\n',output_file='recon_urls.txt'),
        ))
        anew_res=service.execute(anew_prep['plan']['execution_id'],anew_prep['digest'])['execution']
        unique_urls=(anew_res.get('result') or {}).get('added_lines') or filtered
        reqs_used=int((probe_res.get('result') or {}).get('requests_used',1))+int((crawl_res.get('result') or {}).get('requests_used',1))
        return dict(
            discovered_urls=unique_urls[:20],
            requests_used=reqs_used,
            executions=[
                dict(tool='hexstrike.httpx_probe',execution_id=probe_prep['plan']['execution_id'],result_sha256=probe_res.get('result_sha256')),
                dict(tool='hexstrike.katana_crawl',execution_id=crawl_prep['plan']['execution_id'],result_sha256=crawl_res.get('result_sha256')),
                dict(tool='hexstrike.uro_url_filtering',execution_id=uro_prep['plan']['execution_id'],result_sha256=uro_res.get('result_sha256')),
                dict(tool='hexstrike.anew_data_processing',execution_id=anew_prep['plan']['execution_id'],result_sha256=anew_res.get('result_sha256')),
            ],
        )

    def prepare_external_action(self,action,tool_id,budget_cap):
        service=self.external_service()
        fields={p:'1' for p in action.get('parameters',[])}
        if action.get('parameter'):
            fields[action['parameter']]='1'
        url=action['url']
        data_body=''
        if action['method']=='GET':
            if fields:
                url=url+('&' if '?' in url else '?')+urlencode(fields)
        else:
            data_body=urlencode(fields)
        if tool_id=='hexstrike.sqlmap_scan':
            args=dict(url=url,**(dict(data=data_body) if data_body else {}))
            req_cap=min(max(budget_cap,6),300)
            seconds=120
        elif tool_id=='hexstrike.dalfox_xss_scan':
            args=dict(url=url)
            req_cap=min(max(budget_cap,6),120)
            seconds=60
        elif tool_id=='hexstrike.nuclei_scan':
            args=dict(target=url,template='http/misconfiguration/missing-security-headers.yaml')
            req_cap=min(max(budget_cap,3),20)
            seconds=45
        else:
            raise ValueError(f'unsupported external Web adapter in unified flow: {tool_id}')
        prepared=service.prepare(dict(
            tool_id=tool_id,
            arguments=args,
            scope=dict(origins=[self.config['origin']],networks=list(self.scope.allowed_ip_networks)),
            budget=dict(requests=req_cap,connections=req_cap,seconds=seconds),
        ))
        return dict(
            action_id=action['id'],
            tool_id=tool_id,
            execution_id=prepared['plan']['execution_id'],
            digest=prepared['digest'],
            arguments=prepared['plan']['arguments'],
            budget=prepared['plan']['budget'],
        )

    def execute_external_action(self,binding,approval,source,reservation=None):
        if 'validate-run' not in self.settings.enabled_http_commands:
            raise ValueError('validate-run capability is disabled')
        verify_snapshot(source)
        with Session(self.engine) as session:
            row=session.get(Approval,UUID(approval['approval_id']))
            expiry=row.expires_at if row else None
            if expiry and expiry.tzinfo is None: expiry=expiry.replace(tzinfo=timezone.utc)
            if row is None or row.status!='consumed' or expiry is None or expiry<=datetime.now(timezone.utc) or row.operation_hash!=approval['digest']:
                raise ValueError('consumed approval is no longer valid')
        service=self.external_service()
        reservation=reservation or 'mcp:'+str(binding['execution_id'])
        if self.version>=6: self.budget.reserve(reservation,binding['budget']['requests'])
        out=service.execute(binding['execution_id'],binding['digest'])
        execution=out['execution']
        if execution['status'] not in {'succeeded','tool_failed'}:
            raise StepUnknown('inspect external MCP execution '+str(binding['execution_id']))
        res=execution.get('result') or {}
        if self.version>=6: self.budget.settle(reservation,int(res.get('requests_used',0)))
        body=json.dumps(res,ensure_ascii=False,sort_keys=True)
        histogram=res.get('upstream_status') or {}
        status_code,codes=upstream_status_code(res)
        return dict(
            tool_id=binding['tool_id'],
            execution_id=binding['execution_id'],
            plan_digest=binding['digest'],
            mcp_status=execution['status'],
            result_sha256=execution['result_sha256'],
            requests_used=int(res.get('requests_used',0)) if self.version>=6 else int(res.get('requests_used',1) or 1),
            status_code=status_code,
            statuses=codes or ([502] if status_code==502 else []),
            upstream_status=histogram,
            exceptions=res.get('exceptions') or {},
            body=body,
            truncated=bool(res.get('truncated',False)),
            sha256=hashlib.sha256(body.encode()).hexdigest(),
            headers={'x-vulnmind-mcp-tool':binding['tool_id'],'x-vulnmind-mcp-execution':str(binding['execution_id'])},
        )

    def evaluate_external(self,action,mcp_response):
        tool_id=mcp_response['tool_id']
        raw=json.loads(mcp_response['body'])
        stdout=raw.get('stdout') or ''
        lower=stdout.lower()
        histogram=raw.get('upstream_status') or {}
        codes=sorted(int(code) for code in histogram if str(code).isdigit())
        blocked=int(raw.get('blocked_requests') or 0)
        exhausted=bool(raw.get('budget_exhausted'))
        reachable=any(200<=code<400 for code in codes)
        unreachable=(not reachable) and (not codes or exhausted or blocked>0)
        verdict='inconclusive'
        behavior=None
        tool_state='unknown'
        detail=f'已通过受控 MCP 执行 {tool_id}（消耗 {mcp_response["requests_used"]} 次请求），未检出明确候选信号'
        if unreachable:
            tool_state='tool_unreachable'
            detail=(f'受控工具未取得目标的有效响应（上游状态 {histogram or "无"}；'
                    f'blocked={blocked}；预算耗尽={exhausted}；异常 {raw.get("exceptions") or "无"}），'
                    '不能据此判断漏洞存在或不存在')
        elif exhausted or blocked or raw.get('truncated') or raw.get('return_code',0)!=0:
            tool_state='inconclusive'
            detail='工具预算耗尽、请求受阻、输出截断或异常退出；不能作出阴性结论'
        elif tool_id=='hexstrike.sqlmap_scan':
            # Only a real injection summary block (Parameter + Type) is a candidate.
            # Negated sentences such as "does not appear to be injectable" are negative observations.
            has_parameter=bool(re.search(r'(?m)^\s*Parameter:\s*\S+\s*\([A-Z]+\)', stdout))
            has_type=bool(re.search(r'(?m)^\s*Type:\s*\S+', stdout))
            if has_parameter and has_type:
                verdict='candidate'
                behavior='mcp_sqlmap_candidate'
                tool_state='candidate'
                detail='SQLMap 输出包含 Parameter 与 Type 注入摘要；属未验证候选，需人工复核与确认'
            elif ('do not appear to be injectable' in lower
                  or 'does not seem to be injectable' in lower):
                tool_state='negative'
                detail='SQLMap 在本次固定策略下未检出注入；不排除其他输入方式，源码支持的假设可继续内置复核'
            else:
                tool_state='inconclusive'
                detail='SQLMap 未给出注入摘要，也未明确否定；保持不确定，不升级为候选'
        elif tool_id=='hexstrike.dalfox_xss_scan':
            if '"poc"' in lower or 'reflected' in lower:
                verdict='candidate'
                behavior='mcp_dalfox_reflection'
                tool_state='candidate'
                detail='受控 Dalfox 探测发现参数反射或上下文候选；未执行浏览器确认'
            else:
                tool_state='negative' if lower.strip() else 'inconclusive'
        elif tool_id=='hexstrike.nuclei_scan':
            if stdout.strip():
                verdict='candidate'
                behavior='mcp_nuclei_match'
                tool_state='candidate'
                detail='受控 Nuclei 固定模板扫描命中配置或响应头规则；属加固建议或待核实线索'
            else:
                tool_state='negative'
        return dict(
            action_id=action['id'],
            kind=action['kind'],
            url=action['url'],
            method=action['method'],
            parameter=action['parameter'],
            source=action['source'],
            verdict=verdict,
            behavior=behavior,
            tool_state=tool_state,
            detail=detail,
            response_hashes=[mcp_response['sha256']],
            statuses=mcp_response.get('statuses') or [mcp_response['status_code']],
            upstream_status=histogram,
            exceptions=raw.get('exceptions') or {},
            category=action['category'],
            detector_version=action['detector_version'],
            external_tool=tool_id,
            mcp_execution_id=mcp_response['execution_id'],
            mcp_result_sha256=mcp_response['result_sha256'],
        )

    def staged_plan(self,number):
        """Return the already-approved plan for a round, if one exists."""
        from vulnmind.persistence.models import DurableStep
        with Session(self.engine) as session:
            row=session.scalar(select(DurableStep).where(DurableStep.workflow_id==self.job.id,
                DurableStep.stage=='approval_'+str(number)))
            if row is not None and row.status=='completed':
                return (row.payload or {}).get('approved_plan')
        return None

    def establish_session(self,requests,approval,source):
        """Register and log in the one authorized test account; keep the token in memory only."""
        from vulnmind.workbench.account import parse_session
        from vulnmind.workbench.budget import BudgetExhausted
        key='act:0:account'
        if self.version>=6:
            try:
                self.budget.reserve(key,len(requests))
            except BudgetExhausted:
                self.stop_reason='budget_exhausted'
                self.account_status=dict(email=self.account['email'],session_established=False,reason='budget_exhausted')
                return
        responses=[]
        for index,spec in enumerate(requests):
            responses.append(self.stage(f'account_{index}',dict(request=spec,approval=approval),
                lambda audit,r=spec:self.send(r,approval,source,audit)))
        if self.version>=6: self.budget.settle(key,len(responses))
        session=None
        if self._captured_bodies:
            session=parse_session(self._captured_bodies[-1])
            if session: self.vault.save_session(self.job.id,self.config['origin'],session['token'],session.get('bid'))
        if session is None:
            restored=self.vault.load_session(self.job.id,self.config['origin'])
            if restored: session=dict(token=restored['token'],email='',bid=restored.get('bid'))
        if session:
            self.session_headers={'Authorization':'Bearer '+session['token']}
            self.account_bid=session.get('bid')
            self.account_status=dict(email=session.get('email') or self.account['email'],session_established=True,
                bid=self.account_bid,register_status=responses[0].get('status_code') if responses else None)
        else:
            self.account_status=dict(email=self.account['email'],session_established=False,
                register_status=responses[0].get('status_code') if responses else None)

    def run_browser_action(self,action,reservation,approval=None,source=None):
        """Navigate once in a real browser; every subresource is charged to the ledger."""
        from vulnmind.workbench.browser import BrowserRunner,evaluate_browser,BrowserUnavailable
        from vulnmind.workbench.redaction import redact_tokens
        if source is not None: verify_snapshot(source)
        def transport(method,url):
            with Session(self.engine) as session:
                row=session.get(Approval,UUID(approval['approval_id']))
                expiry=row.expires_at if row else None
                if expiry and expiry.tzinfo is None: expiry=expiry.replace(tzinfo=timezone.utc)
                if row is None or row.status!='consumed' or not expiry or expiry<=datetime.now(timezone.utc) or row.operation_hash!=approval['digest']:
                    raise ValueError('browser approval expired or mismatched')
            if 'validate-run' not in self.settings.enabled_http_commands: raise ValueError('HTTP capability disabled')
            check_target(Target(type='web',locator=url),self.scope)
            addresses=sorted({i[4][0] for i in socket.getaddrinfo(urlsplit(url).hostname,None,type=socket.SOCK_STREAM)})
            check_resolved_addresses(Target(type='web',locator=url),self.scope,addresses)
            from vulnmind.analysis.http_broker import IsolatedHttpBroker
            broker=IsolatedHttpBroker(self.scope,distro=self.settings.http_broker_distro,ca_file=self.settings.http_ca_file,max_body_bytes=200000)
            return (self.http or broker.request_api)(method=method,url=url,headers={'Accept':'*/*'},body='',addresses=addresses,
                approval_digest=approval['digest'],auth_origin=self.config['origin'])
        runner=BrowserRunner(self.scope,self.config['origin'],max_requests=40 if self.version>=7 else 120,transport=transport)
        def compute(audit):
            retry_reservation=None
            if self.version>=7:
                from vulnmind.persistence.models import DurableStep
                with Session(self.engine) as session:
                    step=session.get(DurableStep,audit.parent)
                    if step.attempt>1:
                        retry_reservation='browser-retry:'+str(step.id)+':'+str(step.attempt)
                        self.budget.reserve(retry_reservation,action['cost'])
            try:
                if self.version>=7:
                    runs=[runner.run(url) for url in (action['baseline_url'],action['url'],action['url'])]
                    outcome={**runs[-1],'causal_runs':[{k:r.get(k) for k in ('dialogs','status_code','blocked','html_truncated')} for r in runs],
                        'requests':sum(r['requests'] for r in runs),'html':json.dumps(runs,ensure_ascii=False),
                        'request_paths':[p for r in runs for p in r['request_paths']],
                        'blocked':[p for r in runs for p in r['blocked']]}
                else: outcome=runner.run(action['url'])
            except BrowserUnavailable as exc:
                if self.version>=7: raise StepUnknown('browser run uncertain; reservation retained') from exc
                return dict(unavailable=str(exc)[:200],body='',sha256='',requests=0,blocked=[],dialogs=[],
                            title='',elapsed_ms=0,status_code=None)
            except Exception as exc:  # noqa: BLE001 - unknown browser failure is not tested
                if self.version>=7: raise StepUnknown('browser run uncertain; reservation retained') from exc
                return dict(unavailable='browser error '+type(exc).__name__,body='',sha256='',requests=0,
                            blocked=[],dialogs=[],title='',elapsed_ms=0,status_code=None)
            body,redacted=redact_tokens(outcome['html'])
            return dict(body=body,sha256=hashlib.sha256(body.encode()).hexdigest(),requests=outcome['requests'],
                request_paths=outcome['request_paths'],blocked=outcome['blocked'],dialogs=outcome['dialogs'],
                title=outcome['title'],elapsed_ms=outcome['elapsed_ms'],status_code=outcome['status_code'],redacted=redacted,
                **(dict(causal_runs=outcome['causal_runs'],retry_reservation=retry_reservation) if 'causal_runs' in outcome else {}))
        receipt=self.stage('browser_'+action['id'],dict(url=action['url'],kind=action['kind']),compute)
        actual=int(receipt.get('requests') or 0)
        if self.version>=6: self.budget.settle(receipt.get('retry_reservation') or reservation,actual)
        if receipt.get('unavailable'):
            return dict(action_id=action['id'],kind=action['kind'],url=action['url'],method='GET',
                parameter=action.get('parameter',''),category=action['category'],verdict='inconclusive',behavior=None,
                detail='浏览器不可用，未执行脚本核对：'+str(receipt['unavailable'])[:160],statuses=[],response_hashes=[],
                browser=None,detector_version=action.get('detector_version')),actual
        outcome=dict(status_code=receipt.get('status_code'),requests=actual,blocked=receipt.get('blocked') or [],
            dialogs=receipt.get('dialogs') or [],title=receipt.get('title'),elapsed_ms=receipt.get('elapsed_ms'),
            html=receipt.get('body',''),sha256=receipt.get('sha256',''),causal_runs=receipt.get('causal_runs',[]))
        return evaluate_browser(action,outcome),actual

    def run_auth_idor(self,action,approval,source,reservation):
        """Read-only cross-account check with the one authorized test account."""
        from vulnmind.workbench.detectors import evaluate_idor
        if action.get('access_check'):
            from vulnmind.workbench.access_control import requests_for,evaluate
            responses=[]
            for spec in requests_for(action):
                responses.append(self.stage(f"http_{action['id']}_{spec['variant']}",dict(request=spec,approval=approval),
                    lambda audit,r=spec:self.send(r,approval,source,audit)))
            self.budget.settle(reservation,len(responses))
            return evaluate(action,responses),len(responses)
        own=int(self.account_bid or 0)
        from vulnmind.workbench.adapters.juice_shop import seeded_requests
        specs=seeded_requests(self.config['origin'],own)
        responses=[]
        for spec in specs:
            responses.append(self.stage(f"http_{action['id']}_{spec['variant']}",dict(request=spec,approval=approval),
                lambda audit,r=spec:self.send(r,approval,source,audit)))
        if self.version>=6: self.budget.settle(reservation,len(responses))
        return evaluate_idor(action,responses,own),len(responses)

    def run(self):
        from vulnmind.workbench import detectors
        from vulnmind.workbench.knowledge import snapshot as knowledge_snapshot
        base_builder=detectors.requests_for if self.version>=2 else requests_for
        def request_builder(action):
            specs=base_builder(action)
            if self.version>=7 and action['kind'] in {'response_disclosure','exposed_file','config_exposure','well_known_exposure','sql_login','weak_password'}:
                specs=[{**r,'no_session':True} for r in specs]
            return specs
        evaluator=detectors.evaluate if self.version>=2 else evaluate
        with workflow_lock(self.engine,self.job.id):
            if self.version>=6:
                from vulnmind.workbench.budget import BudgetLedger
                budget_path=Path(self.settings.report_root).resolve().parent/'workbench'/'budgets'/(str(self.job.id)+'.sqlite')
                self.stage('budget_init',{'limit':self.config['request_budget']},lambda _:dict(limit=BudgetLedger(budget_path,self.config['request_budget']).limit),safe=True)
                self.budget=BudgetLedger(budget_path,self.config['request_budget'],must_exist=True)
            def initialize(session,value):
                session.add(Scan(id=self.scan,project_id=self.job.project_id,mode='unified',status='running',started_at=datetime.now(timezone.utc)))
                return dict(scan_id=str(self.scan))
            self.stage('initialize',{},lambda _: {},persist=initialize,safe=True)
            def source_snapshot(_):
                saved=snapshot(self.config['repository'],self.scope,extended=self.version>=2)
                if self.version>=4:
                    from vulnmind.workbench.discovery import extend_snapshot
                    saved=extend_snapshot(saved,self.scope)
                if self.version>=6:
                    from vulnmind.workbench.ast_discovery import extend_ast_snapshot
                    saved=extend_ast_snapshot(saved,self.scope)
                return saved
            source=self.stage('source',{},source_snapshot,safe=True)
            verify_snapshot(source)
            mapped=self.stage('correlation',{'source':source['digest']},lambda _:correlate(source,
                imported_routes(self.config.get('routes',[]),self.config['origin']),self.config,self.scope),safe=True)
            # Repository static tooling remains its own resumable child workflow.
            def repository(_):
                from vulnmind.graph.durable_repository import RepositoryFlow
                repo_tools=['checkov_mcp'] if self.config.get('external_execution') and (self.version<4 or self.config.get('repository_iac')) else []
                ext_root=str(self.external_service().root) if self.config.get('external_execution') else None
                opts=dict(actor=self.actor,tools=repo_tools,reports={},report_format='json',report_root=self.settings.report_root,
                    evidence_root=self.settings.evidence_root,agent_model='deepseek-chat',agent_plan=False,agent_analysis=False,
                    agent_review=False,agent_report=False,knowledge_context=False,agent_knowledge=False,
                    **(dict(external_root=ext_root) if ext_root else {}))
                return RepositoryFlow(self.engine,uuid5(self.job.id,'repository'),self.job.project_id,
                    Target(type='repository',locator=self.config['repository']),self.scope,opts,
                    external=self.external_service() if self.config.get('external_execution') else None).run()
            repo=self.stage('repository',{'snapshot':source['digest']},repository,safe=True)
            recon_summary=None
            used=0
            if self.version>=3 and self.config.get('external_execution') and self.config.get('external_recon') and (self.version<4 or self.config['request_budget']>=12):
                recon_summary=self.stage('external_recon',{'origin':self.config['origin'],'source':source['digest']},
                    lambda audit:self.recon_budgeted(mapped,audit),safe=self.version<6)
                used+=int(recon_summary.get('requests_used',0))
                if self.version>=4:
                    from vulnmind.workbench.discovery import discovered_routes
                    observed=discovered_routes(recon_summary.get('discovered_urls',[]),self.config['origin'])
                    mapped=self.stage('discovery_mapping',dict(source=source['digest'],observed=observed),
                        lambda _:correlate(source,observed+imported_routes(self.config.get('routes',[]),self.config['origin']),self.config,self.scope),safe=True)
            all_actions=detectors.actions_for(mapped,list(dict.fromkeys(self.config['detectors'])),limit=240 if self.version>=6 else 60) if self.version>=2 else actions_for(mapped)
            if self.version>=6 and self.adapter=='juice_shop':
                all_actions+=detectors.synthetic_actions(self.config['origin'],list(dict.fromkeys(self.config['detectors'])),
                    auth_probe=bool(self.config.get('auth_probe')),existing=all_actions,account=bool(self.account))
            if self.version>=7:
                all_actions=[a for a in all_actions if a['kind'] not in {'browser_xss','auth_idor'}]
                from vulnmind.workbench.access_control import actions as access_actions
                if 'auth_idor' in self.config['detectors']: all_actions+=access_actions(self.config.get('access_checks',[]))
                from vulnmind.workbench.browser_checks import actions as browser_actions
                if 'browser_xss' in self.config['detectors']: all_actions+=browser_actions(mapped)
            if self.version>=4:
                for action in all_actions:
                    if action['kind']=='sql_boolean': action.update(boolean_closures=True,cost=18)
            knowledge_rounds=[]; knowledge_round_numbers=[]; coverage=[]; tool_routing=None
            if self.version>=2:
                coverage=self.stage('classification',dict(mapping=mapped),lambda _:dict(items=detectors.classify(mapped,enabled=self.config['detectors'] if self.version>=7 else None)),safe=True)['items']
            if self.version>=3:
                from vulnmind.integrations.hexstrike.router import workbench_snapshot
                val_receipts=self.load_external_validation()
                tool_routing=self.stage('tool_routing',dict(actions=all_actions,policy=self.config.get('tool_policy','external_preferred'),
                    external_execution=bool(self.config.get('external_execution'))),
                    lambda _:workbench_snapshot(all_actions,policy=self.config.get('tool_policy','external_preferred'),validation=val_receipts),safe=True)
                for identifier,choice in tool_routing['choices'].items():
                    expected_builtin='builtin.'+next(a['kind'] for a in all_actions if a['id']==identifier)
                    if choice['selected']!=expected_builtin:
                        if not self.config.get('external_execution') or choice['selected'] not in EXTERNAL_WEB_ADAPTERS:
                            raise ValueError('selected external Web adapter needs an execution binding')
            if self.version>=4:
                from vulnmind.workbench.discovery import price_actions
                def pricing(_):
                    routing=json.loads(json.dumps(tool_routing))
                    actions=json.loads(json.dumps(all_actions))
                    if self.version>=6:
                        from vulnmind.workbench.batches import price,schedule
                        actions=schedule(price(actions,routing,authenticated=bool(self.config.get('credential_profile'))))
                    else: price_actions(actions,routing,self.config['request_budget']-used,authenticated=bool(self.config.get('credential_profile')))
                    return dict(actions=actions,routing=routing)
                priced=self.stage('execution_routing',dict(actions=all_actions,routing=tool_routing,budget=self.config['request_budget']-used),pricing,safe=True)
                all_actions,tool_routing=priced['actions'],priced['routing']
            attempted=set(); observations=[]; critiques=[]
            for number in range(self.config['rounds']):
                remaining=[a for a in all_actions if a['id'] not in attempted]
                if self.version>=2: remaining=[a for a in remaining if a['cost']<=self.config['request_budget']-used]
                if self.version>=6:
                    from vulnmind.workbench.batches import batch_limit
                    self.round_budget=batch_limit(number,used,self.config['request_budget'])
                    # Expensive tools enter targeted rounds; retain their catalog entries.
                    remaining=[a for a in remaining if a['cost']<=self.round_budget and (number>0 or a['cost']<=12)]
                    if not remaining: continue
                capacity=min(24 if self.version>=6 else 2,(self.config['request_budget']-used)//3)
                if not remaining or capacity<1: break
                if self.version>=2:
                    categories=sorted({a['category'] for a in remaining})
                    def obtain_knowledge(_):
                        saved=(self.knowledge_provider or knowledge_snapshot)(self.engine,categories,self.config['knowledge_mode'])
                        if self.version>=3:
                            from vulnmind.integrations.hexstrike.knowledge import extend_context
                            return extend_context(self.engine,saved,tool_routing,
                                action_ids=({a['id'] for a in remaining} if self.version>=5 else None),
                                selected_only=self.version>=7)
                        return saved
                    self.knowledge=self.stage(f'knowledge_{number}',dict(categories=categories,mode=self.config['knowledge_mode'],previous=observations,
                        **(dict(tool_routing_digest=digest(tool_routing)) if self.version>=3 else {})),obtain_knowledge,safe=True)
                    knowledge_rounds.append(self.knowledge);knowledge_round_numbers.append(number)
                    supported={tool for skill in self.knowledge['skills'] for tool in skill['tools']}
                    if any(a['kind'] not in supported for a in remaining if a['category'] in categories):
                        raise ValueError('selected skill does not support the planned detector')
                    remaining=[a for a in remaining if a['category'] in categories]
                    if self.version<6: remaining=remaining[:12]
                selected=self.stage(f'plan_{number}',dict(previous=observations,critique=critiques,
                    **(dict(knowledge_digest=digest(self.knowledge),candidates=[a['id'] for a in remaining]) if self.version>=2 else {})),
                    lambda audit:self.plan(audit,remaining,observations,critiques))
                ids=selected['action_ids'][:capacity]
                actions=[next(a for a in remaining if a['id']==i) for i in ids]
                if self.version>=2:
                    budget=self.config['request_budget']-used
                    if self.version>=6:
                        from vulnmind.workbench.batches import batch_limit
                        budget=batch_limit(number,used,self.config['request_budget'])
                    affordable=[]
                    for action in actions:
                        if action['cost']<=budget: affordable.append(action);budget-=action['cost']
                    actions=affordable
                if not actions:
                    if self.version>=6 and remaining: continue
                    self.stop_reason='no_actions_selected'
                    break
                def build_round_plan(_):
                    builtin_reqs=[]
                    external_plans={}
                    rem_budget=self.config['request_budget']-used
                    account_reqs=[]
                    # Round 0 always lists the account requests when an account is configured.
                    # The plan must be identical on every resume, after the login already
                    # happened; the journal replays the account stages instead of resending.
                    if number==0 and self.account:
                        from vulnmind.workbench.account import login_requests,register_requests
                        account_reqs=(register_requests(self.config['origin'],self.account['email'],self.account['password'])
                                      +login_requests(self.config['origin'],self.account['email'],self.account['password']))
                        if self.version>=7:
                            account_reqs=[{**r,'body':'','account_request':i,'account_profile':self.config['account_profile'],
                                'body_sha256':hashlib.sha256(r['body'].encode()).hexdigest()} for i,r in enumerate(account_reqs)]
                        builtin_reqs.extend(account_reqs)
                        rem_budget-=len(account_reqs)
                    for a in actions:
                        if a['kind'] in BROWSER_KINDS or a['kind'] in AUTH_KINDS:
                            # These actions are executed by their own runner with bounded
                            # requests; the approval plan lists them separately.
                            if self.version>=4: rem_budget-=a['cost']
                            continue
                        sel_tool=(tool_routing or {}).get('choices',{}).get(a['id'],{}).get('selected','builtin.'+a['kind'])
                        if sel_tool.startswith('hexstrike.') and self.config.get('external_execution') and rem_budget>=6:
                            ext_plan=self.prepare_external_action(a,sel_tool,min(rem_budget,a['cost']) if self.version>=4 else rem_budget)
                            if self.version>=4: rem_budget-=ext_plan['budget']['requests']
                            external_plans[a['id']]=ext_plan
                            builtin_reqs.append(dict(
                                method=a['method'],
                                url=a['url'],
                                headers={'X-VulnMind-MCP-Tool':sel_tool,'X-VulnMind-MCP-Execution':ext_plan['execution_id']},
                                body=json.dumps(ext_plan['arguments'],ensure_ascii=False),
                                variant=0,
                            ))
                        else:
                            builtin_reqs.extend(request_builder(a))
                            if self.version>=4: rem_budget-=a['cost']
                    browser_actions=[dict(id=a['id'],url=a['url'],cost=a['cost'],baseline_url=a.get('baseline_url'),marker=a.get('marker'),repetitions=2,subresource_methods=['GET','HEAD']) for a in actions if a['kind'] in BROWSER_KINDS]
                    from vulnmind.workbench.access_control import requests_for as access_requests
                    auth_actions=[dict(id=a['id'],url=a['url'],cost=a['cost'],
                        **(dict(requests=access_requests(a)) if a.get('access_check') else {})) for a in actions if a['kind'] in AUTH_KINDS]
                    plan_value=dict(
                        actions=actions,
                        requests=builtin_reqs,
                        source_snapshot=source['digest'],
                        credential_profile=self.config.get('credential_profile'),
                        **(dict(account_requests=account_reqs,account_email=self.account['email']) if account_reqs else {}),
                        **(dict(browser_actions=browser_actions) if browser_actions else {}),
                        **(dict(auth_actions=auth_actions) if auth_actions else {}),
                        **(dict(external_plans=external_plans) if external_plans else {}),
                        **(dict(tool_routing=tool_routing) if self.version>=3 else {}),
                        **(dict(knowledge_digest=digest(self.knowledge)) if self.version>=2 else {}),
                    )
                    import os
                    if os.environ.get('VULNMIND_PLAN_DEBUG'):
                        debug=Path('.devtools')/f'plan-{self.job.id}-{number}-{time.time_ns()}.json'
                        debug.write_text(json.dumps(dict(plan=plan_value,round=number,used=used,
                            available=self.budget.snapshot()['available'] if self.version>=6 else None,
                            round_budget=getattr(self,'round_budget',None)),ensure_ascii=False,sort_keys=True,indent=1),encoding='utf-8')
                    return plan_value
                if self.config.get('external_execution'):
                    plan=self.stage(f'prepare_{number}',dict(actions=[a['id'] for a in actions],source=source['digest']),build_round_plan,safe=True)
                else:
                    # Reuse the approved plan verbatim on resume: recomputing it from the
                    # current ledger made later approvals differ from the approved one.
                    plan=self.staged_plan(number) or build_round_plan(None)
                plan_hash=digest(plan)
                def request(session,value):
                    row=ApprovalService(session).request(scan_id=self.scan,action='unified.requests',target=plan_hash,operation_hash=plan_hash)
                    session.flush(); return dict(approval_id=str(row.id),digest=plan_hash,approved_plan=value)
                approval=self.stage(f'approval_{number}',plan,lambda _: {},persist=request,safe=True)
                with Session(self.engine) as session:
                    row=session.get(Approval,UUID(approval['approval_id']))
                    if row.status=='pending':
                        return dict(status='waiting_approval',scan_id=str(self.scan),round=number+1,mapping=mapped,
                            observations=observations,critics=critiques,plan=plan,planner=selected,**approval,repository=repo,
                            **(dict(external_recon=recon_summary) if recon_summary else {}),
                            **(dict(knowledge=knowledge_rounds,coverage=coverage) if self.version>=2 else {}))
                    if row.status=='denied': return dict(status='denied',scan_id=str(self.scan),approval_id=approval['approval_id'])
                def consume(session,value):
                    if not ApprovalService(session).consume_bound(approval['approval_id'],scan_id=self.scan,action='unified.requests',target=plan_hash,operation_hash=plan_hash):
                        raise ValueError('approval expired or mismatched')
                    return {'consumed':True}
                self.stage(f'consume_{number}',approval,lambda _: {},persist=consume,safe=True)
                if plan.get('account_requests'):
                    self.establish_session(plan['account_requests'],approval,source)
                round_results=[]
                ext_bindings=plan.get('external_plans') or {}
                budget_stop=None
                for position,action in enumerate(actions):
                    if action['kind'] in BROWSER_KINDS or action['kind'] in AUTH_KINDS:
                        planned=int(action['cost'])
                    elif action['id'] in ext_bindings:
                        planned=int(ext_bindings[action['id']]['budget']['requests'])
                    else:
                        planned=len(request_builder(action))
                    reservation=('act:'+str(number)+':'+action['id']) if self.version>=6 else None
                    if self.version>=6:
                        # Reserve the worst case before sending anything; settle to the real
                        # count afterwards. A crash keeps the full hold (conservative).
                        from vulnmind.workbench.budget import BudgetExhausted
                        try:
                            self.budget.reserve(reservation,planned)
                        except BudgetExhausted:
                            budget_stop='budget_exhausted'
                            self.skipped_for_budget+=len(actions)-position
                            break
                    if action['kind'] in BROWSER_KINDS:
                        result,actual=self.run_browser_action(action,reservation,approval,source)
                        used+=actual
                    elif action['kind'] in AUTH_KINDS:
                        result,actual=self.run_auth_idor(action,approval,source,reservation)
                        used+=actual
                    elif action['id'] in ext_bindings:
                        binding=ext_bindings[action['id']]
                        stage='mcp_'+action['id']
                        mcp_resp=self.stage(stage,dict(binding=binding,approval=approval),
                            lambda audit,b=binding:self.execute_external_action(b,approval,source,reservation if self.version>=7 else None))
                        result=self.evaluate_external(action,mcp_resp)
                        actual=int(mcp_resp.get('requests_used',1))
                        if self.version>=6: self.budget.settle(reservation,actual)
                        used+=actual
                        if self.version>=4 and used>self.config['request_budget']: raise ValueError('external receipt exceeded reserved task request budget')
                    else:
                        responses=[]
                        for request_spec in request_builder(action):
                            stage='http_'+action['id']+'_'+str(request_spec['variant'])
                            response=self.stage(stage,dict(request=request_spec,approval=approval),
                                lambda audit,r=request_spec:self.send(r,approval,source,audit))
                            responses.append(response)
                        result=evaluator(action,responses)
                        if self.version>=6: self.budget.settle(reservation,len(responses))
                        used+=len(responses)
                    if self.version>=2:
                        ext_skill_refs=[]
                        if result.get('external_tool'):
                            from vulnmind.integrations.hexstrike.catalog import get_tool
                            t_meta=get_tool(result['external_tool'])
                            if t_meta: ext_skill_refs=[f"skill:{t_meta['skill_id']}"]
                        result.update(knowledge_snapshot=digest(self.knowledge),
                            method_refs=['skill:'+s['skill_id'] for s in self.knowledge['skills'] if s['vuln_type']==action['category']]+ext_skill_refs)
                    stored=self.stage('result_'+action['id'],dict(result=result),lambda _: result,
                        persist=lambda session,value:self.persist_result(session,value),safe=True)
                    round_results.append(stored); attempted.add(action['id'])
                    if self.version>=4:
                        from vulnmind.workbench.discovery import independent_followup
                        followup=independent_followup(action,stored)
                        if followup and not any(a['id']==followup['id'] for a in all_actions): all_actions.insert(0,followup)
                    if self.version>=6 and action['kind'] in {'well_known_exposure','response_disclosure'} \
                            and (self.version>=7 or '/ftp/' in action['url']) and 'exposed_file' in self.config['detectors']:
                        # One listing is enough to derive a few bounded file reads; the
                        # next round decides whether they are worth spending requests on.
                        from vulnmind.workbench.detectors import file_followups
                        listing=next((r['body'] for r in responses if 200<=r['status_code']<300),'')
                        for followup in file_followups(self.config['origin'],listing,**(dict(base_url=action['url']) if self.version>=7 else {})):
                            if not any(a['id']==followup['id'] for a in all_actions): all_actions.insert(0,followup)
                observations+=round_results
                if budget_stop:
                    self.stop_reason=budget_stop
                    break
                remainder=[a for a in all_actions if a['id'] not in attempted]
                critique=self.stage(f'critic_{number}',dict(observations=round_results,remaining=[a['id'] for a in remainder],
                    **(dict(knowledge_digest=digest(self.knowledge)) if self.version>=2 else {})),
                    lambda audit:self.critique(audit,round_results,remainder))
                critiques.append(critique)
                if not critique['continue_investigation']:
                    self.stop_reason='critic_stop'
                    break
            if self.stop_reason is None:
                self.stop_reason='max_rounds'
            if self.version>=7:
                from vulnmind.workbench.batches import effective_stop_reason
                self.stop_reason=effective_stop_reason(self.stop_reason,self.budget.snapshot())
            reported_used=self.budget.snapshot()['charged'] if self.version>=6 else used
            final=self.stage('report',dict(source=source['digest'],observations=observations,critics=critiques),
                lambda _: dict(schema_version='workbench-'+str(self.version),job_id=str(self.job.id),scan_id=str(self.scan),name=self.job.name,
                    origin=self.config['origin'],repository=repo,mapping=mapped,
                    **(dict(target_adapter=self.adapter,knowledge_round_numbers=knowledge_round_numbers) if self.version>=7 else {}),observations=observations,critics=critiques,
                    source_snapshot=source['digest'],requests_used=reported_used,
                    **(dict(external_recon=recon_summary) if recon_summary else {}),
                    **(dict(assessment='not_tested' if not observations else 'partial',
                        coverage_message='未执行漏洞验证：没有可执行接口、预算不足或规划未选择动作，不能判断目标安全' if not observations else '仅覆盖已记录的接口与动作；未测试部分不代表安全',
                        source_file_count=len(source['files'])) if self.version>=4 else {}),
                    **(dict(tool_routing=tool_routing) if self.version>=3 else {}),
                    **(dict(budget_ledger=self.budget.snapshot(),root_causes=__import__('vulnmind.workbench.batches',fromlist=['deduplicated_findings']).deduplicated_findings(observations),
                        benchmark_status='not_evaluated_against_frozen_ground_truth',
                        stop_reason=self.stop_reason,budget_skipped_actions=self.skipped_for_budget,
                        account=self.account_status) if self.version>=6 else {}),
                    **(dict(knowledge=knowledge_rounds,coverage=coverage,detectors=self.config['detectors'],
                            untested_action_count=len(all_actions)-len(attempted)) if self.version>=2 else {}),
                    limitations=['部署关系由本机操作者声明；静态路由不等于实际调用链证明','自动确认仅限具体差分行为；不声称任意代码执行或完整漏洞覆盖','认证和浏览器仅在配置并有执行回执时覆盖；未运行部分不代表安全']),
                persist=self.persist_report,safe=True)
            verify_snapshot(source)
            from vulnmind.reports.store import ReportStore
            ReportStore(Path(self.settings.report_root)).read(final['report_uri'])
            with Session(self.engine) as session:
                from vulnmind.evidence.store import EvidenceStore
                for item in final['observations']:
                    row=session.get(Evidence,UUID(item['evidence_id']))
                    if row is None or hashlib.sha256(EvidenceStore(Path(self.settings.evidence_root)).read(row.content_ref)).hexdigest()!=row.hash:
                        raise ValueError('evidence verification failed')
            return dict(status='finished',**final)

    def send(self,spec,approval,source,audit):
        if 'validate-run' not in self.settings.enabled_http_commands:
            raise ValueError('validate-run capability is disabled')
        verify_snapshot(source)
        with Session(self.engine) as session:
            row=session.get(Approval,UUID(approval['approval_id']))
            expiry=row.expires_at if row else None
            if expiry and expiry.tzinfo is None: expiry=expiry.replace(tzinfo=timezone.utc)
            if row is None or row.status!='consumed' or expiry is None or expiry<=datetime.now(timezone.utc) or row.operation_hash!=approval['digest']:
                raise ValueError('consumed approval is no longer valid')
        check_target(Target(type='web',locator=spec['url']),self.scope)
        host=urlsplit(spec['url']).hostname
        addresses=sorted({item[4][0] for item in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)})
        check_resolved_addresses(Target(type='web',locator=spec['url']),self.scope,addresses)
        wire_body=spec['body']
        if self.version>=7 and 'account_request' in spec:
            from vulnmind.workbench.account import register_requests,login_requests
            if spec['account_profile']!=self.config.get('account_profile') or self.account is None:
                raise ValueError('account request binding changed')
            actual=(register_requests(self.config['origin'],self.account['email'],self.account['password'])+
                login_requests(self.config['origin'],self.account['email'],self.account['password']))[spec['account_request']]
            if actual['url']!=spec['url'] or actual['method']!=spec['method'] or hashlib.sha256(actual['body'].encode()).hexdigest()!=spec['body_sha256']:
                raise ValueError('account secret request hash changed')
            wire_body=actual['body']
        headers=dict(spec['headers']); credentials={}
        if self.session_headers and not spec.get('no_session'):
            headers.update(self.session_headers)
        credential=self.config.get('credential_profile')
        if self.version>=7:
            credential=spec.get('credential_override',None if spec.get('no_session') else credential)
        if credential:
            credentials=self.vault.load(credential,self.config['origin']);headers.update(credentials)
        if self.version>=7:
            from vulnmind.persistence.models import DurableStep
            with Session(self.engine) as session:
                step=session.get(DurableStep,audit.parent)
                if step.attempt>1:
                    retry_key='retry:'+str(step.id)+':'+str(step.attempt)
                    self.budget.reserve(retry_key,1);self.budget.settle(retry_key,1)
        if self.last_request: time.sleep(max(0,.25-(time.monotonic()-self.last_request)))
        self.last_request=time.monotonic()
        from vulnmind.analysis.http_broker import IsolatedHttpBroker
        broker=IsolatedHttpBroker(self.scope,distro=self.settings.http_broker_distro,ca_file=self.settings.http_ca_file,max_body_bytes=200000)
        response=(self.http or broker.request_api)(method=spec['method'],url=spec['url'],headers=headers,body=wire_body,addresses=addresses,
            approval_digest=approval['digest'],auth_origin=self.config['origin'])
        body=response.body.decode('utf-8',errors='replace')
        if self.version>=7 and self.account: body=body.replace(self.account['password'],'[redacted account password]')
        if spec.get('capture_token'):
            # Kept in memory only; the journaled payload is redacted below.
            self._captured_bodies.append(body)
        for value in credentials.values():
            body=body.replace(value,'[redacted credential]')
            for token in value.removeprefix('Bearer ').split(';'):
                token=token.strip().split('=',1)[-1]
                if token: body=body.replace(token,'[redacted credential]')
        from vulnmind.workbench.redaction import redact_tokens
        session_secret=self.session_headers.get('Authorization','').removeprefix('Bearer ')
        if session_secret: body=body.replace(session_secret,'[redacted session]')
        body,redacted=redact_tokens(body)
        saved=dict(status_code=response.status_code,body=body,truncated=response.truncated,sha256=hashlib.sha256(body.encode()).hexdigest())
        if redacted: saved['redacted']=True
        if self.version>=2:
            allowed={'content-type','content-security-policy','x-content-type-options','access-control-allow-origin','access-control-allow-credentials','vary','location'}
            safe_headers={str(k).lower():str(v) for k,v in getattr(response,'headers',{}).items() if str(k).lower() in allowed}
            for key,value in safe_headers.items():
                for secret in credentials.values():
                    value=value.replace(secret,'[redacted credential]')
                    for token in secret.removeprefix('Bearer ').split(';'):
                        token=token.strip().split('=',1)[-1]
                        if token: value=value.replace(token,'[redacted credential]')
                safe_headers[key]=value
            saved['headers']=safe_headers
        return saved

    def persist_result(self,session,result):
        from vulnmind.findings import FindingCandidate,group_findings
        from vulnmind.analysis.persistence import FindingWriter
        from vulnmind.evidence.ingest import ingest_evidence,EvidenceItem
        from vulnmind.evidence.store import EvidenceStore
        source_tool=result.get('external_tool') or 'unified_differential'
        candidate=FindingCandidate(title=result['kind']+' / '+result['verdict'],vulnerability_type=result['kind'],target_id='web',
            location=result['method']+' '+result['url']+' '+result['parameter'],source_tool=source_tool,severity='unknown',
            status='insufficient_evidence' if result['verdict']=='inconclusive' else 'unverified')
        FindingWriter(session).store_groups(self.scan,group_findings([candidate]))
        evidence=ingest_evidence(session,EvidenceStore(Path(self.settings.evidence_root)),scan_id=self.scan,
            items=[EvidenceItem(fingerprint=candidate.fingerprint(),content=json.dumps(result,ensure_ascii=False).encode(),evidence_type='validation_result',locator=result['url'][:1000])])
        row=session.scalar(select(Evidence).join(Finding,Evidence.finding_id==Finding.id).where(Finding.scan_id==self.scan,Finding.fingerprint==candidate.fingerprint(),Evidence.content_ref==evidence.references[0]))
        return {**result,'fingerprint':candidate.fingerprint(),'evidence_id':str(row.id)}

    def persist_report(self,session,payload):
        from vulnmind.reports.store import ReportStore
        from vulnmind.reports.signing import sign_configured
        from vulnmind.persistence.repositories import ReportRepository
        store=ReportStore(Path(self.settings.report_root));ref=store.put(json.dumps(payload,ensure_ascii=False,indent=2),format='json')
        sign_configured(store,ref.uri)
        ReportRepository(session).create(self.scan,format='json',storage_uri=ref.uri)
        row=session.get(Scan,self.scan);row.status='finished';row.finished_at=datetime.now(timezone.utc)
        return {**payload,'report_uri':ref.uri}
