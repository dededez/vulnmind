"""Local workbench application service. Only saved jobs may enter the runner."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import threading
from urllib.parse import urlsplit
from uuid import UUID,uuid4,uuid5
from typing import Literal

from pydantic import BaseModel,ConfigDict,Field
from sqlalchemy import select,func
from sqlalchemy.orm import Session
from vulnmind.persistence.models import WorkbenchJob,Project,DurableStep,Approval,Scan
from vulnmind.schemas import Authorization,Target
from vulnmind.security.scope import check_target
from vulnmind.persistence.audit import SessionAuditSink
from vulnmind.persistence.durable import digest,recover_step
from vulnmind.workbench.engine import UnifiedInvestigation
from vulnmind.workbench.routes import imported_routes


class JobInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    name:str=Field(min_length=1,max_length=120)
    repository:str=Field(min_length=1,max_length=2000)
    origin:str=Field(min_length=1,max_length=1000)
    path_prefix:str=Field(default='',max_length=200)
    deployment_version:str=Field(min_length=1,max_length=128)
    binding_confirmed:bool
    allowed_ip_networks:list[str]=Field(min_length=1,max_length=20)
    actor:str=Field(default='本机操作者',min_length=1,max_length=120)
    authorization_source:str=Field(min_length=1,max_length=1000)
    hours:int=Field(default=24,ge=1,le=168)
    agents:bool=False
    rounds:int=Field(default=2,ge=1,le=3)
    request_budget:int=Field(default=18,ge=3,le=400)
    pipeline_version:Literal[1,2,3,4,5,6]=6
    tool_policy:Literal['external_preferred','builtin_only']='external_preferred'
    external_execution:bool=False
    external_recon:bool=False
    repository_iac:bool=False
    knowledge_mode:Literal['hybrid','keyword']='hybrid'
    detectors:list[Literal['sql_boolean','sql_error','xss_context','template_expression','reflection','cors','security_headers','response_disclosure','redirect_location','nosql_error','sql_login','weak_password','config_exposure','well_known_exposure','browser_xss','auth_idor','exposed_file']]=Field(
        default_factory=lambda:['sql_boolean','sql_error','xss_context','template_expression','reflection','cors','security_headers'],min_length=1,max_length=17)
    allow_post:bool=False
    auth_probe:bool=False
    account_profile:str|None=None
    credential_profile:str|None=None
    routes:dict|list=Field(default_factory=list)


class Workbench:
    def __init__(self,engine,settings,root,*,runner=UnifiedInvestigation):
        from vulnmind.workbench.secrets import Vault
        self.engine,self.settings,self.root,self.runner=engine,settings,Path(root),runner
        self.root.mkdir(parents=True,exist_ok=True)
        self.vault=Vault(self.root/'credentials')
        self.pool=ThreadPoolExecutor(max_workers=2,thread_name_prefix='vulnmind-job')
        self.active={};self.mutex=threading.Lock()
        with Session(engine) as session,session.begin():
            for row in session.scalars(select(WorkbenchJob).where(WorkbenchJob.status.in_(['queued','running']))):
                row.status='interrupted'

    def create(self,data):
        value=JobInput.model_validate(data)
        if not value.binding_confirmed: raise ValueError('请先确认仓库与部署对应关系及授权')
        origin=value.origin.rstrip('/')
        from vulnmind.analysis.http_broker_worker import origin as parse_origin,safe_path
        parse_origin(origin)
        parts=urlsplit(origin)
        if parts.path or parts.query or parts.fragment: raise ValueError('部署地址只填写 scheme、主机和端口；路径前缀单独填写')
        if value.path_prefix: safe_path(value.path_prefix)
        repository=Path(value.repository).resolve(strict=True)
        if not repository.is_dir(): raise ValueError('仓库目录不存在')
        now=datetime.now(timezone.utc)
        scope=Authorization(authorization_source=value.authorization_source,approved_by=value.actor,
            starts_at=now-timedelta(seconds=30),expires_at=now+timedelta(hours=value.hours),repository_roots=[str(repository)],
            web_origins=[origin],allowed_ip_networks=value.allowed_ip_networks)
        check_target(Target(type='web',locator=origin+'/'),scope)
        imported_routes(value.routes,origin)
        if value.credential_profile: self.vault.load(value.credential_profile,origin)
        if value.account_profile: self.vault.load_account(value.account_profile,origin)
        config=value.model_dump(exclude={'name','hours','allowed_ip_networks','authorization_source'})
        # Persist only sanitized import structure. HAR cookies, bodies and headers never enter the job.
        config.update(repository=str(repository),origin=origin,routes=imported_routes(value.routes,origin),scope=scope.model_dump(mode='json'))
        job_id,project_id=uuid4(),uuid4()
        with Session(self.engine) as session,session.begin():
            session.add(Project(id=project_id,name=value.name));session.flush()
            session.add(WorkbenchJob(id=job_id,project_id=project_id,name=value.name,status='draft',config=config))
            SessionAuditSink(session).record(dict(call_id=str(job_id),tool_name='workbench.create',actor=value.actor,target_type='web',status='succeeded',args_hash=digest(config)))
        return self.detail(job_id)

    def list(self):
        with Session(self.engine) as session:
            jobs=list(session.scalars(select(WorkbenchJob).order_by(WorkbenchJob.created_at.desc()).limit(100)))
            return dict(jobs=[dict(id=str(j.id),name=j.name,status=j.status,origin=j.config['origin'],created_at=j.created_at.isoformat(),
                observation_count=len((j.result or {}).get('observations',[]))) for j in jobs],
                capabilities=dict(post=True,auth=['bearer','cookie'],browser='HAR import',agents='model and deterministic modes',local_only=True))

    def detail(self,identifier):
        identifier=UUID(str(identifier))
        with Session(self.engine) as session:
            row=session.get(WorkbenchJob,identifier)
            if row is None: raise ValueError('任务不存在')
            steps=list(session.scalars(select(DurableStep).where(DurableStep.workflow_id.in_([identifier,uuid5(identifier,'repository')])).order_by(DurableStep.created_at)))
            details=[]
            for step in steps:
                payload=step.payload or {}
                preview=None
                if step.stage.startswith(('http_','mcp_')) and step.status=='completed':
                    preview=dict(status_code=payload.get('status_code'),sha256=payload.get('sha256'),body=payload.get('body','')[:1200],truncated=payload.get('truncated'),headers=payload.get('headers',{}),tool_id=payload.get('tool_id'),requests_used=payload.get('requests_used'))
                if step.stage.startswith(('plan_','critic_','approval_','tool_routing','external_recon')): preview=payload
                details.append(dict(stage=step.stage,status=step.status,attempt=step.attempt,operation_id=str(step.id),workflow_id=str(step.workflow_id),preview=preview))
            return dict(id=str(row.id),project_id=str(row.project_id),name=row.name,status=row.status,config=row.config,result=row.result,
                stages=[d for d in details if d['workflow_id']==str(identifier)],child_stages=[d for d in details if d['workflow_id']!=str(identifier)])

    def start(self,identifier):
        identifier=UUID(str(identifier))
        with self.mutex:
            if identifier in self.active and not self.active[identifier].done(): return self.detail(identifier)
            if sum(not f.done() for f in self.active.values())>=2: raise ValueError('已有两个任务运行，请稍后继续')
            with Session(self.engine) as session,session.begin():
                row=session.get(WorkbenchJob,identifier)
                if row is None: raise ValueError('任务不存在')
                if row.status in {'finished','denied','aborted'}: return self.detail(identifier)
                row.status='queued'
            self.active[identifier]=self.pool.submit(self._run,identifier)
        return self.detail(identifier)

    def _run(self,identifier):
        with Session(self.engine) as session,session.begin():
            row=session.get(WorkbenchJob,identifier);row.status='running';row.updated_at=datetime.now(timezone.utc)
            session.flush();session.expunge(row)
        try:
            result=self.runner(self.engine,row,self.settings,self.vault).run()
        except Exception as exc:
            import traceback
            traceback.print_exc()  # local operator log only; the job message stays generic
            result=dict(status='unknown',error_type=type(exc).__name__,message='执行未完成。查看阶段记录；未知外部调用不会自动重发。')
            if type(exc) is ValueError: result['message']=str(exc)[:300]
        with Session(self.engine) as session,session.begin():
            saved=session.get(WorkbenchJob,identifier)
            saved.status=result['status'];saved.result=result;saved.updated_at=datetime.now(timezone.utc)

    def decide(self,identifier,approval_id,approved):
        if type(approved) is not bool: raise ValueError('invalid decision')
        job=self.detail(identifier);scan=uuid5(UUID(job['id']),'unified-scan')
        from vulnmind.security.approvals import ApprovalService
        from vulnmind.security.approval_tokens import ApprovalTokenSigner
        if not self.settings.approval_secret: raise ValueError('本机 HMAC 审批密钥未配置')
        signer=ApprovalTokenSigner(self.settings.approval_secret)
        with Session(self.engine) as session,session.begin():
            row=session.get(Approval,UUID(approval_id))
            if row is None or row.scan_id!=scan or row.action!='unified.requests': raise ValueError('审批不属于当前任务')
            token=signer.sign(approval_id=row.id,scan_id=row.scan_id,action=row.action,target=row.target,
                expires_at=row.expires_at,operation_hash=row.operation_hash,approved=approved)
            ApprovalService(session,signer=signer).decide(row.id,approver=job['config']['actor'],approved=approved,credential=token)
            SessionAuditSink(session).record(dict(call_id=str(row.id),tool_name='workbench.approval',actor=job['config']['actor'],target_type='web',
                status='succeeded',args_hash=digest(dict(approved=approved,plan=row.operation_hash))))
        return self.start(identifier)

    def recover(self,identifier,data):
        job=self.detail(identifier);identifier=UUID(str(identifier))
        if data.get('action') not in {'retry','abort'}: raise ValueError('invalid recovery action')
        with self.mutex:
            if identifier in self.active and not self.active[identifier].done(): raise ValueError('请等待正在执行的任务结束')
        workflow_id=UUID(data.get('workflow_id') or str(identifier))
        if workflow_id not in {identifier,uuid5(identifier,'repository')}: raise ValueError('恢复阶段不属于当前调查')
        recover_step(self.engine,workflow_id,data['stage'],data['action'],job['config']['actor'],data.get('reason',''),data.get('acknowledged') is True)
        if data['action']=='abort':
            with Session(self.engine) as session,session.begin():
                session.get(WorkbenchJob,identifier).status='aborted'
                scan=session.get(Scan,uuid5(identifier,'unified-scan'))
                if scan: scan.status='aborted'
            return self.detail(identifier)
        return self.start(identifier)

    def verify(self,identifier):
        """Read-only report, evidence and journal verification; never sends requests."""
        from vulnmind.workbench.integrity import verify_job
        return verify_job(self,UUID(str(identifier)))

    def close(self):
        self.pool.shutdown(wait=False,cancel_futures=True)
        if hasattr(self,'demo_process') and self.demo_process.poll() is None:
            self.demo_process.communicate(input='stop\n',timeout=10)
