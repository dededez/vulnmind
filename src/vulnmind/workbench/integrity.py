"""Verify the entire local result chain before downloading a workbench report."""
import hashlib
import json
from pathlib import Path
from uuid import UUID,uuid5
from sqlalchemy import select
from sqlalchemy.orm import Session
from vulnmind.persistence.models import WorkbenchJob,DurableStep,AuditEvent,Evidence,Finding,Report
from vulnmind.persistence.durable import digest
from vulnmind.persistence.audit import verify_complete_audit_chain
from vulnmind.reports.store import ReportStore
from vulnmind.evidence.store import EvidenceStore


def verify_job(service,identifier):
    with Session(service.engine) as session:
        row=session.get(WorkbenchJob,identifier)
        if row is None or row.status!='finished': raise ValueError('调查尚未完成，无法校验最终报告')
        result=row.result
        if result.get('schema_version') not in {'workbench-1','workbench-2','workbench-3','workbench-4','workbench-5','workbench-6'}: raise ValueError('unsupported report schema')
        chain=verify_complete_audit_chain(session.connection())
        if not chain.valid or chain.unhashed: raise ValueError('audit chain verification failed')
        steps=list(session.scalars(select(DurableStep).where(DurableStep.workflow_id.in_([identifier,uuid5(identifier,'repository')]))))
        for step in steps:
            if step.status!='completed': raise ValueError('unfinished journal stage')
            receipt=digest(dict(input=step.input_digest,output=digest(step.payload),attempt=step.attempt))
            proof=session.scalar(select(AuditEvent.id).where(AuditEvent.call_id==step.id,AuditEvent.tool_name=='workflow.'+step.stage,
                AuditEvent.status=='succeeded',AuditEvent.args_hash==receipt))
            if digest(step.payload)!=step.output_digest or not proof: raise ValueError('stage receipt verification failed')
        final=next((s.payload for s in steps if s.workflow_id==identifier and s.stage=='report'),None)
        if final!={k:v for k,v in result.items() if k!='status'}: raise ValueError('job result disagrees with final receipt')
        store=ReportStore(Path(service.settings.report_root));content=store.read(result['report_uri'])
        if json.loads(content)!={k:v for k,v in final.items() if k!='report_uri'}: raise ValueError('report identity mismatch')
        report=session.scalar(select(Report).where(Report.scan_id==UUID(final['scan_id']),Report.storage_uri==result['report_uri']))
        if report is None: raise ValueError('report database reference missing')
        if final.get('schema_version') in {'workbench-2','workbench-3','workbench-4','workbench-5','workbench-6'}:
            from vulnmind.knowledge.skills import Skill
            from vulnmind.workbench.knowledge import validate_references
            for index,saved in enumerate(final['knowledge']):
                recorded=next((s.payload for s in steps if s.workflow_id==identifier and s.stage==f'knowledge_{index}'),None)
                if recorded!=saved: raise ValueError('knowledge snapshot link mismatch')
                for skill in saved['skills']: Skill.model_validate(skill)
                for chunk in saved['chunks']:
                    if hashlib.sha256(chunk['content'].encode()).hexdigest()!=chunk['sha256']:
                        raise ValueError('knowledge content hash mismatch')
                for stage in (f'plan_{index}',f'critic_{index}'):
                    value=next((s.payload for s in steps if s.workflow_id==identifier and s.stage==stage),None)
                    if value:
                        validate_references(value['knowledge_refs'],saved)
                        if value.get('mode')=='model' and final['schema_version'] in {'workbench-5','workbench-6'}:
                            from vulnmind.workbench.context_calls import validate_manifest
                            validate_manifest(value,saved,stage)
            snapshots={digest(k):k for k in final['knowledge']}
            for observation in final['observations']:
                if observation['knowledge_snapshot'] not in snapshots: raise ValueError('observation knowledge link missing')
                validate_references(observation['method_refs'],snapshots[observation['knowledge_snapshot']])
        if final.get('schema_version')in {'workbench-3','workbench-4','workbench-5','workbench-6'}:
            routing=next((s.payload for s in steps if s.workflow_id==identifier and s.stage=='tool_routing'),None)
            if final.get('schema_version')in {'workbench-4','workbench-5','workbench-6'}:
                priced=next((s.payload for s in steps if s.workflow_id==identifier and s.stage=='execution_routing'),None)
                routing=priced['routing'] if priced else None
            if routing!=final.get('tool_routing'): raise ValueError('tool routing snapshot mismatch')
        evidence_store=EvidenceStore(Path(service.settings.evidence_root))
        for observation in final['observations']:
            evidence=session.get(Evidence,UUID(observation['evidence_id']))
            finding=session.get(Finding,evidence.finding_id) if evidence else None
            if finding is None or finding.scan_id!=UUID(final['scan_id']) or finding.fingerprint!=observation['fingerprint']:
                raise ValueError('evidence identity mismatch')
            raw=evidence_store.read(evidence.content_ref)
            if hashlib.sha256(raw).hexdigest()!=evidence.hash or json.loads(raw)!={k:v for k,v in observation.items() if k not in {'evidence_id','fingerprint'}}:
                raise ValueError('evidence content mismatch')
            if observation.get('browser') is not None:
                expected=observation['response_hashes'][0]
                browser_step=next((s.payload for s in steps if s.workflow_id==identifier and s.stage==f"browser_{observation['action_id']}"),None)
                if not browser_step or browser_step.get('sha256')!=expected or hashlib.sha256(browser_step.get('body','').encode()).hexdigest()!=expected:
                    raise ValueError('browser evidence link mismatch')
            elif observation.get('kind')=='browser_xss':
                # Browser unavailable: no evidence was produced, so there is nothing to link.
                browser_step=next((s.payload for s in steps if s.workflow_id==identifier and s.stage==f"browser_{observation['action_id']}"),None)
                if not browser_step or not browser_step.get('unavailable'):
                    raise ValueError('browser result without receipt')
            elif observation.get('external_tool'):
                expected=observation['response_hashes'][0]
                mcp_step=next((s.payload for s in steps if s.workflow_id==identifier and s.stage==f"mcp_{observation['action_id']}"),None)
                if not mcp_step or mcp_step['sha256']!=expected or hashlib.sha256(mcp_step['body'].encode()).hexdigest()!=expected:
                    raise ValueError('MCP evidence link mismatch')
            else:
                for i,expected in enumerate(observation['response_hashes']):
                    response=next((s.payload for s in steps if s.workflow_id==identifier and s.stage==f"http_{observation['action_id']}_{i}"),None)
                    if not response or response['sha256']!=expected or hashlib.sha256(response['body'].encode()).hexdigest()!=expected:
                        raise ValueError('HTTP evidence link mismatch')
        signed=False
        if service.settings.report_signing_key or service.settings.report_signing_key_file:
            from vulnmind.reports.signing import resolve_signing_key,verify_bytes
            key,_=resolve_signing_key(key=service.settings.report_signing_key,key_file=service.settings.report_signing_key_file)
            verify_bytes(content.encode(),store.read_signature(result['report_uri']),key=key);signed=True
        return dict(status='verified',report_sha256=hashlib.sha256(content.encode()).hexdigest(),signature_verified=signed,
            evidence_count=len(final['observations']),stage_count=len(steps),audit_valid=True)
