"""Local-owner attestation bound to immutable evidence and observation revision.

This records a human verification decision, not a model's assertion. HMAC proves
local key possession; it is not multi-user identity or proof of exploitability.
"""
import hashlib
import hmac
import json
from pathlib import Path
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.orm import Session
from vulnmind.persistence.models import Finding, Evidence, DurableStep, AuditEvent
from vulnmind.persistence.durable import Journal, workflow_lock, digest
from vulnmind.evidence.store import EvidenceStore


def _signature(statement, key):
    return hmac.new(key,b'vulnmind-attestation-v1\n'+json.dumps(statement,sort_keys=True,separators=(',',':')).encode(),hashlib.sha256).hexdigest()


def _validate(session, statement, store):
    finding=session.scalar(select(Finding).where(Finding.id==UUID(statement['finding_id'])).with_for_update())
    if (finding is None or str(finding.scan_id)!=statement['scan_id'] or finding.fingerprint!=statement['fingerprint']
            or finding.observation_revision!=statement['revision'] or not finding.observation_history_complete):
        raise ValueError('finding changed since attestation')
    if not statement['evidence']:
        raise ValueError('attestation requires evidence')
    for item in statement['evidence']:
        row=session.get(Evidence,UUID(item['id']))
        if row is None or row.finding_id!=finding.id or row.hash!=item['hash'] or row.content_ref!=item['uri']:
            raise ValueError('evidence identity changed')
        if hashlib.sha256(store.read(row.content_ref)).hexdigest()!=row.hash:
            raise ValueError('evidence bytes changed')
    return finding


def attest(engine, operation, scan_id, fingerprint, verdict, evidence_ids, actor, reason, evidence_root, key):
    if not isinstance(key,bytes) or len(key)<32:
        raise ValueError('local signing key required')
    if verdict not in {'confirmed','not_reproduced'} or not actor.strip() or not reason.strip() or len(reason)>2000 or len(actor)>255:
        raise ValueError('explicit actor and reason required')
    with workflow_lock(engine,operation):
        with Session(engine) as s:
            finding=s.scalar(select(Finding).where(Finding.scan_id==scan_id,Finding.fingerprint==fingerprint))
            if finding is None:
                raise ValueError('finding missing')
            rows=list(s.scalars(select(Evidence).where(Evidence.id.in_(evidence_ids),Evidence.finding_id==finding.id)))
            if len(rows)!=len(set(evidence_ids)):
                raise ValueError('evidence not owned by finding')
            statement=dict(finding_id=str(finding.id),scan_id=str(scan_id),fingerprint=fingerprint,revision=finding.observation_revision,
                verdict=verdict,actor=actor,reason=reason,evidence=sorted([dict(id=str(r.id),hash=r.hash,uri=r.content_ref) for r in rows],key=lambda r:r['id']))
        journal=Journal(engine,operation,statement,actor)
        def persist(s,value):
            row=_validate(s,statement,EvidenceStore(Path(evidence_root)))
            row.status=verdict
            row.location={**row.location,'attestation_id':str(operation)}
            return value
        result=journal.run('attestation',{},lambda _:dict(statement=statement,signature=_signature(statement,key)),persist=persist,replay_safe=True)
        with Session(engine) as s:
            _validate(s,result['statement'],EvidenceStore(Path(evidence_root)))
        return result


def verified_for_scan(session, scan_id, evidence_root, key):
    output=[]
    for finding in session.scalars(select(Finding).where(Finding.scan_id==scan_id)):
        operation=(finding.location or {}).get('attestation_id')
        if not operation:
            continue
        receipt=session.scalar(select(DurableStep).where(DurableStep.workflow_id==UUID(operation),DurableStep.stage=='attestation'))
        if receipt is None or receipt.status!='completed':
            raise ValueError('attestation receipt unavailable')
        value=receipt.payload
        from vulnmind.persistence.audit import verify_complete_audit_chain
        chain=verify_complete_audit_chain(session.connection())
        seal=digest(dict(input=receipt.input_digest,output=digest(value),attempt=receipt.attempt))
        event=session.scalar(select(AuditEvent.id).where(AuditEvent.call_id==receipt.id,
            AuditEvent.tool_name=='workflow.attestation',AuditEvent.status=='succeeded',AuditEvent.args_hash==seal))
        if not chain.valid or chain.unhashed or not event or digest(value)!=receipt.output_digest:
            raise ValueError('attestation audit seal invalid')
        statement=value['statement']
        if statement['finding_id']!=str(finding.id) or not hmac.compare_digest(value['signature'],_signature(statement,key)):
            raise ValueError('invalid attestation signature')
        _validate(session,statement,EvidenceStore(Path(evidence_root)))
        output.append({**statement,'attestation_id':operation,'interpretation':'local_owner_evidence_bound_verdict'})
    return output
