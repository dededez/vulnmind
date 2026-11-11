from uuid import uuid4
from pathlib import Path
import json
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from test_durable_flow import flow
from vulnmind.persistence.models import Finding, Evidence
from vulnmind.analysis.attestation import attest, verified_for_scan


def test_attestation_binds_evidence_revision_and_regenerates_report(flow, monkeypatch):
    flow.run()
    key=b'k'*32
    monkeypatch.setenv('VULNMIND_REPORT_SIGNING_KEY',key.decode())
    monkeypatch.setenv('VULNMIND_REPORT_SIGNING_KEY_FILE','')
    monkeypatch.setenv('VULNMIND_EVIDENCE_ROOT',flow.options['evidence_root'])
    with Session(flow.engine) as s,s.begin():
        from vulnmind.evidence.ingest import ingest_evidence,EvidenceItem
        from vulnmind.evidence.store import EvidenceStore
        row=s.scalar(select(Finding).where(Finding.scan_id==flow.scan_id))
        ingest_evidence(s,EvidenceStore(Path(flow.options['evidence_root'])),scan_id=flow.scan_id,
            items=[EvidenceItem(fingerprint=row.fingerprint,content=b'owned reproduction fixture',locator='test.py:2')])
    with Session(flow.engine) as s:
        finding,evidence=s.execute(select(Finding,Evidence).join(Evidence,Evidence.finding_id==Finding.id)).first()
        fingerprint, eid=finding.fingerprint,evidence.id
    operation=uuid4()
    args=(flow.engine,operation,flow.scan_id,fingerprint,'confirmed',[eid],'local-owner','Manually reproduced on owned fixture',flow.options['evidence_root'],key)
    first=attest(*args)
    assert attest(*args)==first
    with Session(flow.engine) as s,s.begin():
        assert verified_for_scan(s,flow.scan_id,flow.options['evidence_root'],key)[0]['verdict']=='confirmed'
        from vulnmind.reports.regenerate import ReportRegenerator
        from vulnmind.reports.store import ReportStore
        report=ReportRegenerator(s,ReportStore(Path(flow.options['report_root']))).regenerate(flow.scan_id,report_format='json')
        assert json.loads(report.report.content)['attested_counts']['confirmed']==1
    with pytest.raises(ValueError):
        attest(flow.engine,uuid4(),flow.scan_id,fingerprint,'confirmed',[uuid4()],'owner','reviewed',flow.options['evidence_root'],key)
    with Session(flow.engine) as s,s.begin():
        row=s.scalar(select(Finding).where(Finding.fingerprint==fingerprint))
        row.observation_revision+=1
    with Session(flow.engine) as s,pytest.raises(ValueError,match='finding changed'):
        verified_for_scan(s,flow.scan_id,flow.options['evidence_root'],key)
