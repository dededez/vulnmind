from uuid import uuid4
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from test_durable_flow import flow
from vulnmind.graph.durable_repository import RepositoryFlow
from vulnmind.persistence.models import DurableStep


def test_skill_snapshot_survives_source_change(flow, tmp_path):
    root = tmp_path/'skills'
    root.mkdir()
    file = root/'tls.md'
    file.write_text('---\nskill_id: tls\nname: TLS review\nversion: "1"\ntarget_type: repository\nvuln_type: tls_certificate_verification_disabled\n---\nCheck certificate verification.', encoding='utf-8')
    options = dict(flow.options, skills=str(root))
    extended = RepositoryFlow(flow.engine, uuid4(), flow.project_id, flow.target, flow.scope, options)
    extended.run(pause_after='knowledge')
    with Session(flow.engine) as s:
        snapshot = s.scalar(select(DurableStep).where(DurableStep.workflow_id==extended.workflow_id, DurableStep.stage=='knowledge')).payload
        assert snapshot['extra_context'][0]['kind']=='skill'
        assert 'certificate' in snapshot['extra_context'][0]['text']
    file.write_text('broken source', encoding='utf-8')
    assert extended.run()['status']=='finished'


def test_validated_memory_selected_only_from_same_project(flow):
    if flow.engine.dialect.name != 'postgresql':
        pytest.skip('memory lineage reads intentionally require timezone-preserving database')
    from vulnmind.memory.manager import MemoryRecord
    from vulnmind.persistence.repositories import MemoryRepository
    extended = RepositoryFlow(flow.engine, uuid4(), flow.project_id, flow.target, flow.scope, dict(flow.options, use_memory=True))
    extended.run(pause_after='initialize')
    with Session(flow.engine) as s, s.begin():
        record=MemoryRecord(level='long_term', project_id=str(flow.project_id), content='Reviewed project TLS context',
            source_refs=(f'scan:{extended.scan_id}',), validated_by='test', confidence=0.0)
        MemoryRepository(s).save(record)
    extended.run(pause_after='knowledge')
    with Session(flow.engine) as s:
        snapshot=s.scalar(select(DurableStep).where(DurableStep.workflow_id==extended.workflow_id,DurableStep.stage=='knowledge')).payload
        assert [x['ref'] for x in snapshot['extra_context']]==[f'memory:{record.id}']
