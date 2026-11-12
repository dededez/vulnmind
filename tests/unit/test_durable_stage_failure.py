from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from vulnmind.persistence.durable import Journal, recover_step
from vulnmind.persistence.models import Base, DurableStep


def make_engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'workflow.db'}")
    Base.metadata.create_all(engine)
    return engine


def test_failed_stage_is_recorded_and_can_be_retried(tmp_path):
    engine = make_engine(tmp_path)
    workflow = uuid4()
    journal = Journal(engine, workflow, {'version': 7}, 'tester', 'web')

    def boom(audit):
        raise RuntimeError('isolated broker unavailable')

    with pytest.raises(RuntimeError):
        journal.run('http_probe', {'url': 'http://127.0.0.1/'}, boom)
    with Session(engine) as session:
        row = session.scalar(select(DurableStep).where(DurableStep.workflow_id == workflow))
        assert row.status == 'failed'
        assert row.payload['error_type'] == 'RuntimeError'
        assert 'isolated broker unavailable' in row.payload['error']

    recover_step(engine, workflow, 'http_probe', 'retry', 'tester', 'broker is back', acknowledged=True)
    with Session(engine) as session:
        row = session.scalar(select(DurableStep).where(DurableStep.workflow_id == workflow))
        assert row.status == 'ready'
    assert journal.run('http_probe', {'url': 'http://127.0.0.1/'}, lambda audit: {'ok': True}) == {'ok': True}
    with Session(engine) as session:
        row = session.scalar(select(DurableStep).where(DurableStep.workflow_id == workflow))
        assert row.status == 'completed'


def test_completed_or_ready_stage_cannot_be_recovered(tmp_path):
    engine = make_engine(tmp_path)
    workflow = uuid4()
    journal = Journal(engine, workflow, {'version': 7}, 'tester', 'web')
    journal.run('stage', {}, lambda audit: {'ok': True})
    with pytest.raises(ValueError, match='only interrupted or failed'):
        recover_step(engine, workflow, 'stage', 'retry', 'tester', 'no reason', acknowledged=True)
