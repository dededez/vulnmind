from uuid import uuid4

from sqlalchemy import create_engine, delete, select, update
from sqlalchemy.orm import Session

from vulnmind.persistence.audit import DatabaseAuditSink, verify_complete_audit_chain
from vulnmind.persistence.models import AuditEvent


def event(index):
    return dict(call_id=str(uuid4()), tool_name='cache.test.' + str(index), actor='tester',
                target_type='web', status='requested')


def make_engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    AuditEvent.__table__.create(engine)
    return engine


def test_incremental_cache_verifies_only_appended_rows(tmp_path):
    engine = make_engine(tmp_path)
    sink = DatabaseAuditSink(engine)
    for index in range(3):
        sink.record(event(index))
    with engine.connect() as connection:
        first = verify_complete_audit_chain(connection, use_cache=True)
        assert first.valid and first.checked == 3
        again = verify_complete_audit_chain(connection, use_cache=True)
        assert again.valid and again.checked == 3
    for index in range(10, 12):
        sink.record(event(index))
    with engine.connect() as connection:
        grown = verify_complete_audit_chain(connection, use_cache=True)
        assert grown.valid and grown.checked == 5
        assert verify_complete_audit_chain(connection, use_cache=False).checked == 5


def test_cache_rejects_removed_rows(tmp_path):
    engine = make_engine(tmp_path)
    sink = DatabaseAuditSink(engine)
    for index in range(3):
        sink.record(event(index))
    with engine.connect() as connection:
        assert verify_complete_audit_chain(connection, use_cache=True).valid
    with Session(engine) as session, session.begin():
        target = session.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(1)).one()
        session.execute(delete(AuditEvent).where(AuditEvent.id == target.id))
    with engine.connect() as connection:
        report = verify_complete_audit_chain(connection, use_cache=True)
    assert not report.valid and report.reason == 'audit rows removed'


def test_full_pass_detects_tampering_cache_alone_does_not(tmp_path):
    engine = make_engine(tmp_path)
    sink = DatabaseAuditSink(engine)
    for index in range(3):
        sink.record(event(index))
    with engine.connect() as connection:
        assert verify_complete_audit_chain(connection, use_cache=True).valid
    with Session(engine) as session, session.begin():
        middle = session.scalars(select(AuditEvent).order_by(AuditEvent.created_at.asc())).all()[1]
        session.execute(update(AuditEvent).where(AuditEvent.id == middle.id).values(entry_hash='00' * 32))
    with engine.connect() as connection:
        assert not verify_complete_audit_chain(connection, use_cache=False).valid
