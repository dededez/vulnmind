"""Cooperating SQLite writers serialize source invalidation and derived saves."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from vulnmind.memory.manager import MemoryRecord
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import MemoryRecordRow, Project, Scan, ScanTask
from vulnmind.persistence.repositories import MemoryRepository


def test_sqlite_invalidation_waits_for_dependent_write(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'memory.db').as_posix()}", connect_args={"timeout": 10})
    Base.metadata.create_all(engine)
    project_id, scan_id, task_id = uuid4(), uuid4(), uuid4()
    with Session(engine) as session, session.begin():
        session.add(Project(id=project_id, name="test"))
        session.flush()
        session.add(Scan(id=scan_id, project_id=project_id, status="created", mode="test"))
        session.flush()
        session.add(ScanTask(id=task_id, scan_id=scan_id, phase="analysis", status="running"))
    source = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id),
                          content="source", confidence=0.5)
    child = MemoryRecord(level="working", project_id=str(project_id), task_id=str(task_id),
                         content="child", confidence=0.5, source_refs=(f"memory:{source.id}",))
    with Session(engine) as session, session.begin():
        MemoryRepository(session).save(source)
    saved, release, invalidation_started, invalidation_done = Event(), Event(), Event(), Event()
    original_lock = MemoryRepository._lock_project_writes

    def observed_lock(repository, requested_project):
        if repository.session.info.get("observe_invalidation"):
            invalidation_started.set()
        return original_lock(repository, requested_project)

    def save_child():
        with Session(engine) as session, session.begin():
            MemoryRepository(session).save(child)
            session.flush()
            saved.set()
            if not release.wait(10):
                raise RuntimeError("test writer release timed out")

    def invalidate_source():
        if not saved.wait(10):
            raise RuntimeError("test writer did not start")
        with Session(engine) as session, session.begin():
            session.info["observe_invalidation"] = True
            MemoryRepository(session).invalidate(source.id)
        invalidation_done.set()

    with monkeypatch.context() as patcher:
        patcher.setattr(MemoryRepository, "_lock_project_writes", observed_lock)
        with ThreadPoolExecutor(max_workers=2) as pool:
            writer, invalidator = pool.submit(save_child), pool.submit(invalidate_source)
            try:
                assert invalidation_started.wait(10)
                assert not invalidation_done.wait(0.3)
            finally:
                release.set()
            writer.result(timeout=10)
            invalidator.result(timeout=10)
    with Session(engine) as session:
        assert session.get(MemoryRecordRow, source.id).invalidated is True
        assert session.get(MemoryRecordRow, child.id).invalidated is True
    engine.dispose()
