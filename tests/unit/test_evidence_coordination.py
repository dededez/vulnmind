"""Cooperative evidence lock remains held until transaction completion."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from vulnmind.evidence.coordination import lock_evidence_transaction
from vulnmind.persistence.base import Base
import vulnmind.persistence.models  # noqa: F401


def test_sqlite_lock_serializes_writers_until_transaction_ends(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'evidence.db').as_posix()}",
                           connect_args={"timeout": 0.1})
    Base.metadata.create_all(engine)
    with Session(engine) as owner, owner.begin():
        lock_evidence_transaction(owner)
        with pytest.raises(OperationalError):
            with Session(engine) as other, other.begin():
                lock_evidence_transaction(other)
    with Session(engine) as other, other.begin():
        lock_evidence_transaction(other)
    engine.dispose()
