"""Transaction-scoped coordination for cooperative evidence writers and GC previews."""
from sqlalchemy import text


def lock_evidence_transaction(session):
    """Hold a DB-wide cooperative lock until the caller's outer transaction ends.

    This alone does not cover direct file writes or arbitrary SQL and is not
    sufficient to enable deletion. PostgreSQL requires a fresh statement
    snapshot after waiting, so fixed-snapshot isolation is rejected.
    """
    dialect = session.get_bind().dialect.name
    with session.no_autoflush:
        if dialect == "postgresql":
            isolation = session.execute(text("SHOW transaction_isolation")).scalar_one()
            if isolation.lower() != "read committed":
                raise ValueError("evidence coordination requires READ COMMITTED")
            session.execute(text("SELECT pg_advisory_xact_lock(621842500318)"))
        elif dialect == "sqlite":
            session.execute(text("UPDATE evidence SET id = id WHERE 1 = 0"))
        else:
            raise ValueError("evidence coordination requires PostgreSQL or SQLite")
