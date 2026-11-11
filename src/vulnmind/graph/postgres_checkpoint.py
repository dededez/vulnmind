"""PostgreSQL checkpointer integration; requires explicitly configured DSN."""
from contextlib import contextmanager
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer


@contextmanager
def postgres_checkpointer(dsn: str, *, initialize: bool = False):
    """Open a sync checkpointer for a trusted PostgreSQL database.

    Setup creates LangGraph tables and is deliberately opt-in. Checkpoint data
    is plaintext unless the database supplies encryption; don't store secrets.
    DSN is a psycopg connection string, not a SQLAlchemy driver URL.
    """
    import psycopg
    from psycopg.rows import dict_row
    from langgraph.checkpoint.postgres import PostgresSaver

    if not dsn.strip():
        raise ValueError("checkpoint DSN is required")
    serializer = JsonPlusSerializer(pickle_fallback=False, allowed_msgpack_modules=[])
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as connection:
        saver = PostgresSaver(connection, serde=serializer)
        if initialize:
            saver.setup()
        yield saver
