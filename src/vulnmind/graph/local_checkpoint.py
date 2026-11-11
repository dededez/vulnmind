"""Optional SQLite checkpoint for local simulations, not production persistence."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer


@contextmanager
def local_checkpointer(path: Path):
    """Open a trusted local DB. State is plaintext: never include secrets.

    PostgreSQL remains the intended primary backend. This helper exists to
    exercise process restart for non-sensitive planning/simulation state only.
    """
    from langgraph.checkpoint.sqlite import SqliteSaver

    serializer = JsonPlusSerializer(pickle_fallback=False, allowed_msgpack_modules=[])
    connection = sqlite3.connect(str(path), check_same_thread=False)
    try:
        yield SqliteSaver(connection, serde=serializer)
    finally:
        connection.close()
