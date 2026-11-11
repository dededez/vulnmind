import pytest
pytest.importorskip("langgraph.checkpoint.postgres")

from vulnmind.graph.postgres_checkpoint import postgres_checkpointer


def test_setup_is_explicit_and_connection_is_closed(monkeypatch):
    import psycopg
    import langgraph.checkpoint.postgres as module

    events = []
    class Connection:
        def __enter__(self):
            events.append("open")
            return self
        def __exit__(self, *args):
            events.append("close")
    def connect(dsn, **kwargs):
        assert kwargs["autocommit"] is True
        assert kwargs["row_factory"] is not None
        return Connection()
    class Saver:
        def __init__(self, conn, *, serde):
            assert serde is not None
        def setup(self):
            events.append("setup")
    monkeypatch.setattr(psycopg, "connect", connect)
    monkeypatch.setattr(module, "PostgresSaver", Saver)
    with postgres_checkpointer("host=example"):
        events.append("use")
    assert events == ["open", "use", "close"]
    events.clear()
    with postgres_checkpointer("host=example", initialize=True):
        events.append("use")
    assert events == ["open", "setup", "use", "close"]
