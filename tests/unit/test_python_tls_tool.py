import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from vulnmind.schemas import Authorization, Target
from vulnmind.tools.python_tls import python_tls_tool
from vulnmind.tools.registry import ToolDenied, ToolRegistry


class Audit:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


def test_registry_runs_bounded_pure_analyzer_without_source_in_audit(tmp_path):
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner", starts_at=now-timedelta(hours=1),
                          expires_at=now+timedelta(hours=1), repository_roots=[str(tmp_path)])
    target = Target(type="repository", locator=str(tmp_path))
    audit = Audit()
    registry = ToolRegistry(audit)
    registry.register(python_tls_tool())
    source = 'requests.get("source-secret-value", verify=False)\n'
    output = asyncio.run(registry.call("python.tls_candidates", {"path": "a.py", "source": source},
                                       actor="tester", target=target, scope=scope))
    assert output.locations == ("a.py:1",) and output.status == "unverified"
    assert "source-secret-value" not in output.model_dump_json() + str(audit.events)
    assert all("args_hash" not in event for event in audit.events)
    assert registry.describe()[0]["target_types"] == ["repository"]


def test_registry_hides_invalid_or_unparsable_source(tmp_path):
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner", starts_at=now-timedelta(hours=1),
                          expires_at=now+timedelta(hours=1), repository_roots=[str(tmp_path)])
    target = Target(type="repository", locator=str(tmp_path))
    registry = ToolRegistry(Audit())
    registry.register(python_tls_tool())
    for args in ({"path": "../private.py", "source": "secret-value"},
                 {"path": "a.py", "source": "secret-value invalid syntax :"}):
        with pytest.raises(ToolDenied) as exc:
            asyncio.run(registry.call("python.tls_candidates", args, actor="tester", target=target, scope=scope))
        assert "secret-value" not in str(exc.value)
        assert exc.value.__cause__ is None


def test_registry_rejects_a_web_target_even_when_web_scope_is_authorized():
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner", starts_at=now-timedelta(hours=1),
                          expires_at=now+timedelta(hours=1), web_origins=["https://example.test"])
    registry = ToolRegistry(Audit())
    registry.register(python_tls_tool())
    with pytest.raises(ToolDenied, match="target type"):
        asyncio.run(registry.call("python.tls_candidates", {"path": "a.py", "source": "x = 1"},
                                  actor="tester", target=Target(type="web", locator="https://example.test"),
                                  scope=scope))


def test_database_audit_does_not_store_source_or_argument_hash(tmp_path):
    from sqlalchemy import create_engine, select
    from vulnmind.persistence.audit import DatabaseAuditSink
    from vulnmind.persistence.models import AuditEvent

    engine = create_engine("sqlite://")
    AuditEvent.__table__.create(engine)
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner", starts_at=now-timedelta(hours=1),
                          expires_at=now+timedelta(hours=1), repository_roots=[str(tmp_path)])
    registry = ToolRegistry(DatabaseAuditSink(engine))
    registry.register(python_tls_tool())
    asyncio.run(registry.call("python.tls_candidates", {"path": "a.py", "source": "password = 'private-value'"},
                              actor="tester", target=Target(type="repository", locator=str(tmp_path)), scope=scope))
    with engine.connect() as connection:
        rows = connection.execute(select(AuditEvent.__table__)).mappings().all()
    assert [row["status"] for row in rows] == ["requested", "started", "succeeded"]
    assert all(row["args_hash"] is None for row in rows)
    assert "private-value" not in str(rows)
    engine.dispose()
