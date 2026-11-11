import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import BaseModel
from sqlalchemy import create_engine, select
from vulnmind.persistence.audit import AuditError, DatabaseAuditSink
from vulnmind.persistence.models import AuditEvent
from vulnmind.schemas import Authorization, Target
from vulnmind.tools.registry import ToolDefinition, ToolRegistry
from vulnmind.tools.http import HttpDenied, HttpRequestInput, HttpRequester
from vulnmind.tools.shell import ShellDenied, ShellExecutor, ShellToolInput


class Input(BaseModel):
    value: int


class Output(BaseModel):
    value: int


def test_database_sink_persists_only_allowlisted_events():
    engine = create_engine("sqlite://")
    AuditEvent.__table__.create(engine)
    sink = DatabaseAuditSink(engine)
    event = {"call_id": str(uuid4()), "tool_name": "fake", "actor": "tester", "target_type": "web", "status": "requested"}
    sink.record(event)
    with pytest.raises(AuditError) as error:
        sink.record({**event, "input": "secret"})
    assert "secret" not in str(error.value)
    with engine.connect() as connection:
        rows = connection.execute(select(AuditEvent.__table__)).mappings().all()
    assert len(rows) == 1
    assert rows[0]["status"] == "requested"


def test_registry_fails_closed_if_audit_database_unavailable():
    engine = create_engine("sqlite://")  # no audit table
    registry = ToolRegistry(DatabaseAuditSink(engine))
    calls = []
    async def fake(value):
        calls.append(value)
        return Output(value=1)
    registry.register(ToolDefinition("fake", Input, fake, "Fake"))
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner", starts_at=now-timedelta(hours=1), expires_at=now+timedelta(hours=1), web_origins=["https://example.test"])
    with pytest.raises(AuditError, match="storage unavailable"):
        asyncio.run(registry.call("fake", {"value": 1}, actor="tester", target=Target(type="web", locator="https://example.test"), scope=scope))
    assert not calls


def test_audit_rejects_control_characters_without_echoing_input():
    engine = create_engine("sqlite://")
    AuditEvent.__table__.create(engine)
    sink = DatabaseAuditSink(engine)
    with pytest.raises(AuditError) as error:
        sink.record({"call_id": str(uuid4()), "tool_name": "fake", "actor": "private\nvalue", "target_type": "web", "status": "requested"})
    assert "private" not in str(error.value)


def test_disabled_http_and_shell_record_denials_in_database():
    engine = create_engine("sqlite://")
    AuditEvent.__table__.create(engine)
    sink = DatabaseAuditSink(engine)
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner", starts_at=now-timedelta(hours=1), expires_at=now+timedelta(hours=1), web_origins=["https://example.test"], repository_roots=[str(Path.cwd())])
    with pytest.raises(HttpDenied):
        HttpRequester(sink).request(HttpRequestInput(url="https://example.test"), actor="tester", target=Target(type="web", locator="https://example.test"), scope=scope)
    with pytest.raises(ShellDenied):
        ShellExecutor(sink).run(ShellToolInput(argv=["example"], cwd=str(Path.cwd()), purpose="test"), actor="tester", target=Target(type="repository", locator=str(Path.cwd())), scope=scope)
    with engine.connect() as connection:
        rows = connection.execute(select(AuditEvent.__table__).order_by(AuditEvent.created_at)).mappings().all()
    assert [row["status"] for row in rows].count("requested") == 2
    assert [row["status"] for row in rows].count("denied") == 2
