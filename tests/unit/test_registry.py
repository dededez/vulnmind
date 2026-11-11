import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import BaseModel, ValidationError
from vulnmind.schemas import Authorization, Target, TargetType
from vulnmind.security.scope import ScopeDenied
from vulnmind.tools.registry import Permission, RiskLevel, ToolDefinition, ToolDenied, ToolRegistry, TransientToolError


class Input(BaseModel):
    number: int


class Output(BaseModel):
    doubled: int


class Audit:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


@pytest.fixture
def setup():
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner", starts_at=now-timedelta(hours=1), expires_at=now+timedelta(hours=1), web_origins=["https://example.test"])
    return scope, Target(type="web", locator="https://example.test"), Audit()


def test_pure_tool_is_validated_and_audited(setup):
    scope, target, audit = setup
    async def double(value):
        return Output(doubled=value.number * 2)
    registry = ToolRegistry(audit)
    registry.register(ToolDefinition("test.double", Input, double, "Test arithmetic"))
    result = asyncio.run(registry.call("test.double", {"number": 2}, actor="tester", target=target, scope=scope))
    assert result.doubled == 4
    assert [event["status"] for event in audit.events] == ["requested", "started", "succeeded"]
    assert len(audit.events[1]["args_hash"]) == 64
    assert "number" not in str(audit.events)


def test_schema_description_reflects_disabled_privileged_tool(setup):
    _, _, audit = setup
    async def fake(value):
        return Output(doubled=value.number * 2)
    registry = ToolRegistry(audit)
    registry.register(ToolDefinition("fake", Input, fake, "No side effects"))
    registry.register(ToolDefinition("network", Input, fake, "Unavailable", permission=Permission.NETWORK))
    descriptions = registry.describe()
    assert descriptions[0]["input_schema"]["properties"]["number"]["type"] == "integer"
    assert descriptions[0]["enabled"] is True
    assert descriptions[1]["enabled"] is False
    assert descriptions[1]["scope_required"] is True


def test_bad_scope_and_schema_do_not_invoke_tool(setup):
    scope, target, audit = setup
    calls = []
    async def tool(value):
        calls.append(value)
        return Output(doubled=1)
    registry = ToolRegistry(audit)
    registry.register(ToolDefinition("test", Input, tool, "Test"))
    with pytest.raises(ValidationError):
        asyncio.run(registry.call("test", {"number": "bad"}, actor="tester", target=target, scope=scope))
    with pytest.raises(ScopeDenied):
        asyncio.run(registry.call("test", {"number": 1}, actor="tester", target=Target(type="web", locator="https://other.test"), scope=scope))
    assert audit.events[-1]["status"] == "denied"
    with pytest.raises(ToolDenied):
        asyncio.run(registry.call("unknown", {}, actor="tester", target=target, scope=scope))
    assert audit.events[-1]["status"] == "denied"
    assert calls == []


def test_timeout_and_audit_start_failure(setup):
    scope, target, audit = setup
    async def slow(value):
        await asyncio.sleep(1)
        return Output(doubled=1)
    registry = ToolRegistry(audit)
    registry.register(ToolDefinition("test", Input, slow, "Test", timeout_seconds=0.01))
    with pytest.raises(TimeoutError):
        asyncio.run(registry.call("test", {"number": 1}, actor="tester", target=target, scope=scope))
    assert audit.events[-1]["status"] == "failed"

    class FailingAudit:
        def record(self, event):
            raise OSError("audit unavailable")
    registry = ToolRegistry(FailingAudit())
    registry.register(ToolDefinition("test", Input, slow, "Test"))
    with pytest.raises(OSError):
        asyncio.run(registry.call("test", {"number": 1}, actor="tester", target=target, scope=scope))


@pytest.mark.parametrize("options", [
    {"permission": Permission.READ}, {"permission": Permission.NETWORK},
    {"permission": Permission.EXECUTE}, {"permission": Permission.WRITE},
    {"risk_level": RiskLevel.MEDIUM}, {"risk_level": RiskLevel.HIGH},
    {"approval_required": True},
])
def test_privileged_tools_remain_blocked(setup, options):
    scope, target, audit = setup
    invoked = []
    async def tool(value):
        invoked.append(True)
        return Output(doubled=1)
    registry = ToolRegistry(audit)
    registry.register(ToolDefinition("test", Input, tool, "Test", **options))
    with pytest.raises(ToolDenied):
        asyncio.run(registry.call("test", {"number": 1}, actor="tester", target=target, scope=scope))
    assert not invoked
    assert audit.events[-1]["status"] == "denied"


def test_cancellation_is_audited(setup):
    scope, target, audit = setup
    started = asyncio.Event()
    async def slow(value):
        started.set()
        await asyncio.sleep(60)
        return Output(doubled=1)
    async def scenario():
        registry = ToolRegistry(audit)
        registry.register(ToolDefinition("test", Input, slow, "Test"))
        task = asyncio.create_task(registry.call("test", {"number": 1}, actor="tester", target=target, scope=scope))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(scenario())
    assert audit.events[-1]["status"] == "cancelled"


def test_only_explicit_idempotent_transient_failures_are_retried(setup):
    scope, target, audit = setup
    attempts = []
    async def flaky(value):
        attempts.append(1)
        if len(attempts) == 1:
            raise TransientToolError()
        return Output(doubled=value.number * 2)
    with pytest.raises(ValueError):
        ToolDefinition("bad", Input, flaky, "Test", max_retries=1)
    registry = ToolRegistry(audit)
    registry.register(ToolDefinition("test", Input, flaky, "Test", idempotent=True, max_retries=1))
    assert asyncio.run(registry.call("test", {"number": 2}, actor="tester", target=target, scope=scope)).doubled == 4
    assert len(attempts) == 2
    assert [event["status"] for event in audit.events] == ["requested", "started", "retrying", "started", "succeeded"]


def test_timeout_is_not_retried(setup):
    scope, target, audit = setup
    attempts = []
    async def slow(value):
        attempts.append(1)
        await asyncio.sleep(1)
        return Output(doubled=1)
    registry = ToolRegistry(audit)
    registry.register(ToolDefinition("test", Input, slow, "Test", timeout_seconds=0.01, idempotent=True, max_retries=1))
    with pytest.raises(TimeoutError):
        asyncio.run(registry.call("test", {"number": 1}, actor="tester", target=target, scope=scope))
    assert len(attempts) == 1


def test_sensitive_tool_omits_argument_hash_and_validation_details(setup):
    scope, target, audit = setup
    async def double(value):
        return Output(doubled=value.number * 2)
    registry = ToolRegistry(audit)
    registry.register(ToolDefinition("sensitive", Input, double, "Test", hash_arguments=False))
    asyncio.run(registry.call("sensitive", {"number": 4}, actor="tester", target=target, scope=scope))
    assert all("args_hash" not in event for event in audit.events)
    with pytest.raises(ToolDenied) as exc:
        asyncio.run(registry.call("sensitive", {"number": "private-source"}, actor="tester", target=target, scope=scope))
    assert "private-source" not in str(exc.value)
    assert "private-source" not in repr(audit.events)


def test_tool_target_type_is_enforced_before_invocation(setup):
    scope, target, audit = setup
    invoked = []
    async def tool(value):
        invoked.append(True)
        return Output(doubled=1)
    registry = ToolRegistry(audit)
    registry.register(ToolDefinition("repo", Input, tool, "Test", target_types=(TargetType.REPOSITORY,)))
    with pytest.raises(ToolDenied, match="target type"):
        asyncio.run(registry.call("repo", {"number": 1}, actor="tester", target=target, scope=scope))
    assert invoked == []
