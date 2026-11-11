"""Governance tests for repository READ tools routed through the registry."""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from vulnmind.findings import FindingCandidate
from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import ScopeDenied
from vulnmind.tools.registry import Permission, RiskLevel, ToolDefinition, ToolDenied, ToolRegistry
from vulnmind.tools.repo_access import (
    RepositoryAccess, build_repository_registry, read_policy, repository_list_tool, repository_read_tool,
)
from vulnmind.tools.repo_files import RepoFileInput, RepoListInput, RepositoryReader


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


def authorization(root):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)])


def repository(root):
    return Target(type="repository", locator=str(root))


def build_repo(tmp_path):
    (tmp_path / "app.py").write_bytes(b"print('ok')\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "note.md").write_bytes(b"# note\n")
    return tmp_path


def test_default_policy_refuses_read_tools(tmp_path):
    build_repo(tmp_path)
    recorder = Recorder()
    registry = ToolRegistry(recorder)
    registry.register(repository_read_tool(RepositoryReader(recorder)))
    with pytest.raises(ToolDenied, match="operation unavailable"):
        asyncio.run(registry.call("repo.read_file", {"path": "app.py"}, actor="tester",
                                  target=repository(tmp_path), scope=authorization(tmp_path)))
    assert [event["status"] for event in recorder.events] == ["requested", "denied"]


def test_read_policy_allows_only_low_risk_repository_reads(tmp_path):
    build_repo(tmp_path)
    read_tool = repository_read_tool(RepositoryReader(Recorder()))
    assert read_policy(read_tool, repository(tmp_path)) is True
    assert read_policy(read_tool, Target(type="web", locator="https://example.test")) is False
    pure = ToolDefinition(name="pure.example", description="pure", input_schema=RepoFileInput,
                          invoke=repository_read_tool(RepositoryReader(Recorder())).invoke)
    assert read_policy(pure, repository(tmp_path)) is False
    high = ToolDefinition(name="repo.high", description="high", input_schema=RepoFileInput,
                          invoke=read_tool.invoke, permission=Permission.READ, risk_level=RiskLevel.HIGH)
    assert read_policy(high, repository(tmp_path)) is False


def test_governed_registry_reads_and_lists(tmp_path):
    build_repo(tmp_path)
    recorder = Recorder()
    registry = build_repository_registry(RepositoryReader(recorder), recorder)
    content = asyncio.run(registry.call("repo.read_file", {"path": "app.py"}, actor="tester",
                                        target=repository(tmp_path), scope=authorization(tmp_path)))
    assert content.content == "print('ok')\n" and content.language == "python"
    listing = asyncio.run(registry.call("repo.list_directory", {"directory": "."}, actor="tester",
                                        target=repository(tmp_path), scope=authorization(tmp_path)))
    assert [entry.path for entry in listing.entries] == ["app.py", "docs"]
    statuses = [(event["tool_name"], event["status"]) for event in recorder.events]
    assert ("repo.read_file", "succeeded") in statuses
    assert ("repo.list_directory", "succeeded") in statuses


def test_scope_and_target_type_are_enforced(tmp_path):
    build_repo(tmp_path)
    recorder = Recorder()
    registry = build_repository_registry(RepositoryReader(recorder), recorder)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    with pytest.raises(ScopeDenied):
        asyncio.run(registry.call("repo.read_file", {"path": "app.py"}, actor="tester",
                                  target=repository(tmp_path), scope=authorization(allowed)))
    now = datetime.now(timezone.utc)
    web_scope = Authorization(authorization_source="test", approved_by="owner",
                              starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                              web_origins=["https://example.test"])
    with pytest.raises(ToolDenied, match="target type"):
        asyncio.run(registry.call("repo.read_file", {"path": "app.py"}, actor="tester",
                                  target=Target(type="web", locator="https://example.test"),
                                  scope=web_scope))


def test_sync_facade_reads_lists_and_refuses_inside_a_loop(tmp_path):
    build_repo(tmp_path)
    access = RepositoryAccess(RepositoryReader(Recorder()), Recorder())
    content = access.read(RepoFileInput(path="app.py"), actor="tester",
                          target=repository(tmp_path), scope=authorization(tmp_path))
    assert content.path == "app.py"
    page = access.list_page(RepoListInput(directory="docs"), actor="tester",
                            target=repository(tmp_path), scope=authorization(tmp_path))
    assert [entry.path for entry in page.entries] == ["docs/note.md"]

    async def inside_loop():
        with pytest.raises(ToolDenied, match="running event loop"):
            access.read(RepoFileInput(path="app.py"), actor="tester",
                        target=repository(tmp_path), scope=authorization(tmp_path))

    asyncio.run(inside_loop())


def test_pipeline_uses_the_governed_access(tmp_path):
    from vulnmind.analysis.repository import RepositoryPipeline

    build_repo(tmp_path)
    recorder = Recorder()
    reader = RepositoryReader(recorder)
    analyzer = lambda content: [FindingCandidate(  # noqa: E731
        title="stub", vulnerability_type="misconfig", target_id="x",
        location=f"{content.path}:1", source_tool="stub")]
    pipeline = RepositoryPipeline(reader, [analyzer], access=RepositoryAccess(reader, recorder))
    analysis = pipeline.run(scan_id="s", project_id="p", target=repository(tmp_path),
                            scope=authorization(tmp_path), actor="tester")
    assert analysis.files_examined == 2
    governed = [event for event in recorder.events
                if event["tool_name"] == "repo.read_file" and event["status"] == "started"]
    assert len(governed) == 2
