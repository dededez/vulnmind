"""Repository file access through the Tool Registry instead of direct calls.

READ tools touch the filesystem, so they are **not** pure tools: they are
declared with ``Permission.READ`` and only execute when the registry is built
with ``read_policy``. The policy plus the reader's own path checks and audit
records give governance, not operating-system isolation; a race between the
check and the open is still possible.
"""
from __future__ import annotations

from vulnmind.schemas import Authorization, Target, TargetType
from vulnmind.tools.registry import (
    AuditSink, Permission, RiskLevel, ToolContext, ToolDefinition, ToolRegistry,
)
from vulnmind.tools.repo_files import (
    DirectoryListing, FileContent, RepoFileInput, RepoListInput, RepositoryReader,
)


def read_policy(definition: ToolDefinition, target: Target) -> bool:
    """Only low-risk, approval-free READ tools against repository targets."""
    return (definition.permission is Permission.READ
            and definition.risk_level is RiskLevel.LOW
            and not definition.approval_required
            and target.type is TargetType.REPOSITORY)


def repository_read_tool(reader: RepositoryReader) -> ToolDefinition:
    async def invoke(request: RepoFileInput, context: ToolContext) -> FileContent:
        return reader.read(request, actor=context.actor, target=context.target, scope=context.scope)

    return ToolDefinition(
        name="repo.read_file", description="Read one authorized repository text file.",
        input_schema=RepoFileInput, invoke=invoke, permission=Permission.READ,
        risk_level=RiskLevel.LOW, idempotent=True, context_aware=True,
        target_types=(TargetType.REPOSITORY,), timeout_seconds=10)


def repository_list_tool(reader: RepositoryReader) -> ToolDefinition:
    async def invoke(request: RepoListInput, context: ToolContext) -> DirectoryListing:
        return reader.list_page(request, actor=context.actor, target=context.target, scope=context.scope)

    return ToolDefinition(
        name="repo.list_directory", description="List one authorized repository directory page.",
        input_schema=RepoListInput, invoke=invoke, permission=Permission.READ,
        risk_level=RiskLevel.LOW, idempotent=True, context_aware=True,
        target_types=(TargetType.REPOSITORY,), timeout_seconds=10)


def build_repository_registry(reader: RepositoryReader, audit: AuditSink) -> ToolRegistry:
    registry = ToolRegistry(audit, policy=read_policy)
    registry.register(repository_read_tool(reader))
    registry.register(repository_list_tool(reader))
    return registry


class RepositoryAccess:
    """Synchronous façade over the governed READ tools."""

    def __init__(self, reader: RepositoryReader, audit: AuditSink):
        self._registry = build_repository_registry(reader, audit)

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    def read(self, request: RepoFileInput, *, actor: str, target: Target,
             scope: Authorization) -> FileContent:
        return self._registry.call_sync("repo.read_file", request.model_dump(), actor=actor,
                                        target=target, scope=scope)

    def list_page(self, request: RepoListInput, *, actor: str, target: Target,
                  scope: Authorization) -> DirectoryListing:
        return self._registry.call_sync("repo.list_directory", request.model_dump(), actor=actor,
                                        target=target, scope=scope)
