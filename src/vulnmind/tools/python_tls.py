"""Registry adapter for bounded, in-memory Python TLS candidate analysis.

No file, network, or process access occurs here. The caller provides source
text; findings are not tied to an authenticated source and remain unverified.
"""
from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vulnmind.analysis.python_tls import MAX_PYTHON_CHARACTERS, find_python_tls_candidates
from vulnmind.schemas import TargetType
from vulnmind.tools.registry import ToolDefinition, ToolDenied
from vulnmind.tools.repo_files import FileContent, RepoFileInput


class PythonTlsInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    path: str = Field(min_length=1, max_length=4096)
    source: str = Field(min_length=1, max_length=MAX_PYTHON_CHARACTERS)

    @field_validator("path")
    @classmethod
    def python_relative_path(cls, value: str) -> str:
        RepoFileInput(path=value)
        if not value.casefold().endswith((".py", ".pyi")):
            raise ValueError("a relative Python file path is required")
        return value


class PythonTlsOutput(BaseModel):
    model_config = ConfigDict(frozen=True)
    locations: tuple[str, ...]
    status: str = "unverified"
    limitations: tuple[str, ...] = (
        "Only literal verify=False on selected requests/httpx calls is inspected.",
        "Aliases, variable shadowing, data flow, runtime behavior, and source authenticity are not verified.",
    )


async def _invoke(value: PythonTlsInput) -> PythonTlsOutput:
    try:
        data = value.source.encode("utf-8")
        content = FileContent(path=value.path, language="python", encoding="utf-8", size_bytes=len(data),
                              sha256=hashlib.sha256(data).hexdigest(), content=value.source)
        candidates = find_python_tls_candidates(content)
    except (ValueError, UnicodeError, RecursionError):
        # Syntax errors can include source snippets; do not expose exception details.
        raise ToolDenied("Python TLS analysis failed") from None
    return PythonTlsOutput(locations=tuple(candidate.location for candidate in candidates))


def python_tls_tool() -> ToolDefinition:
    """Create the pure adapter; registration does not authorize repository reads."""
    return ToolDefinition(name="python.tls_candidates", input_schema=PythonTlsInput, invoke=_invoke,
                          description="Find a limited TLS verification pattern in provided Python text.",
                          hash_arguments=False, target_types=(TargetType.REPOSITORY,))
