"""Read-only repository access for the repository analysis pipeline.

Every path is resolved and re-checked against the authorized repository root
before the file is opened, so ``..``, absolute paths and links that escape the
root are refused. Files are capped and binary content is rejected. This is a
policy layer, not a filesystem sandbox: a race between the check and the open
is still possible, and the caller's process keeps its own file access rights.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PureWindowsPath
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vulnmind.schemas import Authorization, Target, TargetType
from vulnmind.security.scope import ScopeDenied, check_target
from vulnmind.tools.registry import AuditSink

_LANGUAGES = {
    ".py": "python", ".pyi": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java", ".kt": "kotlin",
    ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php", ".cs": "csharp",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp",
    ".swift": "swift", ".scala": "scala", ".sh": "shell", ".ps1": "powershell",
    ".sql": "sql", ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".toml": "toml",
    ".xml": "xml", ".html": "html", ".css": "css", ".md": "markdown", ".tf": "terraform",
    ".dockerfile": "dockerfile", ".gradle": "groovy", ".lua": "lua", ".pl": "perl",
}
_SKIPPED_DIRECTORIES = {".git", ".hg", ".svn", ".venv", "node_modules", "__pycache__", "dist", "build", ".mypy_cache", ".pytest_cache"}


class RepoDenied(Exception):
    """The request is outside the authorized repository or is not readable text."""


class RepoFileInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    path: str = Field(min_length=1, max_length=4096)
    max_bytes: int = Field(default=200_000, ge=1, le=1_000_000)

    @field_validator("path")
    @classmethod
    def relative_only(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("path cannot be blank or padded with whitespace")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("path cannot contain control characters")
        raw = Path(value)
        windows = PureWindowsPath(value)
        if (value.startswith(("/", "\\")) or raw.is_absolute() or raw.drive or ".." in raw.parts
                or windows.drive or ".." in windows.parts):
            raise ValueError("path must be relative to the repository root")
        return value


class RepoListInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    directory: str = Field(default=".", max_length=4096)
    max_entries: int = Field(default=200, ge=1, le=1000)
    max_scanned: int = Field(default=10000, ge=1, le=10000)

    @field_validator("directory")
    @classmethod
    def safe_directory_text(cls, value: str) -> str:
        if value and (value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ValueError("directory cannot contain padding or control characters")
        return value


class FileContent(BaseModel):
    model_config = ConfigDict(frozen=True)
    path: str
    language: str
    encoding: str
    size_bytes: int
    sha256: str
    content: str


class FileEntry(BaseModel):
    model_config = ConfigDict(frozen=True)
    path: str
    is_directory: bool
    size_bytes: int


class DirectoryListing(BaseModel):
    model_config = ConfigDict(frozen=True)
    entries: list[FileEntry]
    scanned_entries: int
    truncated: bool


class RepositoryReader:
    def __init__(self, audit: AuditSink):
        self._audit = audit

    def read(self, request: RepoFileInput, *, actor: str, target: Target,
             scope: Authorization) -> FileContent:
        call_id, event = self._begin("repo.read_file", actor, target)
        try:
            root = self._authorized_root(target, scope, actor)
            path = self._authorized_path(request.path, root, scope)
            if not path.is_file():
                raise RepoDenied("path is not a regular file")
            size = path.stat().st_size
            if size > request.max_bytes:
                raise RepoDenied("file exceeds the configured byte limit")
            with path.open("rb") as stream:
                data = stream.read(request.max_bytes + 1)
            if len(data) > request.max_bytes:
                raise RepoDenied("file exceeds the configured byte limit")
        except RepoDenied:
            self._audit.record({**event, "status": "denied"})
            raise
        except BaseException:
            self._audit.record({**event, "status": "failed"})
            raise
        if b"\x00" in data[:8192]:
            self._audit.record({**event, "status": "denied"})
            raise RepoDenied("binary content is not readable")
        encoding = "utf-8"
        try:
            # utf-8-sig strips a leading BOM, which otherwise breaks parsers.
            content = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            encoding = "latin-1"
            content = data.decode("latin-1")
        self._audit.record({**event, "status": "succeeded"})
        return FileContent(path=request.path, language=_language(path.name), encoding=encoding,
                           size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), content=content)

    def list(self, request: RepoListInput, *, actor: str, target: Target,
             scope: Authorization) -> list[FileEntry]:
        return self.list_page(request, actor=actor, target=target, scope=scope).entries

    def list_page(self, request: RepoListInput, *, actor: str, target: Target,
                  scope: Authorization) -> DirectoryListing:
        _, event = self._begin("repo.list_directory", actor, target)
        try:
            root = self._authorized_root(target, scope, actor)
            directory = self._authorized_path(request.directory or ".", root, scope, allow_root=True)
            if not directory.is_dir():
                raise RepoDenied("path is not a directory")
            entries = []
            scanned = 0
            truncated = False
            scan_limit = min(request.max_scanned, request.max_entries * 10 + 1)
            with os.scandir(directory) as iterator:
                for item in iterator:
                    if scanned >= scan_limit:
                        truncated = True
                        break
                    scanned += 1
                    child = Path(item.path)
                    if item.is_dir() and child.name.lower() in _SKIPPED_DIRECTORIES:
                        continue
                    try:
                        resolved = child.resolve(strict=True)
                    except (OSError, RuntimeError):
                        continue
                    if not resolved.is_relative_to(root):
                        continue
                    is_directory = resolved.is_dir()
                    entries.append(FileEntry(path=str(resolved.relative_to(root)).replace("\\", "/"),
                                             is_directory=is_directory,
                                             size_bytes=0 if is_directory else resolved.stat().st_size))
                    if len(entries) > request.max_entries:
                        truncated = True
                        break
            entries.sort(key=lambda item: (item.path.casefold(), item.path))
            entries = entries[:request.max_entries]
        except RepoDenied:
            self._audit.record({**event, "status": "denied"})
            raise
        except BaseException:
            self._audit.record({**event, "status": "failed"})
            raise
        self._audit.record({**event, "status": "succeeded"})
        return DirectoryListing(entries=entries, scanned_entries=scanned, truncated=truncated)

    @staticmethod
    def _authorized_root(target: Target, scope: Authorization, actor: str) -> Path:
        if not actor.strip():
            raise RepoDenied("actor is required")
        if target.type is not TargetType.REPOSITORY:
            raise RepoDenied("repository access requires a repository target")
        check_target(target, scope)
        return Path(target.locator).resolve(strict=True)

    @staticmethod
    def _authorized_path(raw: str, root: Path, scope: Authorization, *, allow_root: bool = False) -> Path:
        parsed, windows = Path(raw), PureWindowsPath(raw)
        if (raw not in (".", "") and (raw.startswith(("/", "\\")) or parsed.is_absolute() or parsed.drive
                                       or ".." in parsed.parts or windows.drive or ".." in windows.parts)):
            raise RepoDenied("path escapes the authorized repository")
        candidate_path = root if raw in (".", "") else root / raw
        try:
            candidate = candidate_path.resolve(strict=True)
        except (OSError, RuntimeError):
            raise RepoDenied("path does not exist") from None
        if candidate == root and not allow_root:
            raise RepoDenied("a file path is required")
        if not candidate.is_relative_to(root):
            raise RepoDenied("path escapes the authorized repository")
        for denied in scope.denied_repository_roots:
            try:
                denied_path = Path(denied).resolve(strict=True)
            except (OSError, RuntimeError):
                raise RepoDenied("invalid denied repository root") from None
            if candidate.is_relative_to(denied_path):
                raise RepoDenied("path is inside a denied path")
        return candidate

    def _begin(self, tool: str, actor: str, target: Target) -> tuple[str, dict]:
        call_id = str(uuid4())
        event = {"call_id": call_id, "tool_name": tool, "actor": actor,
                 "target_type": target.type.value}
        self._audit.record({**event, "status": "requested"})
        return call_id, event


def _language(name: str) -> str:
    lower = name.lower()
    if lower in {"dockerfile", "makefile"}:
        return lower
    return _LANGUAGES.get(Path(lower).suffix, "unknown")
