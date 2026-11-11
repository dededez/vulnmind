"""Content-addressed report storage.

The database keeps a reference and hash; the report body lives under a dedicated
root. Writes are exclusive and verified before the reference is returned, so a
partially written report is never reported as stored.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict


class ReportStoreError(ValueError):
    """The report is too large, missing, or resolves outside the store."""


class ReportRef(BaseModel):
    model_config = ConfigDict(frozen=True)
    uri: str
    sha256: str
    size_bytes: int
    format: str


class ReportStore:
    def __init__(self, root: Path, *, max_bytes: int = 5_000_000):
        if not 1 <= max_bytes <= 50_000_000:
            raise ValueError("max report size must be between 1 and 50 MB")
        self._root = Path(root).resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        self._max_bytes = max_bytes

    @property
    def root(self) -> Path:
        return self._root

    def put(self, content: str, *, format: str) -> ReportRef:
        if format not in {"markdown", "json"}:
            raise ReportStoreError("unsupported report format")
        data = content.encode("utf-8")
        if not data:
            raise ReportStoreError("report content cannot be empty")
        if len(data) > self._max_bytes:
            raise ReportStoreError("report exceeds the configured size limit")
        digest = hashlib.sha256(data).hexdigest()
        directory = self._root / digest[:2]
        directory.mkdir(exist_ok=True)
        if directory.is_symlink() or (hasattr(directory, "is_junction") and directory.is_junction()):
            raise ReportStoreError("report directory cannot be a link")
        if directory.resolve(strict=True).parent != self._root:
            raise ReportStoreError("report directory escapes the store")
        suffix = "md" if format == "markdown" else "json"
        path = directory / f"{digest}.{suffix}"
        try:
            # Never replace an existing report or another writer's temporary file.
            with path.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            pass
        uri = path.relative_to(self._root).as_posix()
        if path.is_symlink() or self.read(uri) != content:
            raise ReportStoreError("stored report does not match its content")
        return ReportRef(uri=uri, sha256=digest,
                         size_bytes=len(data), format=format)

    def read(self, uri: str, *, max_bytes: int | None = None) -> str:
        if not uri or Path(uri).is_absolute() or ".." in Path(uri).parts:
            raise ReportStoreError("report URI must be relative to the store")
        if max_bytes is not None and (isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1):
            raise ReportStoreError("report read limit must be a positive integer")
        expected_digest = Path(uri).stem
        path = (self._root / uri).resolve(strict=False)
        if not path.is_relative_to(self._root):
            raise ReportStoreError("report URI escapes the store")
        limit = self._max_bytes if max_bytes is None else min(max_bytes, self._max_bytes)
        try:
            with path.open("rb") as handle:
                data = handle.read(limit + 1)
        except OSError as exc:
            raise ReportStoreError("report is missing") from exc
        if len(data) > limit:
            raise ReportStoreError("report exceeds the configured size limit")
        if hashlib.sha256(data).hexdigest() != expected_digest:
            raise ReportStoreError("report hash does not match its reference")
        return data.decode("utf-8")

    def put_signature(self, uri: str, payload: str) -> str:
        """Store a detached signature beside an existing, verified report.

        The report is read first so a signature cannot be attached to a report
        whose bytes do not match the store. An existing signature is never
        replaced: signing again with another key fails instead of silently
        invalidating the earlier claim.
        """
        if not isinstance(payload, str) or not payload.strip():
            raise ReportStoreError("signature payload cannot be empty")
        if len(payload.encode("utf-8")) > 4096:
            raise ReportStoreError("signature payload is too large")
        self.read(uri)
        path = self._signature_path(uri)
        directory = path.parent
        if directory.is_symlink() or (hasattr(directory, "is_junction") and directory.is_junction()):
            raise ReportStoreError("signature directory cannot be a link")
        try:
            with path.open("xb") as handle:
                handle.write(payload.encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            if self.read_signature(uri) != payload:
                raise ReportStoreError("a different signature already exists for this report") from None
        return path.relative_to(self._root).as_posix()

    def read_signature(self, uri: str) -> str | None:
        """Return the stored signature text, or None when none was written."""
        path = self._signature_path(uri)
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ReportStoreError("signature cannot be a link")
        try:
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "rb") as handle:
                data = handle.read(4097)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ReportStoreError("signature is unreadable") from exc
        if len(data) > 4096:
            raise ReportStoreError("signature exceeds the size limit")
        try:
            return data.decode("utf-8")
        except UnicodeError:
            raise ReportStoreError("signature is not UTF-8 text") from None

    def _signature_path(self, uri: str) -> Path:
        if not uri or Path(uri).is_absolute() or ".." in Path(uri).parts:
            raise ReportStoreError("report URI must be relative to the store")
        path = (self._root / uri).resolve(strict=False)
        if not path.is_relative_to(self._root) or path == self._root:
            raise ReportStoreError("report URI escapes the store")
        signature = path.with_suffix(".sig")
        if not signature.is_relative_to(self._root):
            raise ReportStoreError("signature path escapes the store")
        return signature
