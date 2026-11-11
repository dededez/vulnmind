"""Content-addressed evidence storage outside the database.

Evidence bytes live under a dedicated root, addressed by their SHA-256 so the
same snippet is stored once. The database keeps only a reference and hash, which
keeps large responses out of the tables and makes the chain verifiable.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class EvidenceError(ValueError):
    """The evidence is too large, missing or resolves outside the store."""


class EvidenceRef(BaseModel):
    model_config = ConfigDict(frozen=True)
    uri: str
    sha256: str
    size_bytes: int


class EvidenceStore:
    def __init__(self, root: Path, *, max_bytes: int = 1_000_000):
        if not 1 <= max_bytes <= 50_000_000:
            raise ValueError("max evidence size must be between 1 and 50 MB")
        self._root = Path(root).resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        self._max_bytes = max_bytes

    @property
    def root(self) -> Path:
        return self._root

    def put(self, content: bytes, *, evidence_type: str = "text") -> EvidenceRef:
        if not isinstance(content, (bytes, bytearray)) or not content:
            raise EvidenceError("evidence content must be non-empty bytes")
        if len(content) > self._max_bytes:
            raise EvidenceError("evidence exceeds the configured size limit")
        digest = hashlib.sha256(content).hexdigest()
        directory = self._root / digest[:2]
        directory.mkdir(exist_ok=True)
        if directory.is_symlink() or (hasattr(directory, "is_junction") and directory.is_junction()):
            raise EvidenceError("evidence directory cannot be a link")
        if directory.resolve(strict=True).parent != self._root:
            raise EvidenceError("evidence directory escapes the store")
        path = directory / f"{digest}.{_suffix(evidence_type)}"
        try:
            # Exclusive creation does not overwrite an existing evidence file.
            # An interrupted write may leave an invalid file, which read rejects.
            with path.open("xb") as stream:
                stream.write(content)
        except FileExistsError:
            pass
        uri = path.relative_to(self._root).as_posix()
        if self.read(uri) != bytes(content):
            raise EvidenceError("existing evidence does not match content")
        return EvidenceRef(uri=uri, sha256=digest,
                           size_bytes=len(content))

    def read(self, uri: str) -> bytes:
        if not uri or Path(uri).is_absolute() or ".." in Path(uri).parts:
            raise EvidenceError("evidence URI must be relative to the store")
        expected_digest = Path(uri).stem
        path = (self._root / uri).resolve(strict=False)
        if not path.is_relative_to(self._root):
            raise EvidenceError("evidence URI escapes the store")
        try:
            with path.open("rb") as stream:
                data = stream.read(self._max_bytes + 1)
        except OSError as exc:
            raise EvidenceError("evidence is missing") from exc
        if len(data) > self._max_bytes:
            raise EvidenceError("evidence exceeds the configured size limit")
        if hashlib.sha256(data).hexdigest() != expected_digest:
            raise EvidenceError("evidence hash does not match its reference")
        return data

    def verify(self, reference: EvidenceRef) -> bool:
        try:
            data = self.read(reference.uri)
            return len(data) == reference.size_bytes and hashlib.sha256(data).hexdigest() == reference.sha256
        except EvidenceError:
            return False


def _suffix(evidence_type: str) -> str:
    cleaned = "".join(character for character in evidence_type.lower() if character.isalnum())
    return (cleaned or "bin")[:16]
