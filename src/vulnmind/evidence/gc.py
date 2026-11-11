"""Garbage-collect unreferenced evidence files.

Content-addressed files can outlive their database rows when a transaction rolls
back after the bytes were written. This module lists store files that no
``evidence.content_ref`` points at and, only when explicitly asked, deletes the
ones older than a grace period. The public apply path holds the database lock
and uses Windows directory/file handles; standalone deletion remains blocked.
Anything that does not look exactly like a
content-addressed file (link, wrong name, hash mismatch) is never deleted.
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnmind.persistence.models import Evidence

_NAME = re.compile(r"^[0-9a-f]{2}/[0-9a-f]{64}\.[a-z0-9]{1,16}$")
DEFAULT_GRACE_HOURS = 24


class EvidenceGcError(RuntimeError):
    """The store cannot be scanned safely."""


@dataclass(frozen=True)
class GcReport:
    scanned: int
    referenced: int
    orphans: int
    kept_young: int
    unverified: int
    deleted: int
    bytes_deleted: int
    dry_run: bool


def referenced_uris(session: Session) -> set[str]:
    return {row for row in session.scalars(select(Evidence.content_ref)) if row}


def _iter_candidates(root: Path):
    for directory in sorted(root.iterdir()):
        if directory.is_symlink() or not directory.is_dir():
            continue
        if not re.fullmatch(r"[0-9a-f]{2}", directory.name):
            continue
        for path in sorted(directory.iterdir()):
            yield path


def _relative(path: Path, root: Path) -> str | None:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return None


def _is_plain_file(path: Path) -> bool:
    return (path.is_file() and not path.is_symlink()
            and not (hasattr(path, "is_junction") and path.is_junction()))


def _hash_matches(path: Path, digest: str) -> bool:
    hasher = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                hasher.update(chunk)
    except OSError:
        return False
    return hasher.hexdigest() == digest


def scan_store(root: Path, referenced: set[str], *, grace_seconds: float,
               dry_run: bool, now: float | None = None, coordinated: bool = False) -> GcReport:
    if not dry_run and not coordinated:
        raise EvidenceGcError("evidence deletion is disabled until concurrent writers are coordinated")
    if not isinstance(grace_seconds, (int, float)) or isinstance(grace_seconds, bool) or grace_seconds < 0:
        raise ValueError("grace_seconds must be a non-negative number")
    if not root.is_dir():
        raise EvidenceGcError("evidence store root is not a directory")
    moment = time.time() if now is None else now
    scanned = referenced_count = orphans = kept_young = unverified = deleted = bytes_deleted = 0
    for path in _iter_candidates(root):
        relative = _relative(path, root)
        if relative is None:
            continue
        scanned += 1
        if relative in referenced:
            referenced_count += 1
            continue
        if not _NAME.fullmatch(relative) or not _is_plain_file(path):
            unverified += 1
            continue
        digest = Path(relative).stem
        if not _hash_matches(path, digest):
            # A partially written or tampered file: report it, never delete it.
            unverified += 1
            continue
        try:
            modified = path.stat().st_mtime
            size = path.stat().st_size
        except OSError:
            unverified += 1
            continue
        if moment - modified < grace_seconds:
            kept_young += 1
            continue
        orphans += 1
        if not dry_run:
            try:
                from vulnmind.evidence.windows_delete import delete_verified
                removed = delete_verified(root, relative, digest, cutoff=moment-grace_seconds)
                if not removed:
                    continue
            except (OSError, ValueError) as exc:
                raise EvidenceGcError("an orphaned evidence file could not be removed") from exc
            deleted += 1
            bytes_deleted += size
    return GcReport(scanned=scanned, referenced=referenced_count, orphans=orphans,
                    kept_young=kept_young, unverified=unverified, deleted=deleted,
                    bytes_deleted=bytes_deleted, dry_run=dry_run)
