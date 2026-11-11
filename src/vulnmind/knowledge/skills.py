"""Skill discovery and loading (design section 8.2).

A skill is a Markdown file with YAML front matter at ``root/<...>/<name>.md``.
Loading is confined to the configured root: absolute paths and ``..`` are
refused, files are size-capped, and duplicate identifiers are an error rather
than a silent override.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

MAX_SKILL_BYTES = 1_000_000
MAX_SKILL_HEADER_BYTES = 64_000
_REQUIRED = ("skill_id", "name", "version", "target_type")


class SkillError(ValueError):
    """The skill file is missing, unreadable or malformed."""


class SkillMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    skill_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=64)
    target_type: Literal["repository", "web", "both", "network", "cloud", "cluster", "sample", "workspace", "execution", "intelligence"]
    vuln_type: str | None = Field(default=None, max_length=128)
    stage: str | None = Field(default=None, max_length=64)
    risk_level: Literal["low", "medium", "high"] = "low"
    prerequisites: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    path: str

    @field_validator("prerequisites", "tools")
    @classmethod
    def nonblank_entries(cls, value: list[str]) -> list[str]:
        if any(not item.strip() for item in value):
            raise ValueError("skill lists cannot contain blank entries")
        return value


class Skill(SkillMetadata):
    content: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def verify_integrity(self):
        if not self.content.strip() or self.sha256 != skill_digest(self, self.content):
            raise ValueError("skill content and metadata do not match the integrity hash")
        return self


def skill_digest(metadata: SkillMetadata, content: str) -> str:
    """Hash semantic metadata and normalized body, excluding the hash itself."""
    canonical = json.dumps({"metadata": metadata.model_dump(exclude={"content", "sha256"}), "content": content},
                           ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SkillLoader:
    def __init__(self, root: Path):
        self._root = Path(root).resolve(strict=True)
        if not self._root.is_dir():
            raise SkillError("skill root must be a directory")

    @property
    def root(self) -> Path:
        return self._root

    def available(self) -> list[SkillMetadata]:
        skills: dict[str, SkillMetadata] = {}
        for path in sorted(self._root.rglob("*.md")):
            try:
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(self._root):
                    continue
                metadata, _ = self._read(resolved)
            except (SkillError, OSError, RuntimeError):
                continue
            if metadata.skill_id in skills:
                raise SkillError(f"duplicate skill identifier: {metadata.skill_id}")
            skills[metadata.skill_id] = metadata
        return list(skills.values())

    def load(self, skill_id: str) -> Skill:
        if not skill_id.strip():
            raise SkillError("skill identifier is required")
        for metadata in self.available():
            if metadata.skill_id == skill_id:
                try:
                    path = (self._root / metadata.path).resolve(strict=True)
                except (OSError, RuntimeError) as exc:
                    raise SkillError("skill file is unavailable") from exc
                if not path.is_relative_to(self._root):
                    raise SkillError("skill path escapes the configured root")
                metadata, content = self._read(path)
                if metadata.skill_id != skill_id:
                    raise SkillError("skill identity changed during loading")
                return Skill(**metadata.model_dump(), content=content,
                             sha256=skill_digest(metadata, content))
        raise SkillError(f"unknown skill: {skill_id}")

    def select(self, *, target_type: str, vuln_type: str | None = None,
               stage: str | None = None) -> list[SkillMetadata]:
        if target_type not in {"repository", "web", "both", "network", "cloud", "cluster", "sample", "workspace", "execution", "intelligence"}:
            raise SkillError("unknown target type")
        selected = [metadata for metadata in self.available()
                    if metadata.target_type in {target_type, "both"}
                    and (vuln_type is None or metadata.vuln_type == vuln_type)
                    and (stage is None or metadata.stage == stage)]
        return sorted(selected, key=lambda item: (item.stage or "", item.skill_id))

    def _read(self, path: Path) -> tuple[SkillMetadata, str]:
        try:
            path = path.resolve(strict=True)
            if not path.is_relative_to(self._root):
                raise SkillError("skill path escapes the configured root")
            with path.open("rb") as stream:
                data = stream.read(MAX_SKILL_BYTES + 1)
            if len(data) > MAX_SKILL_BYTES:
                raise SkillError("skill file exceeds the size limit")
            # Match text-mode universal newlines on Windows and Unix.
            raw = data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        except (OSError, UnicodeDecodeError, RuntimeError) as exc:
            raise SkillError("skill file cannot be read as UTF-8") from exc
        if not raw.startswith("---\n"):
            raise SkillError("skill file requires YAML front matter")
        _, _, remainder = raw.partition("---\n")
        header, separator, body = remainder.partition("\n---\n")
        if not separator:
            raise SkillError("skill front matter is not terminated")
        if len(header.encode("utf-8")) > MAX_SKILL_HEADER_BYTES:
            raise SkillError("skill front matter exceeds the size limit")
        try:
            if any(isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)) for token in yaml.scan(header)):
                raise SkillError("YAML aliases and anchors are not supported")
            data = yaml.safe_load(header) or {}
        except (yaml.YAMLError, RecursionError) as exc:
            raise SkillError("skill front matter is not valid YAML") from exc
        if not isinstance(data, dict):
            raise SkillError("skill front matter must be a mapping")
        missing = [key for key in _REQUIRED if not str(data.get(key, "")).strip()]
        if missing:
            raise SkillError("skill front matter is missing: " + ", ".join(missing))
        if not body.strip():
            raise SkillError("skill content cannot be blank")
        data["path"] = path.relative_to(self._root).as_posix()
        try:
            return SkillMetadata(**data), body
        except ValidationError as exc:
            raise SkillError("skill metadata is invalid") from exc


class SkillIndexer:
    """Mirror skill metadata into the ``skills`` table; content stays on disk."""

    def __init__(self, session):
        self.session = session

    def load_verified(self, loader: SkillLoader, *, skill_id: str, version: str) -> Skill:
        """Load a snapshot matching an indexed hash; this does not authenticate its author."""
        from sqlalchemy import select
        from vulnmind.persistence.models import SkillRecord

        skill = loader.load(skill_id)
        if skill.version != version:
            raise SkillError("loaded skill version does not match the requested version")
        row = self.session.scalar(select(SkillRecord).where(
            SkillRecord.name == skill_id, SkillRecord.version == version))
        if row is None or not isinstance(row.metadata_, dict) or row.metadata_.get("sha256") != skill.sha256:
            raise SkillError("skill is not indexed with a matching integrity hash")
        return skill

    def sync(self, loader: SkillLoader) -> tuple[int, int]:
        from sqlalchemy import select

        from vulnmind.persistence.models import SkillRecord

        added = updated = 0
        skills = [loader.load(metadata.skill_id) for metadata in loader.available()]
        existing = []
        # Validate the whole batch before mutating rows, even if callers catch errors.
        for skill in skills:
            row = self.session.scalar(select(SkillRecord).where(
                SkillRecord.name == skill.skill_id, SkillRecord.version == skill.version))
            if row is not None and (not isinstance(row.metadata_, dict) or row.metadata_.get("sha256") != skill.sha256):
                raise SkillError("skill version changed or legacy integrity hash is missing")
            existing.append((skill, row))
        for skill, row in existing:
            retained_metadata = dict(row.metadata_) if row is not None else {}
            payload = {"target_type": skill.target_type, "vuln_type": skill.vuln_type,
                       "stage": skill.stage, "content_uri": skill.path,
                       "metadata_": {**retained_metadata, "risk_level": skill.risk_level,
                                     "prerequisites": list(skill.prerequisites),
                                     "tools": list(skill.tools), "sha256": skill.sha256}}
            if row is None:
                from uuid import uuid4
                self.session.add(SkillRecord(id=uuid4(), name=skill.skill_id,
                                             version=skill.version, **payload))
                added += 1
            else:
                for key, value in payload.items():
                    setattr(row, key, value)
                updated += 1
        return added, updated
