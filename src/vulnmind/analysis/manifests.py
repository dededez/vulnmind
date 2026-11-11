"""Parse dependency manifests into a normalised inventory.

Parsing only: no registry lookup, no vulnerability matching and no execution.
Malformed lines are counted and skipped instead of being guessed, and the number
of dependencies per file is capped.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

MAX_DEPENDENCIES = 5000
_NAME_PATTERNS = {
    "pypi": re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?\Z"),
    "npm": re.compile(r"(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*\Z", re.IGNORECASE),
    "go": re.compile(r"[A-Za-z0-9._~/-]+\Z"),
    "cargo": re.compile(r"[A-Za-z0-9_-]+\Z"),
}


class Dependency(BaseModel):
    model_config = ConfigDict(frozen=True)
    name: str = Field(min_length=1, max_length=256)
    version: str | None = Field(default=None, max_length=128)
    ecosystem: str = Field(min_length=1, max_length=32)
    source_file: str = Field(min_length=1, max_length=512)
    scope: str = Field(default="runtime", max_length=32)


class DependencyInventory(BaseModel):
    model_config = ConfigDict(frozen=True)
    dependencies: list[Dependency]
    skipped: int


def parse_manifest(source_file: str, content: str) -> DependencyInventory:
    """Dispatch on the file name; unknown files return an empty inventory."""
    name = Path(source_file).name.lower()
    if name in {"requirements.txt", "requirements-dev.txt", "requirements.in"}:
        return _requirements(source_file, content)
    if name == "package.json":
        return _package_json(source_file, content)
    if name in {"pyproject.toml", "cargo.toml"}:
        return _toml(source_file, content)
    if name == "go.mod":
        return _go_mod(source_file, content)
    return DependencyInventory(dependencies=[], skipped=0)


def _requirements(source_file: str, content: str) -> DependencyInventory:
    dependencies, skipped = [], 0
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name, version = _split_requirement(line)
        if not name or not _valid_name(name, "pypi"):
            skipped += 1
            continue
        dependencies.append(Dependency(name=name, version=version, ecosystem="pypi",
                                       source_file=source_file))
        if len(dependencies) >= MAX_DEPENDENCIES:
            break
    return DependencyInventory(dependencies=dependencies, skipped=skipped)


def _split_requirement(line: str) -> tuple[str, str | None]:
    requirement = line.split(";", 1)[0].strip()
    match = re.search(r"[<>=!~]", requirement)
    if match:
        name = requirement[:match.start()].split("[", 1)[0].strip()
        return name, requirement[match.start():].strip() or None
    name = line.split(";", 1)[0].strip()
    if "[" in name:
        name = name.split("[", 1)[0]
    return name, None


def _package_json(source_file: str, content: str) -> DependencyInventory:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return DependencyInventory(dependencies=[], skipped=1)
    if not isinstance(payload, dict):
        return DependencyInventory(dependencies=[], skipped=1)
    dependencies, skipped = [], 0
    for section, scope in (("dependencies", "runtime"), ("devDependencies", "development")):
        entries = payload.get(section)
        if entries is None:
            continue
        if not isinstance(entries, dict):
            skipped += 1
            continue
        for name, version in entries.items():
            if not isinstance(version, str) or not _valid_name(name, "npm"):
                skipped += 1
                continue
            dependencies.append(Dependency(name=name, version=version, ecosystem="npm",
                                           source_file=source_file, scope=scope))
            if len(dependencies) >= MAX_DEPENDENCIES:
                return DependencyInventory(dependencies=dependencies, skipped=skipped)
    return DependencyInventory(dependencies=dependencies, skipped=skipped)


def _toml(source_file: str, content: str) -> DependencyInventory:
    try:
        payload = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return DependencyInventory(dependencies=[], skipped=1)
    ecosystem = "cargo" if Path(source_file).name.lower() == "cargo.toml" else "pypi"
    groups: list[tuple[str, list]] = []
    project = payload.get("project") if isinstance(payload, dict) else None
    if ecosystem == "cargo":
        for section, scope in (("dependencies", "runtime"), ("dev-dependencies", "development")):
            entries = payload.get(section)
            if isinstance(entries, dict):
                groups.append((scope, [f"{name}=={value}" if isinstance(value, str) else name
                                       for name, value in entries.items()]))
    elif isinstance(project, dict) and isinstance(project.get("dependencies"), list):
        groups.append(("runtime", project["dependencies"]))
    optional = payload.get("project", {}).get("optional-dependencies") if isinstance(project, dict) else None
    if isinstance(optional, dict):
        for key, value in optional.items():
            if isinstance(value, list):
                groups.append((str(key), value))
    dependencies, skipped = [], 0
    for scope, entries in groups:
        for entry in entries:
            if not isinstance(entry, str):
                skipped += 1
                continue
            name, version = _split_requirement(entry.strip())
            if ecosystem == "cargo" and version and version.startswith("=="):
                version = version[2:]
            if not name or not _valid_name(name, "pypi"):
                skipped += 1
                continue
            dependencies.append(Dependency(name=name, version=version, ecosystem=ecosystem,
                                           source_file=source_file, scope=scope))
            if len(dependencies) >= MAX_DEPENDENCIES:
                return DependencyInventory(dependencies=dependencies, skipped=skipped)
    return DependencyInventory(dependencies=dependencies, skipped=skipped)


def _go_mod(source_file: str, content: str) -> DependencyInventory:
    dependencies, skipped = [], 0
    in_block = False
    for raw_line in content.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line == "require (":
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) != 2:
            skipped += 1
            continue
        module, version = parts
        if not _valid_name(module, "go"):
            skipped += 1
            continue
        dependencies.append(Dependency(name=module, version=version, ecosystem="go",
                                       source_file=source_file))
        if len(dependencies) >= MAX_DEPENDENCIES:
            break
    return DependencyInventory(dependencies=dependencies, skipped=skipped)


def _valid_name(name: str, ecosystem: str) -> bool:
    pattern = _NAME_PATTERNS.get(ecosystem)
    return bool(pattern and name and len(name) <= 256 and pattern.fullmatch(name) is not None)

