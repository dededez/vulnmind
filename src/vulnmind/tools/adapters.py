"""Adapters that normalise scanner output into finding candidates.

Adapters never run the scanners and never promote a tool result to a confirmed
finding: everything they produce is ``unverified``. Secrets found by Gitleaks
are deliberately **not** copied into candidates; only the location and rule are
kept. Malformed documents are rejected, individual unusable results are counted
and skipped instead of being invented.
"""
from __future__ import annotations

import json
from pathlib import Path, PureWindowsPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from vulnmind.findings import FindingCandidate

MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
_LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "unknown"}
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")


class AdapterError(ValueError):
    """The document is not a usable scanner report."""


class AdapterResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    findings: list[FindingCandidate]
    skipped: int
    truncated: bool = False


def parse_sarif(document: str | bytes | dict, *, target_id: str, source_tool: str = "sarif",
                max_results: int = 1000) -> AdapterResult:
    _check_limits(max_results)
    payload = _load(document)
    if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
        raise AdapterError("SARIF document requires a runs array")
    findings: list[FindingCandidate] = []
    skipped = 0
    truncated = False
    for run in payload["runs"]:
        if not isinstance(run, dict):
            skipped += 1
            continue
        tool = _sarif_tool_name(run) or source_tool
        results = run.get("results")
        if not isinstance(results, list):
            if results is not None:
                skipped += 1
            continue
        for result in results:
            if len(findings) >= max_results:
                truncated = True
                break
            candidate = _sarif_candidate(result, target_id=target_id, tool=tool)
            if candidate is None:
                skipped += 1
            else:
                findings.append(candidate)
        if truncated:
            break
    return AdapterResult(findings=findings, skipped=skipped, truncated=truncated)


def parse_gitleaks(document: str | bytes | list, *, target_id: str,
                   max_results: int = 1000) -> AdapterResult:
    _check_limits(max_results)
    payload = _load(document)
    if not isinstance(payload, list):
        raise AdapterError("Gitleaks report must be a JSON array")
    findings: list[FindingCandidate] = []
    skipped = 0
    truncated = False
    for item in payload:
        if len(findings) >= max_results:
            truncated = True
            break
        candidate = _gitleaks_candidate(item, target_id=target_id)
        if candidate is None:
            skipped += 1
        else:
            findings.append(candidate)
    return AdapterResult(findings=findings, skipped=skipped, truncated=truncated)


def _sarif_tool_name(run: dict) -> str | None:
    driver = (run.get("tool") or {}).get("driver") if isinstance(run.get("tool"), dict) else None
    name = (driver or {}).get("name") if isinstance(driver, dict) else None
    return name if isinstance(name, str) and name.strip() else None


def _sarif_candidate(result: Any, *, target_id: str, tool: str) -> FindingCandidate | None:
    if not isinstance(result, dict):
        return None
    rule = result.get("ruleId")
    if not isinstance(rule, str) or not rule.strip():
        rule_object = result.get("rule")
        rule = rule_object.get("id") if isinstance(rule_object, dict) else None
    rule = rule if isinstance(rule, str) and rule.strip() else "unknown-rule"
    message = (result.get("message") or {}).get("text") if isinstance(result.get("message"), dict) else None
    title = message.strip() if isinstance(message, str) and message.strip() else f"SARIF result {rule}"
    location = None
    locations = result.get("locations")
    if not isinstance(locations, list):
        return None
    for item in locations:
        physical = (item or {}).get("physicalLocation") if isinstance(item, dict) else None
        if not isinstance(physical, dict):
            continue
        artifact_location = physical.get("artifactLocation")
        if not isinstance(artifact_location, dict):
            continue
        artifact = artifact_location.get("uri")
        region = physical.get("region") or {}
        if isinstance(artifact, str) and artifact.strip():
            line = region.get("startLine") if isinstance(region, dict) else None
            location = f"{artifact.strip()}:{line}" if isinstance(line, int) and not isinstance(line, bool) and line > 0 else artifact.strip()
            break
    if location is None:
        return None
    level = result.get("level")
    severity = _LEVEL_SEVERITY.get(level, "unknown") if isinstance(level, str) else "unknown"
    return FindingCandidate(title=title[:500], vulnerability_type=rule[:128], target_id=target_id,
                            location=location[:1000], source_tool=tool[:128], severity=severity)


def _gitleaks_candidate(item: Any, *, target_id: str) -> FindingCandidate | None:
    if not isinstance(item, dict):
        return None
    file = item.get("File")
    if not isinstance(file, str) or not file.strip():
        return None
    line = item.get("StartLine")
    location = f"{file.strip()}:{line}" if isinstance(line, int) and not isinstance(line, bool) and line > 0 else file.strip()
    # Description and rule ID are untrusted and can themselves contain a secret.
    return FindingCandidate(title="Potential secret", vulnerability_type="secret", target_id=target_id,
                            location=location[:1000], source_tool="gitleaks", severity="unknown")


def _load(document: str | bytes | dict | list) -> Any:
    if isinstance(document, (dict, list)):
        return document
    if isinstance(document, bytes):
        if len(document) > MAX_DOCUMENT_BYTES:
            raise AdapterError("scanner report exceeds the size limit")
        try:
            return json.loads(document.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise AdapterError("scanner report is not valid UTF-8 JSON") from None
    if isinstance(document, str):
        try:
            length = len(document.encode("utf-8"))
        except UnicodeEncodeError:
            raise AdapterError("scanner report is not valid UTF-8 JSON") from None
        if length > MAX_DOCUMENT_BYTES:
            raise AdapterError("scanner report exceeds the size limit")
        try:
            return json.loads(document)
        except (json.JSONDecodeError, RecursionError):
            raise AdapterError("scanner report is not valid JSON") from None
    raise AdapterError("unsupported scanner report type")


def _check_limits(max_results: int) -> None:
    if isinstance(max_results, bool) or not isinstance(max_results, int) or not 1 <= max_results <= 5000:
        raise AdapterError("max_results must be between 1 and 5000")


def resolve_path(base: Path, value: str) -> Path | None:
    """Return a path under ``base`` or None; used by adapters that reference files."""
    if not value or not value.strip():
        return None
    raw, windows = Path(value), PureWindowsPath(value)
    if raw.is_absolute() or ".." in raw.parts or windows.drive or windows.root or ".." in windows.parts:
        return None
    try:
        root = base.resolve(strict=True)
        resolved = (root / raw).resolve(strict=False)
        return resolved if resolved.is_relative_to(root) else None
    except (OSError, RuntimeError, ValueError):
        return None

_TRIVY_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
                   "LOW": "low", "UNKNOWN": "unknown"}


def parse_trivy(document: str | bytes | dict, *, target_id: str,
                max_results: int = 2000) -> AdapterResult:
    """Convert a Trivy filesystem JSON report into unverified candidates."""
    _check_limits(max_results)
    payload = _load(document)
    if not isinstance(payload, dict):
        raise AdapterError("Trivy report must be a JSON object")
    if "Results" not in payload:
        raise AdapterError("Trivy report has no Results")
    results = payload.get("Results")
    if results is None:
        results = []
    if not isinstance(results, list):
        raise AdapterError("Trivy Results must be a list")
    findings: list[FindingCandidate] = []
    skipped = 0
    truncated = False
    for result in results:
        if not isinstance(result, dict):
            skipped += 1
            continue
        target = result.get("Target") if isinstance(result.get("Target"), str) else ""
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            vulnerabilities = []
        if not isinstance(vulnerabilities, list):
            skipped += 1
            continue
        for item in vulnerabilities:
            if len(findings) >= max_results:
                truncated = True
                break
            if not isinstance(item, dict):
                skipped += 1
                continue
            package = item.get("PkgName")
            installed = item.get("InstalledVersion")
            identifier = item.get("VulnerabilityID")
            if not all(isinstance(value, str) and value.strip() for value in (package, installed, identifier)):
                skipped += 1
                continue
            title = f"{package} {installed}: {identifier}"
            if len(title) > 300:
                title = title[:300]
            location = f"{target or 'repository'}:{package}"
            findings.append(FindingCandidate(
                title=title, vulnerability_type="dependency_vulnerability",
                target_id=target_id, location=location[:512], source_tool="trivy",
                status="unverified",
                severity=_TRIVY_SEVERITY.get(str(item.get("Severity", "")).upper(), "unknown")))
    return AdapterResult(findings=findings, skipped=skipped, truncated=truncated)
