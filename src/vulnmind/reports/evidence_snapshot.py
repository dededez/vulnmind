"""Compare v5-v7 report evidence IDs to the current scan's database rows.

This verifies only the listed associations. It does not authenticate the report,
prove a file is intact, or establish that evidence confirms a vulnerability.
"""
from __future__ import annotations

import json
import re
from uuid import UUID

MAX_SNAPSHOT_IDS = 1000
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")


def check_evidence_snapshot(content: str, format: str, scan_id: UUID,
                            current: dict[UUID, str]) -> tuple[str, list[str]]:
    if format != "json":
        return "not_checked", []
    try:
        payload = json.loads(content)
    except (ValueError, TypeError, RecursionError):
        return "invalid", []
    if not isinstance(payload, dict):
        return "invalid", []
    if payload.get("schema_version") not in (5, 6, 7):
        return "not_checked", []
    if payload.get("scan_id") != str(scan_id):
        return "invalid", []
    snapshot = payload.get("evidence_snapshot")
    truncated = payload.get("evidence_snapshot_truncated")
    groups = payload.get("groups")
    if (not isinstance(snapshot, str) or snapshot not in {"available", "unavailable"}
            or not isinstance(truncated, bool) or not isinstance(groups, list)):
        return "invalid", []
    pairs: list[tuple[UUID, str]] = []
    seen: set[UUID] = set()
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("fingerprint"), str):
            return "invalid", []
        fingerprint = group["fingerprint"]
        ids = group.get("stored_evidence_ids")
        if not isinstance(ids, list) or len(ids) > MAX_SNAPSHOT_IDS - len(pairs):
            return "invalid", []
        for raw_id in ids:
            try:
                if not isinstance(raw_id, str):
                    return "invalid", []
                identifier = UUID(raw_id)
            except ValueError:
                return "invalid", []
            if str(identifier) != raw_id or identifier in seen:
                return "invalid", []
            seen.add(identifier)
            pairs.append((identifier, fingerprint))
    if snapshot == "unavailable":
        return ("invalid", []) if pairs or truncated else ("not_checked", [])
    missing = [str(identifier) for identifier, fingerprint in pairs if current.get(identifier) != fingerprint]
    if missing:
        return "broken", missing
    return ("partial" if truncated else "valid"), []


def check_finding_snapshot(content: str, format: str, scan_id: UUID,
                           current: set[str]) -> tuple[str, int, int]:
    """Compare report group identities with current rows, not their truth.

    Counts may change legitimately after a report was written. Legacy reports
    and Markdown are explicitly not checked; no fingerprints are returned.
    """
    if format != "json":
        return "not_checked", 0, 0
    try:
        payload = json.loads(content)
    except (ValueError, TypeError, RecursionError):
        return "invalid", 0, 0
    if not isinstance(payload, dict):
        return "invalid", 0, 0
    if payload.get("schema_version") not in (5, 6, 7):
        return "not_checked", 0, 0
    if payload.get("scan_id") != str(scan_id) or not isinstance(payload.get("groups"), list):
        return "invalid", 0, 0
    fingerprints: set[str] = set()
    for group in payload["groups"]:
        if not isinstance(group, dict):
            return "invalid", 0, 0
        fingerprint = group.get("fingerprint")
        if (not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint)
                or fingerprint in fingerprints):
            return "invalid", 0, 0
        fingerprints.add(fingerprint)
    if any(not isinstance(item, str) or not _FINGERPRINT.fullmatch(item) for item in current):
        return "invalid", 0, 0
    report_only = len(fingerprints - current)
    database_only = len(current - fingerprints)
    return ("incomplete" if report_only or database_only else "valid"), report_only, database_only
