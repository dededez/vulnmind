import json
from uuid import uuid4

import pytest

from vulnmind.reports.evidence_snapshot import check_evidence_snapshot, check_finding_snapshot


def test_snapshot_associations_and_compatibility():
    scan_id, record_id = uuid4(), uuid4()
    payload = {"schema_version": 5, "scan_id": str(scan_id), "evidence_snapshot": "available",
               "evidence_snapshot_truncated": False,
               "groups": [{"fingerprint": "finding-a", "stored_evidence_ids": [str(record_id)]}]}
    content = json.dumps(payload)
    assert check_evidence_snapshot(content, "json", scan_id, {record_id: "finding-a"}) == ("valid", [])
    payload["schema_version"] = 6
    assert check_evidence_snapshot(json.dumps(payload), "json", scan_id, {record_id: "finding-a"}) == ("valid", [])
    payload["schema_version"] = 7
    assert check_evidence_snapshot(json.dumps(payload), "json", scan_id, {record_id: "finding-a"}) == ("valid", [])
    payload["schema_version"] = 5
    assert check_evidence_snapshot(content, "json", scan_id, {record_id: "different"}) == ("broken", [str(record_id)])
    assert check_evidence_snapshot(content, "markdown", scan_id, {}) == ("not_checked", [])
    payload["evidence_snapshot_truncated"] = True
    assert check_evidence_snapshot(json.dumps(payload), "json", scan_id, {record_id: "finding-a"}) == ("partial", [])
    payload["schema_version"] = 4
    assert check_evidence_snapshot(json.dumps(payload), "json", scan_id, {}) == ("not_checked", [])


@pytest.mark.parametrize("update", [
    {"evidence_snapshot": []},
    {"evidence_snapshot_truncated": "false"},
    {"groups": [{"fingerprint": "x", "stored_evidence_ids": ["not-a-uuid"]}]},
    {"groups": [{"fingerprint": "x", "stored_evidence_ids": ["x"] * 1001}]},
])
def test_malformed_v5_snapshot_is_invalid(update):
    scan_id = uuid4()
    payload = {"schema_version": 5, "scan_id": str(scan_id), "evidence_snapshot": "available",
               "evidence_snapshot_truncated": False, "groups": []}
    payload.update(update)
    assert check_evidence_snapshot(json.dumps(payload), "json", scan_id, {}) == ("invalid", [])


def test_finding_snapshot_detects_both_directions_of_drift():
    scan_id = uuid4()
    report_fingerprint, database_fingerprint = "a" * 64, "b" * 64
    payload = {"schema_version": 6, "scan_id": str(scan_id),
               "groups": [{"fingerprint": report_fingerprint}]}
    content = json.dumps(payload)
    assert check_finding_snapshot(content, "json", scan_id, {report_fingerprint}) == ("valid", 0, 0)
    assert check_finding_snapshot(content, "json", scan_id, {database_fingerprint}) == ("incomplete", 1, 1)
    assert check_finding_snapshot(content, "markdown", scan_id, set()) == ("not_checked", 0, 0)
    payload["groups"].append({"fingerprint": report_fingerprint})
    assert check_finding_snapshot(json.dumps(payload), "json", scan_id, set()) == ("invalid", 0, 0)
