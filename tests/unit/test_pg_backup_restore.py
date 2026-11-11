"""The drill must fail if any advertised restoration check fails."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location(
    "pg_backup_restore", Path(__file__).resolve().parents[2] / "scripts" / "pg_backup_restore.py")
drill = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drill)


def valid_checks():
    return dict(head="0011", version="0011", before={"counts": {"projects": 1},
                "chain_valid": True, "chain_checked": 3, "chain_head": "abc"}, counts={"projects": 1},
                chain=SimpleNamespace(valid=True, checked=3),
                chain_head="abc", vector=SimpleNamespace(returncode=0, stdout="vector\n"), identities_match=True)


def test_all_checks_must_succeed():
    assert drill._drill_success(**valid_checks())


@pytest.mark.parametrize("field,value", [
    ("head", None), ("version", "older"), ("counts", {}),
    ("before", {"counts": {"projects": 1}, "chain_valid": False, "chain_checked": 3, "chain_head": "abc"}),
    ("before", {"counts": {"projects": 1}, "chain_valid": True, "chain_checked": 0, "chain_head": "abc"}),
    ("chain", SimpleNamespace(valid=False, checked=3)),
    ("chain", SimpleNamespace(valid=True, checked=2)),
    ("chain_head", "changed"),
    ("vector", SimpleNamespace(returncode=1, stdout="vector")),
    ("vector", SimpleNamespace(returncode=0, stdout="")),
    ("identities_match", False),
])
def test_missing_or_failed_check_never_reports_success(field, value):
    checks = valid_checks()
    checks[field] = value
    assert not drill._drill_success(**checks)
