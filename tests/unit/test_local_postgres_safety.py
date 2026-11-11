"""Verify the disposable PostgreSQL cleanup path without deleting test data."""
import importlib.util
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location("local_postgres_script", Path(__file__).resolve().parents[2] / "scripts" / "test_local_postgres.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_cleanup_accepts_only_the_new_test_directory(tmp_path, monkeypatch):
    temporary = (tmp_path / "vulnmind-pg-test-123").resolve()
    temporary.mkdir()
    deleted = []
    monkeypatch.setattr(module.shutil, "rmtree", lambda path: deleted.append(path))
    module._remove_created_test_dir(temporary, tmp_path.resolve())
    assert deleted == [temporary]
    with pytest.raises(RuntimeError, match="unexpected"):
        module._remove_created_test_dir(temporary, tmp_path.parent.resolve())
    other = (tmp_path / "unrelated").resolve()
    other.mkdir()
    with pytest.raises(RuntimeError, match="unexpected"):
        module._remove_created_test_dir(other, tmp_path.resolve())
    assert deleted == [temporary]
