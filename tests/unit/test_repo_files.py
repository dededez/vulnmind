"""Boundary tests for the read-only repository adapter."""
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import ScopeDenied
from vulnmind.tools.repo_files import RepoDenied, RepoFileInput, RepoListInput, RepositoryReader


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


def authorization(root, *, denied=()):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)], denied_repository_roots=list(denied))


def repository(root):
    return Target(type="repository", locator=str(root))


def reader():
    return RepositoryReader(Recorder())


def test_reads_source_file_with_language_and_hash(tmp_path):
    source = tmp_path / "app.py"
    source.write_bytes(b"print('hello')\n")
    content = reader().read(RepoFileInput(path="app.py"), actor="tester",
                            target=repository(tmp_path), scope=authorization(tmp_path))
    assert content.language == "python" and content.encoding == "utf-8"
    assert content.content == "print('hello')\n"
    assert content.size_bytes == len(content.content.encode())
    assert content.sha256 == __import__("hashlib").sha256(source.read_bytes()).hexdigest()


def test_utf8_bom_is_stripped_from_decoded_content(tmp_path):
    # Windows editors and PowerShell 5.1 write a UTF-8 BOM; leaving it in breaks
    # Python parsers downstream.
    source = tmp_path / "bom.py"
    source.write_bytes(b"\xef\xbb\xbfprint('hello')\n")
    content = reader().read(RepoFileInput(path="bom.py"), actor="tester",
                            target=repository(tmp_path), scope=authorization(tmp_path))
    assert content.content == "print('hello')\n"
    assert content.encoding == "utf-8"


def test_reads_nested_path_and_maps_extension(tmp_path):
    nested = tmp_path / "src" / "lib"
    nested.mkdir(parents=True)
    (nested / "main.go").write_text("package main\n", encoding="utf-8")
    content = reader().read(RepoFileInput(path="src/lib/main.go"), actor="tester",
                            target=repository(tmp_path), scope=authorization(tmp_path))
    assert content.language == "go"


def test_path_traversal_and_absolute_paths_are_rejected():
    for bad in ("../secret.txt", "..\\secret.txt", "src/../../secret.txt", "C:\\Windows\\win.ini", "/etc/passwd"):
        with pytest.raises(ValidationError):
            RepoFileInput(path=bad)


def test_missing_file_and_directory_are_refused(tmp_path):
    (tmp_path / "folder").mkdir()
    with pytest.raises(RepoDenied, match="does not exist"):
        reader().read(RepoFileInput(path="missing.txt"), actor="tester",
                      target=repository(tmp_path), scope=authorization(tmp_path))
    with pytest.raises(RepoDenied, match="not a regular file"):
        reader().read(RepoFileInput(path="folder"), actor="tester",
                      target=repository(tmp_path), scope=authorization(tmp_path))


def test_size_limit_is_enforced(tmp_path):
    (tmp_path / "big.txt").write_text("x" * 100, encoding="utf-8")
    with pytest.raises(RepoDenied, match="byte limit"):
        reader().read(RepoFileInput(path="big.txt", max_bytes=10), actor="tester",
                      target=repository(tmp_path), scope=authorization(tmp_path))


def test_binary_content_is_refused(tmp_path):
    (tmp_path / "image.bin").write_bytes(b"\x89PNG\x00\x00binary")
    with pytest.raises(RepoDenied, match="binary"):
        reader().read(RepoFileInput(path="image.bin"), actor="tester",
                      target=repository(tmp_path), scope=authorization(tmp_path))


def test_non_utf8_falls_back_to_latin1(tmp_path):
    (tmp_path / "legacy.txt").write_bytes(b"caf\xe9")
    content = reader().read(RepoFileInput(path="legacy.txt"), actor="tester",
                            target=repository(tmp_path), scope=authorization(tmp_path))
    assert content.encoding == "latin-1" and content.content == "café"


def test_denied_root_inside_repository_fails_the_target_check(tmp_path):
    denied = tmp_path / "vendor"
    denied.mkdir()
    (denied / "secret.py").write_text("token = 'x'\n", encoding="utf-8")
    with pytest.raises(ScopeDenied, match="overlaps an explicitly denied path"):
        reader().read(RepoFileInput(path="vendor/secret.py"), actor="tester",
                      target=repository(tmp_path), scope=authorization(tmp_path, denied=[str(denied)]))


def test_web_target_is_refused(tmp_path):
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner",
                          starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                          web_origins=["https://example.test"])
    with pytest.raises(RepoDenied, match="repository target"):
        reader().read(RepoFileInput(path="app.py"), actor="tester",
                      target=Target(type="web", locator="https://example.test"), scope=scope)


def test_listing_skips_ignored_directories_and_stays_inside_root(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "README.md").write_text("# readme\n", encoding="utf-8")
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    entries = reader().list(RepoListInput(), actor="tester",
                            target=repository(tmp_path), scope=authorization(tmp_path))
    assert [entry.path for entry in entries] == ["README.md", "src"]
    assert entries[1].is_directory is True
    with pytest.raises(RepoDenied, match="escapes"):
        reader().list(RepoListInput(directory=".."), actor="tester",
                      target=repository(tmp_path), scope=authorization(tmp_path))


def test_listing_respects_max_entries(tmp_path):
    for index in range(5):
        (tmp_path / f"file{index}.txt").write_text("x", encoding="utf-8")
    entries = reader().list(RepoListInput(max_entries=2), actor="tester",
                            target=repository(tmp_path), scope=authorization(tmp_path))
    assert len(entries) == 2


def test_listing_rejects_absolute_path_even_inside_root(tmp_path):
    with pytest.raises(RepoDenied, match="escapes"):
        reader().list(RepoListInput(directory=str(tmp_path)), actor="tester",
                      target=repository(tmp_path), scope=authorization(tmp_path))


@pytest.mark.parametrize("path", ["C:relative.txt", "..\\outside.txt", "C:\\absolute.txt"])
def test_file_input_rejects_windows_path_forms_on_all_platforms(path):
    with pytest.raises(ValidationError):
        RepoFileInput(path=path)


def test_read_enforces_limit_if_file_grows_after_stat(tmp_path, monkeypatch):
    import builtins
    from pathlib import Path
    path = tmp_path / "growing.txt"
    path.write_bytes(b"small")
    original = Path.open
    def grow_then_open(candidate, mode="r", *args, **kwargs):
        if candidate == path and mode == "rb":
            with builtins.open(candidate, "wb") as stream:
                stream.write(b"x" * 32)
        return original(candidate, mode, *args, **kwargs)
    monkeypatch.setattr(Path, "open", grow_then_open)
    audit = Recorder()
    with pytest.raises(RepoDenied, match="byte limit"):
        RepositoryReader(audit).read(RepoFileInput(path="growing.txt", max_bytes=8), actor="tester",
                                     target=repository(tmp_path), scope=authorization(tmp_path))
    assert audit.events[-1]["status"] == "denied"


def test_directory_listing_reports_truncation(tmp_path):
    for index in range(3):
        (tmp_path / f"file{index}.txt").write_text("x", encoding="utf-8")
    result = reader().list_page(RepoListInput(max_entries=2), actor="tester",
                                target=repository(tmp_path), scope=authorization(tmp_path))
    assert len(result.entries) == 2
    assert result.truncated is True
    assert result.scanned_entries == 3


def test_directory_listing_respects_explicit_scan_budget(tmp_path):
    for index in range(4):
        (tmp_path / f"file{index}.txt").write_text("x", encoding="utf-8")
    result = reader().list_page(RepoListInput(max_entries=4, max_scanned=2), actor="tester",
                                target=repository(tmp_path), scope=authorization(tmp_path))
    assert result.scanned_entries == 2 and result.truncated is True
    assert len(result.entries) == 2


def test_listing_caps_scanned_entries_even_when_all_are_ignored(tmp_path, monkeypatch):
    import vulnmind.tools.repo_files as module
    ignored = tmp_path / ".git"
    ignored.mkdir()
    class Entry:
        path = str(ignored)
        def is_dir(self): return True
    class Iter:
        def __enter__(self): return iter([Entry()] * 30)
        def __exit__(self, *args): pass
    monkeypatch.setattr(module.os, "scandir", lambda path: Iter())
    result = reader().list_page(RepoListInput(max_entries=2), actor="tester",
                                target=repository(tmp_path), scope=authorization(tmp_path))
    assert result.entries == []
    assert result.scanned_entries == 21 and result.truncated is True
