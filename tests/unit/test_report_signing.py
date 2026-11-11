"""Report signing: key resolution, detached signatures and tamper detection."""
import json

import pytest

from vulnmind.reports.signing import (ReportSignature, SigningError, resolve_signing_key, sign_bytes,
                                      signature_json, verify_bytes)
from vulnmind.reports.store import ReportStore, ReportStoreError

KEY = "v" * 40


def test_key_resolution_requires_exactly_one_source():
    key, key_id = resolve_signing_key(key=KEY)
    assert key == KEY.encode() and len(key_id) == 16
    with pytest.raises(SigningError):
        resolve_signing_key(key=KEY, key_file="key.txt")
    with pytest.raises(SigningError):
        resolve_signing_key()
    with pytest.raises(SigningError):
        resolve_signing_key(key="short")


def test_key_file_is_read_and_bounded(tmp_path):
    path = tmp_path / "signing.key"
    path.write_text(KEY + "\n", encoding="utf-8")
    key, _ = resolve_signing_key(key_file=path)
    assert key == KEY.encode()
    with pytest.raises(SigningError):
        resolve_signing_key(key_file=tmp_path / "missing.key")
    path.write_text("x" * 5000, encoding="utf-8")
    with pytest.raises(SigningError):
        resolve_signing_key(key_file=path)


def test_key_with_control_characters_is_rejected():
    with pytest.raises(SigningError):
        resolve_signing_key(key="v" * 39 + "\x00")


def test_sign_and_verify_roundtrip():
    content = b"# report\n"
    key, key_id = resolve_signing_key(key=KEY)
    record = sign_bytes(content, key=key, key_id=key_id)
    assert verify_bytes(content, signature_json(record), key=key) == record
    assert json.loads(signature_json(record))["algorithm"] == "hmac-sha256"


def test_tampered_content_and_wrong_key_are_rejected():
    content = b"# report\n"
    key, key_id = resolve_signing_key(key=KEY)
    record = sign_bytes(content, key=key, key_id=key_id)
    with pytest.raises(SigningError):
        verify_bytes(content + b"x", record, key=key)
    other, _ = resolve_signing_key(key="w" * 40)
    with pytest.raises(SigningError):
        verify_bytes(content, record, key=other)
    with pytest.raises(SigningError, match="key id"):
        verify_bytes(content, record.model_copy(update={"key_id": "0" * 16}), key=key)
    with pytest.raises(SigningError, match="key id"):
        sign_bytes(content, key=key, key_id="0" * 16)


def test_malformed_signature_records_are_rejected():
    key, _ = resolve_signing_key(key=KEY)
    with pytest.raises(SigningError):
        verify_bytes(b"data", "not json", key=key)
    with pytest.raises(SigningError):
        verify_bytes(b"data", {"version": 1}, key=key)
    with pytest.raises(SigningError):
        verify_bytes(b"data", {"version": 2, "algorithm": "hmac-sha256", "key_id": "a" * 16,
                               "sha256": "a" * 64, "size_bytes": 4, "signature": "a" * 64}, key=key)
    with pytest.raises(SigningError):
        sign_bytes(b"", key=key, key_id="a" * 16)


def test_signature_sidecar_is_exclusive_and_verified(tmp_path):
    store = ReportStore(tmp_path / "reports")
    reference = store.put("# report\n", format="markdown")
    key, key_id = resolve_signing_key(key=KEY)
    record = sign_bytes(b"# report\n", key=key, key_id=key_id)
    store.put_signature(reference.uri, signature_json(record))
    assert store.read_signature(reference.uri) == signature_json(record)
    assert store.put_signature(reference.uri, signature_json(record)) == reference.uri.rsplit(".", 1)[0] + ".sig"
    with pytest.raises(ReportStoreError):
        store.put_signature(reference.uri, signature_json(record.model_copy(update={"signature": "0" * 64})))


def test_signature_paths_cannot_escape_the_store(tmp_path):
    store = ReportStore(tmp_path / "reports")
    with pytest.raises(ReportStoreError):
        store.read_signature("../outside.md")
    with pytest.raises(ReportStoreError):
        store.put_signature("missing.md", "{}")
    assert store.read_signature("aa/" + "a" * 64 + ".md") is None


def test_signature_sidecar_detected_link_is_never_read(tmp_path, monkeypatch):
    from pathlib import Path
    store = ReportStore(tmp_path / "reports")
    reference = store.put("# report\n", format="markdown")
    signature = store.root / reference.uri.replace(".md", ".sig")
    signature.write_text("untrusted", encoding="utf-8")
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == signature or original(path))
    with pytest.raises(ReportStoreError, match="link"):
        store.read_signature(reference.uri)
    with pytest.raises(ReportStoreError, match="link"):
        store.put_signature(reference.uri, "untrusted")


def test_existing_signature_is_bounded_on_repeat_sign(tmp_path):
    store = ReportStore(tmp_path / "reports")
    reference = store.put("# report\n", format="markdown")
    signature = store.root / reference.uri.replace(".md", ".sig")
    signature.write_bytes(b"x" * 4097)
    with pytest.raises(ReportStoreError, match="size limit"):
        store.put_signature(reference.uri, "x")


def test_real_signature_symlink_outside_store_is_rejected(tmp_path):
    store = ReportStore(tmp_path / "reports")
    reference = store.put("# report\n", format="markdown")
    outside = tmp_path / "outside.txt"
    outside.write_text("not a signature", encoding="utf-8")
    signature = store.root / reference.uri.replace(".md", ".sig")
    try:
        signature.symlink_to(outside)
    except OSError:
        pytest.skip("creating symbolic links is unavailable")
    with pytest.raises(ReportStoreError, match="link"):
        store.read_signature(reference.uri)


def test_signature_schema_requires_hex_digests():
    with pytest.raises(ValueError):
        ReportSignature(key_id="zz", sha256="a" * 64, size_bytes=1, signature="a" * 64)
