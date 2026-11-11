"""Detached HMAC signatures for stored report bytes.

A signature proves that whoever holds the configured key signed this exact
report content. It is symmetric: any key holder can produce a valid signature,
so it is authenticity among operators, not a public or third-party attestation.
The key is never written to the signature file or printed; only a short
non-secret key id is recorded so an operator can tell which key was used.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

SIGNATURE_VERSION = 1
MIN_KEY_CHARACTERS = 32
MAX_KEY_BYTES = 4096
MAX_SIGNATURE_BYTES = 4096


def sign_configured(store, uri):
    """Sign a newly stored report when local signing is configured."""
    from vulnmind.config import Settings
    settings = Settings()
    if not settings.report_signing_key and not settings.report_signing_key_file:
        return False
    key, key_id = resolve_signing_key(key=settings.report_signing_key, key_file=settings.report_signing_key_file)
    signature = sign_bytes(store.read(uri).encode('utf-8'), key=key, key_id=key_id)
    store.put_signature(uri, signature.model_dump_json())
    return True
_PURPOSE = b"vulnmind-report-signature-v1\n"


class SigningError(ValueError):
    """The key source is misconfigured or a signature does not verify."""


class ReportSignature(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal[1] = 1
    algorithm: Literal["hmac-sha256"] = "hmac-sha256"
    key_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=1, le=50_000_000)
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")


def resolve_signing_key(*, key: str | None = None, key_file: str | Path | None = None) -> tuple[bytes, str]:
    """Return (key bytes, key id) from exactly one configured source."""
    # Empty environment values mean "not configured", not an empty secret.
    key = key if key else None
    key_file = key_file if key_file else None
    if key is not None and key_file is not None:
        raise SigningError("configure either a signing key or a key file, not both")
    if key is not None:
        raw = key
    elif key_file is not None:
        path = Path(key_file)
        try:
            if path.stat().st_size > MAX_KEY_BYTES:
                raise SigningError("signing key file is too large")
            raw = path.read_text(encoding="utf-8")
        except OSError:
            raise SigningError("signing key file is unreadable") from None
    else:
        raise SigningError("no report signing key is configured")
    raw = raw.strip()
    if len(raw) < MIN_KEY_CHARACTERS:
        raise SigningError(f"signing key must contain at least {MIN_KEY_CHARACTERS} characters")
    if len(raw.encode("utf-8")) > MAX_KEY_BYTES:
        raise SigningError("signing key is too large")
    if any(ord(character) < 32 for character in raw):
        raise SigningError("signing key must not contain control characters")
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return raw.encode("utf-8"), digest[:16]


def _message(data: bytes) -> bytes:
    return _PURPOSE + hashlib.sha256(data).hexdigest().encode("ascii") + b"\n" + str(len(data)).encode("ascii") + b"\n"


def sign_bytes(data: bytes, *, key: bytes, key_id: str) -> ReportSignature:
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise SigningError("report content cannot be empty")
    if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_CHARACTERS:
        raise SigningError("signing key is too short")
    if not isinstance(key_id, str) or len(key_id) != 16 or any(c not in "0123456789abcdef" for c in key_id):
        raise SigningError("key id is invalid")
    if not hmac.compare_digest(key_id, hashlib.sha256(bytes(key)).hexdigest()[:16]):
        raise SigningError("key id does not match the signing key")
    payload = bytes(data)
    signature = hmac.new(bytes(key), _message(payload), hashlib.sha256).hexdigest()
    return ReportSignature(key_id=key_id, sha256=hashlib.sha256(payload).hexdigest(),
                           size_bytes=len(payload), signature=signature)


def verify_bytes(data: bytes, record: ReportSignature | str | dict, *, key: bytes) -> ReportSignature:
    """Verify a detached signature; raises SigningError on any mismatch."""
    if isinstance(record, (str, bytes)):
        try:
            record = json.loads(record)
        except (ValueError, TypeError, RecursionError):
            raise SigningError("signature file is not valid JSON") from None
    if isinstance(record, dict):
        try:
            record = ReportSignature.model_validate(record)
        except ValidationError:
            raise SigningError("signature file does not match the expected schema") from None
    if not isinstance(record, ReportSignature):
        raise SigningError("signature record is invalid")
    if not hmac.compare_digest(record.key_id, hashlib.sha256(bytes(key)).hexdigest()[:16]):
        raise SigningError("signature key id does not match the configured key")
    payload = bytes(data)
    if len(payload) != record.size_bytes or hashlib.sha256(payload).hexdigest() != record.sha256:
        raise SigningError("report content does not match the signed digest")
    expected = hmac.new(bytes(key), _message(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, record.signature):
        raise SigningError("signature does not match the configured key")
    return record


def signature_json(record: ReportSignature) -> str:
    return json.dumps(record.model_dump(), sort_keys=True, separators=(",", ":"))
