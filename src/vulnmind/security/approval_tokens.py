"""HMAC credentials binding an approval decision to its subject.

This is not a user identity system: it proves that the caller holds the shared
secret; credentials bind an approval ID, scan, action, target, operation hash
and expiry. They do not establish the identity of the approver.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from uuid import UUID

_TAG = "vulnmind.approval.v3"


class ApprovalTokenError(ValueError):
    """The credential is malformed or does not match the approval."""


class ApprovalTokenSigner:
    def __init__(self, secret: bytes | str):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        if not isinstance(secret, bytes) or len(secret) < 16:
            raise ApprovalTokenError("approval secret must contain at least 16 bytes")
        self._secret = secret

    def sign(self, *, approval_id: UUID, scan_id: UUID, action: str, target: str,
             expires_at: datetime, operation_hash: str | None, approved: bool) -> str:
        return hmac.new(self._secret, self._message(approval_id, scan_id, action, target, expires_at, operation_hash, approved),
                        hashlib.sha256).hexdigest()

    def verify(self, token: str, *, approval_id: UUID, scan_id: UUID, action: str, target: str,
               expires_at: datetime | None, operation_hash: str | None, approved: bool,
               now: datetime | None = None) -> bool:
        if not isinstance(token, str) or len(token) != 64 or any(character not in "0123456789abcdef" for character in token):
            return False
        if expires_at is None:
            return False
        expiry = expires_at if expires_at.tzinfo is not None else expires_at.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        if current.utcoffset() is None or current >= expiry:
            return False
        expected = self.sign(approval_id=approval_id, scan_id=scan_id, action=action, target=target,
                             expires_at=expiry, operation_hash=operation_hash, approved=approved)
        return hmac.compare_digest(expected, token)

    @staticmethod
    def _message(approval_id: UUID, scan_id: UUID, action: str, target: str, expires_at: datetime,
                 operation_hash: str | None, approved: bool) -> bytes:
        if type(approved) is not bool:
            raise ValueError("approved must be a boolean")
        expiry = expires_at if expires_at.tzinfo is not None else expires_at.replace(tzinfo=timezone.utc)
        parts = [_TAG, str(approval_id), str(scan_id), action, target,
                 expiry.astimezone(timezone.utc).isoformat(), operation_hash, approved]
        return json.dumps(parts, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
