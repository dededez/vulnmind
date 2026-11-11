"""Human approval records for privileged actions (design sections 7.2 and 15).

The table already existed in migration 0002; this module is the workflow around
it. Approvals are scoped to one scan, one action and one target string, and a
decision can only be taken while the request is still pending.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Protocol
from uuid import UUID, uuid4

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from vulnmind.persistence.models import Approval
from vulnmind.security.approval_tokens import ApprovalTokenSigner


def operation_digest(operation: dict) -> str:
    """Fingerprint server-constructed operation data, which must exclude secrets."""
    if not isinstance(operation, dict) or not operation:
        raise ValueError("a nonempty operation object is required")
    pending = [(operation, 0)]
    visited = 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if depth > 32 or visited > 10000:
            raise ValueError("operation is too deeply nested or complex")
        if isinstance(value, dict):
            if len(value) > 10000 - visited - len(pending):
                raise ValueError("operation is too deeply nested or complex")
            if any(not isinstance(key, str) or len(key) > 65536 for key in value):
                raise ValueError("operation object keys must be strings")
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            if len(value) > 10000 - visited - len(pending):
                raise ValueError("operation is too deeply nested or complex")
            pending.extend((item, depth + 1) for item in value)
        elif isinstance(value, str) and len(value) > 65536:
            raise ValueError("operation object exceeds size limit")
        elif value is not None and not isinstance(value, (str, int, float, bool)):
            raise ValueError("operation must contain only JSON values")
    try:
        data = json.dumps(operation, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("operation must be JSON serializable") from exc
    if len(data) > 65536:
        raise ValueError("operation object exceeds size limit")
    return hashlib.sha256(data).hexdigest()


class ApprovalGate(Protocol):
    """What an executor may ask; it cannot approve anything itself."""

    def is_approved(self, approval_id: str, *, scan_id: UUID, action: str, target: str) -> bool: ...


class ApprovalService:
    def __init__(self, session: Session, signer: ApprovalTokenSigner | None = None,
                 ssh_verifier: "SshSignatureVerifier | None" = None):
        if signer is not None and not isinstance(signer, ApprovalTokenSigner):
            raise ValueError("signer must be an ApprovalTokenSigner")
        if ssh_verifier is not None:
            from vulnmind.security.ssh_approvals import SshSignatureVerifier

            if not isinstance(ssh_verifier, SshSignatureVerifier):
                raise ValueError("ssh_verifier must be an SshSignatureVerifier")
        self.session = session
        self._signer = signer
        self._ssh_verifier = ssh_verifier

    def request(self, *, scan_id: UUID, action: str, target: str,
                valid_for: timedelta = timedelta(hours=24), operation_hash: str | None = None) -> Approval:
        if not action.strip() or len(action) > 255:
            raise ValueError("approval action must contain 1 to 255 characters")
        if not target.strip():
            raise ValueError("approval target cannot be blank")
        if not isinstance(valid_for, timedelta) or valid_for <= timedelta(0):
            raise ValueError("approval validity must be a positive duration")
        if operation_hash is not None and (not isinstance(operation_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", operation_hash)):
            raise ValueError("operation hash must be a lowercase SHA-256 digest")
        row = Approval(id=uuid4(), scan_id=scan_id, action=action, target=target, status="pending",
                       expires_at=datetime.now(timezone.utc) + valid_for, operation_hash=operation_hash)
        self.session.add(row)
        return row

    def decide(self, approval_id: UUID, *, approver: str, approved: bool,
               credential: str | None = None) -> Approval:
        if not approver.strip() or len(approver) > 255:
            raise ValueError("approver must contain 1 to 255 characters")
        if type(approved) is not bool:
            raise ValueError("approved must be a boolean")
        now = datetime.now(timezone.utc)
        verified_fields = []
        if self._ssh_verifier is not None:
            # The signature proves which key signed this exact statement, provided
            # the server-side allowed_signers list is trusted.
            from vulnmind.security.ssh_approvals import decode_credential, statement_for

            row = self.session.get(Approval, approval_id)
            if row is None:
                raise KeyError(approval_id)
            try:
                signature = decode_credential(credential or "")
                statement = statement_for(row, approved=approved)
            except ValueError:
                raise ValueError("approval signature is missing or invalid") from None
            if not self._ssh_verifier.verify(statement, signature, principal=approver):
                raise ValueError("approval signature is missing or invalid")
            verified_fields = [Approval.scan_id == row.scan_id, Approval.action == row.action,
                               Approval.target == row.target, Approval.expires_at == row.expires_at,
                               Approval.operation_hash == row.operation_hash]
        elif self._signer is not None:
            # The credential binds this decision to the exact request; possession
            # of the shared secret is the only proof, not a user identity.
            row = self.session.get(Approval, approval_id)
            if row is None:
                raise KeyError(approval_id)
            if not self._signer.verify(credential or "", approval_id=row.id, scan_id=row.scan_id,
                                       action=row.action, target=row.target, expires_at=row.expires_at,
                                       operation_hash=row.operation_hash, approved=approved, now=now):
                raise ValueError("approval credential is missing or invalid")
            verified_fields = [Approval.scan_id == row.scan_id, Approval.action == row.action,
                               Approval.target == row.target, Approval.expires_at == row.expires_at,
                               Approval.operation_hash == row.operation_hash]
        # Compare-and-set prevents concurrent approvers from both deciding the
        # same request; an expired or legacy NULL-expiry request fails closed.
        self.session.flush()
        result = self.session.execute(
            update(Approval).where(Approval.id == approval_id, Approval.status == "pending",
                                   Approval.expires_at.is_not(None), Approval.expires_at > now,
                                   *verified_fields)
            .values(status="approved" if approved else "denied", approver=approver, approved_at=now)
            .execution_options(synchronize_session="fetch"))
        if result.rowcount != 1:
            row = self.session.get(Approval, approval_id)
            if row is None:
                raise KeyError(approval_id)
            raise ValueError("approval was already decided or expired")
        # Re-read so the caller sees the values this transaction just wrote.
        row = self.session.get(Approval, approval_id, populate_existing=True)
        return row

    def get(self, approval_id: UUID) -> Approval | None:
        return self.session.get(Approval, approval_id)

    def list_pending(self, scan_id: UUID) -> list[Approval]:
        statement = select(Approval).where(Approval.scan_id == scan_id, Approval.status == "pending").order_by(
            Approval.id)
        return list(self.session.scalars(statement))

    def is_approved(self, approval_id: str, *, scan_id: UUID, action: str, target: str) -> bool:
        """Status lookup only: does not bind an operation or grant execution."""
        try:
            parsed = UUID(str(approval_id))
        except (TypeError, ValueError, AttributeError):
            return False
        row = self.session.get(Approval, parsed)
        if row is None or row.status != "approved" or row.scan_id != scan_id or row.action != action or row.target != target:
            return False
        expires_at = _as_utc(row.expires_at)
        return expires_at is not None and datetime.now(timezone.utc) < expires_at

    def consume_bound(self, approval_id: str, *, scan_id: UUID, action: str, target: str,
                      operation_hash: str) -> bool:
        """Atomically mark an exact, unexpired approval consumed within this transaction.

        This is not authentication or isolation. A caller must commit before
        any side effect, and must construct the operation digest from trusted
        server-side values; rollback restores the approval.
        """
        try:
            parsed = UUID(str(approval_id))
        except (TypeError, ValueError, AttributeError):
            return False
        if not isinstance(operation_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", operation_hash):
            return False
        now = datetime.now(timezone.utc)
        self.session.flush()
        result = self.session.execute(
            update(Approval).where(Approval.id == parsed, Approval.scan_id == scan_id,
                                   Approval.action == action, Approval.target == target,
                                   Approval.status == "approved", Approval.operation_hash == operation_hash,
                                   Approval.approved_at.is_not(None), Approval.approver.is_not(None),
                                   func.length(func.trim(Approval.approver)) > 0,
                                   Approval.consumed_at.is_(None), Approval.expires_at.is_not(None),
                                   Approval.expires_at > now)
            .values(status="consumed", consumed_at=now)
            .execution_options(synchronize_session="fetch"))
        return result.rowcount == 1


def _as_utc(value: datetime | None) -> datetime | None:
    """Approval timestamps are written in UTC; SQLite drops the offset."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
