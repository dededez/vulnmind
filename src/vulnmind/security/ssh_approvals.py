"""OpenSSH-signed approvals: proof of the approver's private key.

The HMAC token in ``approval_tokens`` proves only that a caller knows a shared
secret. An SSHSIG proves which key signed a specific statement, provided the
server keeps an ``allowed_signers`` file. This module never parses keys itself;
it delegates to ``ssh-keygen -Y`` and fails closed on any error.
"""
from __future__ import annotations

import base64
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool

NAMESPACE = "vulnmind"


class ApprovalStatement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    approval_id: str = Field(min_length=1)
    scan_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    target: str = Field(min_length=1)
    expires_at: str = Field(min_length=1)
    operation_hash: str | None = None
    approved: StrictBool


def statement_for(approval, *, approved: bool) -> ApprovalStatement:
    """Build the canonical statement from an approval row."""
    expires = approval.expires_at
    if expires is None:
        raise ValueError("approval has no expiry and cannot be signed")
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return ApprovalStatement(approval_id=str(approval.id), scan_id=str(approval.scan_id),
                             action=approval.action, target=approval.target,
                             expires_at=expires.astimezone(timezone.utc).isoformat(),
                             operation_hash=approval.operation_hash, approved=approved)


def statement_bytes(statement: ApprovalStatement) -> bytes:
    return json.dumps(statement.model_dump(), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class SshSignatureVerifier:
    """Verify ``ssh-keygen -Y sign`` signatures against an allowed_signers file."""

    def __init__(self, allowed_signers: Path, *, namespace: str = NAMESPACE,
                 ssh_keygen: str = "ssh-keygen", timeout_seconds: float = 20.0):
        path = Path(allowed_signers).resolve(strict=True)
        if not path.is_file():
            raise ValueError("allowed_signers must be a file")
        if not namespace.strip():
            raise ValueError("namespace is required")
        if not 1 <= timeout_seconds <= 120:
            raise ValueError("timeout must be between 1 and 120 seconds")
        self._allowed = path
        self._namespace = namespace
        self._ssh_keygen = ssh_keygen
        self._timeout = timeout_seconds

    def verify(self, statement: ApprovalStatement, signature: bytes, *, principal: str) -> bool:
        if not principal.strip() or not signature:
            return False
        try:
            decoded = base64.b64decode(signature, validate=True)
        except (ValueError, TypeError):
            return False
        with tempfile.TemporaryDirectory(prefix="vulnmind-ssh-") as workspace:
            signature_file = Path(workspace) / "approval.sig"
            signature_file.write_bytes(decoded)
            try:
                completed = subprocess.run(
                    [self._ssh_keygen, "-Y", "verify", "-f", str(self._allowed), "-I", principal,
                     "-n", self._namespace, "-s", str(signature_file)],
                    input=statement_bytes(statement), capture_output=True,
                    timeout=self._timeout,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            except (OSError, subprocess.SubprocessError):
                return False
        return completed.returncode == 0


def sign_statement(statement: ApprovalStatement, key_path: Path, *,
                   ssh_keygen: str = "ssh-keygen", passphrase: str | None = None) -> bytes:
    """Sign a statement with the approver's private key (used by operators/tests)."""
    key = Path(key_path).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="vulnmind-ssh-sign-") as workspace:
        payload = Path(workspace) / "approval.json"
        payload.write_bytes(statement_bytes(statement))
        command = [ssh_keygen, "-Y", "sign", "-f", str(key), "-n", NAMESPACE, str(payload)]
        if passphrase is not None:
            command = [ssh_keygen, "-Y", "sign", "-f", str(key), "-n", NAMESPACE,
                       "-P", passphrase, str(payload)]
        completed = subprocess.run(command, capture_output=True, timeout=30,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", "replace")[:200]
            raise RuntimeError(f"ssh-keygen could not sign the statement: {detail}")
        signature = Path(str(payload) + ".sig")
        return base64.b64encode(signature.read_bytes())


def allowed_signers_line(principal: str, public_key: Path) -> str:
    if not principal.strip():
        raise ValueError("principal is required")
    try:
        text = Path(public_key).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError("public key is unreadable") from exc
    if not text.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-")):
        raise ValueError("unsupported public key type")
    return f"{principal} {text}\n"


def credential(signature: bytes) -> str:
    """Encode a signature for the ``decide`` credential field."""
    return "ssh-sig:" + base64.b64encode(signature).decode("ascii")


def decode_credential(value: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("ssh-sig:"):
        raise ValueError("not an ssh signature credential")
    try:
        return base64.b64decode(value[len("ssh-sig:"):], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid ssh signature encoding") from exc
