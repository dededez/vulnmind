"""Read-only operational self-check for a VulnMind deployment.

``doctor`` never writes to the database, never creates directories and never
prints credentials. A failing check is a configuration or integrity signal, not a
security certification: passing only means these probes succeeded.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from vulnmind.persistence.audit import AuditError, verify_complete_audit_chain

_STATUS = Literal["ok", "warn", "fail"]


class CheckResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    name: str
    status: _STATUS
    detail: str


class DoctorReport(BaseModel):
    model_config = ConfigDict(frozen=True)
    status: Literal["ok", "degraded", "failed"]
    checks: list[CheckResult]


def _writable(path: Path) -> bool:
    return path.is_dir() and os.access(path, os.W_OK)


def _check_database(database_url: str | None) -> list[CheckResult]:
    if not database_url:
        return [CheckResult(name="database", status="fail", detail="database URL is not configured")]
    checks: list[CheckResult] = []
    engine = None
    try:
        engine = create_engine(database_url)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            checks.append(CheckResult(name="database", status="ok", detail="connection succeeded"))
            try:
                version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
                checks.append(_schema_check(version))
            except SQLAlchemyError:
                connection.rollback()
                checks.append(CheckResult(name="schema", status="warn",
                                          detail="alembic_version is missing; run migrations"))
            try:
                chain = verify_complete_audit_chain(connection)
                checks.append(CheckResult(
                    name="audit_chain", status="ok" if chain.valid else "fail",
                    detail=(f"checked={chain.checked} unhashed={chain.unhashed}" if chain.valid
                            else f"chain breaks at {chain.first_break_id}: {chain.reason}")))
            except SQLAlchemyError:
                connection.rollback()
                checks.append(CheckResult(name="audit_chain", status="warn",
                                          detail="audit_events is missing; run migrations"))
            except (AuditError, ValueError) as exc:
                checks.append(CheckResult(name="audit_chain", status="fail",
                                          detail=f"chain check unavailable: {type(exc).__name__}"))
    except (SQLAlchemyError, ImportError, OSError, ValueError):
        checks.append(CheckResult(name="database", status="fail", detail="connection failed"))
    finally:
        if engine is not None:
            engine.dispose()
    return checks


def _schema_check(version: str | None) -> CheckResult:
    if not version:
        return CheckResult(name="schema", status="warn", detail="no migration version recorded")
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        root = Path(__file__).resolve().parents[2]
        config = Config(str(root / "alembic.ini"))
        config.set_main_option("script_location", str(root / "migrations"))
        head = ScriptDirectory.from_config(config).get_current_head()
    except Exception:  # noqa: BLE001 - missing packaging is a warning, not a failure
        return CheckResult(name="schema", status="warn",
                           detail=f"current={version}; head unavailable")
    if head == version:
        return CheckResult(name="schema", status="ok", detail=f"at head {version}")
    return CheckResult(name="schema", status="warn", detail=f"current={version} head={head}")


def _check_root(name: str, value: str | None) -> CheckResult:
    if not value:
        return CheckResult(name=name, status="warn", detail="not configured")
    path = Path(value)
    if not path.exists():
        return CheckResult(name=name, status="warn", detail="missing; created on first use")
    if not _writable(path):
        return CheckResult(name=name, status="fail", detail="not a writable directory")
    return CheckResult(name=name, status="ok", detail="writable")


def _check_credentials(env: dict[str, str]) -> list[CheckResult]:
    checks: list[CheckResult] = []
    secret = bool(env.get("VULNMIND_APPROVAL_SECRET"))
    signers = bool(env.get("VULNMIND_APPROVAL_ALLOWED_SIGNERS"))
    if secret and signers:
        checks.append(CheckResult(name="approvals", status="fail",
                                  detail="configure either HMAC or SSH signers, not both"))
    elif secret or signers:
        checks.append(CheckResult(name="approvals", status="ok",
                                   detail="SSH signers configured" if signers else "HMAC secret configured"))
    else:
        checks.append(CheckResult(name="approvals", status="warn",
                                  detail="no approval credential; shell/validation approvals cannot be decided"))
    model = bool(env.get("DEEPSEEK_API_KEY") or env.get("VULNMIND_DEEPSEEK_API_KEY"))
    checks.append(CheckResult(name="model_key", status="ok" if model else "warn",
                              detail="present" if model else "missing; agent features stay disabled"))
    checks.append(_signing_check(env))
    return checks


def _signing_check(env: dict[str, str]) -> CheckResult:
    key = env.get("VULNMIND_REPORT_SIGNING_KEY") or ""
    key_file = env.get("VULNMIND_REPORT_SIGNING_KEY_FILE") or ""
    if key and key_file:
        return CheckResult(name="report_signing", status="fail",
                           detail="configure either a signing key or a key file, not both")
    if key:
        if len(key.strip()) < 32:
            return CheckResult(name="report_signing", status="warn",
                               detail="signing key is too short; report signing will be refused")
        return CheckResult(name="report_signing", status="ok", detail="signing key configured")
    if key_file:
        return CheckResult(name="report_signing", status="ok", detail="signing key file configured")
    return CheckResult(name="report_signing", status="warn",
                       detail="not configured; report signatures stay disabled")


def run_checks(*, database_url: str | None, report_root: str | None,
               evidence_root: str | None, env: dict[str, str] | None = None) -> DoctorReport:
    environment = dict(os.environ if env is None else env)
    checks = _check_database(database_url)
    checks.append(_check_root("report_root", report_root))
    if evidence_root:
        checks.append(_check_root("evidence_root", evidence_root))
    checks.extend(_check_credentials(environment))
    failed = any(check.status == "fail" for check in checks)
    warned = any(check.status == "warn" for check in checks)
    return DoctorReport(status="failed" if failed else ("degraded" if warned else "ok"),
                        checks=checks)
