"""Backup/restore drill on a disposable loopback PostgreSQL cluster.

Boots a throwaway cluster from .devtools/pgsql/bin, migrates a drill database,
seeds a project/scan/audit chain, dumps it with ``pg_dump -Fc``, restores into a
second database, and then verifies the migration head, row counts, pgvector and
the audit hash chain. Nothing touches an existing database or service.

Usage::

    .venv/Scripts/python scripts/pg_backup_restore.py
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid4

from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _remove_created_test_dir(temporary: Path, temp_parent: Path) -> None:
    if temporary.is_symlink() or (hasattr(temporary, "is_junction") and temporary.is_junction()):
        raise RuntimeError("refusing to clean a linked test directory")
    resolved = temporary.resolve(strict=True)
    if (resolved != temporary or resolved.parent != temp_parent.resolve(strict=True)
            or not resolved.name.startswith("vulnmind-pg-drill-")):
        raise RuntimeError("refusing to clean an unexpected test directory")
    shutil.rmtree(resolved)


def _binaries() -> Path:
    bindir = (ROOT / ".devtools" / "pgsql" / "bin").resolve()
    if not bindir.is_relative_to(ROOT):
        raise RuntimeError("development tools directory escaped the project")
    for name in ("initdb.exe", "pg_ctl.exe", "pg_dump.exe", "pg_restore.exe", "createdb.exe", "psql.exe"):
        if not (bindir / name).is_file():
            raise RuntimeError("trusted PostgreSQL binaries are incomplete in .devtools/pgsql/bin")
    return bindir


def _bootstrap(bindir: Path):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    temp_parent = Path(os.environ.get("PUBLIC", r"C:\Users\Public")) if os.name == "nt" and not str(bindir).isascii() else ROOT / ".devtools"
    temp_parent = temp_parent.resolve(strict=True)
    if not str(temp_parent).isascii():
        raise RuntimeError("PostgreSQL temporary directory must have an ASCII path")
    temporary = temp_parent / ("vulnmind-pg-drill-" + secrets.token_hex(12))
    temporary.mkdir()
    temporary = temporary.resolve(strict=True)
    if temporary.parent != temp_parent or not temporary.name.startswith("vulnmind-pg-drill-"):
        raise RuntimeError("invalid temporary drill directory")
    if not str(bindir).isascii():
        # initdb/postgres cannot reliably start from a non-ASCII path; use a copy
        # of the trusted binaries inside the ASCII drill directory.
        source = bindir.parent
        if any(path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())
               for path in source.rglob("*")):
            raise RuntimeError("PostgreSQL development binaries must not contain links")
        copy = temporary / "pgsql"
        shutil.copytree(source, copy)
        bindir = copy / "bin"
    data = temporary / "data"
    passfile = temporary / "password"
    log = temporary / "postgres.log"
    password = secrets.token_hex(32)
    passfile.write_text(password, encoding="ascii")
    try:
        subprocess.run([str(bindir / "initdb.exe"), "-D", str(data), "-U", "vulnmind_drill",
                        "--pwfile", str(passfile), "--auth=scram-sha-256", "--encoding=UTF8",
                        "--locale=C"], check=True, cwd=temporary, stdout=subprocess.DEVNULL,
                       creationflags=flags)
    except subprocess.CalledProcessError:
        _remove_created_test_dir(temporary, temp_parent)
        raise
    finally:
        passfile.unlink(missing_ok=True)
    return temporary, data, log, password, flags, bindir


def _psql(bindir, port, password, database, sql, flags, env=None):
    return subprocess.run([str(bindir / "psql.exe"), "-h", "127.0.0.1", "-p", str(port),
                           "-U", "vulnmind_drill", "-d", database, "-v", "ON_ERROR_STOP=1",
                           "-tAc", sql], capture_output=True, text=True,
                          env={**(env or os.environ), "PGPASSWORD": password},
                          creationflags=flags)


def _seed(url: str) -> dict:
    from vulnmind.persistence.audit import verify_audit_chain
    from vulnmind.persistence.models import AuditEvent, Project, Scan
    from vulnmind.persistence.audit import DatabaseAuditSink

    engine = create_engine(url)
    project_id, scan_id = uuid4(), uuid4()
    sink = DatabaseAuditSink(engine)
    for status in ("requested", "started", "succeeded"):
        sink.record({"call_id": str(uuid4()), "tool_name": "drill.seed", "actor": "drill",
                     "target_type": "repository", "status": status})
    with Session(engine) as session, session.begin():
        session.add(Project(id=project_id, name="drill project"))
        session.add(Scan(id=scan_id, project_id=project_id, status="finished", mode="analysis"))
    with engine.connect() as connection:
        chain = verify_audit_chain(connection)
        head_hash = connection.execute(select(AuditEvent.entry_hash).where(
            AuditEvent.entry_hash.is_not(None)).order_by(AuditEvent.created_at.desc()).limit(1)).scalar_one_or_none()
        counts = {"projects": connection.execute(select(func.count()).select_from(Project)).scalar_one(),
                  "scans": connection.execute(select(func.count()).select_from(Scan)).scalar_one(),
                  "audit_events": connection.execute(select(func.count()).select_from(AuditEvent)).scalar_one()}
    engine.dispose()
    return {"counts": counts, "chain_checked": chain.checked, "chain_valid": chain.valid,
            "chain_head": head_hash,
            "project_id": str(project_id), "scan_id": str(scan_id)}


def _drill_success(*, head, version, before, counts, chain, chain_head, vector, identities_match):
    """Require every advertised check, including the source audit chain, to pass."""
    return (head is not None and version == head and counts == before["counts"]
            and before["chain_valid"] and before["chain_checked"] > 0
            and chain.valid and chain.checked == before["chain_checked"]
            and before["chain_head"] is not None and chain_head == before["chain_head"]
            and vector.returncode == 0 and vector.stdout.strip() == "vector"
            and identities_match)


def main() -> int:
    bindir = _binaries()
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    temporary, data, log, password, flags, bindir = _bootstrap(bindir)
    drill = restore = None
    try:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        subprocess.run([str(bindir / "pg_ctl.exe"), "-D", str(data), "-l", str(log),
                        "-o", f"-h 127.0.0.1 -p {port}", "-w", "start"], check=True, cwd=temporary,
                       stdout=subprocess.DEVNULL, creationflags=flags)
        createdb = bindir / "createdb.exe"
        subprocess.run([str(createdb), "-h", "127.0.0.1", "-p", str(port), "-U", "vulnmind_drill",
                        "vulnmind_drill"], check=True, cwd=temporary,
                       env={**os.environ, "PGPASSWORD": password}, stdout=subprocess.DEVNULL,
                       creationflags=flags)
        drill = f"postgresql+psycopg://vulnmind_drill:{password}@127.0.0.1:{port}/vulnmind_drill"
        env = {**os.environ, "VULNMIND_DATABASE_URL": drill, "PGPASSWORD": password}
        migrated = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"],
                                  cwd=ROOT, env=env, capture_output=True, text=True, creationflags=flags)
        if migrated.returncode != 0:
            raise RuntimeError("alembic upgrade failed: " + migrated.stderr[-800:])
        before = _seed(drill)
        from alembic.config import Config

        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("script_location", str(ROOT / "migrations"))
        head = ScriptDirectory.from_config(config).get_current_head()
        dump = temporary / "drill.dump"
        subprocess.run([str(bindir / "pg_dump.exe"), "-h", "127.0.0.1", "-p", str(port),
                        "-U", "vulnmind_drill", "-Fc", "-f", str(dump), "vulnmind_drill"], check=True,
                       cwd=temporary, env={**os.environ, "PGPASSWORD": password},
                       stdout=subprocess.DEVNULL, creationflags=flags)
        subprocess.run([str(createdb), "-h", "127.0.0.1", "-p", str(port), "-U", "vulnmind_drill",
                        "vulnmind_restore"], check=True, cwd=temporary,
                       env={**os.environ, "PGPASSWORD": password}, stdout=subprocess.DEVNULL,
                       creationflags=flags)
        restored = subprocess.run([str(bindir / "pg_restore.exe"), "-h", "127.0.0.1", "-p", str(port),
                                   "-U", "vulnmind_drill", "-d", "vulnmind_restore", "--no-owner",
                                   str(dump)], cwd=temporary, env={**os.environ, "PGPASSWORD": password},
                                  capture_output=True, text=True, creationflags=flags)
        if restored.returncode != 0:
            raise RuntimeError("pg_restore failed: " + restored.stderr[-800:])
        restore = f"postgresql+psycopg://vulnmind_drill:{password}@127.0.0.1:{port}/vulnmind_restore"
        from vulnmind.persistence.audit import verify_audit_chain
        from vulnmind.persistence.models import AuditEvent, Project, Scan

        engine = create_engine(restore)
        with engine.connect() as connection:
            version = connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()
            counts = {"projects": connection.execute(select(func.count()).select_from(Project)).scalar_one(),
                      "scans": connection.execute(select(func.count()).select_from(Scan)).scalar_one(),
                      "audit_events": connection.execute(select(func.count()).select_from(AuditEvent)).scalar_one()}
            chain = verify_audit_chain(connection)
            chain_head = connection.execute(select(AuditEvent.entry_hash).where(
                AuditEvent.entry_hash.is_not(None)).order_by(AuditEvent.created_at.desc()).limit(1)).scalar_one_or_none()
            project_exists = connection.execute(select(Project.id).where(
                Project.id == UUID(before["project_id"]))).scalar_one_or_none() is not None
            scan_exists = connection.execute(select(Scan.id).where(
                Scan.id == UUID(before["scan_id"]),
                Scan.project_id == UUID(before["project_id"]))).scalar_one_or_none() is not None
        engine.dispose()
        vector = _psql(bindir, port, password, "vulnmind_restore",
                       "SELECT extname FROM pg_extension WHERE extname = 'vector';", flags)
        identities_match = project_exists and scan_exists
        success = _drill_success(head=head, version=version, before=before, counts=counts,
                                 chain=chain, chain_head=chain_head, vector=vector,
                                 identities_match=identities_match)
        result = {"status": "ok" if success else "failed",
                  "head": head, "restored_version": version, "counts_before": before["counts"],
                  "counts_after": counts, "audit_chain": {"checked": chain.checked, "valid": chain.valid},
                  "vector_extensions": vector.stdout.strip(), "identities_match": identities_match,
                  "dump_bytes": dump.stat().st_size}
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["status"] == "ok" else 1
    finally:
        status = subprocess.run([str(bindir / "pg_ctl.exe"), "-D", str(data), "status"], cwd=temporary,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
        if status.returncode == 0:
            subprocess.run([str(bindir / "pg_ctl.exe"), "-D", str(data), "-m", "fast", "-w", "stop"],
                           check=True, cwd=temporary, stdout=subprocess.DEVNULL, creationflags=flags)
        elif status.returncode != 3:
            raise RuntimeError("could not verify PostgreSQL drill server shutdown")
        _remove_created_test_dir(temporary, temporary.parent)


if __name__ == "__main__":
    raise SystemExit(main())
