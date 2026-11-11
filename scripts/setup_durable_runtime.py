"""Back up and migrate the configured LOCAL development database, preserve data.

No URL or secret is printed. Existing credentials and explicit roots are kept.
The backup and runtime directories are inside this project's ignored .devtools.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import subprocess

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from vulnmind.config import Settings


def main():
    root = Path(__file__).resolve().parents[1]
    settings = Settings()
    url = make_url(settings.database_url)
    if url.get_backend_name() != "postgresql" or url.host not in {"localhost", "127.0.0.1", "::1"}:
        raise RuntimeError("this setup only accepts a configured local PostgreSQL database")
    engine = create_engine(url)
    with engine.connect() as conn:
        before = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        chunks = conn.execute(text("SELECT count(*) FROM knowledge_chunks")).scalar_one()
    directory = root / ".devtools" / "backups"
    directory.mkdir(parents=True, exist_ok=True)
    backup = directory / ("before-durable-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".dump")
    if backup.exists():
        raise RuntimeError("backup path exists")
    pg = root / ".devtools" / "pgsql" / "bin"
    environment = {**os.environ, "PGPASSWORD": url.password or ""}
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    result = subprocess.run([str(pg / "pg_dump.exe"), "-h", url.host, "-p", str(url.port or 5432),
        "-U", url.username, "-d", url.database, "-Fc", "-f", str(backup)], env=environment,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, creationflags=flags, timeout=120)
    if result.returncode:
        raise RuntimeError("database backup failed; no migration applied")
    check = subprocess.run([str(pg / "pg_restore.exe"), "--list", str(backup)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags, timeout=30)
    if check.returncode or backup.stat().st_size == 0:
        raise RuntimeError("backup archive could not be read; no migration applied")
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    previous_url = os.environ.get("VULNMIND_DATABASE_URL")
    os.environ["VULNMIND_DATABASE_URL"] = settings.database_url
    try:
        command.upgrade(config, "head")
    finally:
        if previous_url is None:
            os.environ.pop("VULNMIND_DATABASE_URL", None)
        else:
            os.environ["VULNMIND_DATABASE_URL"] = previous_url
    with engine.connect() as conn:
        after = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        if conn.execute(text("SELECT count(*) FROM knowledge_chunks")).scalar_one() != chunks:
            raise RuntimeError("knowledge row count changed unexpectedly")
    env_path = root / ".env"
    content = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
    additions = {}
    for name, value in (("REPORT_ROOT", settings.report_root), ("EVIDENCE_ROOT", settings.evidence_root)):
        if not value:
            path = root / ".devtools" / "runtime" / name.lower().removesuffix("_root")
            path.mkdir(parents=True, exist_ok=True)
            additions["VULNMIND_" + name] = path.as_posix()
    if not settings.approval_secret and not settings.approval_allowed_signers:
        additions["VULNMIND_APPROVAL_SECRET"] = secrets.token_hex(32)
    # Explicit requested capability settings; retain unrelated user configuration.
    additions["VULNMIND_ENABLED_HTTP_COMMANDS"] = '["fetch","crawl","validate-run"]'
    if "VULNMIND_HTTP_BROKER_DISTRO=" not in content:
        additions["VULNMIND_HTTP_BROKER_DISTRO"] = "VulnMindLab"
    lines = content.splitlines()
    lines = [line for line in lines if line.partition("=")[0].strip() not in additions]
    lines.extend(name + "='" + value + "'" for name, value in additions.items())
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    engine.dispose()
    print(json.dumps({"status": "ready", "before": before, "after": after, "knowledge_chunks_preserved": chunks,
                      "backup": str(backup), "backup_bytes": backup.stat().st_size,
                      "http_capabilities": ["fetch", "crawl", "validate-run"], "local_approval_configured": True}))


if __name__ == "__main__":
    main()
