"""Run live tests against a disposable, loopback-only PostgreSQL cluster.

Requires user-provided trusted PostgreSQL 17 binaries in .devtools/pgsql/bin.
The cluster and server log use a unique disposable test directory; the
temporary password file is removed. Never uses an existing database or changes
a system PostgreSQL service.

Pass ``--require-pgvector`` to fail before the suite when the installed
PostgreSQL build cannot load the ``vector`` extension.
"""
from pathlib import Path
import argparse
import os
import secrets
import shutil
import socket
import subprocess
import sys


def _remove_created_test_dir(temporary: Path, temp_parent: Path) -> None:
    """Remove only the exact, newly created test directory after rechecking it."""
    if temporary.is_symlink() or (hasattr(temporary, "is_junction") and temporary.is_junction()):
        raise RuntimeError("refusing to clean a linked test directory")
    resolved = temporary.resolve(strict=True)
    if (resolved != temporary or resolved.parent != temp_parent.resolve(strict=True)
            or not resolved.name.startswith("vulnmind-pg-test-")):
        raise RuntimeError("refusing to clean an unexpected test directory")
    shutil.rmtree(resolved)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-pgvector", action="store_true",
                        help="verify CREATE EXTENSION vector before running pytest")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    devtools = (root / ".devtools").resolve()
    if not devtools.is_relative_to(root):
        raise RuntimeError("development tools directory escaped the project")
    devtools.mkdir(exist_ok=True)
    bindir = devtools / "pgsql" / "bin"
    initdb = bindir / "initdb.exe"
    pg_ctl = bindir / "pg_ctl.exe"
    if not initdb.is_file() or not pg_ctl.is_file():
        raise RuntimeError("trusted PostgreSQL binaries are not available in .devtools/pgsql/bin")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    # initdb on some Windows installations cannot bootstrap UTF-8 when its
    # data path contains non-ASCII characters. Use a throwaway ASCII path in
    # the Windows public temp area in that case; this database has no user data.
    temp_parent = Path(os.environ.get("PUBLIC", r"C:\Users\Public")) if os.name == "nt" and not str(devtools).isascii() else devtools
    temp_parent = temp_parent.resolve(strict=True)
    if not str(temp_parent).isascii():
        raise RuntimeError("PostgreSQL temporary directory must have an ASCII path")
    temporary = temp_parent / ("vulnmind-pg-test-" + secrets.token_hex(16))
    # A single mkdir fails immediately on permissions, unlike mkdtemp's Windows
    # permission retry loop on some drive roots.
    temporary.mkdir()
    temporary = temporary.resolve(strict=True)
    if temporary.parent != temp_parent or not temporary.name.startswith("vulnmind-pg-test-"):
        raise RuntimeError("invalid temporary test directory")
    if not str(bindir).isascii():
        binary_source = bindir.parent
        if any(path.is_symlink() or path.is_junction() for path in binary_source.rglob("*")):
            raise RuntimeError("PostgreSQL development binaries must not contain links")
        binary_copy = temporary / "pgsql"
        shutil.copytree(binary_source, binary_copy)
        initdb = binary_copy / "bin" / "initdb.exe"
        pg_ctl = binary_copy / "bin" / "pg_ctl.exe"
    data = temporary / "data"
    passfile = temporary / "password"
    log = temporary / "postgres.log"
    password = secrets.token_hex(32)
    passfile.write_text(password, encoding="ascii")
    try:
        subprocess.run([str(initdb), "-D", str(data), "-U", "vulnmind_test", "--pwfile", str(passfile),
                        "--auth=scram-sha-256", "--encoding=UTF8", "--locale=C"],
                       check=True, cwd=temporary, stdout=subprocess.DEVNULL, creationflags=flags)
    except subprocess.CalledProcessError:
        # Recheck the final path even on bootstrap failure before recursive removal.
        _remove_created_test_dir(temporary, temp_parent)
        raise
    finally:
        if temporary.resolve(strict=False) != temporary or passfile.parent.resolve(strict=False) != temporary:
            raise RuntimeError("refusing to remove password outside the test directory")
        passfile.unlink(missing_ok=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    try:
        subprocess.run([str(pg_ctl), "-D", str(data), "-l", str(log), "-o", f"-h 127.0.0.1 -p {port}", "-w", "start"],
                       check=True, cwd=temporary, stdout=subprocess.DEVNULL, creationflags=flags)
        env = os.environ.copy()
        env["VULNMIND_TEST_DATABASE_URL"] = f"postgresql+psycopg://vulnmind_test:{password}@127.0.0.1:{port}/postgres"
        # A second database lets the retained-schema test (upgrade + FTS trigger +
        # concurrent approval consumption) run in this throwaway cluster too.
        createdb = bindir.parent / "bin" / "createdb.exe"
        if createdb.is_file():
            subprocess.run([str(createdb), "-h", "127.0.0.1", "-p", str(port), "-U", "vulnmind_test",
                            "vulnmind_test"], check=True, cwd=temporary,
                           env={**os.environ, "PGPASSWORD": password},
                           stdout=subprocess.DEVNULL, creationflags=flags)
            env["VULNMIND_RETAINED_TEST_DATABASE_URL"] = (
                f"postgresql+psycopg://vulnmind_test:{password}@127.0.0.1:{port}/vulnmind_test")
        if arguments.require_pgvector:
            psql = bindir.parent / "bin" / "psql.exe"
            vector = subprocess.run(
                [str(psql), "-h", "127.0.0.1", "-p", str(port), "-U", "vulnmind_test", "-d", "postgres",
                 "-v", "ON_ERROR_STOP=1", "-tAc",
                 "CREATE EXTENSION IF NOT EXISTS vector; SELECT '[1,2,3]'::vector <-> '[1,2,4]'::vector;"],
                cwd=temporary, env={**os.environ, "PGPASSWORD": password},
                capture_output=True, creationflags=flags)
            if vector.returncode != 0:
                detail = vector.stderr.decode("utf-8", "replace").strip()
                raise RuntimeError(f"pgvector extension is not available: {detail}")
            sys.stdout.write("pgvector extension ready: " + vector.stdout.decode("utf-8", "replace").strip() + "\n")
        # Capture the child output: a console-less parent (for example a sandboxed
        # agent shell) otherwise discards it, making a passing run look empty.
        result = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=root, env=env,
                                creationflags=flags, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        sys.stdout.write(result.stdout.decode("utf-8", "replace"))
        sys.stdout.flush()
        return result.returncode
    finally:
        status = subprocess.run([str(pg_ctl), "-D", str(data), "status"], cwd=temporary,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
        if status.returncode == 0:
            subprocess.run([str(pg_ctl), "-D", str(data), "-m", "fast", "-w", "stop"],
                           check=True, cwd=temporary, stdout=subprocess.DEVNULL, creationflags=flags)
        elif status.returncode != 3:
            raise RuntimeError("could not verify PostgreSQL test server shutdown")
        # Delete only the freshly created, verified test directory after stop.
        _remove_created_test_dir(temporary, temp_parent)


if __name__ == "__main__":
    raise SystemExit(main())
