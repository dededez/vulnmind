"""WSL helpers and a confined Gitleaks execution path.

Generic ``run`` has no filesystem isolation. ``run_isolated_gitleaks`` creates
private network and mount namespaces, a temporary root, and a read-only repo
mount, then runs a fixed binary without root privileges. The WSL distribution
and kernel remain trusted; path races and resource exhaustion require further
work.
"""
from __future__ import annotations

import subprocess
import os
from collections.abc import Sequence
from pathlib import Path, PureWindowsPath

DEFAULT_DISTRO = "VulnMindSandbox"
MAX_OUTPUT_BYTES = 32 * 1024 * 1024

# Only read-only BusyBox applets are linked inside the shell sandbox. No shell,
# interpreter, package manager, VCS or network client is available there.
SHELL_APPLETS = frozenset({
    "cat", "cut", "file", "grep", "head", "ls", "sha256sum",
    "stat", "strings", "tail", "tr", "uniq", "wc",
})

# The repository is bind-mounted read-only at /repo; the command runs as nobody
# in private mount, network and PID namespaces. argv is passed through files, not
# interpolated into the shell command line.
_SHELL_SCRIPT = r'''set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset LD_PRELOAD LD_LIBRARY_PATH ENV BASH_ENV
src="$1"; sub="$2"; limit="$3"; limit_bytes="$4"; shift 4
t=$(mktemp -d /tmp/vulnmind-shell.XXXXXXXX)
case "$t" in /tmp/vulnmind-shell.*) ;; *) exit 1;; esac
cleanup() { umount -R "$t" 2>/dev/null || true; rmdir "$t" 2>/dev/null || true; }
trap cleanup EXIT
mount --make-rprivate /
mount -t tmpfs -o size=64m,mode=755 tmpfs "$t"
mkdir -p "$t/bin" "$t/lib" "$t/etc" "$t/repo" "$t/tmp"
: > "$t/bin/busybox"; : > "$t/lib/ld-musl-x86_64.so.1"
mount --bind /bin/busybox "$t/bin/busybox"; mount -o remount,bind,ro "$t/bin/busybox"
mount --bind /lib/ld-musl-x86_64.so.1 "$t/lib/ld-musl-x86_64.so.1"; mount -o remount,bind,ro "$t/lib/ld-musl-x86_64.so.1"
mount --bind "$src" "$t/repo"; mount -o remount,bind,ro "$t/repo"
ln -s busybox "$t/bin/sh"
for applet in cat cut file grep head ls sha256sum stat strings tail tr uniq wc; do
    ln -s busybox "$t/bin/$applet"
done
chmod 1777 "$t/tmp"
printf 'nobody:x:65534:65534:nobody:/tmp:/bin/sh\n' > "$t/etc/passwd"
printf 'nobody:x:65534:\n' > "$t/etc/group"
target="/repo"
[ -z "$sub" ] || target="/repo/$sub"
printf '%s\n' "$target" > "$t/tmp/cwd"
printf '%s\n' "$@" > "$t/tmp/args"
cat > "$t/tmp/run.sh" <<'RUNEOF'
#!/bin/sh
dir=$(/bin/cat /tmp/cwd)
cd "$dir" || exit 1
set --
while IFS= read -r line; do set -- "$@" "$line"; done < /tmp/args
exec "$@"
RUNEOF
chmod 755 "$t/tmp/run.sh"; chmod 644 "$t/tmp/cwd" "$t/tmp/args"
ulimit -f 65536
set +e
timeout -s KILL "$limit" chroot "$t" /bin/busybox su -s /bin/sh nobody -c 'exec /bin/sh /tmp/run.sh' > "$t/tmp/out" 2>&1
code=$?
set -e
/bin/busybox head -c "$limit_bytes" "$t/tmp/out"
exit $code
'''

# Passed on stdin, not interpolated into a command line. All mounts are in a
# fresh private mount namespace, which disappears when the child exits.
_GITLEAKS_SCRIPT = r'''set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset LD_PRELOAD LD_LIBRARY_PATH ENV BASH_ENV
src="$1"
limit="$2"
t=$(mktemp -d /tmp/vulnmind-scan.XXXXXXXX)
case "$t" in /tmp/vulnmind-scan.*) ;; *) exit 1;; esac
cleanup() { umount -R "$t" 2>/dev/null || true; rmdir "$t" 2>/dev/null || true; }
trap cleanup EXIT
mount --make-rprivate /
mount -t tmpfs -o size=64m,mode=755 tmpfs "$t"
mkdir -p "$t/bin" "$t/lib" "$t/etc" "$t/repo" "$t/tmp"
: > "$t/bin/busybox"; : > "$t/bin/gitleaks"; : > "$t/lib/ld-musl-x86_64.so.1"
mount --bind /bin/busybox "$t/bin/busybox"; mount -o remount,bind,ro "$t/bin/busybox"
mount --bind /usr/local/bin/gitleaks "$t/bin/gitleaks"; mount -o remount,bind,ro "$t/bin/gitleaks"
mount --bind /lib/ld-musl-x86_64.so.1 "$t/lib/ld-musl-x86_64.so.1"; mount -o remount,bind,ro "$t/lib/ld-musl-x86_64.so.1"
mount --bind "$src" "$t/repo"; mount -o remount,bind,ro "$t/repo"
ln -s busybox "$t/bin/sh"; chmod 1777 "$t/tmp"
printf 'nobody:x:65534:65534:nobody:/tmp:/bin/sh\n' > "$t/etc/passwd"
printf 'nobody:x:65534:\n' > "$t/etc/group"
ulimit -f 65536
/usr/bin/timeout -s KILL "$limit" chroot "$t" /bin/busybox su -s /bin/sh nobody -c 'cd /repo && exec /bin/gitleaks detect --no-git --redact --exit-code 0 --report-format json --report-path /tmp/report.json --source .'
/bin/busybox head -c 33554433 "$t/tmp/report.json"
'''


_TRIVY_SCRIPT = r'''set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset LD_PRELOAD LD_LIBRARY_PATH ENV BASH_ENV
src="$1"
limit="$2"
limit_bytes="$3"
t=$(mktemp -d /tmp/vulnmind-trivy.XXXXXXXX)
case "$t" in /tmp/vulnmind-trivy.*) ;; *) exit 1;; esac
cleanup() { umount -R "$t" 2>/dev/null || true; rmdir "$t" 2>/dev/null || true; }
trap cleanup EXIT
mount --make-rprivate /
mount -t tmpfs -o size=128m,mode=755 tmpfs "$t"
mkdir -p "$t/bin" "$t/lib" "$t/etc" "$t/repo" "$t/tmp" "$t/cache" "$t/usr/local/bin"
: > "$t/bin/busybox"; : > "$t/lib/ld-musl-x86_64.so.1"; : > "$t/usr/local/bin/trivy"
mount --bind /bin/busybox "$t/bin/busybox"; mount -o remount,bind,ro "$t/bin/busybox"
mount --bind /lib/ld-musl-x86_64.so.1 "$t/lib/ld-musl-x86_64.so.1"; mount -o remount,bind,ro "$t/lib/ld-musl-x86_64.so.1"
mount --bind /usr/local/bin/trivy "$t/usr/local/bin/trivy"; mount -o remount,bind,ro "$t/usr/local/bin/trivy"
mount --bind /var/cache/trivy "$t/cache"; mount -o remount,bind,ro "$t/cache"
mount --bind "$src" "$t/repo"; mount -o remount,bind,ro "$t/repo"
ln -s busybox "$t/bin/sh"; chmod 1777 "$t/tmp"
printf 'nobody:x:65534:65534:nobody:/tmp:/bin/sh\n' > "$t/etc/passwd"
printf 'nobody:x:65534:\n' > "$t/etc/group"
ulimit -f 65536
set +e
/usr/bin/timeout -s KILL "$limit" chroot "$t" /bin/busybox su -s /bin/sh nobody -c 'cd /repo && export HOME=/tmp && exec /usr/local/bin/trivy fs --offline-scan --skip-db-update --cache-dir /cache --scanners vuln --format json --output /tmp/report.json --exit-code 0 --no-progress --quiet .' >/dev/null 2>&1
code=$?
set -e
if [ -f "$t/tmp/report.json" ]; then
    /bin/busybox head -c "$limit_bytes" "$t/tmp/report.json"
else
    exit 1
fi
exit $code
'''


class SandboxError(RuntimeError):
    """The sandbox is missing, unreachable, or returned an error."""


def windows_to_wsl(path: Path | str) -> str:
    """Map a Windows path to its WSL ``/mnt/<drive>`` form."""
    text = str(path)
    if text.startswith("\\\\") or text.startswith("//"):
        raise SandboxError("UNC paths cannot be mapped into the sandbox")
    if (len(text) >= 3 and text[0].isascii() and text[0].isalpha()
            and text[1] == ":" and text[2] in "\\/" and ".." not in PureWindowsPath(text).parts
            and not any(ord(char) < 32 or ord(char) == 127 for char in text)):
        drive = text[0].lower()
        rest = text[2:].replace("\\", "/")
        if not rest.startswith("/"):
            rest = "/" + rest
        return f"/mnt/{drive}{rest}"
    raise SandboxError("only absolute Windows paths can be mapped into the sandbox")


class WslSandbox:
    """Execute an argv inside a WSL distribution with networking disabled."""

    def __init__(self, distro: str = DEFAULT_DISTRO, *, wsl: str = "wsl.exe",
                 timeout_seconds: float = 180.0, runner=None):
        if not distro.strip():
            raise ValueError("distro name is required")
        if not 1 <= timeout_seconds <= 900:
            raise ValueError("timeout must be between 1 and 900 seconds")
        self._distro = distro
        self._wsl = wsl
        self._timeout = timeout_seconds
        self._runner = runner or self._execute

    @property
    def distro(self) -> str:
        return self._distro

    def run(self, argv: Sequence[str], *, cwd_windows: Path | None = None,
            network: bool = False) -> tuple[int, bytes]:
        """Run ``argv``; ``network=False`` prepends ``unshare -n``."""
        if not argv or any(not str(item) for item in argv):
            raise ValueError("argv must contain at least one non-empty argument")
        command = ["/usr/bin/unshare", "-n", *[str(item) for item in argv]] if not network \
            else [str(item) for item in argv]
        return self._runner(command, cwd_windows)

    def run_stdin(self, script: str, *, network: bool = False) -> tuple[int, bytes]:
        """Run a shell script passed on stdin; never interpolated into a command line."""
        if not isinstance(script, str) or not script.strip():
            raise ValueError("script is required")
        command = ["/usr/bin/unshare", "-n", "/bin/sh", "-s"] if not network else ["/bin/sh", "-s"]
        arguments = [self._wsl, "-d", self._distro, "-u", "root", "--", *command]
        try:
            completed = subprocess.run(arguments, input=script.encode("utf-8"),
                                       capture_output=True, timeout=self._timeout,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError) as exc:
            raise SandboxError("sandbox script could not be executed") from exc
        if len(completed.stdout) > MAX_OUTPUT_BYTES:
            raise SandboxError("sandbox output exceeds the size limit")
        return completed.returncode, completed.stdout

    def read_file(self, linux_path: str) -> bytes:
        if not linux_path.startswith("/") or ".." in linux_path:
            raise SandboxError("sandbox path must be absolute")
        code, data = self.run(["/bin/cat", linux_path], network=False)
        if code != 0:
            raise SandboxError("sandbox file could not be read")
        return data

    def remove(self, linux_path: str) -> None:
        if not linux_path.startswith("/") or ".." in linux_path:
            raise SandboxError("sandbox path must be absolute")
        self.run(["/bin/rm", "-f", linux_path], network=False)

    def run_shell_isolated(self, root: Path, *, argv: Sequence[str], cwd_relative: str,
                           timeout_seconds: float, max_output_bytes: int) -> tuple[int, bytes]:
        """Run one allowlisted BusyBox applet against a read-only copy of ``root``.

        The command runs as nobody with no network namespace; the host kernel and
        the WSL distribution remain trusted. This returns the command's exit code
        and at most ``max_output_bytes`` of combined output; it is not a general
        shell and does not provide write access to the repository.
        """
        if not isinstance(argv, (list, tuple)) or not 1 <= len(argv) <= 64:
            raise ValueError("argv must contain 1 to 64 arguments")
        if any(not isinstance(item, str) or not item for item in argv):
            raise ValueError("every argument must be a non-empty string")
        program = argv[0]
        if program not in SHELL_APPLETS:
            raise SandboxError("program is not allowed in the shell sandbox")
        if any(len(item) > 4096 for item in argv):
            raise ValueError("every argument must contain at most 4096 characters")
        if any(ord(character) < 32 or ord(character) == 127 for item in argv for character in item):
            raise ValueError("arguments must not contain control characters")
        if not isinstance(cwd_relative, str) or cwd_relative.startswith("/") or ".." in cwd_relative.split("/"):
            raise ValueError("cwd must be a repository-relative path")
        if any(ord(character) < 32 or ord(character) == 127 for character in cwd_relative):
            raise ValueError("cwd must not contain control characters")
        if not 1 <= timeout_seconds <= 600:
            raise ValueError("timeout must be between 1 and 600 seconds")
        if not 1 <= max_output_bytes <= MAX_OUTPUT_BYTES:
            raise ValueError("output limit is out of range")
        source = windows_to_wsl(Path(root).resolve(strict=True))
        command = [self._wsl, "-d", self._distro, "-u", "root", "--", "/usr/bin/timeout",
                   "-s", "KILL", str(int(timeout_seconds) + 10), "/usr/bin/unshare",
                   "-m", "-n", "-p", "--fork", "/bin/sh", "-s", "--", source,
                   cwd_relative, str(int(timeout_seconds)), str(int(max_output_bytes) + 1), *argv]
        environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP")
                       if key in os.environ}
        try:
            completed = subprocess.run(command, input=_SHELL_SCRIPT.encode("utf-8"),
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       timeout=timeout_seconds + 20, env=environment,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError) as exc:
            raise SandboxError("sandbox shell could not be executed") from exc
        if len(completed.stdout) > max_output_bytes + 32:
            raise SandboxError("sandbox output exceeds the size limit")
        return completed.returncode, completed.stdout

    def run_isolated_gitleaks(self, root: Path, *, binary: str, timeout_seconds: float) -> bytes:
        """Scan a read-only bind mount as nobody in private mount and net namespaces."""
        if binary != "/usr/local/bin/gitleaks":
            raise SandboxError("sandbox scanner binary is not trusted")
        if not 1 <= timeout_seconds <= 600:
            raise ValueError("scanner timeout must be between 1 and 600 seconds")
        source = windows_to_wsl(Path(root).resolve(strict=True))
        command = [self._wsl, "-d", self._distro, "-u", "root", "--", "/usr/bin/timeout",
                   "-s", "KILL", str(int(timeout_seconds) + 10), "/usr/bin/unshare", "-m", "-n",
                   "/bin/sh", "-s", "--", source, str(int(timeout_seconds))]
        environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP")
                       if key in os.environ}
        try:
            completed = subprocess.run(command, input=_GITLEAKS_SCRIPT.encode("utf-8"),
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       timeout=timeout_seconds + 20, env=environment,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError) as exc:
            raise SandboxError("isolated scanner could not be executed") from exc
        if completed.returncode != 0:
            raise SandboxError("isolated scanner failed or timed out")
        if len(completed.stdout) > MAX_OUTPUT_BYTES:
            raise SandboxError("sandbox output exceeds the size limit")
        return completed.stdout

    def run_isolated_trivy(self, root: Path, *, binary: str, cache_dir: str,
                           timeout_seconds: float) -> bytes:
        """Run Trivy with private mount/net namespaces, a read-only repo and DB.

        This is the filesystem-isolated contract the analyzer requires; there is
        no fallback to the generic ``run`` helper. The DB cache is mounted
        read-only, the repository is read-only and the process runs as nobody.
        """
        if binary != "/usr/local/bin/trivy":
            raise SandboxError("sandbox scanner binary is not trusted")
        if cache_dir != "/var/cache/trivy":
            raise SandboxError("sandbox cache path is not trusted")
        if not 1 <= timeout_seconds <= 900:
            raise ValueError("scanner timeout must be between 1 and 900 seconds")
        try:
            source = windows_to_wsl(Path(root).resolve(strict=True))
        except (OSError, RuntimeError) as exc:
            raise SandboxError("repository root cannot be mapped into the sandbox") from exc
        command = [self._wsl, "-d", self._distro, "-u", "root", "--", "/usr/bin/timeout",
                   "-s", "KILL", str(int(timeout_seconds) + 10), "/usr/bin/unshare", "-m", "-n", "-p", "--fork",
                   "/bin/sh", "-s", "--", source, str(int(timeout_seconds)),
                   str(MAX_OUTPUT_BYTES + 1)]
        environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP")
                       if key in os.environ}
        try:
            completed = subprocess.run(command, input=_TRIVY_SCRIPT.encode("utf-8"),
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       timeout=timeout_seconds + 20, env=environment,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError) as exc:
            raise SandboxError("isolated scanner could not be executed") from exc
        if completed.returncode != 0:
            raise SandboxError("isolated scanner failed or timed out")
        if len(completed.stdout) > MAX_OUTPUT_BYTES:
            raise SandboxError("sandbox output exceeds the size limit")
        return completed.stdout

    def _execute(self, command: Sequence[str], cwd_windows: Path | None) -> tuple[int, bytes]:
        arguments = [self._wsl, "-d", self._distro, "-u", "root"]
        if cwd_windows is not None:
            arguments += ["--cd", windows_to_wsl(cwd_windows)]
        arguments += ["--", *command]
        try:
            completed = subprocess.run(arguments, capture_output=True, timeout=self._timeout,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError) as exc:
            raise SandboxError("sandbox command could not be executed") from exc
        if len(completed.stdout) > MAX_OUTPUT_BYTES:
            raise SandboxError("sandbox output exceeds the size limit")
        return completed.returncode, completed.stdout


def sandbox_gitleaks_report(sandbox: WslSandbox, root: Path, *, binary: str = "/usr/local/bin/gitleaks",
                            timeout_seconds: float = 180.0) -> bytes:
    """Use the isolated scanner contract; do not fall back to a host mount."""
    return sandbox.run_isolated_gitleaks(root, binary=binary, timeout_seconds=timeout_seconds)

