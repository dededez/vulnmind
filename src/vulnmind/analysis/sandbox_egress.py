"""Per-call isolated HTTP egress inside the WSL sandbox.

Each request gets a private network namespace, a veth pair and one ``socat``
proxy bound to the sandbox-side veth address. The namespace may only reach that
proxy port; the proxy connects only to the single pre-validated target address
and port. No global forwarding, NAT or firewall setting is touched, so other
sandbox processes keep their own network behaviour.
"""
from __future__ import annotations

import ipaddress
import shlex
from uuid import uuid4

from vulnmind.analysis.sandbox import SandboxError, WslSandbox
from vulnmind.tools.http_single_hop import HttpDenied

MAX_BODY_BYTES = 1_000_000
PROXY_PORT = 18443


def build_egress_script(*, method: str, url: str, headers: dict[str, str], host: str,
                        port: int, address: str, timeout: float, max_body: int,
                        curl: str = "/usr/bin/curl", socat: str = "/usr/bin/socat") -> str:
    """Build the POSIX sh program; all values are quoted, never interpolated raw."""
    token = uuid4().hex[:8]
    namespace = f"vm{token}"
    outer = f"va{token}"
    inner = f"vb{token}"
    subnet = 200 + (int(token[:2], 16) % 40)
    gateway = f"10.{subnet}.{int(token[2:4], 16) % 250}.1"
    runtime = f"10.{subnet}.{int(token[2:4], 16) % 250}.2"
    # Keep inherited proxy variables and curl's per-user config from changing
    # the validated connection. The real WSL path remains disabled until its
    # process/network isolation is independently verified.
    command = [curl, "-q", "--noproxy", "*", "-sS", "--max-redirs", "0", "--max-time", str(int(timeout)),
               "--connect-to",
               f"{host}:{port}:{gateway}:{PROXY_PORT}", "-X", method.upper(), "-D", "-"]
    for name, value in headers.items():
        command += ["-H", f"{name}: {value}"]
    command.append(url)
    lines = [
        "set -eu",
        # POSIX sh normally reports only head's status for the bounded pipe.
        # Do not run if this shell cannot propagate the request's failure.
        "if (set -o pipefail) 2>/dev/null; then set -o pipefail; else exit 1; fi",
        "umask 077",
        "exec 9>/tmp/vulnmind-egress.lock",
        "/usr/bin/flock 9",
        f"NS={shlex.quote(namespace)}",
        f"A={shlex.quote(outer)}",
        f"B={shlex.quote(inner)}",
        f"GW={shlex.quote(gateway)}",
        f"RT={shlex.quote(runtime)}",
        f"TARGET={shlex.quote(address)}",
        f"TPORT={port}",
        f"PPORT={PROXY_PORT}",
        f"CAP={max_body + 65536}",
        "SPID=",
        "cleanup() {",
        "  [ -n \"$SPID\" ] && kill \"$SPID\" 2>/dev/null || true",
        "  ip netns del \"$NS\" 2>/dev/null || true",
        "  ip link del \"$A\" 2>/dev/null || true",
        "}",
        "trap cleanup EXIT INT TERM",
        "ip netns del \"$NS\" 2>/dev/null || true",
        "ip link del \"$A\" 2>/dev/null || true",
        "ip netns add \"$NS\"",
        "ip link add \"$A\" type veth peer name \"$B\"",
        "ip link set \"$B\" netns \"$NS\"",
        "ip addr add \"$GW/30\" dev \"$A\"",
        "ip link set \"$A\" up",
        "ip netns exec \"$NS\" ip addr add \"$RT/30\" dev \"$B\"",
        "ip netns exec \"$NS\" ip link set \"$B\" up",
        "ip netns exec \"$NS\" ip link set lo up",
        "ip netns exec \"$NS\" ip route add default via \"$GW\"",
        f"{socat} TCP-LISTEN:$PPORT,bind=$GW,reuseaddr,fork TCP:$TARGET:$TPORT &",
        "SPID=$!",
        "sleep 0.4",
        "ip netns exec \"$NS\" nft add table inet vmout",
        "ip netns exec \"$NS\" nft 'add chain inet vmout out { type filter hook output priority 0; policy drop; }'",
        "ip netns exec \"$NS\" nft 'add rule inet vmout out oif \"lo\" accept'",
        "ip netns exec \"$NS\" nft \"add rule inet vmout out ip daddr $GW tcp dport $PPORT accept\"",
        "ip netns exec \"$NS\" " + " ".join(shlex.quote(item) for item in command) + " | /usr/bin/head -c $CAP",
        "RC=$?",
        "exit \"$RC\"",
    ]
    return "\n".join(lines)


def sandbox_http_request(sandbox, *, method: str, url: str, headers: dict[str, str], host: str,
                         port: int, address: str, timeout: float, max_body: int,
                         curl: str = "/usr/bin/curl",
                         socat: str = "/usr/bin/socat") -> tuple[bytes, bool]:
    if isinstance(sandbox, WslSandbox):
        raise HttpDenied("real HTTP execution is paused")
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise HttpDenied("transport received an invalid address") from exc
    if parsed.version != 4:
        raise HttpDenied("isolated egress currently supports IPv4 only")
    if not 1 <= max_body <= MAX_BODY_BYTES:
        raise HttpDenied("response limit is out of range")
    script = build_egress_script(method=method, url=url, headers=headers, host=host, port=port,
                                 address=str(parsed), timeout=timeout, max_body=max_body,
                                 curl=curl, socat=socat)
    try:
        runner = getattr(sandbox, "run_stdin", None)
        if callable(runner):
            code, output = runner(script, network=True)
        else:
            code, output = sandbox.run(["/bin/sh", "-s"], network=True)
    except SandboxError as exc:
        raise HttpDenied("sandboxed HTTP transport is unavailable") from exc
    if code != 0:
        raise HttpDenied("sandboxed HTTP request failed")
    return output, len(output) >= max_body + 65536


__all__ = ["build_egress_script", "sandbox_http_request", "WslSandbox"]
