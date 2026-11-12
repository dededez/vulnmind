"""Only product HTTP transport: a fixed trusted broker, no shell or raw tunnel."""
import base64
import json
from pathlib import Path
import subprocess

from vulnmind.schemas import Target, Authorization
from vulnmind.security.scope import check_resolved_addresses
from vulnmind.tools.http import HttpDenied
from vulnmind.tools.http_single_hop import HopResponse


class IsolatedHttpBroker:
    def __init__(self, scope, *, distro="VulnMindLab", max_body_bytes=200_000, ca_file=None):
        self.scope = Authorization.model_validate(scope.model_dump())
        self.distro, self.max_body = distro, max_body_bytes
        self.ca_pem = None
        if ca_file:
            with Path(ca_file).open("r", encoding="ascii") as stream:
                self.ca_pem = stream.read(100_001)
            if len(self.ca_pem) > 100_000:
                raise ValueError("CA file too large")

    def __call__(self, *, method, url, headers, addresses, timeout):
        check_resolved_addresses(Target(type="web", locator=url), self.scope, list(addresses))
        data = {"method": method, "url": url, "headers": headers, "addresses": list(addresses),
                "timeout": timeout, "max_body": self.max_body, "scope": self.scope.model_dump(mode="json"),
                "ca_pem": self.ca_pem}
        return self._execute(data, timeout)

    def request_api(self, *, method, url, headers, body, addresses, approval_digest, auth_origin, timeout=10):
        check_resolved_addresses(Target(type='web',locator=url),self.scope,list(addresses))
        data=dict(method=method,url=url,headers=headers,body=body,addresses=list(addresses),timeout=timeout,
            max_body=self.max_body,scope=self.scope.model_dump(mode='json'),ca_pem=self.ca_pem,
            api_profile=dict(version=1,origin=auth_origin,approval_digest=approval_digest))
        return self._execute(data,timeout)

    def _execute(self, data, timeout):
        # -I ignores PYTHONPATH, user site and Python environment variables.
        # env -i also prevents TLS key logging, custom proxies and loader hooks.
        source = Path(__file__).with_name("http_broker_worker.py").read_text(encoding="utf-8")
        command = ["wsl.exe", "-d", self.distro, "-u", "root", "--", "/usr/bin/env", "-i",
                   "PATH=/usr/bin:/bin", "/usr/bin/timeout", "-s", "KILL", str(int(timeout) + 4),
                   "/usr/bin/python3", "-I", "-c", source]
        try:
            result = subprocess.run(command, input=json.dumps(data).encode(), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=timeout + 10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode or len(result.stdout) > 2_000_000:
                # Keep a bounded, printable reason so a policy/transport failure is
                # actionable instead of a bare "broker failed".
                reason = (result.stderr or b"")[-400:].decode("utf-8", "replace")
                reason = " ".join(char for char in reason if char.isprintable()).strip()
                try:
                    payload = json.loads(result.stdout or b"{}")
                    detail = (payload.get("detail") or payload.get("error")) if isinstance(payload, dict) else None
                except ValueError:
                    detail = None
                hint = (str(detail) if detail else reason)[:200]
                raise HttpDenied("isolated broker failed" + (": " + hint if hint else ""))
            response = json.loads(result.stdout)
            return HopResponse(status_code=response["status_code"], headers=response["headers"],
                body=base64.b64decode(response["body"], validate=True), truncated=response["truncated"],
                location=response["headers"].get("location"))
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            raise HttpDenied("isolated broker unavailable") from None
