"""Regression checks for the review's fail-closed execution boundaries."""
import json
import sys

import pytest

from vulnmind import __main__
from vulnmind.analysis.sandbox import SandboxError, WslSandbox
from vulnmind.analysis.sandbox_http import WslCurlTransport
from vulnmind.tools.http_single_hop import HttpDenied


@pytest.mark.parametrize("args", [
    ["fetch", "--url", "https://example.test", "--scope-file", "missing"],
    ["crawl", "--start", "https://example.test", "--scope-file", "missing"],
    ["validate-run", "--scan-id", "x", "--url", "https://example.test",
     "--scope-file", "missing", "--approval-token", "x"],
])
def test_network_cli_rejects_missing_scope_before_network_or_approval(monkeypatch, capsys, args):
    monkeypatch.setattr(sys, "argv", ["vulnmind", *args])
    monkeypatch.setattr(__main__, "_" + args[0].replace("-", "_"),
                        lambda _: pytest.fail("paused handler executed"))
    assert __main__.main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"


def test_real_wsl_transport_is_blocked_before_sandbox_execution():
    sandbox = WslSandbox(runner=lambda *_: pytest.fail("sandbox executed"))
    with pytest.raises(HttpDenied, match="paused"):
        WslCurlTransport(sandbox)(method="GET", url="https://example.test/", headers={},
                                  addresses=["192.0.2.1"], timeout=5)


@pytest.mark.parametrize("applet", ["awk", "find", "sed", "sort"])
def test_shell_rejects_applets_with_command_or_write_capabilities(tmp_path, applet):
    with pytest.raises(SandboxError, match="not allowed"):
        WslSandbox().run_shell_isolated(tmp_path, argv=[applet], cwd_relative="",
                                        timeout_seconds=5, max_output_bytes=1024)
