import http.client
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

# The worker module imports the Unix-only ``resource`` module at top level.
sys.modules.setdefault('resource', types.ModuleType('resource'))

from vulnmind.integrations.hexstrike import offline_worker  # noqa: E402


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'ok'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


def _target():
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _proxy(target, requests_budget=5):
    scope = {'origins': [f'http://127.0.0.1:{target.server_port}']}
    return offline_worker.start_egress_proxy(scope, {'requests': requests_budget},
                                             '127.0.0.1', target.server_port, {'GET'})


def _fetch(proxy_port, url):
    """Send an absolute-URI request exactly like a CLI scanner does."""
    conn = http.client.HTTPConnection('127.0.0.1', proxy_port, timeout=10)
    try:
        conn.request('GET', url)
        return conn.getresponse()
    finally:
        conn.close()


def test_proxy_records_real_upstream_status():
    target = _target()
    proxy, state = _proxy(target)
    try:
        response = _fetch(proxy.server_port, f'http://127.0.0.1:{target.server_port}/')
        assert response.status == 200 and response.read() == b'ok'
        assert state['upstream_status'] == {'200': 1}
        assert state['exceptions'] == {}
    finally:
        proxy.shutdown(); proxy.server_close(); target.shutdown(); target.server_close()


def test_proxy_records_connection_exception_and_returns_502():
    # Reserve a port, then close it so the upstream connection is refused.
    temp = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    port = temp.server_port
    temp.server_close()
    scope = {'origins': [f'http://127.0.0.1:{port}']}
    proxy, state = offline_worker.start_egress_proxy(scope, {'requests': 5},
                                                     '127.0.0.1', port, {'GET'})
    try:
        response = _fetch(proxy.server_port, f'http://127.0.0.1:{port}/')
        assert response.status == 502
        assert state['upstream_status'] == {}
        assert state['exceptions'].get('ConnectionRefusedError') == 1
        assert state['last_error'].startswith('ConnectionRefusedError')
    finally:
        proxy.shutdown(); proxy.server_close()


def test_proxy_enforces_request_budget_and_records_429():
    target = _target()
    proxy, state = _proxy(target, requests_budget=1)
    try:
        assert _fetch(proxy.server_port, f'http://127.0.0.1:{target.server_port}/').status == 200
        assert _fetch(proxy.server_port, f'http://127.0.0.1:{target.server_port}/').status == 429
        assert state['budget_exhausted'] is True
        assert state['blocked_requests'] == 1
        assert state['requests_used'] == 1
    finally:
        proxy.shutdown(); proxy.server_close(); target.shutdown(); target.server_close()
