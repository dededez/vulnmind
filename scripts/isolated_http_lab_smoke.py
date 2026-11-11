"""Self-contained loopback lab smoke test; does not run a VulnMind transport.

Run inside a *new* Linux network namespace with loopback enabled. It neither
changes the host network nor contacts a non-loopback address. This deliberately
does not open any product HTTP entry point or certify egress isolation.
"""
import http.client
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


def main():
    if os.name != "posix" or not os.path.exists("/proc/1/ns/net"):
        raise SystemExit("a Linux network namespace is required")
    if os.stat("/proc/self/ns/net").st_ino == os.stat("/proc/1/ns/net").st_ino:
        raise SystemExit("refusing to start outside a private network namespace")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "7")
            self.end_headers()
            self.wfile.write(b"lab-ok\n")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        try:
            conn.request("GET", "/")
            response = conn.getresponse()
            body = response.read(32)
        finally:
            conn.close()
        if response.status != 200 or body != b"lab-ok\n":
            raise RuntimeError("loopback HTTP smoke test failed")
        print(json.dumps({"status": "ok", "scope": "isolated_loopback_only",
                          "vulnmind_transport_tested": False}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
