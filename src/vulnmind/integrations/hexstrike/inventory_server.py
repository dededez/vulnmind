"""Expose upstream schemas without starting its HTTP server or allowing calls."""
import hashlib
import importlib.util
from pathlib import Path
import sys

SOURCE_SHA256 = '214bd81987766133b88fad0f4c8f87152100937c5169386eae0b0335efcb8b4a'
COMMIT = 'd689933ff579d839c676c82b231f8e98326c5f04'


def load_upstream(path):
    path = Path(path).resolve(strict=True)
    if hashlib.sha256(path.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError('upstream source differs from reviewed commit')
    spec = importlib.util.spec_from_file_location('vulnmind_pinned_hexstrike', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InventoryOnlyClient:
    def __getattr__(self, name):
        raise ValueError('inventory connection cannot execute tools')


if __name__ == '__main__':
    load_upstream(sys.argv[1]).setup_mcp_server(InventoryOnlyClient()).run()
