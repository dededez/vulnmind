"""Conservative, offline Python TLS configuration candidate detector.

This detector does not import or execute the inspected code. It recognizes only
literal ``verify=False`` on qualified requests/httpx calls, and does not resolve
aliases, shadowing, data flow or runtime behavior. Results require human review.
"""
from __future__ import annotations

import ast

from vulnmind.findings import FindingCandidate
from vulnmind.tools.repo_files import FileContent

MAX_PYTHON_CHARACTERS = 200_000
MAX_AST_NODES = 30_000
MAX_FINDINGS = 100
_CLIENTS = {"requests", "httpx"}
_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "request"}


def find_python_tls_candidates(content: FileContent) -> list[FindingCandidate]:
    """Return unverified candidates without recording source text or values.

    Oversized or unparsable Python files fail explicitly so a scan does not
    silently present incomplete coverage as a successful analysis.
    """
    if content.language != "python":
        return []
    if len(content.content) > MAX_PYTHON_CHARACTERS:
        raise ValueError("Python TLS analyzer input exceeds its character limit")
    try:
        tree = ast.parse(content.content)
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise ValueError("Python TLS analyzer could not parse the source file") from exc
    found: list[FindingCandidate] = []
    for count, node in enumerate(ast.walk(tree), start=1):
        if count > MAX_AST_NODES:
            raise ValueError("Python TLS analyzer input exceeds its syntax node limit")
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if (not isinstance(node.func.value, ast.Name) or node.func.value.id not in _CLIENTS
                or node.func.attr not in _METHODS):
            continue
        if not any(kw.arg == "verify" and isinstance(kw.value, ast.Constant)
                   and kw.value.value is False for kw in node.keywords):
            continue
        if len(found) >= MAX_FINDINGS:
            raise ValueError("Python TLS analyzer exceeds its finding limit")
        found.append(FindingCandidate(title="可能禁用了 TLS 证书验证",
                                      vulnerability_type="tls_certificate_verification_disabled",
                                      target_id="repository", location=f"{content.path}:{node.lineno}",
                                      source_tool="builtin.python_tls", status="unverified",
                                      severity="medium"))
    return found
