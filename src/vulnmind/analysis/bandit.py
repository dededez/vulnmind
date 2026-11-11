"""Import external Bandit JSON without executing Bandit or target code."""
from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path

from vulnmind.analysis.repo_analyzers import MAX_REPORT_BYTES, RepoScanFindings, ScannerError
from vulnmind.findings import FindingCandidate
from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import check_target
from vulnmind.tools.adapters import resolve_path

_RULE = re.compile(r"B[0-9]{3,6}\Z")
_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNDEFINED": "unknown"}


class BanditReportAnalyzer:
    """Read a bounded untrusted report and keep only confined source locations."""

    def __init__(self, report: Path, *, target_id: str, max_results: int = 5000,
                 max_bytes: int = MAX_REPORT_BYTES, expected_sha256: str | None = None):
        try:
            self._report = Path(report).resolve(strict=True)
            if not self._report.is_file():
                raise OSError("not a file")
        except (OSError, RuntimeError) as exc:
            raise ScannerError("Bandit report is not a readable file") from exc
        if not isinstance(target_id, str) or not target_id.strip():
            raise ValueError("target_id is required")
        if isinstance(max_results, bool) or not isinstance(max_results, int) or not 1 <= max_results <= 5000:
            raise ValueError("max_results must be between 1 and 5000")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= MAX_REPORT_BYTES:
            raise ValueError("max_bytes is out of range")
        if expected_sha256 is not None and (not isinstance(expected_sha256, str)
                                             or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)):
            raise ValueError("invalid expected report digest")
        self._target_id, self._max_results, self._max_bytes = target_id, max_results, max_bytes
        self._expected_sha256 = expected_sha256

    def analyze(self, *, root: Path, actor: str, target: Target, scope: Authorization) -> list[FindingCandidate]:
        if not actor.strip() or target.type.value != "repository":
            raise ScannerError("repository target and actor are required")
        root = Path(root).resolve(strict=True)
        check_target(target, scope)
        if not root.is_dir() or root != Path(target.locator).resolve(strict=True):
            raise ScannerError("scanner root does not match authorized target")
        try:
            with self._report.open("rb") as stream:
                data = stream.read(self._max_bytes + 1)
            if len(data) > self._max_bytes:
                raise ScannerError("Bandit report exceeds the size limit")
            if self._expected_sha256 is not None and hashlib.sha256(data).hexdigest() != self._expected_sha256:
                raise ScannerError("Bandit report changed after workflow binding")
            payload = json.loads(data.decode("utf-8"))
        except (OSError, UnicodeError, ValueError, RecursionError):
            raise ScannerError("Bandit report is not usable") from None
        if (not isinstance(payload, dict) or not isinstance(payload.get("results"), list)
                or not isinstance(payload.get("errors", []), list)):
            raise ScannerError("Bandit report is not usable")
        results, errors = payload["results"], payload.get("errors", [])
        if len(results) > self._max_results or len(errors) > self._max_results:
            raise ScannerError("Bandit report exceeds the result limit")
        # Imported observations are claims from an untrusted external file.
        # Do not retain scanner snippets or arbitrary scanner-supplied text.
        from vulnmind.analysis.repository import AnnotatedFinding, EvidencePayload
        findings = []
        report_sha256 = hashlib.sha256(data).hexdigest()
        skipped = 0
        for item in results:
            if not isinstance(item, dict):
                skipped += 1
                continue
            path, rule, line, severity = (item.get("filename"), item.get("test_id"),
                                          item.get("line_number"), item.get("issue_severity"))
            if (not isinstance(path, str) or len(path) > 1000
                    or any(ord(char) < 32 or ord(char) == 127 for char in path)
                    or not isinstance(rule, str) or not _RULE.fullmatch(rule)
                    or isinstance(line, bool) or not isinstance(line, int) or not 1 <= line <= 10_000_000
                    or not isinstance(severity, str) or severity not in _SEVERITY):
                skipped += 1
                continue
            resolved = resolve_path(root, path)
            if resolved is None or not resolved.is_file():
                skipped += 1
                continue
            location = f"{resolved.relative_to(root).as_posix()}:{line}"
            if len(location) > 1000:
                skipped += 1
                continue
            candidate = FindingCandidate(title=f"Bandit security finding {rule}", vulnerability_type=rule,
                                         target_id=self._target_id, location=location,
                                         source_tool="bandit", severity=_SEVERITY[severity],
                                         status="unverified")
            evidence = json.dumps({"source": "untrusted_external_bandit_report", "report_sha256": report_sha256,
                                   "rule": rule, "location": candidate.location, "severity": severity},
                                  sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            findings.append(AnnotatedFinding(finding=candidate, evidence=[EvidencePayload(
                content=evidence, evidence_type="scanner_metadata", locator=candidate.location)]))
        imported = RepoScanFindings(findings, skipped=skipped, source="Bandit")
        imported.coverage_limitations += ("Bandit 结果来自未经认证的外部报告，元数据不能证明扫描实际执行或漏洞存在",)
        if errors:
            imported.coverage_limitations += (f"Bandit 报告包含 {len(errors)} 条扫描错误，覆盖可能不完整",)
        return imported
