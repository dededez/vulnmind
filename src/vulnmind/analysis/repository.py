"""Repository analysis pipeline: read -> analyse -> normalise -> group.

The pipeline itself contains no detection rules. It walks the authorized
repository through ``RepositoryReader``, hands each text file to the injected
analysers (the place where Semgrep/Gitleaks adapters are plugged in), forces the
target identity onto every candidate and groups the result. Analysers cannot
widen scope: the reader has already confined the paths.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vulnmind.findings import FindingCandidate, FindingGroup, group_findings
from vulnmind.analysis.repo_analyzers import RepoScanFindings
from vulnmind.reports.generator import AgentReviewSummary, DecisionSummary, ReportInput
from vulnmind.schemas import Authorization, Target
from vulnmind.tools.repo_files import FileContent, RepoDenied, RepoFileInput, RepoListInput, RepositoryReader
from vulnmind.tools.repo_access import RepositoryAccess


class EvidencePayload(BaseModel):
    """Bytes an analyser wants kept as evidence for one finding."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    content: bytes = Field(min_length=1)
    evidence_type: str = Field(default="text", min_length=1, max_length=64)
    locator: str | None = Field(default=None, max_length=1000)

    @field_validator("locator")
    @classmethod
    def single_line(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or "\n" in value or "\r" in value):
            raise ValueError("evidence locator must be a single non-blank line")
        return value


class AnnotatedFinding(BaseModel):
    """A candidate plus the evidence bytes that support it."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    finding: FindingCandidate
    evidence: list[EvidencePayload] = Field(default_factory=list)


class EvidenceAttachment(BaseModel):
    model_config = ConfigDict(frozen=True)
    fingerprint: str
    content: bytes
    evidence_type: str
    locator: str


AnalyzerResult = FindingCandidate | AnnotatedFinding
Analyzer = Callable[[FileContent], Sequence[AnalyzerResult]]


class RepositoryAnalysis(BaseModel):
    model_config = ConfigDict(frozen=True)
    scan_id: str
    project_id: str
    target_id: str
    files_examined: int
    files_skipped: int
    coverage_limitations: list[str] = Field(default_factory=list)
    findings: list[FindingCandidate]
    groups: list[FindingGroup]
    evidence: list[EvidenceAttachment] = Field(default_factory=list)
    repo_analyzers: list[str] = Field(default_factory=list)

    def to_report_input(self, *, mode: str = "analysis", limitations: Sequence[str] = (),
                        decisions: Sequence[DecisionSummary] = (),
                        agent_review: AgentReviewSummary | None = None) -> ReportInput:
        return ReportInput(scan_id=self.scan_id, project_id=self.project_id, mode=mode,
                           groups=self.groups, decisions=list(decisions),
                           limitations=[*limitations, *self.coverage_limitations],
                           agent_review=agent_review)


class RepositoryPipeline:
    def __init__(self, reader: RepositoryReader, analyzers: Sequence[Analyzer],
                 access: RepositoryAccess | None = None,
                 repo_analyzers: Sequence["RepoAnalyzer"] = ()):
        self._reader = reader
        self._access = access
        self._analyzers = list(analyzers)
        self._repo_analyzers = list(repo_analyzers)

    def _read(self, request: RepoFileInput, *, actor: str, target: Target, scope: Authorization):
        if self._access is not None:
            return self._access.read(request, actor=actor, target=target, scope=scope)
        return self._reader.read(request, actor=actor, target=target, scope=scope)

    def _list_page(self, request: RepoListInput, *, actor: str, target: Target, scope: Authorization):
        if self._access is not None:
            return self._access.list_page(request, actor=actor, target=target, scope=scope)
        return self._reader.list_page(request, actor=actor, target=target, scope=scope)

    def run(self, *, scan_id: str, project_id: str, target: Target, scope: Authorization,
            actor: str, max_files: int = 200, max_bytes: int = 200_000,
            max_depth_files: int = 2000, target_id: str | None = None) -> RepositoryAnalysis:
        if not self._analyzers and not self._repo_analyzers:
            raise ValueError("at least one analyser must be configured")
        if isinstance(max_files, bool) or not isinstance(max_files, int) or not 1 <= max_files <= 5000:
            raise ValueError("max_files must be between 1 and 5000")
        resolved_target_id = target_id or target.locator
        examined = skipped = 0
        findings: list[FindingCandidate] = []
        attachments: list[EvidenceAttachment] = []
        paths, limits = self._walk(actor, target, scope, max_depth_files=max_depth_files)
        for index, path in enumerate(paths):
            try:
                content = self._read(RepoFileInput(path=path, max_bytes=max_bytes), actor=actor,
                                     target=target, scope=scope)
            except RepoDenied:
                skipped += 1
                continue
            examined += 1
            for analyzer in self._analyzers:
                for item in analyzer(content):
                    candidate, payloads = _normalize_result(item, resolved_target_id)
                    findings.append(candidate)
                    fingerprint = candidate.fingerprint()
                    for payload in payloads:
                        attachments.append(EvidenceAttachment(
                            fingerprint=fingerprint, content=payload.content,
                            evidence_type=payload.evidence_type,
                            locator=payload.locator or candidate.location))
            if examined >= max_files:
                if index + 1 < len(paths):
                    limits.append("文件数达到上限，仓库分析不完整")
                break
        if skipped:
            limits.append(f"有 {skipped} 个文件未读取，仓库分析不完整")
        analyzer_names: list[str] = []
        for repo_analyzer in self._repo_analyzers:
            analyzer_names.append(type(repo_analyzer).__name__)
            results = repo_analyzer.analyze(root=Path(target.locator), actor=actor,
                                            target=target, scope=scope)
            if isinstance(results, RepoScanFindings):
                limits.extend(results.coverage_limitations)
            for item in results:
                candidate, payloads = _normalize_result(item, resolved_target_id)
                findings.append(candidate)
                fingerprint = candidate.fingerprint()
                for payload in payloads:
                    attachments.append(EvidenceAttachment(
                        fingerprint=fingerprint, content=payload.content,
                        evidence_type=payload.evidence_type,
                        locator=payload.locator or candidate.location))
        groups = group_findings(findings)
        return RepositoryAnalysis(scan_id=scan_id, project_id=project_id, target_id=resolved_target_id,
                                  files_examined=examined, files_skipped=skipped, coverage_limitations=limits,
                                  findings=findings, groups=groups, evidence=attachments,
                                  repo_analyzers=analyzer_names)

    def _walk(self, actor: str, target: Target, scope: Authorization, *,
              max_depth_files: int) -> tuple[list[str], list[str]]:
        pending = ["."]
        collected: list[str] = []
        visited = 0
        scanned = 0
        limits: list[str] = []
        if isinstance(max_depth_files, bool) or not isinstance(max_depth_files, int) or not 1 <= max_depth_files <= 10000:
            raise ValueError("max_depth_files must be between 1 and 10000")
        while pending and len(collected) < max_depth_files and scanned < max_depth_files:
            directory = pending.pop(0)
            remaining = max_depth_files - scanned
            listing = self._list_page(RepoListInput(directory=directory, max_entries=min(1000, remaining),
                                                    max_scanned=remaining),
                                      actor=actor, target=target, scope=scope)
            scanned += listing.scanned_entries
            entries = listing.entries
            if listing.truncated:
                limits.append("目录条目达到上限，仓库分析可能不完整")
            for entry in entries:
                visited += 1
                if visited > max_depth_files:
                    limits.append("遍历条目达到上限，仓库分析不完整")
                    break
                if entry.is_directory:
                    pending.append(entry.path)
                else:
                    collected.append(entry.path)
                    if len(collected) >= max_depth_files:
                        limits.append("遍历文件达到上限，仓库分析可能不完整")
                        break
            if visited > max_depth_files:
                break
        if pending and scanned >= max_depth_files:
            limits.append("遍历条目达到上限，仓库分析不完整")
        return collected, list(dict.fromkeys(limits))


def _normalize_result(item: object, target_id: str) -> tuple[FindingCandidate, list[EvidencePayload]]:
    """Analyser claims cannot assign target identity or validation status."""
    if isinstance(item, AnnotatedFinding):
        candidate, payloads = item.finding, list(item.evidence)
    elif isinstance(item, FindingCandidate):
        candidate, payloads = item, []
    else:
        raise ValueError("analyser returned an unsupported result type")
    normalized = FindingCandidate.model_validate({**candidate.model_dump(), "target_id": target_id,
                                                  "status": "unverified"})
    return normalized, payloads


