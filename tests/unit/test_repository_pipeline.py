"""Pipeline tests: walk, confinement, analyser injection, grouping, reporting."""
from datetime import datetime, timedelta, timezone

import pytest

from vulnmind.analysis.repository import RepositoryPipeline
from vulnmind.findings import FindingCandidate
from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import ScopeDenied
from vulnmind.tools.repo_files import DirectoryListing, RepositoryReader


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


def authorization(root, *, denied=()):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         repository_roots=[str(root)], denied_repository_roots=list(denied))


def target(root):
    return Target(type="repository", locator=str(root))


def one_finding_per_file(content):
    return [FindingCandidate(title=f"Rule hit in {content.path}", vulnerability_type="misconfig",
                             target_id="wrong-target", location=f"{content.path}:1", source_tool="stub")]


def silent(content):
    return []


def build_repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "src" / "config.yaml").write_text("debug: true\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\x00data")
    return tmp_path


def test_walk_reads_text_files_and_skips_ignored_and_binary(tmp_path):
    build_repo(tmp_path)
    pipeline = RepositoryPipeline(RepositoryReader(Recorder()), [one_finding_per_file])
    analysis = pipeline.run(scan_id="s-1", project_id="p-1", target=target(tmp_path),
                            scope=authorization(tmp_path), actor="tester")
    assert analysis.files_examined == 2
    assert analysis.files_skipped == 1
    assert sorted(finding.location for finding in analysis.findings) == ["src/app.py:1", "src/config.yaml:1"]


def test_analyser_cannot_relabel_the_target(tmp_path):
    build_repo(tmp_path)
    pipeline = RepositoryPipeline(RepositoryReader(Recorder()), [one_finding_per_file])
    analysis = pipeline.run(scan_id="s-1", project_id="p-1", target=target(tmp_path),
                            scope=authorization(tmp_path), actor="tester", target_id="target-uuid")
    assert analysis.target_id == "target-uuid"
    assert {finding.target_id for finding in analysis.findings} == {"target-uuid"}


def test_analyser_cannot_claim_a_finding_is_verified(tmp_path):
    build_repo(tmp_path)
    def claims_confirmation(content):
        return [FindingCandidate(title="claim", vulnerability_type="sqli", target_id="t", location=content.path,
                                 source_tool="injected", status="confirmed", evidence_refs=["unverified:ref"])]
    pipeline = RepositoryPipeline(RepositoryReader(Recorder()), [claims_confirmation])
    analysis = pipeline.run(scan_id="s", project_id="p", target=target(tmp_path), scope=authorization(tmp_path), actor="tester")
    assert analysis.findings and all(item.status == "unverified" for item in analysis.findings)


def test_grouping_is_applied_to_pipeline_output(tmp_path):
    build_repo(tmp_path)
    duplicate = lambda content: [  # noqa: E731 - same identity twice
        FindingCandidate(title="dup", vulnerability_type="secret", target_id="x",
                         location=f"{content.path}:9", source_tool="a"),
        FindingCandidate(title="dup", vulnerability_type="secret", target_id="x",
                         location=f"{content.path}:9", source_tool="b"),
    ]
    pipeline = RepositoryPipeline(RepositoryReader(Recorder()), [duplicate])
    analysis = pipeline.run(scan_id="s-1", project_id="p-1", target=target(tmp_path),
                            scope=authorization(tmp_path), actor="tester")
    assert len(analysis.findings) == 4 and len(analysis.groups) == 2
    assert analysis.groups[0].source_tools == ["a", "b"]


def test_limits_and_validation(tmp_path):
    build_repo(tmp_path)
    with pytest.raises(ValueError, match="analyser"):
        RepositoryPipeline(RepositoryReader(Recorder()), []).run(
            scan_id="s", project_id="p", target=target(tmp_path), scope=authorization(tmp_path), actor="a")
    with pytest.raises(ValueError, match="max_files"):
        RepositoryPipeline(RepositoryReader(Recorder()), [silent]).run(
            scan_id="s", project_id="p", target=target(tmp_path), scope=authorization(tmp_path), actor="a",
            max_files=0)
    limited = RepositoryPipeline(RepositoryReader(Recorder()), [silent]).run(
        scan_id="s", project_id="p", target=target(tmp_path), scope=authorization(tmp_path), actor="a",
        max_files=1)
    assert limited.files_examined == 1


def test_scope_denial_propagates(tmp_path):
    build_repo(tmp_path)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    pipeline = RepositoryPipeline(RepositoryReader(Recorder()), [silent])
    with pytest.raises(ScopeDenied):
        pipeline.run(scan_id="s", project_id="p", target=target(tmp_path),
                     scope=authorization(allowed), actor="tester")


def test_analysis_converts_to_report_input(tmp_path):
    build_repo(tmp_path)
    pipeline = RepositoryPipeline(RepositoryReader(Recorder()), [one_finding_per_file])
    analysis = pipeline.run(scan_id="s-1", project_id="p-1", target=target(tmp_path),
                            scope=authorization(tmp_path), actor="tester")
    report = analysis.to_report_input(limitations=["仅静态分析"])
    assert report.scan_id == "s-1" and report.mode == "analysis"
    assert len(report.groups) == 2 and report.limitations[0] == "仅静态分析"
    assert any("不完整" in text for text in report.limitations)


def test_pipeline_reports_truncation_even_if_no_entries_returned(tmp_path, monkeypatch):
    repo_reader = RepositoryReader(Recorder())
    monkeypatch.setattr(repo_reader, "list_page", lambda *args, **kwargs: DirectoryListing(entries=[], scanned_entries=10000, truncated=True))
    pipeline = RepositoryPipeline(repo_reader, [silent])
    result = pipeline.run(scan_id="s", project_id="p", target=target(tmp_path), scope=authorization(tmp_path), actor="tester")
    assert any("不完整" in text for text in result.coverage_limitations)


def test_pipeline_global_traversal_budget_is_bounded(tmp_path):
    for index in range(4):
        (tmp_path / f"file{index}.txt").write_text("x", encoding="utf-8")
    pipeline = RepositoryPipeline(RepositoryReader(Recorder()), [silent])
    result = pipeline.run(scan_id="s", project_id="p", target=target(tmp_path), scope=authorization(tmp_path),
                          actor="tester", max_depth_files=2)
    assert result.files_examined <= 2
    assert any("不完整" in text for text in result.coverage_limitations)
    with pytest.raises(ValueError, match="max_depth_files"):
        pipeline.run(scan_id="s", project_id="p", target=target(tmp_path), scope=authorization(tmp_path),
                     actor="tester", max_depth_files=10001)
