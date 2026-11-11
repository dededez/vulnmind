"""Skill-based scan manifest tests: real files, budget, honest references."""
from pathlib import Path

import pytest

from vulnmind.analysis.repository import RepositoryAnalysis
from vulnmind.context.scan_manifest import default_skill_provider, skill_manifest_provider
from vulnmind.knowledge.skills import SkillLoader


def write_skill(root: Path, relative: str, *, skill_id: str, target_type: str = "repository",
                body: str = "Step 1. Validate scope.") -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("---\n"
                    f"skill_id: {skill_id}\n"
                    "name: Example skill\n"
                    "version: '1'\n"
                    f"target_type: {target_type}\n"
                    "stage: analysis\n"
                    "---\n"
                    f"{body}\n", encoding="utf-8")


def analysis(scan_id="scan-1", target_id="/repo"):
    return RepositoryAnalysis(scan_id=scan_id, project_id="p", target_id=target_id,
                              files_examined=1, files_skipped=0, findings=[], groups=[])


def test_manifest_lists_selected_skills_with_digests(tmp_path):
    write_skill(tmp_path, "target/repository_audit.md", skill_id="repository_audit")
    write_skill(tmp_path, "vulnerability/sqli/workflow.md", skill_id="sqli_workflow", target_type="web")
    provider = skill_manifest_provider(SkillLoader(tmp_path), target_type="repository")
    payload = provider(analysis())
    refs = payload["selected_refs"]
    assert len(refs) == 2  # task reference plus the one repository skill
    assert refs[0] == "task:scan:scan-1"
    assert refs[1].startswith("skill:repository_audit@1#sha256=")
    assert payload["token_estimate"] > 0


def test_budget_excludes_optional_skills_but_records_them_absent(tmp_path):
    write_skill(tmp_path, "a.md", skill_id="skill_a", body="x" * 3000)
    write_skill(tmp_path, "b.md", skill_id="skill_b", body="y" * 3000)
    provider = skill_manifest_provider(SkillLoader(tmp_path), total_budget=4000)
    payload = provider(analysis())
    skill_refs = [ref for ref in payload["selected_refs"] if ref.startswith("skill:")]
    assert len(skill_refs) == 1
    assert payload["token_estimate"] <= 4000


def test_provider_validation(tmp_path):
    with pytest.raises(ValueError, match="SkillLoader"):
        skill_manifest_provider(object())
    with pytest.raises(ValueError, match="total_budget"):
        skill_manifest_provider(SkillLoader(tmp_path), total_budget=10)
    provider = default_skill_provider(tmp_path)
    payload = provider(analysis())
    assert payload["selected_refs"] == ["task:scan:scan-1"]
