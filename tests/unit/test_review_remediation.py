from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from vulnmind.analysis.manifests import parse_manifest
from vulnmind.analysis.repository import RepositoryPipeline
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Approval
from vulnmind.schemas import Authorization, Target
from vulnmind.security.approvals import ApprovalService
from vulnmind.tools.repo_files import RepositoryReader
from vulnmind.tools.shell import ShellDenied, ShellExecutor, ShellToolInput
from vulnmind import __main__
from vulnmind.tools import adapters

class Audit:
    def __init__(self): self.events = []
    def record(self, event): self.events.append(event)

def test_shell_default_denies_even_with_low_risk_and_no_network(tmp_path):
    audit = Audit()
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner", starts_at=now-timedelta(hours=1), expires_at=now+timedelta(hours=1), repository_roots=[str(tmp_path)])
    with pytest.raises(ShellDenied, match="disabled"):
        ShellExecutor(audit).run(ShellToolInput(argv=["python", "-c", "print(1)"], cwd=str(tmp_path), purpose="test"), actor="tester", target=Target(type="repository", locator=str(tmp_path)), scope=scope)
    assert [x["status"] for x in audit.events] == ["requested", "denied"]

def test_approval_requires_matching_scan_and_expiry():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        scan = uuid4()
        row = Approval(id=uuid4(), scan_id=scan, action="shell.exec", target="repo", status="approved", expires_at=datetime.now(timezone.utc)+timedelta(hours=1))
        session.add(row); session.flush()
        service = ApprovalService(session)
        assert service.is_approved(str(row.id), scan_id=scan, action="shell.exec", target="repo")
        assert not service.is_approved(str(row.id), scan_id=uuid4(), action="shell.exec", target="repo")
        row.expires_at = None
        assert not service.is_approved(str(row.id), scan_id=scan, action="shell.exec", target="repo")
    engine.dispose()

def test_manifest_go_blocks_and_constraints():
    go = parse_manifest("go.mod", "require (\n example.org/a v1.0.0\n example.org/b v1.2.0 // indirect\n)\n")
    assert [(x.name, x.version) for x in go.dependencies] == [("example.org/a", "v1.0.0"), ("example.org/b", "v1.2.0")]
    py = parse_manifest("requirements.txt", "urllib3>=1.26,<3\nrequests!=2.31.0\n")
    assert [x.version for x in py.dependencies] == [">=1.26,<3", "!=2.31.0"]

def test_report_marks_incomplete_coverage(tmp_path):
    for n in range(3): (tmp_path / f"{n}.txt").write_text("safe")
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="owner", starts_at=now-timedelta(hours=1), expires_at=now+timedelta(hours=1), repository_roots=[str(tmp_path)])
    result = RepositoryPipeline(RepositoryReader(Audit()), [lambda x: []]).run(scan_id="s", project_id="p", actor="tester", target=Target(type="repository", locator=str(tmp_path)), scope=scope, max_files=1)
    assert result.files_examined == 1
    assert any("不完整" in x for x in result.to_report_input().limitations)

def test_cli_read_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(adapters, "MAX_DOCUMENT_BYTES", 4)
    path = tmp_path / "report.json"
    path.write_bytes(b"12345")
    with pytest.raises(adapters.AdapterError): __main__._read_report(path)
