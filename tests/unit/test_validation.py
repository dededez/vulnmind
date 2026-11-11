"""Non-destructive validation probes: planning, verdicts, approval consumption."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from vulnmind.analysis.crawler import FetchResult
from vulnmind.analysis.validation import (MAX_PROBES, MARKER, Probe, ValidationDenied, ValidationEngine,
                                          plan_digest, plan_probes)
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Approval, Project, Scan
from vulnmind.persistence.unit_of_work import transaction
from vulnmind.security.approvals import ApprovalService


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


class Fetcher:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        result = self.responses.get(url, FetchResult(status_code=404, content_type="text/html",
                                                     body=b"missing", final_url=url))
        if isinstance(result, Exception):
            raise result
        return result


def page(url, body="ok", headers=None):
    return FetchResult(status_code=200, content_type="text/html", body=body.encode("utf-8"),
                       final_url=url, headers=headers or {})


@pytest.fixture
def factory():
    engine = create_engine("sqlite://")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def seeded(factory):
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="validation")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="crawl")
        session.add(scan)
        session.flush()
        return scan.id


def approve(factory, seeded, probes, *, approved=True):
    digest = plan_digest(probes)
    with transaction(factory) as session:
        row = ApprovalService(session).request(scan_id=seeded, action="validation.probes",
                                               target=digest, valid_for=timedelta(hours=1),
                                               operation_hash=digest)
        session.flush()
        ApprovalService(session).decide(row.id, approver="owner", approved=approved)
        session.flush()
        return str(row.id)


def engine_for(factory, recorder=None):
    session = factory()
    return ValidationEngine(recorder or Recorder(), approvals=ApprovalService(session),
                            session=session), session


def test_plan_builds_probes_and_skips_urls_without_parameters():
    probes = plan_probes(["https://app.test/search?q=x&page=2", "https://app.test/about"])
    kinds = [probe.kind for probe in probes]
    assert kinds.count("reflection") == 2 and kinds.count("sql_error") == 2
    assert kinds.count("xss_reflection") == 2
    assert all(probe.url.startswith("https://app.test/search?") for probe in probes)
    assert any(MARKER in probe.url for probe in probes)


def test_plan_adds_open_redirect_only_for_redirect_parameters():
    probes = plan_probes(["https://app.test/go?next=/home"])
    assert [probe.kind for probe in probes] == ["reflection", "sql_error", "xss_reflection",
                                                 "open_redirect"]
    assert "https%3A%2F%2Fredirect.invalid%2Fvmx" in probes[3].url


def test_plan_adds_template_probe_only_for_expression_parameters():
    probes = plan_probes(["https://app.test/search?q=x"])
    template = [probe for probe in probes if probe.kind == "template_injection"]
    assert len(template) == 1 and template[0].parameter == "q"
    assert "%7B%7B7788%2A3%7D%7D" in template[0].url
    assert all(probe.kind != "template_injection"
               for probe in plan_probes(["https://app.test/check?flag=1"]))


def test_plan_is_capped_and_validated():
    urls = [f"https://app.test/p{i}?q=x" for i in range(30)]
    assert len(plan_probes(urls)) == MAX_PROBES
    assert plan_probes(urls, max_probes=3) == plan_probes(urls)[:3]
    for bad in (0, -1, MAX_PROBES + 1, True):
        with pytest.raises(ValueError, match="max_probes"):
            plan_probes(urls, max_probes=bad)
    with pytest.raises(ValueError, match="at least one probe"):
        plan_digest([])


def test_reflection_and_database_error_verdicts(factory, seeded):
    url = "https://app.test/search?q=x"
    probes = plan_probes([url])
    reflection = next(probe for probe in probes if probe.kind == "reflection")
    sqli = next(probe for probe in probes if probe.kind == "sql_error")
    fetcher = Fetcher({reflection.url: page(reflection.url, f"results for {MARKER}"),
                       sqli.url: page(sqli.url, "You have an error in your SQL syntax")})
    token = approve(factory, seeded, probes)
    runner, session = engine_for(factory)
    try:
        report = runner.run(probes, fetch=fetcher, actor="tester", scan_id=seeded, approval_token=token)
        session.commit()
    finally:
        session.close()
    assert report.candidates == 2 and report.errors == 0
    assert [item.verdict for item in report.results if item.kind in {"reflection", "sql_error"}] == [
        "candidate", "candidate"]
    assert "not proof" in report.results[0].detail


def test_clean_responses_are_inconclusive_not_negative(factory, seeded):
    url = "https://app.test/search?q=x"
    probes = plan_probes([url])
    fetcher = Fetcher({probe.url: page(probe.url) for probe in probes})
    token = approve(factory, seeded, probes)
    runner, session = engine_for(factory)
    try:
        report = runner.run(probes, fetch=fetcher, actor="tester", scan_id=seeded, approval_token=token)
        session.commit()
    finally:
        session.close()
    assert report.candidates == 0 and report.inconclusive == len(probes)
    assert "not proof" in report.results[0].detail


def test_audit_failure_aborts_remaining_probes_and_cannot_reuse_approval(factory, seeded):
    from vulnmind.persistence.audit import AuditError
    probes = plan_probes(["https://app.test/search?q=x"])[:2]
    token = approve(factory, seeded, probes)
    calls = []
    def unavailable(url):
        calls.append(url)
        raise AuditError("audit storage unavailable")
    recorder = Recorder()
    runner, session = engine_for(factory, recorder)
    try:
        with pytest.raises(AuditError):
            runner.run(probes, fetch=unavailable, actor="tester", scan_id=seeded, approval_token=token)
    finally:
        session.close()
    assert calls == [probes[0].url]
    assert [event["status"] for event in recorder.events] == ["requested", "started"]
    runner, session = engine_for(factory)
    try:
        with pytest.raises(ValidationDenied):
            runner.run(probes, fetch=unavailable, actor="tester", scan_id=seeded, approval_token=token)
    finally:
        session.close()
    assert calls == [probes[0].url]


def test_approval_commit_uncertainty_never_sends_probe():
    from vulnmind.analysis.validation import ValidationStateUnknown
    class Approved:
        def consume_bound(self, *args, **kwargs): return True
    class UncertainSession:
        def commit(self): raise OSError("private connection error")
        def rollback(self): pass
    recorder = Recorder()
    calls = []
    runner = ValidationEngine(recorder, approvals=Approved(), session=UncertainSession())
    probes = plan_probes(["https://app.test/search?q=x"])[:1]
    with pytest.raises(ValidationStateUnknown):
        runner.run(probes, fetch=lambda url: calls.append(url), actor="tester", scan_id=uuid4(), approval_token="x")
    assert calls == []
    assert [event["status"] for event in recorder.events] == ["requested"]


def test_independent_audit_and_replay_denial_with_file_sqlite(tmp_path):
    from vulnmind.persistence.audit import DatabaseAuditSink
    from vulnmind.persistence.models import AuditEvent

    db = create_engine(f"sqlite:///{(tmp_path / 'audit.db').as_posix()}", connect_args={"timeout": 1})
    Base.metadata.create_all(db)
    factory = sessionmaker(db, expire_on_commit=False)
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="validation-audit")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="finished", mode="crawl")
        session.add(scan)
        scan_id = scan.id
    probes = plan_probes(["https://app.test/search?q=x"])[:1]
    token = approve(factory, scan_id, probes)
    calls = []
    with factory() as session:
        assert session.get(Scan, scan_id) is not None
        runner = ValidationEngine(DatabaseAuditSink(db), approvals=ApprovalService(session), session=session)
        runner.run(probes, fetch=lambda url: (calls.append(url), page(url))[1], actor="tester",
                   scan_id=scan_id, approval_token=token)
        session.rollback()
    with factory() as session:
        runner = ValidationEngine(DatabaseAuditSink(db), approvals=ApprovalService(session), session=session)
        with pytest.raises(ValidationDenied):
            runner.run(probes, fetch=lambda url: calls.append(url), actor="tester",
                       scan_id=scan_id, approval_token=token)
    with factory() as session:
        statuses = list(session.scalars(select(AuditEvent.status).order_by(AuditEvent.created_at)))
    assert statuses == ["requested", "started", "succeeded", "requested", "denied"]
    assert calls == [probes[0].url]
    db.dispose()


def test_xss_verdict_requires_an_unencoded_reflection(factory, seeded):
    probes = plan_probes(["https://app.test/search?q=x"])
    xss = next(probe for probe in probes if probe.kind == "xss_reflection")
    encoded = Fetcher({probe.url: page(probe.url) for probe in probes})
    encoded.responses[xss.url] = page(xss.url, "&lt;vulnmind-probe-8f3a&gt;")
    token = approve(factory, seeded, probes)
    runner, session = engine_for(factory)
    try:
        report = runner.run(probes, fetch=encoded, actor="tester", scan_id=seeded, approval_token=token)
        session.commit()
    finally:
        session.close()
    assert next(item for item in report.results if item.kind == "xss_reflection").verdict == "inconclusive"

    raw = Fetcher({probe.url: page(probe.url) for probe in probes})
    raw.responses[xss.url] = page(xss.url, "<vulnmind-probe-8f3a>search</vulnmind-probe-8f3a>")
    token = approve(factory, seeded, probes)
    runner, session = engine_for(factory)
    try:
        report = runner.run(probes, fetch=raw, actor="tester", scan_id=seeded, approval_token=token)
        session.commit()
    finally:
        session.close()
    result = next(item for item in report.results if item.kind == "xss_reflection")
    assert result.verdict == "candidate" and "not proof" in result.detail


def test_template_verdict_requires_evaluation(factory, seeded):
    probes = plan_probes(["https://app.test/search?q=x"])
    template = next(probe for probe in probes if probe.kind == "template_injection")
    evaluated = Fetcher({probe.url: page(probe.url) for probe in probes})
    evaluated.responses[template.url] = page(template.url, "result: 23364")
    token = approve(factory, seeded, probes)
    runner, session = engine_for(factory)
    try:
        report = runner.run(probes, fetch=evaluated, actor="tester", scan_id=seeded, approval_token=token)
        session.commit()
    finally:
        session.close()
    assert next(item for item in report.results if item.kind == "template_injection").verdict == "candidate"

    echoed = Fetcher({probe.url: page(probe.url) for probe in probes})
    echoed.responses[template.url] = page(template.url, "your query: {{7788*3}}")
    token = approve(factory, seeded, probes)
    runner, session = engine_for(factory)
    try:
        report = runner.run(probes, fetch=echoed, actor="tester", scan_id=seeded, approval_token=token)
        session.commit()
    finally:
        session.close()
    assert next(item for item in report.results if item.kind == "template_injection").verdict == "inconclusive"


def test_open_redirect_verdict(factory, seeded):
    url = "https://app.test/go?next=/home"
    probes = plan_probes([url])
    redirect = next(probe for probe in probes if probe.kind == "open_redirect")
    fetcher = Fetcher({probe.url: page(probe.url) for probe in probes})
    fetcher.responses[redirect.url] = FetchResult(
        status_code=302, content_type="text/html", body=b"",
        final_url=redirect.url, headers={"Location": "https://evil.test/x"})
    token = approve(factory, seeded, probes)
    runner, session = engine_for(factory)
    try:
        report = runner.run(probes, fetch=fetcher, actor="tester", scan_id=seeded, approval_token=token)
        session.commit()
    finally:
        session.close()
    assert next(item for item in report.results if item.kind == "open_redirect").verdict == "candidate"


def test_approval_is_consumed_before_probing_and_cannot_replay(factory, seeded):
    probes = plan_probes(["https://app.test/search?q=x"])
    token = approve(factory, seeded, probes)
    fetcher = Fetcher({})
    recorder = Recorder()
    runner, session = engine_for(factory, recorder)
    runner.run(probes, fetch=fetcher, actor="tester", scan_id=seeded, approval_token=token)
    session.commit()
    session.close()
    with transaction(factory) as check:
        row = check.scalar(select(Approval))
        assert row.status == "consumed" and row.consumed_at is not None
    replay, replay_session = engine_for(factory)
    try:
        with pytest.raises(ValidationDenied):
            replay.run(probes, fetch=fetcher, actor="tester", scan_id=seeded, approval_token=token)
    finally:
        replay_session.close()
    assert recorder.events[-1]["status"] == "succeeded"


def test_missing_or_mismatched_approval_denies_without_requests(factory, seeded):
    probes = plan_probes(["https://app.test/search?q=x"])
    other = plan_probes(["https://app.test/other?q=x"])
    token = approve(factory, seeded, other)
    fetcher = Fetcher({})
    runner, session = engine_for(factory)
    try:
        with pytest.raises(ValidationDenied):
            runner.run(probes, fetch=fetcher, actor="tester", scan_id=seeded, approval_token="")
        with pytest.raises(ValidationDenied):
            runner.run(probes, fetch=fetcher, actor="tester", scan_id=seeded, approval_token=token)
    finally:
        session.close()
    assert fetcher.calls == []


def test_probe_failures_are_recorded_as_errors(factory, seeded):
    probes = plan_probes(["https://app.test/search?q=x"])
    fetcher = Fetcher({probes[0].url: OSError("boom"), probes[1].url: page(probes[1].url)})
    token = approve(factory, seeded, probes)
    runner, session = engine_for(factory)
    try:
        report = runner.run(probes, fetch=fetcher, actor="tester", scan_id=seeded, approval_token=token)
        session.commit()
    finally:
        session.close()
    assert report.errors == 1 and report.results[0].verdict == "error"
    assert "failed" in report.results[0].detail


def test_engine_argument_validation(factory, seeded):
    session = factory()
    try:
        with pytest.raises(ValueError, match="audit"):
            ValidationEngine(object(), approvals=ApprovalService(session), session=session)
        with pytest.raises(ValueError, match="approval service"):
            ValidationEngine(Recorder(), approvals=object(), session=session)
        with pytest.raises(ValueError, match="session"):
            ValidationEngine(Recorder(), approvals=ApprovalService(session), session=object())
        runner = ValidationEngine(Recorder(), approvals=ApprovalService(session), session=session)
        with pytest.raises(ValueError, match="at least one probe"):
            runner.run([], fetch=lambda url: page(url), actor="t", scan_id=seeded, approval_token="x")
        with pytest.raises(ValueError, match="fetch"):
            runner.run([Probe(kind="reflection", url="https://a.test/?q=x", parameter="q")],
                       fetch=object(), actor="t", scan_id=seeded, approval_token="x")
        with pytest.raises(ValueError, match="actor"):
            runner.run([Probe(kind="reflection", url="https://a.test/?q=x", parameter="q")],
                       fetch=lambda url: page(url), actor=" ", scan_id=seeded, approval_token="x")
    finally:
        session.close()


def test_plan_adds_path_traversal_only_for_file_like_parameters():
    probes = plan_probes(["https://app.test/view?file=index.html&q=x"])
    files = [probe for probe in probes if probe.kind == "path_traversal"]
    assert len(files) == 1 and files[0].parameter == "file"
    assert "..%2F..%2F..%2F..%2Fetc%2Fpasswd" in files[0].url
    assert all(probe.kind != "path_traversal" for probe in plan_probes(["https://app.test/s?q=x"]))


def test_path_traversal_signature_is_a_candidate(factory, seeded):
    probes = plan_probes(["https://app.test/view?file=index.html"])
    traversal = next(probe for probe in probes if probe.kind == "path_traversal")
    fetcher = Fetcher({probe.url: page(probe.url) for probe in probes})
    fetcher.responses[traversal.url] = page(traversal.url, "root:x:0:0:root:/root:/bin/sh\nbin:x:1:1::/bin:/sbin/nologin")
    token = approve(factory, seeded, probes)
    runner, session = engine_for(factory)
    try:
        report = runner.run(probes, fetch=fetcher, actor="tester", scan_id=seeded, approval_token=token)
        session.commit()
    finally:
        session.close()
    result = next(item for item in report.results if item.kind == "path_traversal")
    assert result.verdict == "candidate" and "file content signature" in result.detail
    assert report.errors == 0


def test_path_traversal_without_a_signature_stays_inconclusive(factory, seeded):
    probes = plan_probes(["https://app.test/view?file=index.html"])
    traversal = next(probe for probe in probes if probe.kind == "path_traversal")
    fetcher = Fetcher({probe.url: page(probe.url, "file not found") for probe in probes})
    token = approve(factory, seeded, probes)
    runner, session = engine_for(factory)
    try:
        report = runner.run(probes, fetch=fetcher, actor="tester", scan_id=seeded, approval_token=token)
        session.commit()
    finally:
        session.close()
    result = next(item for item in report.results if item.kind == "path_traversal")
    assert result.verdict == "inconclusive"
    assert traversal.url.startswith("https://app.test/view?")
