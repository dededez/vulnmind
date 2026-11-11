"""web_endpoints persistence and crawl storage (SQLite, no network)."""
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from vulnmind.analysis.crawl_store import store_crawl_result
from vulnmind.persistence.base import Base
from vulnmind.persistence.models import Project, Scan, WebEndpoint
from vulnmind.persistence.repositories import WebEndpointRepository
from vulnmind.persistence.unit_of_work import transaction


@pytest.fixture
def factory():
    engine = create_engine("sqlite://")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def seed(factory):
    with transaction(factory) as session:
        project = Project(id=uuid4(), name="crawl")
        session.add(project)
        session.flush()
        scan = Scan(id=uuid4(), project_id=project.id, status="running", mode="crawl",
                    started_at=datetime.now(timezone.utc))
        session.add(scan)
        session.flush()
        return project.id, scan.id


def endpoint(url="https://app.test/a", method="GET", source="https://app.test/"):
    return {"url": url, "method": method, "source": source}


def test_store_crawl_result_creates_a_finished_scan(factory):
    project_id, _ = seed(factory)
    with transaction(factory) as session:
        scan = store_crawl_result(session=session, project_id=project_id, actor="tester",
                                  endpoints=[endpoint(), endpoint(method="POST", url="https://app.test/login"),
                                             endpoint()])
        assert scan.status == "finished" and scan.mode == "crawl"
        rows = WebEndpointRepository(session).list_for_scan(scan.id)
    assert [(row.method, row.url) for row in rows] == [("GET", "https://app.test/a"),
                                                       ("POST", "https://app.test/login")]
    assert all(row.project_id == project_id for row in rows)


def test_replace_for_scan_is_idempotent(factory):
    project_id, scan_id = seed(factory)
    repository = WebEndpointRepository
    with transaction(factory) as session:
        repository(session).replace_for_scan(scan_id, project_id, [endpoint(), endpoint(url="https://app.test/b")])
    with transaction(factory) as session:
        repository(session).replace_for_scan(scan_id, project_id, [endpoint(url="https://app.test/c")])
    with transaction(factory) as session:
        rows = repository(session).list_for_scan(scan_id)
        assert [row.url for row in rows] == ["https://app.test/c"]
        assert session.scalar(select(WebEndpoint).where(WebEndpoint.scan_id == scan_id)) is not None


def test_invalid_endpoints_are_rejected(factory):
    project_id, scan_id = seed(factory)
    bad_inputs = [
        [{"url": "", "method": "GET", "source": "https://app.test/"}],
        [{"url": "https://app.test/a b", "method": "GET", "source": "https://app.test/"}],
        [{"url": "https://app.test/a", "method": "G3T", "source": "https://app.test/"}],
        [{"url": "https://app.test/\x01", "method": "GET", "source": "https://app.test/"}],
        [{"url": "https://app.test/" + "a" * 3000, "method": "GET", "source": "https://app.test/"}],
        ["not a mapping"],
        [{"url": "https://app.test/a", "parameters": ["x", "x"]}],
        [{"url": "https://app.test/a", "parameters": ["bad\x00name"]}],
        [{"url": "https://app.test/a", "parameters": ["x" * 256]}],
        [{"url": "https://app.test/a", "parameters": [str(i) for i in range(257)]}],
    ]
    with transaction(factory) as session:
        for bad in bad_inputs:
            with pytest.raises(ValueError):
                WebEndpointRepository(session).replace_for_scan(scan_id, project_id, bad)
        assert session.scalar(select(WebEndpoint)) is None


def test_unknown_and_observed_empty_parameters_are_distinct(factory):
    project_id, scan_id = seed(factory)
    with transaction(factory) as session:
        WebEndpointRepository(session).replace_for_scan(scan_id, project_id, [
            {"url": "https://app.test/unknown"},
            {"url": "https://app.test/empty", "parameters": []},
            {"url": "https://app.test/form", "parameters": ["q"]}])
    with transaction(factory) as session:
        rows = {row.url.rsplit("/", 1)[-1]: row.parameters
                for row in WebEndpointRepository(session).list_for_scan(scan_id)}
        assert rows == {"unknown": None, "empty": [], "form": ["q"]}


def test_duplicate_endpoints_merge_parameters_and_preserve_first_source(factory):
    project_id, scan_id = seed(factory)
    with transaction(factory) as session:
        repository = WebEndpointRepository(session)
        repository.replace_for_scan(scan_id, project_id, [
            {"url": "https://app.test/a", "source_url": "https://app.test/first", "parameters": ["q"]},
            {"url": "https://app.test/a", "source_url": "https://app.test/second", "parameters": ["q", "page"]},
        ])
        row = repository.list_for_scan(scan_id)[0]
        assert row.parameters == ["q", "page"]
        assert row.source_url == "https://app.test/first"


def test_duplicate_endpoint_merge_over_limit_does_not_replace_existing_rows(factory):
    project_id, scan_id = seed(factory)
    with transaction(factory) as session:
        repository = WebEndpointRepository(session)
        repository.replace_for_scan(scan_id, project_id, [endpoint()])
        with pytest.raises(ValueError, match="exceed"):
            repository.replace_for_scan(scan_id, project_id, [
                {"url": "https://app.test/b", "parameters": [str(i) for i in range(200)]},
                {"url": "https://app.test/b", "parameters": [str(i) for i in range(200, 257)]},
            ])
        assert repository.list_for_scan(scan_id)[0].url == "https://app.test/a"


def test_duplicate_endpoint_with_unknown_parameters_remains_unknown(factory):
    project_id, scan_id = seed(factory)
    with transaction(factory) as session:
        repository = WebEndpointRepository(session)
        repository.replace_for_scan(scan_id, project_id, [
            {"url": "https://app.test/a", "parameters": ["q"]},
            {"url": "https://app.test/a"},
        ])
        assert repository.list_for_scan(scan_id)[0].parameters is None


def test_scan_project_mismatch_is_rejected(factory):
    project_id, scan_id = seed(factory)
    with transaction(factory) as session:
        with pytest.raises(ValueError, match="do not match"):
            WebEndpointRepository(session).replace_for_scan(scan_id, uuid4(), [endpoint()])
        with pytest.raises(ValueError, match="status"):
            WebEndpointRepository(session).replace_for_scan(scan_id, project_id, [endpoint()], status="")


def test_list_limit_is_validated(factory):
    project_id, scan_id = seed(factory)
    with transaction(factory) as session:
        repository = WebEndpointRepository(session)
        for limit in (0, -1, 2001, True):
            with pytest.raises(ValueError, match="limit"):
                repository.list_for_scan(scan_id, limit=limit)


def test_store_requires_an_existing_project(factory):
    with transaction(factory) as session:
        with pytest.raises(ValueError, match="project is not stored"):
            store_crawl_result(session=session, project_id=uuid4(), actor="tester", endpoints=[])
        with pytest.raises(ValueError, match="actor"):
            store_crawl_result(session=session, project_id=uuid4(), actor=" ", endpoints=[])
