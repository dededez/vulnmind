"""Crawler tests: BFS, scope filtering, dedupe and limits (no network)."""
from datetime import datetime, timedelta, timezone

import pytest

from vulnmind.analysis.crawler import CrawlError, FetchResult, crawl
from vulnmind.schemas import Authorization, Target

BASE = "https://app.test/"


def authorization():
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         web_origins=["https://app.test"])


def html(*links):
    return ("<html><body>" + "".join(f'<a href="{link}">x</a>' for link in links) + "</body></html>").encode()


class FakeFetch:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        value = self.pages[url]
        if isinstance(value, Exception):
            raise value
        if value.final_url == BASE and url != BASE:
            return FetchResult(status_code=value.status_code, content_type=value.content_type,
                               body=value.body, final_url=url)
        return value


def page(body=b"", *, status=200, content_type="text/html", final=None):
    return FetchResult(status_code=status, content_type=content_type, body=body,
                       final_url=final or BASE)


def test_crawls_same_origin_pages_and_dedupes_endpoints():
    pages = {
        BASE: page(html("/a", "/a#frag", "https://evil.test/x", "mailto:a@b")),
        "https://app.test/a": page(html("/b")),
        "https://app.test/b": page(b"<html>done</html>"),
    }
    fetcher = FakeFetch(pages)
    result = crawl(start=Target(type="web", locator=BASE), scope=authorization(), fetch=fetcher)
    assert [item.url for item in result.pages] == [BASE, "https://app.test/a", "https://app.test/b"]
    urls = [item["url"] for item in result.endpoints]
    assert urls.count("https://app.test/a") == 1
    assert next(item for item in result.endpoints if item["url"] == "https://app.test/a")["source_url"] == BASE
    assert next(item for item in result.endpoints if item["url"] == "https://app.test/b")["source_url"] == "https://app.test/a"
    assert "https://evil.test/x" not in urls and result.out_of_scope >= 1
    assert all(call.startswith("https://app.test/") for call in fetcher.calls)
    assert {item["vulnerability_type"] for item in result.findings} >= {"missing_content_security_policy"}
    assert all(item["status"] == "unverified" for item in result.findings)


def test_form_parameters_merge_with_previously_discovered_link():
    pages = {
        BASE: page(b'<a href="/search">search</a><form action="/search"><input name="q"></form>'),
        "https://app.test/search": page(b'<form action="/search"><input name="page"></form>'),
    }
    result = crawl(start=Target(type="web", locator=BASE), scope=authorization(), fetch=FakeFetch(pages))
    assert result.endpoints[0]["parameters"] == ["q", "page"]
    assert result.endpoints[0]["source_url"] == BASE


def test_skips_errors_non_html_and_non_success():
    pages = {
        BASE: page(html("/missing", "/json", "/boom")),
        "https://app.test/missing": page(status=404),
        "https://app.test/json": page(content_type="application/json"),
        "https://app.test/boom": RuntimeError("network down"),
    }
    result = crawl(start=Target(type="web", locator=BASE), scope=authorization(), fetch=FakeFetch(pages))
    assert [item.url for item in result.pages] == [BASE]
    assert result.skipped == 2 and result.errors == ["https://app.test/boom"]


def test_audit_failure_aborts_crawl_before_next_page():
    from vulnmind.persistence.audit import AuditError

    pages = {BASE: page(html("/a", "/b")),
             "https://app.test/a": AuditError("audit unavailable"),
             "https://app.test/b": page()}
    fetcher = FakeFetch(pages)
    with pytest.raises(AuditError):
        crawl(start=Target(type="web", locator=BASE), scope=authorization(), fetch=fetcher)
    assert fetcher.calls == [BASE, "https://app.test/a"]


def test_redirect_to_another_origin_is_not_parsed():
    pages = {BASE: page(html("/a"), final="https://other.test/")}
    result = crawl(start=Target(type="web", locator=BASE), scope=authorization(), fetch=FakeFetch(pages))
    assert result.pages == [] and result.out_of_scope == 1


def test_page_limit_truncates():
    pages = {BASE: page(html("/a", "/b"))}
    for name in ("a", "b"):
        pages[f"https://app.test/{name}"] = page(html("/a", "/b"))
    result = crawl(start=Target(type="web", locator=BASE), scope=authorization(),
                   fetch=FakeFetch(pages), max_pages=2)
    assert len(result.pages) == 2 and result.truncated is True


def test_validation():
    with pytest.raises(ValueError, match="web target"):
        crawl(start=Target(type="repository", locator="/tmp"), scope=authorization(), fetch=FakeFetch({}))
    with pytest.raises(ValueError, match="fetch callable"):
        crawl(start=Target(type="web", locator=BASE), scope=authorization(), fetch=None)
    with pytest.raises(ValueError, match="max_pages"):
        crawl(start=Target(type="web", locator=BASE), scope=authorization(), fetch=FakeFetch({}), max_pages=0)
