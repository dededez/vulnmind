"""Snapshot parsing and bounds for offline web analysis."""
import json

import pytest

from vulnmind.analysis.web_service import (MAX_HTML_CHARACTERS, MAX_PAGES, WebPageSnapshot,
                                           WebSnapshot, parse_snapshot)


def page(**updates):
    payload = {"url": "https://example.test/", "status_code": 200,
               "content_type": "text/html", "headers": {"server": "test"}, "html": "<html></html>"}
    payload.update(updates)
    return payload


def test_valid_snapshot_roundtrip():
    snapshot = parse_snapshot(json.dumps({"version": 1,
                                          "target": {"type": "web", "locator": "https://example.test/"},
                                          "pages": [page()]}).encode())
    assert snapshot.version == 1
    assert snapshot.target.type.value == "web"
    assert snapshot.pages[0].url == "https://example.test/"


@pytest.mark.parametrize("update", [
    {"version": 2},
    {"target": {"type": "repository", "locator": "/repo"}},
    {"pages": []},
    {"pages": [page(), page()]},
    {"pages": [page(url="https://user:pass@example.test/")]},
    {"pages": [page(url="https://example.test/#fragment")]},
    {"pages": [page(url="file:///etc/passwd")]},
    {"pages": [page(headers={"x-test": "bad\nvalue"})]},
    {"pages": [page(status_code=99)]},
])
def test_snapshot_rejects_invalid_shapes(update):
    payload = {"version": 1, "target": {"type": "web", "locator": "https://example.test/"},
               "pages": [page()]}
    payload.update(update)
    with pytest.raises(ValueError):
        WebSnapshot.model_validate(payload)


def test_snapshot_page_and_header_limits():
    with pytest.raises(ValueError):
        WebPageSnapshot.model_validate(page(html="x" * (MAX_HTML_CHARACTERS + 1)))
    with pytest.raises(ValueError):
        WebPageSnapshot.model_validate(page(headers={f"h{index}": "v" for index in range(101)}))
    with pytest.raises(ValueError):
        WebSnapshot.model_validate({"version": 1,
                                    "target": {"type": "web", "locator": "https://example.test/"},
                                    "pages": [page(url=f"https://example.test/{index}")
                                              for index in range(MAX_PAGES + 1)]})


def test_parse_snapshot_rejects_bad_input():
    with pytest.raises(ValueError):
        parse_snapshot(b"")
    with pytest.raises(ValueError):
        parse_snapshot(b"\xff\xfe")
    with pytest.raises(ValueError):
        parse_snapshot(b"not json")
    with pytest.raises(ValueError):
        parse_snapshot(b"[]")
    with pytest.raises(ValueError):
        parse_snapshot(b"x" * 10_000_001)
