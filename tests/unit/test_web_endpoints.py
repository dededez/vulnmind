"""Passive endpoint extraction tests: scope filtering, dedupe, caps, no network."""
from datetime import datetime, timedelta, timezone

import pytest

from vulnmind.analysis.web import extract_endpoints
from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import ScopeDenied

BASE = "https://example.test/app/"


def authorization(origin="https://example.test", *, allowed_paths=None):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner",
                         starts_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
                         web_origins=[origin], allowed_web_paths=allowed_paths or {})


def base_target(url=BASE):
    return Target(type="web", locator=url)


def test_links_forms_and_scripts_are_resolved_and_deduplicated():
    html = """
    <html><body>
      <a href="/login">login</a>
      <a href="/login">login again</a>
      <a href="item?id=1">relative</a>
      <form action="/submit" method="post">
        <input name="user"><input name="pass"><input type="submit">
      </form>
      <script src="/static/app.js"></script>
      <iframe src="/frame"></iframe>
      <a href="javascript:void(0)">ignore</a>
      <a href="mailto:a@example.test">ignore</a>
    </body></html>
    """
    inventory = extract_endpoints(base=base_target(), scope=authorization(), html=html)
    urls = [(endpoint.method, endpoint.url) for endpoint in inventory.endpoints]
    assert ("GET", "https://example.test/login") in urls
    assert ("GET", "https://example.test/app/item?id=1") in urls
    assert ("POST", "https://example.test/submit") in urls
    assert ("GET", "https://example.test/static/app.js") in urls
    assert ("GET", "https://example.test/frame") in urls
    assert len(urls) == len(set(urls))
    form = [endpoint for endpoint in inventory.endpoints if endpoint.source == "form"][0]
    assert form.parameters == ["user", "pass"]
    assert inventory.ignored == 2


def test_out_of_scope_endpoints_are_counted_not_returned():
    html = ('<a href="https://evil.test/x">off</a>'
            '<a href="http://example.test:8080/x">other port</a>'
            '<a href="/allowed">ok</a>')
    inventory = extract_endpoints(base=base_target(), scope=authorization(), html=html)
    assert [endpoint.url for endpoint in inventory.endpoints] == ["https://example.test/allowed"]
    assert inventory.out_of_scope == 2


def test_path_policy_is_applied_to_discovered_links():
    html = '<a href="/api/users">ok</a><a href="/admin">denied</a>'
    inventory = extract_endpoints(
        base=base_target("https://example.test/api/page"),
        scope=authorization(allowed_paths={"https://example.test": ["/api"]}), html=html)
    assert [endpoint.url for endpoint in inventory.endpoints] == ["https://example.test/api/users"]
    assert inventory.out_of_scope == 1


def test_caps_and_truncation_are_reported():
    html = "".join(f'<a href="/p{i}">x</a>' for i in range(10))
    inventory = extract_endpoints(base=base_target(), scope=authorization(), html=html, max_endpoints=3)
    assert len(inventory.endpoints) == 3 and inventory.truncated is True


def test_invalid_form_names_are_skipped_with_truncation():
    html = '<form><input name="ok"><input name="' + ('x' * 256) + '"><input name="bad&#10;name"></form>'
    inventory = extract_endpoints(base=base_target(), scope=authorization(), html=html)
    assert inventory.endpoints[0].parameters == ["ok"]
    assert inventory.truncated


def test_scope_and_parameter_validation():
    with pytest.raises(ScopeDenied):
        extract_endpoints(base=base_target(), scope=authorization("https://other.test"), html="<a href='/x'>x</a>")
    with pytest.raises(ValueError, match="web target"):
        extract_endpoints(base=Target(type="repository", locator="C:\\repo"), scope=authorization(), html="")
    for bad in (0, 501, True):
        with pytest.raises(ValueError, match="max_endpoints"):
            extract_endpoints(base=base_target(), scope=authorization(), html="", max_endpoints=bad)


def test_ambiguous_links_are_ignored():
    html = ('<a href=" /spaces ">x</a>'
            '<a href="/new\nline">x</a>'
            '<a href="https://user:pass@example.test/x">x</a>'
            '<a href="/anchor#fragment">x</a>')
    inventory = extract_endpoints(base=base_target(), scope=authorization(), html=html)
    assert inventory.endpoints == [] and inventory.ignored == 4


def test_malformed_url_does_not_prevent_other_endpoint_extraction():
    html = '<a href="http://[broken">bad</a><a href="/valid">ok</a>'
    inventory = extract_endpoints(base=base_target(), scope=authorization(), html=html)
    assert inventory.ignored == 1
    assert [item.url for item in inventory.endpoints] == ["https://example.test/valid"]


def test_passive_extraction_enforces_input_and_candidate_limits():
    from vulnmind.analysis.web import MAX_CANDIDATES, MAX_HTML_CHARACTERS
    with pytest.raises(ValueError, match="character limit"):
        extract_endpoints(base=base_target(), scope=authorization(), html="x" * (MAX_HTML_CHARACTERS + 1))
    html = '<a href="/same">x</a>' * (MAX_CANDIDATES + 1)
    inventory = extract_endpoints(base=base_target(), scope=authorization(), html=html)
    assert len(inventory.endpoints) == 1 and inventory.truncated


def test_form_parameter_limit_marks_inventory_incomplete():
    from vulnmind.analysis.web import MAX_FORM_PARAMETERS
    html = '<form action="/submit">' + ''.join(
        f'<input name="p{i}">' for i in range(MAX_FORM_PARAMETERS + 1)) + '</form>'
    inventory = extract_endpoints(base=base_target(), scope=authorization(), html=html)
    assert len(inventory.endpoints[0].parameters) == MAX_FORM_PARAMETERS
    assert inventory.truncated


def test_empty_form_action_targets_document_and_dialog_does_not_submit():
    html = ('<form method="post"><input name="q"></form>'
            '<form action="" method="dialog"><input name="cancel"></form>')
    inventory = extract_endpoints(base=base_target(), scope=authorization(), html=html)
    assert [(item.method, item.url, item.parameters) for item in inventory.endpoints] == [
        ("POST", BASE, ["q"])]


def test_forms_merge_parameters_without_losing_link_provenance():
    html = ('<a href="/search">search</a>'
            '<form action="/search"><input name="q"></form>'
            '<form action="/search"><input name="lang"></form>')
    inventory = extract_endpoints(base=base_target(), scope=authorization(), html=html)
    assert [(item.source, item.parameters) for item in inventory.endpoints] == [
        ("link", []), ("form", ["q", "lang"])]
