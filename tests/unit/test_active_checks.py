"""Passive check tests: headers, cookies, disclosure, skips."""
import pytest

from vulnmind.analysis.active_checks import PageMetadata, check_page, check_pages


def page(headers=None, *, url="https://app.test/", status=200, content_type="text/html; charset=utf-8"):
    return PageMetadata(url=url, status_code=status, headers=headers or {}, content_type=content_type)


def kinds(result):
    return {item.vulnerability_type for item in result.findings}


def test_missing_headers_are_reported_as_unverified_low_risk_evidence():
    result = check_page(page())
    assert "missing_content_security_policy" in kinds(result)
    assert "missing_strict_transport_security" in kinds(result)
    assert all(item.status == "unverified" for item in result.findings)
    assert all(item.target_id == "https://app.test/" for item in result.findings)


def test_complete_headers_produce_no_findings():
    headers = {"Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff",
               "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
               "Permissions-Policy": "geolocation=()", "Strict-Transport-Security": "max-age=31536000"}
    assert check_page(page(headers)).findings == []


def test_http_does_not_require_hsts():
    result = check_page(page({}, url="http://app.test/"))
    assert "missing_strict_transport_security" not in kinds(result)


def test_cookie_attributes_and_disclosure():
    headers = {"Set-Cookie": "session=abc; Path=/; SameSite=Lax",
               "Server": "nginx/1.25.3", "X-Powered-By": "Express"}
    result = check_page(page(headers))
    cookies = [item for item in result.findings if item.vulnerability_type == "cookie_attribute_missing"]
    assert cookies and "HttpOnly" in cookies[0].title and "Secure" in cookies[0].title
    assert len([item for item in result.findings if item.vulnerability_type == "technology_disclosure"]) == 2


def test_header_and_cookie_values_are_not_copied_into_findings():
    result = check_page(page({"Server": "secret-server-value", "Set-Cookie": "secret-name=secret-value"}))
    titles = " ".join(item.title for item in result.findings)
    assert "secret-server-value" not in titles and "secret-name" not in titles
    assert "secret-value" not in titles


def test_cookie_expires_comma_does_not_create_a_second_cookie():
    result = check_page(page({"Set-Cookie": "session=secret; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Secure; HttpOnly; SameSite=Lax"}))
    assert "cookie_attribute_missing" not in kinds(result)


def test_cookie_quoted_comma_does_not_create_a_second_cookie():
    result = check_page(page({"Set-Cookie": 'session="one,two=three"; Secure; HttpOnly; SameSite=Lax'}))
    assert "cookie_attribute_missing" not in kinds(result)


@pytest.mark.parametrize("attribute", ["SameSiteExtra=Lax", "SameSite=", "SameSite=invalid"])
def test_cookie_invalid_samesite_is_not_treated_as_present(attribute):
    result = check_page(page({"Set-Cookie": f"session=secret; Secure; HttpOnly; {attribute}"}))
    cookies = [item for item in result.findings if item.vulnerability_type == "cookie_attribute_missing"]
    assert len(cookies) == 1
    assert "SameSite" in cookies[0].title
    assert "secret" not in cookies[0].title


def test_multiple_cookies_are_checked_individually_after_expires():
    result = check_page(page({"Set-Cookie": "first=one; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Secure; HttpOnly; SameSite=Strict, second=two; Secure; HttpOnly"}))
    cookies = [item for item in result.findings if item.vulnerability_type == "cookie_attribute_missing"]
    assert len(cookies) == 1
    assert "SameSite" in cookies[0].title


def test_non_html_and_error_pages_are_skipped():
    assert check_page(page({}, content_type="application/json")).skipped == 1
    assert check_page(page({}, status=404)).skipped == 1
    results = check_pages([page({}), page({}, status=500)])
    assert len(results) == 2 and results[1].skipped == 1
