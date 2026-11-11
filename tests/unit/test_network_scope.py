from datetime import datetime, timedelta, timezone

import pytest
from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import ScopeDenied, check_redirect, check_resolved_addresses


@pytest.fixture
def scope():
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="test", approved_by="owner", starts_at=now-timedelta(hours=1), expires_at=now+timedelta(hours=1), web_origins=["https://example.test"], allowed_web_paths={"https://example.test": ["/api"]}, allowed_ip_networks=["192.0.2.0/24"], denied_ip_networks=["192.0.2.128/25"])


def test_every_dns_answer_must_be_allowed(scope):
    target = Target(type="web", locator="https://example.test/api")
    check_resolved_addresses(target, scope, ["192.0.2.1", "192.0.2.2"])
    for addresses in ([], ["192.0.2.1", "203.0.113.1"], ["192.0.2.1", "192.0.2.200"], ["not-an-ip"]):
        with pytest.raises(ScopeDenied):
            check_resolved_addresses(target, scope, addresses)


def test_mapped_ipv6_cannot_bypass_deny(scope):
    target = Target(type="web", locator="https://example.test/api")
    check_resolved_addresses(target, scope, ["::ffff:192.0.2.1"])
    with pytest.raises(ScopeDenied):
        check_resolved_addresses(target, scope, ["::ffff:192.0.2.200"])
    scope.denied_ip_networks = ["::/0"]
    with pytest.raises(ScopeDenied):
        check_resolved_addresses(target, scope, ["::ffff:192.0.2.1"])


def test_missing_or_malformed_ip_policy_fails_closed(scope):
    target = Target(type="web", locator="https://example.test/api")
    scope.allowed_ip_networks = []
    with pytest.raises(ScopeDenied):
        check_resolved_addresses(target, scope, ["192.0.2.1"])
    scope.allowed_ip_networks = ["192.0.2.1/24"]  # host bits are not a network
    with pytest.raises(ScopeDenied):
        check_resolved_addresses(target, scope, ["192.0.2.1"])


def test_literal_ip_must_match_dns_answer(scope):
    scope.web_origins = ["https://192.0.2.1"]
    scope.allowed_web_paths = {}
    target = Target(type="web", locator="https://192.0.2.1/")
    check_resolved_addresses(target, scope, ["192.0.2.1"])
    with pytest.raises(ScopeDenied):
        check_resolved_addresses(target, scope, ["192.0.2.2"])


def test_redirect_is_checked_for_origin_path_and_control_chars(scope):
    current = Target(type="web", locator="https://example.test/api/a")
    assert check_redirect(current, "/api/b", scope).locator == "https://example.test/api/b"
    for location in ("https://other.test/api", "/admin", "//evil.test/api", "\n/api", "/api/%2fadmin",
                     "http://[broken", 42):
        with pytest.raises(ScopeDenied):
            check_redirect(current, location, scope)
