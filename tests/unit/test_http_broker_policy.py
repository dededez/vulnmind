from datetime import datetime, timedelta, timezone

import pytest

from vulnmind.analysis.http_broker_worker import validate
from vulnmind.schemas import Authorization


def request():
    now = datetime.now(timezone.utc)
    scope = Authorization(authorization_source="test", approved_by="test", starts_at=now-timedelta(minutes=1),
        expires_at=now+timedelta(hours=1), web_origins=["https://test.invalid"],
        allowed_web_paths={"https://test.invalid": ["/api"]}, denied_web_paths={"https://test.invalid": ["/api/admin"]},
        allowed_ip_networks=["192.0.2.0/24"], denied_ip_networks=["192.0.2.10/32"])
    return {"scope": scope.model_dump(mode="json"), "url": "https://test.invalid/api/search?q=x",
            "addresses": ["192.0.2.1"], "method": "GET", "max_body": 1000, "timeout": 2, "headers": {}}


@pytest.mark.parametrize("change", [
    {"url": "https://other.invalid/api"}, {"url": "https://test.invalid:444/api"},
    {"url": "https://test.invalid/api/admin"}, {"url": "https://test.invalid/api/%2e%2e/admin"},
    {"url": "https://test.invalid/api/../admin"}, {"url": "https://test.invalid/api\\admin"},
    {"url": "https://test.invalid/outside"}, {"addresses": ["192.0.2.1", "127.0.0.1"]},
    {"addresses": ["192.0.2.10"]}, {"addresses": []}, {"method": "POST"},
    {"headers": {"Host": "other.invalid"}}, {"headers": {"Transfer-Encoding": "chunked"}},
    {"headers": {"Accept": "a\r\nb"}}, {"headers": {"Proxy-Authorization": "secret"}},
])
def test_broker_rechecks_policy_independently(change):
    with pytest.raises(ValueError):
        validate({**request(), **change})


def test_validated_ip_is_returned_without_another_dns_lookup(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a: pytest.fail("second DNS lookup"))
    origin, address = validate(request())
    assert origin == ("https", "test.invalid", 443) and str(address) == "192.0.2.1"
