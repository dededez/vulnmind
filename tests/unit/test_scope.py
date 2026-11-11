from datetime import datetime, timedelta, timezone
import pytest
from pydantic import ValidationError
from vulnmind.schemas import Authorization, Target, TargetType
from vulnmind.security.scope import ScopeDenied, check_target


@pytest.fixture
def scope(tmp_path):
    now = datetime.now(timezone.utc)
    return Authorization(authorization_source="written authorization", approved_by="owner", starts_at=now-timedelta(hours=1), expires_at=now+timedelta(hours=1), repository_roots=[str(tmp_path)], web_origins=["https://example.test"])


def test_repo_inside_and_outside(scope, tmp_path):
    child = tmp_path / "repo"
    child.mkdir()
    check_target(Target(type=TargetType.REPOSITORY, locator=str(child)), scope)
    with pytest.raises(ScopeDenied):
        check_target(Target(type=TargetType.REPOSITORY, locator=str(tmp_path.parent)), scope)


def test_inaccessible_and_malformed_repository_targets_fail_as_denials(scope, tmp_path):
    for locator in (str(tmp_path / "missing-sensitive-name"), "invalid\x00path"):
        with pytest.raises(ScopeDenied) as exc:
            check_target(Target(type=TargetType.REPOSITORY, locator=locator), scope)
        assert locator not in str(exc.value)
    with pytest.raises(ScopeDenied, match="time window"):
        check_target(Target(type=TargetType.WEB, locator="https://example.test"), scope, now="not-a-time")


def test_web_origin_exact(scope):
    check_target(Target(type=TargetType.WEB, locator="https://example.test:443/api"), scope)
    for url in ["https://example.test.evil/", "http://example.test", "https://example.test:444/", "https://example.test@evil.test/"]:
        with pytest.raises(ScopeDenied):
            check_target(Target(type=TargetType.WEB, locator=url), scope)


def test_expired(scope):
    with pytest.raises(ScopeDenied):
        check_target(Target(type=TargetType.WEB, locator="https://example.test"), scope, scope.expires_at)


def test_naive_window_rejected():
    with pytest.raises(ValidationError):
        Authorization(authorization_source="owner", approved_by="owner", starts_at=datetime(2026, 1, 1), expires_at=datetime(2027, 1, 1))


def test_allowlist_cannot_silently_ignore_path(scope):
    scope.web_origins = ["https://example.test/allowed"]
    with pytest.raises(ScopeDenied):
        check_target(Target(type=TargetType.WEB, locator="https://example.test/elsewhere"), scope)


def test_denylists_override_allowlists(scope, tmp_path):
    child = tmp_path / "denied"
    child.mkdir()
    scope.denied_repository_roots = [str(child)]
    with pytest.raises(ScopeDenied):
        check_target(Target(type=TargetType.REPOSITORY, locator=str(child)), scope)
    with pytest.raises(ScopeDenied):
        check_target(Target(type=TargetType.REPOSITORY, locator=str(tmp_path)), scope)
    scope.denied_web_origins = ["https://example.test"]
    with pytest.raises(ScopeDenied):
        check_target(Target(type=TargetType.WEB, locator="https://example.test"), scope)


@pytest.mark.parametrize("url", ["https://example.test:0", "https://example.test\n.evil", " https://example.test"])
def test_malformed_web_target_is_rejected(scope, url):
    with pytest.raises(ScopeDenied):
        check_target(Target(type=TargetType.WEB, locator=url), scope)


def test_malformed_scope_entry_fails_closed(scope):
    scope.web_origins = ["https://example.test", "https://example.test/some-path"]
    with pytest.raises(ScopeDenied):
        check_target(Target(type=TargetType.WEB, locator="https://example.test"), scope)


def test_blank_scope_entries_are_rejected(scope):
    data = scope.model_dump()
    data["repository_roots"] = [""]
    with pytest.raises(ValidationError):
        Authorization.model_validate(data)


def test_web_path_boundaries_and_deny_priority(scope):
    scope.allowed_web_paths = {"https://example.test": ["/api"]}
    scope.denied_web_paths = {"https://example.test": ["/api/private"]}
    for path in ("/api", "/api/", "/api/users"):
        check_target(Target(type="web", locator="https://example.test" + path), scope)
    for path in ("/api2", "/api/private", "/api/private/x", "/"):
        with pytest.raises(ScopeDenied):
            check_target(Target(type="web", locator="https://example.test" + path), scope)


@pytest.mark.parametrize("path", ["/api/../admin", "/api/%2e%2e/admin", "/api//admin", "/api;param/admin", "/api/%252fadmin"])
def test_web_path_rejects_ambiguous_encodings(scope, path):
    with pytest.raises(ScopeDenied):
        check_target(Target(type="web", locator="https://example.test" + path), scope)


def test_configured_paths_do_not_default_to_allow_for_other_origins(scope):
    scope.web_origins.append("https://other.test")
    scope.allowed_web_paths = {"https://example.test": ["/api"]}
    with pytest.raises(ScopeDenied):
        check_target(Target(type="web", locator="https://other.test/"), scope)


def test_mutated_scope_is_revalidated_before_use(scope):
    scope.repository_roots = [""]
    with pytest.raises(ScopeDenied):
        check_target(Target(type="web", locator="https://example.test"), scope)
