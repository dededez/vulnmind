"""Preflight authorization checks. Not a network or filesystem sandbox."""
from datetime import datetime, timezone
from pathlib import Path
import re
import ipaddress
from urllib.parse import urljoin, urlsplit
from vulnmind.schemas import Authorization, Target, TargetType


class ScopeDenied(ValueError):
    pass


def _path(value: str) -> str:
    """Accept an unambiguous conservative path, not a general URL normalizer."""
    value = value or "/"
    if (not value.startswith("/") or not re.fullmatch(r"/[A-Za-z0-9._~/-]*", value)
            or "//" in value or any(part in {".", ".."} for part in value.split("/"))):
        raise ScopeDenied("ambiguous or invalid web path")
    return value.rstrip("/") or "/"


def _within_path(path: str, prefix: str) -> bool:
    return prefix == "/" or path == prefix or path.startswith(prefix + "/")


def _path_policy(entries: dict[str, list[str]]) -> dict[tuple[str, str, int], list[str]]:
    result = {}
    for origin, paths in entries.items():
        key = _origin(origin, origin_only=True)
        if key in result or not paths or any(not path for path in paths):
            raise ScopeDenied("duplicate origin or empty web path policy")
        result[key] = [_path(path) for path in paths]
    return result


def _origin(value: str, *, origin_only: bool = False) -> tuple[str, str, int]:
    try:
        if value != value.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError("invalid whitespace or control character")
        u = urlsplit(value)
        if u.scheme.lower() not in {"http", "https"} or not u.hostname or u.username is not None or u.password is not None:
            raise ValueError("invalid HTTP origin")
        if origin_only and (u.path not in ("", "/") or u.query or u.fragment):
            raise ValueError("allowlist must contain origins only")
        if u.fragment:
            raise ValueError("fragment is not a target")
        host = u.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if not host or "%" in host or "\\" in value:
            raise ValueError("invalid host")
        port = u.port if u.port is not None else (443 if u.scheme.lower() == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError("invalid port")
        return u.scheme.lower(), host, port
    except (ValueError, UnicodeError) as exc:
        raise ScopeDenied("invalid web target or authorized origin") from exc


def check_target(target: Target, scope: Authorization, now: datetime | None = None) -> None:
    try:
        # Pydantic models are mutable; revalidate a snapshot immediately before use.
        target = Target.model_validate(target.model_dump())
        scope = Authorization.model_validate(scope.model_dump())
    except (AttributeError, ValueError, TypeError) as exc:
        raise ScopeDenied("invalid target or authorization") from exc
    now = datetime.now(timezone.utc) if now is None else now
    if not isinstance(now, datetime) or now.utcoffset() is None or not (scope.starts_at <= now < scope.expires_at):
        raise ScopeDenied("authorization is outside its time window")
    if target.type == TargetType.REPOSITORY:
        try:
            path = Path(target.locator).resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            raise ScopeDenied("invalid or inaccessible repository target") from None
        if not path.is_dir():
            raise ScopeDenied("repository must be an existing directory")
        for root in scope.denied_repository_roots:
            try:
                denied = Path(root).resolve(strict=True)
            except (OSError, RuntimeError, ValueError):
                raise ScopeDenied("invalid denied repository root") from None
            # A whole-repository analyzer could traverse a denied descendant.
            # Until every filesystem access is independently enforced, deny overlap.
            if path.is_relative_to(denied) or denied.is_relative_to(path):
                raise ScopeDenied("repository overlaps an explicitly denied path")
        for root in scope.repository_roots:
            try:
                allowed = Path(root).resolve(strict=True)
                if allowed.is_dir() and path.is_relative_to(allowed):
                    return
            except (OSError, RuntimeError, ValueError):
                continue
        raise ScopeDenied("repository is outside authorized roots")
    if target.type == TargetType.WEB:
        candidate = _origin(target.locator)
        # Validate all entries before making an allow decision; malformed policy is denied.
        denied = {_origin(origin, origin_only=True) for origin in scope.denied_web_origins}
        allowed = {_origin(origin, origin_only=True) for origin in scope.web_origins}
        path = _path(urlsplit(target.locator).path)
        allowed_paths = _path_policy(scope.allowed_web_paths)
        denied_paths = _path_policy(scope.denied_web_paths)
        if candidate in denied:
            raise ScopeDenied("web origin is explicitly denied")
        if candidate not in allowed:
            raise ScopeDenied("web origin is outside authorization")
        if any(_within_path(path, prefix) for prefix in denied_paths.get(candidate, [])):
            raise ScopeDenied("web path is explicitly denied")
        if allowed_paths and not any(_within_path(path, prefix) for prefix in allowed_paths.get(candidate, [])):
            raise ScopeDenied("web path is outside authorization")
        return
    raise ScopeDenied("unsupported target type")


def check_resolved_addresses(target: Target, scope: Authorization, addresses: list[str]) -> None:
    """Check caller-supplied DNS answers. This does not resolve or pin a socket."""
    if target.type != TargetType.WEB:
        raise ScopeDenied("IP checks require a web target")
    check_target(target, scope)
    if not addresses or not scope.allowed_ip_networks:
        raise ScopeDenied("IP addresses and explicit IP allowlist are required")
    try:
        if any("%" in item for item in [*addresses, *scope.allowed_ip_networks, *scope.denied_ip_networks]):
            raise ValueError("IPv6 zone identifiers are not accepted")
        allowed = [ipaddress.ip_network(item, strict=True) for item in scope.allowed_ip_networks]
        denied = [ipaddress.ip_network(item, strict=True) for item in scope.denied_ip_networks]
        parsed = [ipaddress.ip_address(item) for item in addresses]
    except ValueError as exc:
        raise ScopeDenied("invalid IP address or network policy") from exc
    try:
        literal = ipaddress.ip_address(urlsplit(target.locator).hostname)
    except ValueError:
        literal = None
    if literal is not None and any(address != literal for address in parsed):
        raise ScopeDenied("resolved address does not match literal target")
    for address in parsed:
        if any(address.version == network.version and address in network for network in denied):
            raise ScopeDenied("IP address is explicitly denied")
        # IPv4-mapped IPv6 must not bypass IPv4 allow/deny networks.
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if any(address.version == network.version and address in network for network in denied):
            raise ScopeDenied("IP address is explicitly denied")
        if not any(address.version == network.version and address in network for network in allowed):
            raise ScopeDenied("IP address is outside authorization")


def check_redirect(current: Target, location: str, scope: Authorization) -> Target:
    """Check redirect URL only; caller must resolve and validate its address separately."""
    if current.type != TargetType.WEB:
        raise ScopeDenied("redirects require a web target")
    check_target(current, scope)
    if (not isinstance(location, str) or not location or location != location.strip() or "\\" in location
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in location)):
        raise ScopeDenied("invalid redirect location")
    try:
        destination = Target(type=TargetType.WEB, locator=urljoin(current.locator, location))
    except (ValueError, TypeError) as exc:
        raise ScopeDenied("invalid redirect location") from exc
    check_target(destination, scope)
    return destination
