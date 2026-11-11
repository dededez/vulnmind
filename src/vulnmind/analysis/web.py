"""Passive endpoint extraction from an already-fetched HTML page.

No request is made here. Links, forms, frames and script sources are resolved
against the authorized target and filtered through the same scope guard used by
the HTTP tool; anything outside the authorization is counted, never returned.
"""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from vulnmind.schemas import Authorization, Target
from vulnmind.security.scope import ScopeDenied, check_target

MAX_ENDPOINTS = 500
MAX_HTML_CHARACTERS = 2_000_000
MAX_CANDIDATES = 5_000
MAX_FORM_PARAMETERS = 256
_ALLOWED_SCHEMES = {"http", "https"}


class Endpoint(BaseModel):
    model_config = ConfigDict(frozen=True)
    url: str
    method: str = "GET"
    source: str
    parameters: list[str] = Field(default_factory=list)


class EndpointInventory(BaseModel):
    model_config = ConfigDict(frozen=True)
    endpoints: list[Endpoint]
    out_of_scope: int
    ignored: int
    truncated: bool


def extract_endpoints(*, base: Target, scope: Authorization, html: str,
                      max_endpoints: int = MAX_ENDPOINTS) -> EndpointInventory:
    if base.type.value != "web":
        raise ValueError("endpoint extraction requires a web target")
    if not isinstance(max_endpoints, int) or isinstance(max_endpoints, bool) or not 1 <= max_endpoints <= MAX_ENDPOINTS:
        raise ValueError(f"max_endpoints must be between 1 and {MAX_ENDPOINTS}")
    if not isinstance(html, str):
        raise ValueError("html must be text")
    if len(html) > MAX_HTML_CHARACTERS:
        raise ValueError("html exceeds the character limit")
    check_target(base, scope)
    parser = _Collector()
    parser.feed(html)
    parser.close()
    endpoints: list[Endpoint] = []
    seen: dict[tuple[str, str, str], int] = {}
    out_of_scope = ignored = 0
    truncated = parser.truncated
    for raw_url, method, source, parameters in parser.items:
        # Missing/empty form action submits to the document URL.
        resolved = base.locator if source == "form" and not raw_url else _resolve(base.locator, raw_url)
        if resolved is None:
            ignored += 1
            continue
        try:
            check_target(Target(type="web", locator=resolved), scope)
        except ScopeDenied:
            out_of_scope += 1
            continue
        key = (method, resolved, source)
        if key in seen:
            position = seen[key]
            old = endpoints[position]
            merged = list(dict.fromkeys([*old.parameters, *parameters]))
            if len(merged) > MAX_FORM_PARAMETERS:
                truncated = True
            endpoints[position] = old.model_copy(update={"parameters": merged[:MAX_FORM_PARAMETERS]})
            continue
        if len(endpoints) >= max_endpoints:
            truncated = True
            break
        seen[key] = len(endpoints)
        endpoints.append(Endpoint(url=resolved, method=method, source=source, parameters=parameters))
    return EndpointInventory(endpoints=endpoints, out_of_scope=out_of_scope, ignored=ignored,
                             truncated=truncated)


def _resolve(base: str, raw: str) -> str | None:
    if not raw or raw != raw.strip():
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        return None
    try:
        candidate = urljoin(base, raw)
        parts = urlsplit(candidate)
        if parts.scheme.lower() not in _ALLOWED_SCHEMES or not parts.hostname:
            return None
        if parts.username is not None or parts.password is not None or parts.fragment:
            return None
    except ValueError:
        return None
    return candidate


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.items: list[tuple[str, str, str, list[str]]] = []
        self._form: tuple[str, str, list[str]] | None = None
        self.truncated = False

    def _add(self, item: tuple[str, str, str, list[str]]) -> None:
        if len(self.items) < MAX_CANDIDATES:
            self.items.append(item)
        else:
            self.truncated = True

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): (value or "") for name, value in attrs}
        if self._form is not None and tag in {"input", "select", "textarea"} and values.get("name"):
            name = values["name"]
            if len(name) > 255 or any(ord(c) < 32 or ord(c) == 127 for c in name):
                self.truncated = True
            elif name not in self._form[2]:
                if len(self._form[2]) < MAX_FORM_PARAMETERS:
                    self._form[2].append(name)
                else:
                    self.truncated = True
        if tag in {"a", "area"} and values.get("href"):
            self._add((values["href"], "GET", "link", []))
        elif tag == "script" and values.get("src"):
            self._add((values["src"], "GET", "script", []))
        elif tag in {"iframe", "frame"} and values.get("src"):
            self._add((values["src"], "GET", "frame", []))
        elif tag == "link" and values.get("href") and "stylesheet" in values.get("rel", "").lower():
            self._add((values["href"], "GET", "stylesheet", []))
        elif tag == "form":
            method = values.get("method", "GET").upper() or "GET"
            # dialog forms close a dialog and do not submit to a network endpoint.
            self._form = None if method == "DIALOG" else (
                values.get("action") or "", method if method in {"GET", "POST"} else "GET", [])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            action, method, parameters = self._form
            self._add((action, method, "form", parameters))
            self._form = None

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_data(self, data: str) -> None:
        return
