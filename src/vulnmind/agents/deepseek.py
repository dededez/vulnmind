"""DeepSeek chat-completions client behind the provider-neutral ModelClient contract.

The API key is read from the environment and never logged or echoed. Requests are
bounded, redirects are refused, and error messages never include response bodies.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from pydantic import ValidationError

from vulnmind.agents.model import ModelError, ModelMessage, ModelRequest, ModelResponse, ModelUsage

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"
_KEY_ENV = ("DEEPSEEK_API_KEY", "VULNMIND_DEEPSEEK_API_KEY")
MAX_RESPONSE_BYTES = 2_000_000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        return None


class DeepSeekClient:
    """``ModelClient`` for ``https://api.deepseek.com/chat/completions``."""

    def __init__(self, api_key: str | None = None, *, base_url: str = DEFAULT_BASE_URL,
                 model: str = DEFAULT_MODEL, timeout_seconds: float = 60.0,
                 max_response_bytes: int = MAX_RESPONSE_BYTES,
                 transport=None):
        key = api_key or next((os.environ[name] for name in _KEY_ENV if os.environ.get(name)), None)
        if not isinstance(key, str) or not key.strip():
            raise ValueError("a DeepSeek API key is required")
        if any(ord(char) < 32 or ord(char) == 127 for char in key):
            raise ValueError("the DeepSeek API key is invalid")
        if not isinstance(base_url, str) or any(char.isspace() or ord(char) < 32 or ord(char) == 127
                                               or char == "\\" for char in base_url):
            raise ValueError("the DeepSeek endpoint must be a valid HTTPS URL")
        try:
            parsed = urlsplit(base_url)
            port = parsed.port
        except ValueError:
            raise ValueError("the DeepSeek endpoint must be a valid HTTPS URL") from None
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or "?" in base_url or "#" in base_url
                or "%" in parsed.netloc or (port is not None and port == 0)):
            raise ValueError("the DeepSeek endpoint must be a valid HTTPS URL without credentials or query")
        if not 1 <= timeout_seconds <= 300:
            raise ValueError("timeout must be between 1 and 300 seconds")
        if not 1_000 <= max_response_bytes <= 10_000_000:
            raise ValueError("max_response_bytes is out of range")
        self._api_key = key.strip()
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._model = model
        self._timeout = timeout_seconds
        self._max_bytes = max_response_bytes
        self._transport = transport or self._default_transport

    def complete(self, request: ModelRequest) -> ModelResponse:
        payload = {
            "model": self._model,
            "messages": [{"role": message.role, "content": message.content}
                         for message in request.messages],
            "temperature": request.temperature,
            "max_tokens": request.max_output_tokens,
            "stream": False,
            "response_format": {"type": "json_object"},
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json",
                   "Accept": "application/json"}
        status, raw = self._transport(self._url, headers, body, self._timeout)
        if status != 200:
            raise ModelError(f"provider returned HTTP {status}")
        if len(raw) > self._max_bytes:
            raise ModelError("provider response exceeds the size limit")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise ModelError("provider returned unparseable JSON") from None
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ModelError("provider response has no completion") from None
        if not isinstance(content, str) or not content.strip():
            raise ModelError("provider returned an empty completion")
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        try:
            return ModelResponse(text=content, usage=_usage(usage))
        except (ValidationError, ValueError):
            raise ModelError("provider returned an invalid completion") from None

    def _default_transport(self, url: str, headers: dict[str, str], body: bytes,
                           timeout: float) -> tuple[int, bytes]:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=timeout) as response:
                return response.status, response.read(self._max_bytes + 1)
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except (urllib.error.URLError, OSError, TimeoutError):
            raise ModelError("provider is unreachable") from None


def _usage(payload: dict) -> ModelUsage:
    def number(name: str) -> int | None:
        value = payload.get(name)
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None
    return ModelUsage(input_tokens=number("prompt_tokens"), output_tokens=number("completion_tokens"))
