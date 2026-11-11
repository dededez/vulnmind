"""Redact credentials from response bodies before they reach journals or evidence."""
import re

_TOKEN_FIELD = re.compile(r'("?(?:token|jwt|access_token|id_token)"?\s*:\s*")[^"]+(")', re.I)
_JWT = re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b')
_BEARER = re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}')


def redact_tokens(text):
    """Return (redacted_text, changed). Only targets credential-shaped values."""
    if not isinstance(text, str) or not text:
        return text, False
    value = _TOKEN_FIELD.sub(r'\1[redacted]\2', text)
    value = _JWT.sub('[redacted jwt]', value)
    value = _BEARER.sub('Bearer [redacted]', value)
    return value, value != text
