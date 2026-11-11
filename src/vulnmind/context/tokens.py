"""Conservative token estimation for pre-flight context budgets.

No model tokenizer is bundled with the project, so this estimate is deliberately
simple and biased high: ASCII text is about four characters per token, CJK and
full-width text about one character per token, and other non-ASCII about two
characters per token. The budget profiles keep additional headroom; this value
must never be described as the model's exact token count.
"""
import math
import unicodedata

ASCII_CHARS_PER_TOKEN = 4.0
CJK_CHARS_PER_TOKEN = 1.0
OTHER_CHARS_PER_TOKEN = 2.0


def estimate_tokens(text: str) -> int:
    """Return a positive, conservative token estimate for nonblank text."""
    if not isinstance(text, str):
        raise TypeError('text must be a string')
    if not text.strip():
        raise ValueError('text must not be blank')
    value = 0.0
    for char in text:
        if unicodedata.east_asian_width(char) in {'W', 'F'}:
            value += 1.0 / CJK_CHARS_PER_TOKEN
        elif ord(char) < 128:
            value += 1.0 / ASCII_CHARS_PER_TOKEN
        else:
            value += 1.0 / OTHER_CHARS_PER_TOKEN
    return max(1, math.ceil(value))
