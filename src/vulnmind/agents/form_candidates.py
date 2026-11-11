"""Create bounded, offline-only GET form candidates from stored observations."""
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MAX_CANDIDATE_URLS = 2000
MAX_QUERY_PARAMETERS = 3


def form_candidate_urls(rows) -> tuple[list[str], int]:
    """Return plan input URLs and count form names omitted by bounds/validation.

    Empty values are placeholders, not captured form values. This function does
    not make requests, grant authorization, or claim the form is executable.
    """
    urls: list[str] = []
    seen: set[str] = set()
    omitted = 0
    for row in rows:
        if row.method != "GET":
            continue
        parameters = row.parameters
        if parameters is not None and (not isinstance(parameters, list) or len(parameters) > 256):
            omitted += 1
            parameters = []
        try:
            if (not isinstance(row.url, str) or len(row.url) > 2048 or row.url != row.url.strip()
                    or any(ord(c) < 32 or ord(c) == 127 for c in row.url)):
                raise ValueError("invalid endpoint URL")
            parts = urlsplit(row.url)
            host = parts.hostname
            _ = parts.port  # Reject malformed or out-of-range ports.
        except (ValueError, TypeError):
            omitted += len(parameters or ())
            continue
        if parts.scheme not in {"http", "https"} or not host or parts.username is not None or parts.fragment:
            omitted += len(parameters or ())
            continue
        first_names = [name for name, _ in parse_qsl(parts.query, keep_blank_values=True)[:MAX_QUERY_PARAMETERS]]
        if any(not name or len(name) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in name)
               for name in first_names):
            omitted += len(parameters or ())
            continue
        if parts.query and row.url not in seen and len(urls) < MAX_CANDIDATE_URLS:
            urls.append(row.url)
            seen.add(row.url)
        try:
            pairs = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=MAX_QUERY_PARAMETERS)
        except ValueError:
            omitted += len(parameters or ())
            continue
        existing = {name for name, _ in pairs}
        for name in parameters or ():
            if (not isinstance(name, str) or not name or len(name) > 128
                    or any(ord(c) < 32 or ord(c) == 127 for c in name)):
                omitted += 1
                continue
            if name in existing:
                continue
            if len(pairs) >= MAX_QUERY_PARAMETERS:
                omitted += 1
                continue
            query = parts.query + ("&" if parts.query else "") + urlencode([(name, "")])
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
            if len(url) > 2048 or (url not in seen and len(urls) >= MAX_CANDIDATE_URLS):
                omitted += 1
                continue
            if url not in seen:
                urls.append(url)
                seen.add(url)
    return urls, omitted
