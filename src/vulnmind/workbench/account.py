"""One operator-authorized test account: register, log in, keep the token in memory."""
import json
import secrets
import string

ALPHABET = string.ascii_lowercase + string.digits


def random_account(prefix='vmprobe'):
    email = prefix + '-' + ''.join(secrets.choice(ALPHABET) for _ in range(10)) + '@example.invalid'
    password = 'Vm!' + ''.join(secrets.choice(ALPHABET) for _ in range(20))
    return dict(email=email, password=password)


def register_requests(origin, email, password):
    body = json.dumps(dict(email=email, password=password, passwordRepeat=password))
    return [dict(method='POST', url=origin.rstrip('/') + '/api/Users', body=body,
                 headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
                 variant=0, no_session=True)]


def login_requests(origin, email, password):
    body = json.dumps(dict(email=email, password=password))
    return [dict(method='POST', url=origin.rstrip('/') + '/rest/user/login', body=body,
                 headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
                 variant=0, no_session=True, capture_token=True)]


def parse_session(body):
    """Return {token, email, bid} only when the server issued a session; never logs the body."""
    try:
        data = json.loads(body)
    except (TypeError, ValueError):
        return None
    authentication = data.get('authentication') if isinstance(data, dict) else None
    if not isinstance(authentication, dict):
        return None
    token = authentication.get('token')
    if not isinstance(token, str) or not token:
        return None
    bid = authentication.get('bid')
    return dict(token=token, email=str(authentication.get('umail') or '')[:200],
                bid=bid if isinstance(bid, int) and not isinstance(bid, bool) else None)
