import json
import os

import pytest

from vulnmind.workbench.account import random_account, register_requests, login_requests, parse_session
from vulnmind.workbench.secrets import Vault

ORIGIN = 'http://127.0.0.1:3000'


def test_random_account_shape():
    account = random_account()
    assert account['email'].startswith('vmprobe-') and account['email'].endswith('@example.invalid')
    assert len(account['password']) >= 20
    assert random_account()['email'] != account['email']


def test_register_and_login_requests_are_exact_and_flagged():
    account = dict(email='vm-a@example.invalid', password='Vm!abcdefghijklmnop')
    register = register_requests(ORIGIN, **account)
    login = login_requests(ORIGIN, **account)
    assert len(register) == 1 and len(login) == 1
    assert register[0]['method'] == 'POST' and register[0]['url'] == ORIGIN + '/api/Users'
    assert login[0]['url'] == ORIGIN + '/rest/user/login'
    assert register[0]['no_session'] is True and login[0]['no_session'] is True
    assert json.loads(register[0]['body'])['passwordRepeat'] == account['password']


def test_parse_session_requires_token_and_email():
    good = json.dumps({'authentication': {'token': 'header.payload.signature', 'umail': 'a@b.c', 'bid': 3}})
    assert parse_session(good) == {'token': 'header.payload.signature', 'email': 'a@b.c', 'bid': 3}
    assert parse_session('{"authentication":{}}') is None
    assert parse_session('not json') is None
    assert parse_session('{"authentication":{"token":"x"}}')['email'] == ''
    assert parse_session('{"authentication":{"token":"x","bid":"3"}}')['bid'] is None


@pytest.mark.skipif(os.name != 'nt', reason='credential vault requires Windows DPAPI')
def test_account_vault_roundtrip_and_origin_binding(tmp_path):
    vault = Vault(tmp_path)
    account = dict(email='vm-b@example.invalid', password='Vm!abcdefghijklmnop')
    identifier = vault.save_account(ORIGIN, **account)
    assert vault.load_account(identifier, ORIGIN) == account
    with pytest.raises(ValueError, match='origin mismatch'):
        vault.load_account(identifier, 'http://127.0.0.2:3000')
    with pytest.raises(ValueError, match='password'):
        vault.save_account(ORIGIN, 'x@y.z', 'short')
    with pytest.raises(ValueError, match='email'):
        vault.save_account(ORIGIN, 'not-an-email', 'Vm!abcdefghijklmnop')
    assert not (tmp_path / (identifier + '.bin')).exists()


@pytest.mark.skipif(os.name != 'nt', reason='credential vault requires Windows DPAPI')
def test_session_token_roundtrip_is_workflow_and_origin_bound(tmp_path):
    from uuid import uuid4
    vault = Vault(tmp_path)
    workflow = uuid4()
    assert vault.load_session(workflow, ORIGIN) is None
    vault.save_session(workflow, ORIGIN, 'header.payload.signature', 4)
    assert vault.load_session(workflow, ORIGIN) == {'token': 'header.payload.signature', 'bid': 4}
    assert vault.load_session(uuid4(), ORIGIN) is None
    assert vault.load_session(workflow, 'http://127.0.0.2:3000') is None
    with pytest.raises(ValueError):
        vault.save_session(workflow, ORIGIN, '')
