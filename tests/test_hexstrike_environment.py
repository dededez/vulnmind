import json
from types import SimpleNamespace

import pytest
from vulnmind.integrations.hexstrike import catalog
from vulnmind.integrations.hexstrike.backend import probe
from vulnmind.integrations.hexstrike.catalog import FAMILIES, FAMILY_PROGRAMS, PROBE_PROGRAMS, directory


def test_probe_program_list_is_bounded_unique_and_consistent():
    assert len(PROBE_PROGRAMS) == len(set(PROBE_PROGRAMS)) <= 128
    assert all(name and name.replace('-', '').replace('_', '').replace('.', '').isalnum()
               and name.lower() == name for name in PROBE_PROGRAMS)
    assert set(FAMILY_PROGRAMS) == set(FAMILIES)
    assert set(PROBE_PROGRAMS) == {name for required in FAMILY_PROGRAMS.values() for name in required}


def test_environment_summary_reports_family_readiness():
    programs = {'nmap': {'found': True}, 'masscan': {'found': True}}
    summary = catalog.environment_summary(programs)
    assert summary['network']['status'] == 'partial'
    assert set(summary['network']['present']) == {'nmap', 'masscan'}
    assert 'rustscan' in summary['network']['missing']
    assert summary['binary']['status'] == 'missing'
    assert summary['maintenance']['status'] == 'no_external_program'
    assert catalog.environment_summary(None)['network']['status'] == 'unchecked'


def test_directory_embeds_readiness_without_changing_totals():
    default = directory()
    probed = directory(environment={'nmap': {'found': True}, 'xxd': {'found': True}, 'strings': {'found': True}})
    assert default['totals'] == probed['totals']
    assert default['totals'] == dict(catalog=150, schemas=150, adapters=23, skills=150, validated=0, eligible=0)
    assert default['environment']['network']['status'] == 'unchecked'
    assert set(probed['environment']['binary']['present']) == {'strings', 'xxd'}
    assert probed['environment']['network']['present'] == ['nmap']


def test_probe_accepts_a_valid_report_and_rejects_failures():
    report = {'programs': {'nmap': {'found': False}}, 'python': '3.12.13'}
    runner = lambda command, payload: SimpleNamespace(returncode=0, stdout=json.dumps(report).encode())
    assert probe(runner=runner) == report
    failed = lambda command, payload: SimpleNamespace(returncode=1, stdout=b'')
    with pytest.raises(RuntimeError):
        probe(runner=failed)
    broken = lambda command, payload: SimpleNamespace(returncode=0, stdout=b'{"other": 1}')
    with pytest.raises(RuntimeError):
        probe(runner=broken)
    huge = lambda command, payload: SimpleNamespace(returncode=0, stdout=b'x' * 2_000_001)
    with pytest.raises(RuntimeError):
        probe(runner=huge)
