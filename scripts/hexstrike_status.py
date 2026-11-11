"""Per-family coverage and environment-readiness report (read-only).

Runs the same bridge/isolation health check and read-only PATH probe as the
workbench, then prints one row per tool family. Nothing is installed, executed
or approved by this script; a found program is not proof that an adapter or a
verified execution exists.
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from vulnmind.workbench.external import ExternalWorkbench


def build(service, catalog):
    families = []
    for family, status in catalog['environment'].items():
        tools = [tool for tool in catalog['tools'] if tool['family'] == family]
        families.append(dict(family=family, catalog=len(tools),
                             adapters=sum(tool['adapter_implemented'] for tool in tools),
                             validated=sum(tool['validated'] for tool in tools),
                             eligible=sum(tool['eligible'] for tool in tools),
                             status=status['status'], required=status['required'],
                             present=status['present'], missing=status['missing']))
    families.sort(key=lambda row: row['family'])
    return dict(recorded_at=datetime.now(timezone.utc).isoformat(),
                environment_sha256=catalog['environment_sha256'],
                connection=catalog['connection'], probe_error=catalog.get('probe_error'),
                totals=catalog['totals'], families=families,
                found={name: value for name, value in (service.programs or {}).items() if value.get('found')},
                note='coverage and PATH readiness only; not production acceptance or tool verification')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    service = ExternalWorkbench(args.root)
    catalog = service.refresh()
    report = build(service, catalog)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return
    totals = report['totals']
    print('catalog=%s adapters=%s validated=%s eligible=%s' % (
        totals['catalog'], totals['adapters'], totals['validated'], totals['eligible']))
    print('%-16s %8s %9s %10s %-9s %s' % ('family', 'catalog', 'adapters', 'validated', 'env', 'missing'))
    for row in report['families']:
        print('%-16s %8d %9d %10d %-9s %s' % (row['family'], row['catalog'], row['adapters'],
                                              row['validated'], row['status'], ', '.join(row['missing']) or '-'))
    if report['probe_error']:
        print('probe: ' + report['probe_error'])


if __name__ == '__main__': main()
