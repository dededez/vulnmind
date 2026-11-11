"""Offline coverage report CLI.

Reads the frozen truth JSON and a saved job result JSON; never talks to the
target. The mapping logic lives in ``vulnmind.workbench.coverage`` so the local
UI can request the same report from an explicit operator action.
"""
import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))

from vulnmind.workbench.coverage import build_report, markdown


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--truth', type=pathlib.Path, required=True)
    parser.add_argument('--result', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--markdown', type=pathlib.Path, required=True)
    parser.add_argument('--label', default='fixed-config')
    args = parser.parse_args()
    truth = json.loads(args.truth.read_text(encoding='utf-8'))
    result = json.loads(args.result.read_text(encoding='utf-8')).get('result') or {}
    report, entries, covered = build_report(truth, result, args.label)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(report=report, entries=entries), ensure_ascii=False, indent=1) + '\n',
                           encoding='utf-8')
    args.markdown.write_text(markdown(report, entries, covered), encoding='utf-8')
    print(json.dumps(dict(output=str(args.output), markdown=str(args.markdown),
                          coverage=report['coverage'], requests=report['requests_used'],
                          status=report['status']), ensure_ascii=False))


if __name__ == '__main__':
    main()
