import hashlib
import json

from vulnmind.workbench.detectors import CATALOG, evaluate, file_followups, requests_for


def test_listing_yields_bounded_file_followups():
    listing = json.dumps(["quarantine", "acquisitions.md", "coupons_2013.md.bak", "package.json.bak",
                          "incident-support.kdbx", "legal.md", "notes.txt"])
    actions = file_followups('http://127.0.0.1:3000', listing, limit=3)
    assert len(actions) == 3
    assert [a['filename'] for a in actions] == ['acquisitions.md', 'coupons_2013.md.bak', 'package.json.bak']
    assert all(a['kind'] == 'exposed_file' and a['url'].startswith('http://127.0.0.1:3000/ftp/') for a in actions)
    assert len({a['id'] for a in actions}) == 3


def test_html_links_and_directories_are_handled():
    listing = '<a href="logs/">logs/</a><a href="legal.md">legal.md</a><a href="..">..</a>'
    actions = file_followups('http://127.0.0.1:3000', listing)
    assert [a['filename'] for a in actions] == ['legal.md']


def test_exposed_file_candidate_requires_content_not_error_page():
    action = dict(id='f1', kind='exposed_file', url='http://127.0.0.1:3000/ftp/legal.md', method='GET',
                  category=CATALOG['exposed_file'][0], parameter='', filename='legal.md', detector_version='2.4.0')

    def response(body, status=200):
        return dict(body=body, headers={}, status_code=status, truncated=False,
                    sha256=hashlib.sha256(body.encode()).hexdigest())

    assert len(requests_for(action)) == CATALOG['exposed_file'][2] == 2
    good = evaluate(action, [response('# Legal information'), response('# Legal information')])
    assert good['verdict'] == 'candidate' and good['behavior'] == 'anonymous_file_download'
    assert good['filename'] == 'legal.md'
    assert good['source'] == {}
    assert evaluate(action, [response('<title>Error</title>', 404), response('')])['verdict'] == 'inconclusive'
    # A truncated but non-empty 200 still proves anonymous access; the note says so.
    truncated = [dict(response('# big file'), truncated=True), dict(response('# big file'), truncated=True)]
    result = evaluate(action, truncated)
    assert result['verdict'] == 'candidate' and '截断' in result['detail']
