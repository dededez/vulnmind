"""Evaluation labels remain tied to the pinned source text."""
import json
from pathlib import Path


def test_holdout_excerpts_match_the_recorded_source_offsets():
    root=Path(__file__).resolve().parents[2]
    names=('owasp_cheatsheets_757270a','owasp_expansion_757270a')
    docs={item['title']:item['content'] for name in names
          for item in json.loads((root/'knowledge/corpora'/name/'corpus.json').read_text(encoding='utf-8'))}
    cases=json.loads((root/'evaluation/knowledge_holdout_20261105.json').read_text(encoding='utf-8'))['cases']
    positives=[x for x in cases if x['answerable']]
    negatives=[x for x in cases if not x['answerable']]
    assert len(positives)==12 and len(negatives)==4
    for case in positives:
        text=docs[case['expected_title']]
        assert text[case['expected_start_offset']:case['expected_end_offset']]==case['expected_excerpt']
    assert all('reason' in case for case in negatives)
