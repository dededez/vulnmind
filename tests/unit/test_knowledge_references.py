import pytest
from vulnmind.workbench.knowledge import filter_references, validate_references


def test_filter_references_keeps_known_and_reports_unknown():
    allowed = {'skill:a', 'rag:x'}
    valid, unknown = filter_references(['skill:a', 'rag:x', 'skill:missing', 'skill:a'], allowed)
    assert valid == ['skill:a', 'rag:x']
    assert unknown == ['skill:missing']


def test_validate_references_is_strict_by_default_but_can_be_lenient():
    saved = dict(skills=[dict(skill_id='a')], chunks=[dict(ref='rag:x')])
    assert validate_references(['skill:a', 'rag:x'], saved) == ['skill:a', 'rag:x']
    with pytest.raises(ValueError):
        validate_references(['skill:missing'], saved)
    assert validate_references(['skill:missing', 'skill:a'], saved, strict=False) == ['skill:a']
    assert validate_references(['skill:missing'], saved, strict=False, allowed={'skill:a'}) == []
