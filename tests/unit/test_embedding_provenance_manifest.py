"""Local embedding manifest records file hashes without network or DB writes."""
import importlib.util
from pathlib import Path


def test_manifest_fingerprints_local_files(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location('embedding_manifest', Path(__file__).resolve().parents[2] / 'src/vulnmind/knowledge/model_fingerprint.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    snapshot = tmp_path / 'revision-123'
    snapshot.mkdir()
    (snapshot / 'config.json').write_text('first', encoding='utf-8')
    monkeypatch.setattr(module, 'snapshot_download', lambda *a, **kw: str(snapshot))
    first = module.fingerprint()
    assert first['cached_revision'] == 'revision-123'
    assert first['files']['config.json']['bytes'] == 5
    (snapshot / 'config.json').write_text('second', encoding='utf-8')
    second = module.fingerprint()
    assert first['files']['config.json']['sha256'] != second['files']['config.json']['sha256']
    assert 'historical database vector provenance' in first['note']


def test_vector_hash_detects_changes_hidden_by_six_decimal_rounding():
    from vulnmind.knowledge.embedding_batch import vector_hash
    first = [1.0] + [0.0] * 1023
    slightly_changed = [0.99999994] + [0.0] * 1023
    assert round(first[0], 6) == round(slightly_changed[0], 6)
    assert vector_hash(first) != vector_hash(slightly_changed)
