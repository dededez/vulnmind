"""Curated corpus keeps original bytes, attribution and revision metadata."""
import hashlib
import json
import csv
import io
from zipfile import ZipFile
from pathlib import Path


def test_owasp_corpus_matches_pinned_local_sources():
    root = Path(__file__).resolve().parents[2] / "knowledge/corpora/owasp_cheatsheets_757270a"
    items = json.loads((root / "corpus.json").read_text(encoding="utf-8"))
    assert len(items) == 6 and (root / "LICENSE.md").is_file()
    revision = "757270a26306e5edda9957bb7f86cfcde03c30f9"
    for item in items:
        assert item["license"] == "CC-BY-SA-4.0" and item["version"] == revision
        assert item["source_url"].startswith("https://github.com/OWASP/CheatSheetSeries/blob/" + revision + "/")
        name = item["source_url"].rsplit("/", 1)[-1]
        content = (root / name).read_text(encoding="utf-8")
        assert item["content"] == content
        assert item["content_sha256"] == hashlib.sha256(content.encode("utf-8")).hexdigest()


def test_new_corpora_provenance_and_integrity():
    root = Path(__file__).resolve().parents[2] / "knowledge/corpora"
    public = root / "owasp_expansion_757270a"
    items = json.loads((public / "corpus.json").read_text(encoding="utf-8"))
    assert len(items) == 18 and (public / "LICENSE.md").is_file()
    for item in items:
        name = item["source_url"].rsplit("/", 1)[-1]
        assert item["license"] == "CC-BY-SA-4.0"
        assert item["version"] == "757270a26306e5edda9957bb7f86cfcde03c30f9"
        assert (public / name).read_bytes().decode("utf-8") == item["content"]
        assert hashlib.sha256(item["content"].encode("utf-8")).hexdigest() == item["content_sha256"]
    generated = json.loads((root / "ai_guidance_20261105/corpus.json").read_text(encoding="utf-8"))
    assert len(generated) == 16
    for item in generated:
        assert item["source_type"] == "AI_GENERATED" and item["trust_level"] == "unverified_ai"
        assert "未经人工审核" in item["content"]
        assert hashlib.sha256(item["content"].encode("utf-8")).hexdigest() == item["content_sha256"]


def test_cwe_snapshot_derived_from_original_archive():
    root = Path(__file__).resolve().parents[2] / "knowledge/corpora/cwe_699_20261105"
    archive = (root / "699.csv.zip").read_bytes()
    digest = hashlib.sha256(archive).hexdigest()
    with ZipFile(io.BytesIO(archive)) as z, z.open("699.csv") as f:
        rows = {r["CWE-ID"]: r for r in csv.DictReader(io.TextIOWrapper(f, encoding="utf-8-sig", newline=""))}
    items = json.loads((root / "corpus.json").read_text(encoding="utf-8"))
    assert len(items) == 12 and digest in (root / "SOURCE.md").read_text(encoding="utf-8")
    assert "MITRE Corporation" in (root / "LICENSE.md").read_text(encoding="utf-8")
    for item in items:
        identifier = item["source_url"].rsplit("/", 1)[-1].removesuffix(".html")
        assert item["version"] == "snapshot-sha256-" + digest[:16]
        assert rows[identifier]["Description"] in item["content"]
        assert hashlib.sha256(item["content"].encode("utf-8")).hexdigest() == item["content_sha256"]
