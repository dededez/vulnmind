"""Form plan candidates are bounded and never send requests."""
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

from vulnmind.agents.form_candidates import form_candidate_urls
from vulnmind.analysis.validation import load_plan, plan_digest, plan_probes
import json


def row(url, parameters, method="GET"):
    return SimpleNamespace(url=url, parameters=parameters, method=method)


def test_get_form_names_produce_synthetic_query_and_valid_bound_plan():
    urls, omitted = form_candidate_urls([row("https://app.test/search", ["q", "page"])])
    assert urls == ["https://app.test/search?q=", "https://app.test/search?page="]
    assert omitted == 0
    probes = plan_probes(urls)
    assert {item.parameter for item in probes} == {"q", "page"}
    plan = {"version": 1, "digest": plan_digest(probes),
            "probes": [item.model_dump(mode="json") for item in probes]}
    assert load_plan(json.dumps(plan)) == probes


def test_existing_queries_are_preserved_post_and_unknown_do_not_create_forms():
    urls, omitted = form_candidate_urls([
        row("https://app.test/search?lang=en", ["q", "lang"]),
        row("https://app.test/login", ["password"], "POST"),
        row("https://app.test/unknown", None),
    ])
    assert urls[0] == "https://app.test/search?lang=en"
    assert parse_qsl(urlsplit(urls[1]).query, keep_blank_values=True) == [("lang", "en"), ("q", "")]
    assert len(urls) == 2 and omitted == 0


def test_too_many_existing_query_fields_or_invalid_form_names_are_counted():
    urls, omitted = form_candidate_urls([
        row("https://app.test/search?a=1&b=2&c=3", ["q"]),
        row("https://app.test/", ["x" * 129, "bad\nname"]),
    ])
    assert urls == ["https://app.test/search?a=1&b=2&c=3"]
    assert omitted == 3


def test_invalid_stored_urls_and_queries_fail_closed():
    urls, omitted = form_candidate_urls([
        row("https://app.test:99999/", ["q"]),
        row("https://app.test/?" + ("x" * 129) + "=1", ["q"]),
        row("https://app.test/\n", ["q"]),
    ])
    assert urls == [] and omitted == 3
