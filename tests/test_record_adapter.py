"""Offline integration coverage of record APIs, cache, memory and HTML parsing."""

import base64
import json
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from cyber_rag.memory import MemoryStore
from cyber_rag.models import digest
from cyber_rag.ondemand import FetchResponse, RemoteError
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.source_adapters import RecordAdapter, normalize
from cyber_rag.source_registry import SOURCES

ONE, TWO = "CVE-2021-44228", "CVE-2024-1234"


def envelope(
    identifier=ONE,
    *,
    timestamp="first response",
    modified="2026-01-01",
    description="PowerShell defensive evidence",
):
    return json.dumps(
        {
            "timestamp": timestamp,
            "resultsPerPage": 1,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": identifier,
                        "lastModified": modified,
                        "descriptions": [{"lang": "en", "value": description}],
                    }
                }
            ],
        }
    ).encode()


@pytest.fixture
def api(tmp_path):
    spec = replace(SOURCES["nvd"], min_interval_seconds=0)
    replies = {ONE: envelope(), TWO: envelope(TWO)}
    clock = [datetime.now(UTC)]
    calls = []

    def fetch(url, **kwargs):
        assert kwargs["allowed"](url)
        calls.append(url)
        value = replies[url.rsplit("=", 1)[1]]
        if isinstance(value, Exception):
            raise value
        return FetchResponse(200, value)

    adapter = RecordAdapter(spec, fetcher=fetch)
    store = RemoteStore(tmp_path, adapter, clock=lambda: clock[0])
    return store, adapter, replies, calls, clock


def test_nvd_envelope_timestamp_not_revision_and_original_bytes_preserved(api):
    store, _, replies, calls, clock = api
    original_raw = replies[ONE]
    original = store.research(ONE)["results"][0]
    replies[ONE] = envelope(timestamp="second response")
    clock[0] += timedelta(seconds=1)
    refreshed = store.research(ONE, freshness="refresh")["results"][0]
    assert refreshed["revision"] == original["revision"]
    assert refreshed["original_hash"] == digest(original_raw)
    assert refreshed["checked_at"] != original["checked_at"]
    assert "timestamp" not in refreshed["passages"][0]["text"]
    assert "timestamp" in refreshed["metadata"]["excluded_from_revision"]
    assert base64.b64decode(store.get_document(original["document_id"])["content"]) == original_raw
    assert len(calls) == 2 and store.catalog()["cached_versions"] == 1


@pytest.mark.parametrize(
    "bad",
    [
        b"not json",
        b"null",
        b"[]",
        b"{}",
        b'{"vulnerabilities":null}',
        b'{"vulnerabilities":[null]}',
        b'{"vulnerabilities":[{"cve":null}]}',
        b'{"vulnerabilities":[{"cve":[]}]}',
        b'{"vulnerabilities":[{"cve":{}}]}',
        envelope(TWO),
    ],
)
def test_nvd_wrong_identity_and_bad_schema_return_controlled_failure(api, bad):
    store, _, replies, _, _ = api
    replies[ONE] = bad
    failed = store.research(ONE)
    assert failed["remote_status"] == "failed"
    assert failed["catalog"]["document_failures"] == 1
    assert failed["catalog"]["last_failure"] is None
    assert failed["catalog"]["cached_versions"] == 0
    assert failed["results"] == []
    assert store.research(TWO)["results"][0]["freshness"] == "current"


def test_memory_references_stay_independent_when_record_is_added_or_updated(api, tmp_path):
    store, _, replies, _, clock = api
    memory = MemoryStore(tmp_path, clock=lambda: clock[0].timestamp())
    one = store.research(ONE)["results"][0]
    first_note = memory.remember(
        "defensive observation alpha", [one["reference"]], resolve_reference=store.resolve_reference
    )
    two = store.research(TWO)["results"][0]
    second_note = memory.remember(
        "defensive observation beta", [two["reference"]], resolve_reference=store.resolve_reference
    )
    found = memory.search("defensive observation", resolve_reference=store.resolve_reference)
    assert {item["memory_id"] for item in found["results"]} == {
        first_note["result"]["memory_id"],
        second_note["result"]["memory_id"],
    }
    replies[ONE] = envelope(modified="2026-02-01", description="Updated defensive evidence")
    store.research(ONE, freshness="refresh")
    found = memory.search("defensive observation", resolve_reference=store.resolve_reference)
    assert [item["memory_id"] for item in found["results"]] == [second_note["result"]["memory_id"]]
    assert found["suppressed"] == {"superseded": 1}


def test_api_record_failure_temporarily_suppresses_only_its_memory(api, tmp_path):
    store, _, replies, calls, clock = api
    memory = MemoryStore(tmp_path, clock=lambda: clock[0].timestamp())
    for identifier in [ONE, TWO]:
        item = store.research(identifier)["results"][0]
        memory.remember(
            "Evidence note " + identifier, [item["reference"]], resolve_reference=store.resolve_reference
        )
    replies[ONE] = RemoteError("http_404")
    failed = store.research(ONE, freshness="refresh")
    assert failed["results"][0]["freshness"] == "unknown"
    found = memory.search("Evidence note", resolve_reference=store.resolve_reference)
    assert len(found["results"]) == 1 and TWO in found["results"][0]["text"]
    assert found["suppressed"] == {"unknown": 1}
    count = len(calls)
    assert store.research(TWO)["results"][0]["freshness"] == "current"
    assert len(calls) == count
    clock[0] += timedelta(seconds=61)
    replies[ONE] = envelope()
    store.research(ONE)
    assert len(memory.search("Evidence note", resolve_reference=store.resolve_reference)["results"]) == 2


def test_failed_multi_record_lookup_does_not_leave_observed_old_revision_current(api):
    store, _, replies, _, _ = api
    original = store.research(ONE)["results"][0]
    store.research(TWO)
    # The first response establishes a changed record. A subsequent response
    # failing must not erase that observation and keep the old record current.
    replies[ONE] = envelope(modified="2026-03-01", description="Observed new revision")
    replies[TWO] = RemoteError("http_503")
    store.research(ONE + " " + TWO, freshness="refresh")
    assert store.resolve_reference(original["reference"])["state"] != "current"


@pytest.mark.parametrize(
    "source,path,valid_id",
    [
        ("nvd", "CVE-2021-44228.json", ONE),
        ("cwe", "CWE-79.json", "79"),
        ("windows-events", "event-4624.html", "4624"),
    ],
)
def test_record_url_allowlist_is_exact_and_path_cannot_traverse(source, path, valid_id):
    adapter = RecordAdapter(
        SOURCES[source], fetcher=lambda *a, **kw: pytest.fail("Path validation must not fetch")
    )
    url = SOURCES[source].url_template.format(id=valid_id)
    assert adapter.url(path) == url and adapter.allowed(url)
    for suffix in ["/../private", "%2Fprivate", "&other=value", "#fragment", "/extra"]:
        assert not adapter.allowed(url + suffix)
    assert not adapter.allowed(url.replace("https://", "http://"))
    for forged in [
        "../" + path,
        path + "/extra",
        path + "?other=value",
        path.replace(".", "%2E"),
        "https://evil.example/" + path,
    ]:
        with pytest.raises(RemoteError, match="invalid_record_path"):
            adapter.url(forged)


def test_offline_calls_do_not_prepare_or_fetch_existing_or_missing_ids(api, monkeypatch):
    store, adapter, _, calls, _ = api
    original = store.research(ONE)["results"][0]
    count = len(calls)
    monkeypatch.setattr(adapter, "prepare", lambda *a: pytest.fail("Offline mode called prepare"))
    monkeypatch.setattr(adapter, "fetcher", lambda *a, **kw: pytest.fail("Offline mode attempted HTTP"))
    assert store.research(ONE, freshness="offline")["results"][0]["reference"] == original["reference"]
    assert not store.research(TWO, freshness="offline")["results"]
    assert len(calls) == count


def test_api_ttl_is_per_record_and_other_activity_does_not_freshen_it(api):
    store, _, _, calls, clock = api
    original = store.research(ONE)["results"][0]
    clock[0] += timedelta(hours=2)
    second = store.research(TWO)["results"][0]
    assert store.resolve_reference(original["reference"])["state"] == "stale"
    checked = store.research(ONE)["results"][0]
    assert checked["freshness"] == "current"
    assert checked["checked_at"] != original["checked_at"]
    assert store.resolve_reference(second["reference"])["state"] == "current"
    assert len(calls) == 3


@pytest.mark.parametrize(
    "timestamp", [None, "", "malformed", 17, [], "2026-10-21T12:00:00", "9999-12-31T23:59:59+00:00"]
)
def test_prepare_bad_or_future_validation_time_requires_refresh_without_exception(timestamp):
    adapter = RecordAdapter(replace(SOURCES["nvd"], min_interval_seconds=0))
    path = ONE + ".json"
    old = {
        "entries": [
            {
                "path": path,
                "url": adapter.url(path),
                "checked_at": timestamp,
                "adapter_fingerprint": adapter.fingerprint,
            }
        ]
    }
    old["adapter_fingerprint"] = adapter.fingerprint
    assert adapter.prepare(ONE, None, old)


def test_prepare_recent_aware_validation_time_is_a_cache_hit():
    adapter = RecordAdapter(replace(SOURCES["nvd"], min_interval_seconds=0))
    path = ONE + ".json"
    old = {
        "entries": [
            {
                "path": path,
                "url": adapter.url(path),
                "checked_at": (datetime.now(UTC) - timedelta(seconds=5)).isoformat(),
                "adapter_fingerprint": adapter.fingerprint,
            }
        ]
    }
    old["adapter_fingerprint"] = adapter.fingerprint
    assert not adapter.prepare(ONE, None, old)


def test_record_license_change_invalidates_offline_and_refreshes_provenance(tmp_path):
    original_spec = replace(SOURCES["nvd"], min_interval_seconds=0)
    fetch = lambda *a, **kw: FetchResponse(200, envelope())
    first = RemoteStore(tmp_path, RecordAdapter(original_spec, fetcher=fetch))
    old = first.research(ONE)["results"][0]
    changed = replace(original_spec, license_url="https://www.nist.gov/revised-license")
    second = RemoteStore(tmp_path, RecordAdapter(changed, fetcher=fetch))
    assert second.research(ONE, freshness="offline")["results"][0]["freshness"] == "unknown"
    current = second.research(ONE)["results"][0]
    assert current["freshness"] == "current"
    assert current["revision"] != old["revision"]
    assert current["original_hash"] == old["original_hash"]
    assert current["citation"]["license_reference"] == changed.license_url


@pytest.mark.parametrize(
    "bad",
    [b"[]", b"null", b"{}", b'{"Weaknesses":null}', b'{"Weaknesses":[null]}', b'{"Weaknesses":[{"ID":80}]}'],
)
def test_cwe_wrong_identity_and_schema_are_controlled_failures(tmp_path, bad):
    adapter = RecordAdapter(SOURCES["cwe"], fetcher=lambda *a, **kw: FetchResponse(200, bad))
    store = RemoteStore(tmp_path, adapter)
    result = store.research("CWE-79")
    assert result["remote_status"] == "failed"
    assert not result["results"] and result["catalog"]["cached_versions"] == 0


def test_cwe_record_and_provenance_are_preserved(tmp_path):
    raw = b'{"Weaknesses":[{"ID":79,"Name":"Cross-site scripting","Status":"Stable"}]}'
    adapter = RecordAdapter(SOURCES["cwe"], fetcher=lambda *a, **kw: FetchResponse(200, raw))
    store = RemoteStore(tmp_path, adapter)
    item = store.research("CWE-79")["results"][0]
    assert "CWE-79" in item["passages"][0]["text"]
    assert item["metadata"]["representation"] == "derived_cwe_weakness"
    assert item["original_hash"] == digest(raw)


@pytest.mark.parametrize("charset", ["iso-8859-1", "windows-1252", "latin1"])
def test_html_charset_struck_out_script_and_hidden_text_exclusion(tmp_path, charset):
    visible = "Proteção de dados: esta redação vigente mantém segurança, transparência e informação sobre responsabilidades."
    html = f'''<html><head><meta charset="{charset}"><script>window.secret="SCRIPT_OLD"</script>
    <style>.old {{ content: "STYLE_OLD" }}</style></head><body><h1>Evento 4624</h1>
    <del>DELETED_OLD</del><s>STRUCK_OLD</s><strike>STRIKE_OLD</strike>
    <span style="text-decoration: line-through">CSS_OLD</span><div hidden>HIDDEN_OLD</div>
    <div style="display: none">INVISIBLE_OLD</div><p>{visible}</p></body></html>'''.encode(charset)
    adapter = RecordAdapter(SOURCES["windows-events"], fetcher=lambda *a, **kw: FetchResponse(200, html))
    store = RemoteStore(tmp_path, adapter)
    item = store.research("event 4624")["results"][0]
    text = "\n".join(p["text"] for p in item["passages"])
    assert visible in text
    assert "_OLD" not in text
    assert item["metadata"]["charset"] == charset
    assert base64.b64decode(store.get_document(item["document_id"])["content"]) == html


@pytest.mark.parametrize(
    "message",
    [
        "Enable JavaScript and cookies to continue",
        "Verify you are human",
        "Checking your browser",
        "Just a moment...",
        "In order to continue, we need to verify that you're not a robot. This requires JavaScript. Enable JavaScript and then reload the page.",
        "In order to continue, we need to verify that you’re not a robot. This requires JavaScript.",
        "Please verify that\n you are not a robot before continuing.",
    ],
)
def test_html_challenge_pages_are_rejected_even_when_large(message):
    html = (
        "<html><body><h1>"
        + message
        + "</h1><p>"
        + "Request verification is required. " * 5
        + "</p></body></html>"
    ).encode()
    with pytest.raises(RemoteError, match="html_content_unavailable"):
        normalize(html, "html")


def test_record_changed_between_discover_and_load_is_rejected(api):
    _, adapter, replies, _, _ = api
    adapter.prepare(ONE, None, None)
    catalog = adapter.discover(None, time.monotonic() + 10)
    entry = catalog["entries"][0]
    adapter.pending.clear()
    replies[ONE] = envelope(description="Actual changed evidence")
    with pytest.raises(RemoteError, match="source_changed_during_fetch"):
        adapter.load(entry, entry["revision"], time.monotonic() + 10)


def test_html_boolean_style_attribute_is_not_an_exception():
    raw = b"<html><body><div style>" + b"Visible source evidence. " * 10 + b"</div></body></html>"
    text, _ = normalize(raw, "html")
    assert "Visible source evidence." in text


def test_html_excessive_nesting_is_rejected_before_expensive_traversal():
    with pytest.raises(RemoteError, match="html_complexity_exceeded"):
        normalize(b"<div>" * 257 + b"Evidence text " * 10, "html")
