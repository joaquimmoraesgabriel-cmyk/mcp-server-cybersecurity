"""Offline tests for exact-URL evidence collection, independent of any source."""

import hashlib
import json
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from cyber_rag.ondemand import FetchResponse, RemoteError
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.source_adapters import PublicAdapter
from cyber_rag.source_registry import SourceSpec

URL = "https://evidence.example/catalog.json"
RAW = b'{"name":"PowerShell","description":"Defensive guidance"}'


@pytest.fixture
def spec():
    return SourceSpec(
        source_id="public-fixture",
        title="Fixture",
        repository="",
        branch="",
        paths=("catalog.json",),
        subjects=("fixture",),
        format="json",
        discovery="public",
        urls=(("catalog.json", URL),),
        homepage="https://evidence.example/",
        license_url="https://evidence.example/license",
        max_bytes=1000,
    )


def deadline():
    return time.monotonic() + 20


def test_public_original_bytes_are_hash_pinned_and_reused_after_discovery(spec):
    calls = []

    def fetch(url, **kwargs):
        assert kwargs["allowed"](url)
        calls.append((url, kwargs))
        return FetchResponse(200, RAW, '"original"')

    adapter = PublicAdapter(spec, fetcher=fetch)
    catalog = adapter.discover(None, deadline())
    item = adapter.load(catalog["entries"][0], catalog["revision"], deadline())
    assert len(calls) == 1
    assert item["raw"] == RAW
    assert json.loads(item["text"]) == json.loads(RAW)
    assert item["text"].encode() != item["raw"]
    assert item["metadata"]["content_hash"] == hashlib.sha256(RAW).hexdigest()
    assert item["metadata"]["origin_url_mutable"]
    assert item["url"] == URL and item["license_reference"] == spec.license_url
    assert len(catalog["revision"]) == 64
    assert calls[0][1]["max_bytes"] == 1000


@pytest.mark.parametrize(
    "url",
    [
        "http://evidence.example/catalog.json",
        "https://evidence.example/catalog.json?download=1",
        "https://evidence.example/catalog.json#fragment",
        "https://evidence.example/catalog.json/extra",
        "https://evidence.example/private.json",
        "https://evidence.example.evil/catalog.json",
        "https://evidence.example@evil.example/catalog.json",
        "https://user@evidence.example/catalog.json",
        "https://evidence.example:443/catalog.json",
        "https://evidence.example/%63atalog.json",
        "file:///catalog.json",
    ],
)
def test_public_allowlist_accepts_only_exact_reviewed_url(spec, url):
    adapter = PublicAdapter(spec)
    assert adapter.allowed(URL)
    assert not adapter.allowed(url)


@pytest.mark.parametrize(
    "old",
    [
        None,
        {"entries": []},
        {
            "entries": [{"path": "catalog.json", "content_hash": hashlib.sha256(RAW).hexdigest()}],
        },
        {"entries": [{"path": "catalog.json", "etag": '"old"'}]},
    ],
)
def test_unsolicited_304_without_both_old_hash_and_etag_is_rejected(spec, old):
    adapter = PublicAdapter(spec, fetcher=lambda *a, **kw: FetchResponse(304, etag='"new"'))
    with pytest.raises(RemoteError, match="invalid_public_response"):
        adapter.discover(old, deadline())


def test_valid_304_keeps_hash_and_fetches_verified_bytes_on_a_new_adapter(spec):
    original = PublicAdapter(spec, fetcher=lambda *a, **kw: FetchResponse(200, RAW, '"old"'))
    old = original.discover(None, deadline())
    responses = [FetchResponse(304, etag='"old"'), FetchResponse(200, RAW)]
    calls = []

    def fetch(url, **kwargs):
        calls.append(kwargs)
        return responses.pop(0)

    adapter = PublicAdapter(spec, fetcher=fetch)
    catalog = adapter.discover(old, deadline())
    assert catalog == old
    loaded = adapter.load(catalog["entries"][0], catalog["revision"], deadline())
    assert loaded["raw"] == RAW
    assert calls[0]["etag"] == '"old"'
    assert calls[1].get("etag") is None


def test_changed_bytes_between_discovery_and_load_are_rejected(spec):
    adapter = PublicAdapter(spec, fetcher=lambda *a, **kw: FetchResponse(200, RAW))
    catalog = adapter.discover(None, deadline())
    # A later process may only have the catalog; mutable origin must still
    # match its recorded content hash before bytes enter the local cache.
    reader = PublicAdapter(spec, fetcher=lambda *a, **kw: FetchResponse(200, RAW + b"\n"))
    with pytest.raises(RemoteError, match="source_changed_during_fetch"):
        reader.load(catalog["entries"][0], catalog["revision"], deadline())


def test_304_during_unconditional_original_load_is_rejected(spec):
    original = PublicAdapter(spec, fetcher=lambda *a, **kw: FetchResponse(200, RAW))
    catalog = original.discover(None, deadline())
    reader = PublicAdapter(spec, fetcher=lambda *a, **kw: FetchResponse(304))
    with pytest.raises(RemoteError, match="public_source_unavailable"):
        reader.load(catalog["entries"][0], catalog["revision"], deadline())


@pytest.mark.parametrize(
    "entry",
    [
        {"path": "catalog.json", "url": "https://evil.example/payload"},
        {"path": "../catalog.json", "url": URL},
        {"path": "unregistered.json", "url": URL},
    ],
)
def test_loading_forged_entry_never_calls_fetcher(spec, entry):
    adapter = PublicAdapter(spec, fetcher=lambda *a, **kw: pytest.fail("Forged entry reached fetcher"))
    with pytest.raises(RemoteError, match="url_rejected"):
        adapter.load(entry, "a" * 64, deadline())


@pytest.mark.parametrize(
    "response",
    [
        FetchResponse(200, b""),
        FetchResponse(200, b"a" * 1001),
        FetchResponse(302, RAW),
        FetchResponse(503, RAW),
    ],
)
def test_invalid_status_or_size_cannot_become_catalog_evidence(spec, response):
    adapter = PublicAdapter(spec, fetcher=lambda *a, **kw: response)
    with pytest.raises(RemoteError, match="invalid_public_response"):
        adapter.discover(None, deadline())


def test_revision_changes_when_an_original_changes(spec):
    first = PublicAdapter(spec, fetcher=lambda *a, **kw: FetchResponse(200, RAW))
    second = PublicAdapter(spec, fetcher=lambda *a, **kw: FetchResponse(200, RAW + b"\n"))
    assert first.discover(None, deadline())["revision"] != second.discover(None, deadline())["revision"]


def test_public_failure_preserves_evidence_without_freshening_other_sources(spec, tmp_path):
    now = datetime(2026, 10, 21, 12, tzinfo=UTC)
    first_adapter = PublicAdapter(spec, fetcher=lambda *a, **kw: FetchResponse(200, RAW))
    second_adapter = PublicAdapter(
        replace(spec, source_id="other-public"), fetcher=lambda *a, **kw: FetchResponse(200, RAW)
    )
    first = RemoteStore(tmp_path, first_adapter, clock=lambda: now)
    second = RemoteStore(tmp_path, second_adapter, clock=lambda: now)
    original = first.research("PowerShell")["results"][0]
    other = second.research("PowerShell")["results"][0]
    now += timedelta(minutes=1)

    def unavailable(*a, **kw):
        raise RemoteError("http_503")

    first_adapter.fetcher = unavailable
    failed = first.research("PowerShell", freshness="refresh")
    assert failed["remote_status"] == "failed"
    assert failed["results"][0]["original_hash"] == original["original_hash"]
    assert failed["results"][0]["checked_at"] == original["checked_at"]
    assert failed["results"][0]["freshness"] == "unknown"
    assert second.resolve_reference(other["reference"])["state"] == "current"


@pytest.mark.parametrize("raw", [b"not json", b'{"bad":"\x00"}', b"\xff"])
def test_invalid_text_never_becomes_persisted_evidence(spec, tmp_path, raw):
    adapter = PublicAdapter(spec, fetcher=lambda *a, **kw: FetchResponse(200, raw))
    store = RemoteStore(tmp_path, adapter)
    failed = store.research("PowerShell")
    assert failed["remote_status"] == "failed"
    assert failed["catalog"]["cached_versions"] == 0
    assert failed["results"] == []
