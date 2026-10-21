import base64
from datetime import UTC, datetime, timedelta

import pytest

from cyber_rag.memory import MemoryStore
from cyber_rag.models import digest
from cyber_rag.ondemand import FetchResponse, RemoteError
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.source_adapters import RecordAdapter, make_adapter
from cyber_rag.source_registry import SOURCES

RAW = b"<html><body><h1>VirtualAlloc</h1><p>Fixture documentation for memory allocation. This synthetic test page describes an API for cache validation without executing any code or allocating process memory.</p></body></html>"


@pytest.mark.parametrize(
    "query, expected",
    [
        ("VirtualAlloc", ["VirtualAlloc.html"]),
        ("ApiSetQueryApiSetPresence", ["ApiSetQueryApiSetPresence.html"]),
        ("MalAPI VirtualAlloc", ["VirtualAlloc.html"]),
        ("winapi: Sleep", ["Sleep.html"]),
        ("accept", ["accept.html"]),
        ("O que faz VirtualAlloc?", ["VirtualAlloc.html"]),
        ("VirtualAlloc WriteProcessMemory VirtualAlloc", ["VirtualAlloc.html", "WriteProcessMemory.html"]),
        ("palavras sem identificador", []),
    ],
)
def test_malapi_selects_api_names_without_alternative_sources(query, expected):
    adapter = make_adapter(SOURCES["malapi"])
    assert isinstance(adapter, RecordAdapter)
    assert adapter.select_paths(query, None) == expected
    assert adapter.url("VirtualAlloc.html") == "https://malapi.io/winapi/VirtualAlloc"


@pytest.mark.parametrize(
    "path",
    [
        "../VirtualAlloc.html",
        "http://localhost/a",
        "VirtualAlloc%2f.html",
        "VirtualAlloc.html?x=1",
        "VirtualAlloc/extra.html",
        "/VirtualAlloc.html",
        "VirtualAlloc.html#fragment",
        "A" * 129 + ".html",
        {},
        None,
    ],
)
def test_malapi_path_rejects_traversal_and_malformed_identifiers(path):
    adapter = RecordAdapter(SOURCES["malapi"])
    with pytest.raises(RemoteError, match="invalid_record_path"):
        adapter.identifier(path)


@pytest.mark.parametrize(
    "url",
    [
        "http://malapi.io/winapi/VirtualAlloc",
        "https://evil.example/winapi/VirtualAlloc",
        "https://malapi.io.evil.example/winapi/VirtualAlloc",
        "https://malapi.io/winapi/VirtualAlloc?redirect=evil",
        "https://malapi.io/winapi/VirtualAlloc/extra",
        "https://malapi.io/winapi/VirtualAlloc%2fextra",
        "https://malapi.io/winapi/../private",
        "https://malapi.io/winapi/VirtualAlloc#fragment",
        "https://learn.microsoft.com/VirtualAlloc",
        None,
    ],
)
def test_malapi_fetch_allowlist_is_exact(url):
    assert not RecordAdapter(SOURCES["malapi"]).allowed(url)


def test_initial_outage_keeps_empty_cache_and_offline_never_fetches(tmp_path):
    calls = []

    def unavailable(url, **kwargs):
        assert kwargs["allowed"](url)
        calls.append(url)
        raise RemoteError("network_unavailable")

    store = RemoteStore(tmp_path, RecordAdapter(SOURCES["malapi"], fetcher=unavailable))
    response = store.research("VirtualAlloc")
    assert response["remote_status"] == "failed" and response["results"] == []
    assert response["catalog"]["cached_versions"] == response["catalog"]["known_paths"] == 0
    assert store.research("VirtualAlloc", freshness="offline")["results"] == []
    assert calls == ["https://malapi.io/winapi/VirtualAlloc"]


def test_recovered_origin_preserves_raw_then_outage_suppresses_memory(tmp_path):
    clock = [datetime.now(UTC)]
    failed = [True]
    calls = []

    def fetch(url, **kwargs):
        assert kwargs["allowed"](url)
        calls.append(url)
        if failed[0]:
            raise RemoteError("network_unavailable")
        return FetchResponse(200, RAW)

    store = RemoteStore(tmp_path, RecordAdapter(SOURCES["malapi"], fetcher=fetch), clock=lambda: clock[0])
    assert not store.research("VirtualAlloc")["results"]
    failed[0] = False
    clock[0] += timedelta(seconds=61)
    evidence = store.research("VirtualAlloc")["results"][0]
    assert evidence["source_id"] == "malapi" and evidence["original_hash"] == digest(RAW)
    assert evidence["citation"]["url"] == "https://malapi.io/winapi/VirtualAlloc"
    assert base64.b64decode(store.get_document(evidence["document_id"])["content"]) == RAW
    memory = MemoryStore(tmp_path, clock=lambda: clock[0].timestamp())
    memory.remember(
        "VirtualAlloc fixture observation", [evidence["reference"]], resolve_reference=store.resolve_reference
    )
    count = len(calls)
    assert store.research("VirtualAlloc", freshness="offline")["results"][0]["freshness"] == "current"
    assert len(calls) == count
    failed[0] = True
    response = store.research("VirtualAlloc", freshness="refresh")
    assert response["results"][0]["freshness"] == "unknown"
    assert response["results"][0]["checked_at"] == evidence["checked_at"]
    assert memory.search("VirtualAlloc", resolve_reference=store.resolve_reference)["suppressed"] == {
        "unknown": 1
    }
    clock[0] += timedelta(seconds=61)
    failed[0] = False
    store.research("VirtualAlloc")
    assert len(memory.search("VirtualAlloc", resolve_reference=store.resolve_reference)["results"]) == 1


def test_catalog_discloses_unavailability_without_claiming_verified_content():
    from cyber_rag.catalog import source_catalog

    entry = next(row for row in source_catalog() if row["source_id"] == "malapi")
    assert entry["repository"] == "https://malapi.io/"
    assert "DNS failure" in entry["access_note"]
    assert "no live-verified MalAPI content" in entry["access_note"]
