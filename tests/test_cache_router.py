import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from cyber_rag import cache_router
from cyber_rag.cache_router import CacheRouter
from cyber_rag.memory import MemoryStore
from cyber_rag.models import KnowledgeError, digest
from cyber_rag.ondemand import RemoteError
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.research import _bound_evidence
from cyber_rag.service import KnowledgeService, _filters

REVISION = "a" * 40


class Adapter:
    ttl_seconds = 86400

    def __init__(self, source_id):
        self.source_id = source_id
        self.revision = REVISION
        self.now = datetime.now(UTC)
        self.failure = False
        self.calls = 0

    def discover(self, old, deadline):
        self.calls += 1
        if self.failure:
            raise RemoteError("fixture_unavailable")
        return {"revision": self.revision, "entries": [{"path": "bundle.json", "title": "Password evidence"}]}

    def load(self, entry, revision, deadline):
        self.calls += 1
        return {
            "raw": (self.source_id + revision).encode(),
            "text": "Password evidence from " + self.source_id,
            "title": entry["title"],
            "url": f"https://example.org/{self.source_id}/{revision}",
            "license_reference": "https://example.org/license",
        }


@pytest.fixture
def federation(tmp_path, monkeypatch):
    # Synthetic namespaces exercise infrastructure without adding real sources.
    names = ["fixture_a", "fixture_b"]
    monkeypatch.setattr(
        cache_router, "SOURCES", {name: SimpleNamespace(subjects=("password",)) for name in names}
    )
    monkeypatch.setattr(cache_router, "source_catalog", lambda: [{"source_id": name} for name in names])
    router = CacheRouter(tmp_path)
    adapters = {name: Adapter(name) for name in names}
    for name, adapter in adapters.items():
        router.stores[name] = RemoteStore(tmp_path, adapter, clock=lambda item=adapter: item.now)
    return router, adapters


def research(router, **kwargs):
    return router.research_sources("Password", source_ids=["fixture_a", "fixture_b"], **kwargs)


def test_distinct_source_ids_same_path_offline_and_pinned_roundtrip(federation):
    router, adapters = federation
    result = research(router)
    items = result["results"]
    assert len(items) == 2 and len({item["document_id"] for item in items}) == 2
    calls = sum(adapter.calls for adapter in adapters.values())
    assert len(research(router, freshness="offline")["results"]) == 2
    for item in items:
        document = router.get_document(item["document_id"], item["revision"])
        assert document["source_id"] == item["source_id"]
        assert document["original_hash"] == item["original_hash"]
    assert sum(adapter.calls for adapter in adapters.values()) == calls


def test_snapshot_record_not_in_bundle_uses_source_revision(federation):
    router, adapters = federation
    research(router)
    derived_id = "doc_" + digest(b"fixture_a:derived_record")[:32]
    assert router.latest_state(derived_id, REVISION, "f" * 64, "fixture_a") == "current"
    adapters["fixture_b"].revision = "b" * 40
    research(router, freshness="refresh")
    assert router.latest_state(derived_id, REVISION, "f" * 64, "fixture_a") == "current"
    assert router.latest_state(derived_id, REVISION, "f" * 64, "fixture_b") == "superseded"
    adapters["fixture_a"].now += timedelta(days=2)
    assert router.latest_state(derived_id, REVISION, "f" * 64, "fixture_a") == "stale"
    adapters["fixture_a"].failure = True
    research(router, freshness="refresh")
    assert router.latest_state(derived_id, REVISION, "f" * 64, "fixture_a") == "unknown"


def test_source_update_invalidates_only_its_own_note(federation):
    router, adapters = federation
    evidence = research(router)["results"]
    notes = MemoryStore(router.data_dir)
    for item in evidence:
        notes.remember(
            "Password note for " + item["source_id"],
            [item["evidence_reference"]],
            resolve_reference=router.resolve_reference,
        )
    adapters["fixture_a"].revision = "b" * 40
    router.research_sources("Password", source_ids=["fixture_a"], freshness="refresh")
    result = notes.search("Password", resolve_reference=router.resolve_reference)
    assert len(result["results"]) == 1
    assert result["results"][0]["citations"][0]["source_id"] == "fixture_b"
    assert result["suppressed"] == {"superseded": 1}


def test_corrupt_owasp_does_not_block_other_sources_or_reference(federation):
    router, _ = federation
    path = router.data_dir / "ondemand" / "cache.sqlite3"
    path.write_bytes(b"broken database")
    result = router.research_sources("Password", source_ids=["owasp", "fixture_a"])
    assert result["sources"]["owasp"]["remote_status"] == "failed"
    item = result["results"][0]
    assert item["source_id"] == "fixture_a"
    assert router.resolve_reference(item["evidence_reference"])["state"] == "current"
    assert router.get_document(item["document_id"])["source_id"] == "fixture_a"
    catalog = router.catalog()
    assert catalog["sources"]["owasp"]["status"] == "unavailable"
    assert catalog["sources"]["fixture_a"]["cached_versions"] == 1


def test_corrupt_source_is_unknown_and_memory_recovers(federation):
    router, _ = federation
    evidence = research(router)["results"]
    notes = MemoryStore(router.data_dir)
    item = evidence[0]
    notes.remember(
        "Password remembered", [item["evidence_reference"]], resolve_reference=router.resolve_reference
    )
    backend = router.stores[item["source_id"]]
    original = backend.path.read_bytes()
    backend.path.write_bytes(b"broken database")
    result = research(router, freshness="offline")
    assert result["sources"][item["source_id"]]["remote_status"] == "failed"
    assert result["results"][0]["source_id"] != item["source_id"]
    assert router.resolve_reference(item["evidence_reference"])["state"] == "unknown"
    assert (
        router.resolve_reference({**item["evidence_reference"], "document_id": "doc_" + "f" * 32})["state"]
        == "unknown"
    )
    assert notes.search("Password", resolve_reference=router.resolve_reference)["suppressed"] == {
        "unknown": 1
    }
    backend.path.write_bytes(original)
    assert len(notes.search("Password", resolve_reference=router.resolve_reference)["results"]) == 1
    assert (
        router.resolve_reference({**item["evidence_reference"], "document_id": "doc_" + "f" * 32})["state"]
        == "missing"
    )


@pytest.mark.parametrize("field,corrupt", [
    pytest.param("catalog", "[]", id="catalog-list"),
    pytest.param("catalog", '"text"', id="catalog-string"),
    pytest.param("catalog", "null", id="catalog-null"),
    pytest.param("catalog", "{", id="catalog-invalid-json"),
    pytest.param("catalog", "[" * 1500 + "0" + "]" * 1500, id="catalog-deep-json"),
    pytest.param("catalog", json.dumps({"revision": REVISION, "entries": {}}), id="entries-object"),
    pytest.param("catalog", json.dumps({"revision": REVISION, "entries": [None]}), id="entry-null"),
    pytest.param("catalog", json.dumps({"revision": REVISION, "entries": [{"path": "bundle.json", "title": []}]}), id="entry-title-type"),
    pytest.param("catalog", json.dumps({"revision": REVISION, "entries": [{"path": "../bundle.json", "title": "title"}]}), id="entry-invalid-path"),
    pytest.param("document_failures", '{"bundle.json": []}', id="failure-list"),
    pytest.param("last_failure", "[]", id="source-failure-list"),
    pytest.param("version_metadata", "[]", id="version-list"),
    pytest.param("version_metadata", "null", id="version-null"),
    pytest.param("version_metadata", "{", id="version-invalid-json"),
])
def test_corrupt_persisted_json_is_isolated_and_notes_recover(federation, field, corrupt):
    router, adapters = federation
    evidence = {item["source_id"]: item for item in research(router)["results"]}
    notes = MemoryStore(router.data_dir)
    for source, item in evidence.items():
        notes.remember(
            "Password note for " + source, [item["evidence_reference"]],
            resolve_reference=router.resolve_reference,
        )
    backend = router.stores["fixture_a"]
    with closing(sqlite3.connect(backend.path)) as db:
        if field == "version_metadata":
            original = db.execute("SELECT metadata FROM versions LIMIT 1").fetchone()[0]
            db.execute("UPDATE versions SET metadata=?", (corrupt,))
        else:
            original = db.execute("SELECT value FROM metadata WHERE key=?", (field,)).fetchone()
            db.execute("INSERT OR REPLACE INTO metadata VALUES(?,?)", (field, corrupt))
        db.commit()
    calls = sum(adapter.calls for adapter in adapters.values())
    broken = evidence["fixture_a"]
    with pytest.raises(KnowledgeError) as caught:
        backend.get_document(broken["document_id"], broken["revision"])
    assert caught.value.code == "CACHE_INTEGRITY"
    result = research(router, freshness="offline")
    assert result["sources"]["fixture_a"] == {"remote_status": "failed", "error_code": "CACHE_INTEGRITY"}
    assert [item["source_id"] for item in result["results"]] == ["fixture_b"]
    assert router.resolve_reference(broken["evidence_reference"])["state"] == "unknown"
    catalog = router.catalog()
    assert catalog["sources"]["fixture_b"]["cached_versions"] == 1
    if field != "version_metadata":
        assert catalog["sources"]["fixture_a"]["error_code"] == "CACHE_INTEGRITY"
    found = notes.search("Password", resolve_reference=router.resolve_reference)
    assert found["suppressed"] == {"unknown": 1}
    assert [item["citations"][0]["source_id"] for item in found["results"]] == ["fixture_b"]
    assert sum(adapter.calls for adapter in adapters.values()) == calls
    with closing(sqlite3.connect(backend.path)) as db:
        if field == "version_metadata":
            db.execute("UPDATE versions SET metadata=?", (original,))
        elif original is None:
            db.execute("DELETE FROM metadata WHERE key=?", (field,))
        else:
            db.execute("UPDATE metadata SET value=? WHERE key=?", (original[0], field))
        db.commit()
    restored = notes.search("Password", resolve_reference=router.resolve_reference)
    assert len(restored["results"]) == 2 and not restored["suppressed"]


def test_constructor_failure_is_per_source(federation, monkeypatch):
    router, _ = federation
    research(router)
    router.stores.pop("fixture_a")
    constructor = cache_router.RemoteStore

    def open_store(data_dir, adapter):
        if adapter.source_id == "fixture_a":
            raise sqlite3.DatabaseError("private data must not escape")
        return constructor(data_dir, adapter)

    monkeypatch.setattr(cache_router, "make_adapter", lambda spec: SimpleNamespace(source_id="fixture_a"))
    monkeypatch.setattr(cache_router, "RemoteStore", open_store)
    result = research(router, freshness="offline")
    assert [item["source_id"] for item in result["results"]] == ["fixture_b"]
    assert router.catalog()["sources"]["fixture_a"]["status"] == "unavailable"
    assert "private data" not in str(result)


def test_owner_closes_owasp_lookup_connection(tmp_path, monkeypatch):
    router = CacheRouter(tmp_path)
    backend = router.owasp
    connect = backend._connect
    connections = []

    def capture():
        connection = connect()
        connections.append(connection)
        return connection

    monkeypatch.setattr(backend, "_connect", capture)
    with pytest.raises(KnowledgeError) as error:
        router.get_document("doc_" + "f" * 32)
    assert error.value.code == "NOT_FOUND"
    assert connections
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


@pytest.mark.parametrize("selection", [["unknown"], "owasp", [], ["owasp"] * 65, [None]])
def test_unknown_invalid_sources_fail_before_cache_creation(tmp_path, selection):
    router = CacheRouter(tmp_path)
    with pytest.raises(KnowledgeError) as error:
        router.research_sources("Password", source_ids=selection, freshness="offline")
    assert error.value.code == "INVALID_ARGUMENT"
    assert not (tmp_path / "ondemand").exists()


def test_many_sources_offline_and_remote_source_cap(federation, monkeypatch):
    router, _ = federation
    names = [f"fixture_{index}" for index in range(64)]
    monkeypatch.setattr(cache_router, "source_catalog", lambda: [{"source_id": name} for name in names])
    assert router.route("Password", names, "offline") == names
    assert _filters({"source_ids": names})["source_ids"] == names
    with pytest.raises(KnowledgeError):
        router.route("Password", names[:4], "auto")
    with pytest.raises(KnowledgeError):
        _filters({"source_ids": names + ["fixture_64"]})
    note = MemoryStore(router.data_dir)
    reference = {
        "store": "cache",
        "document_id": "doc_fixture",
        "revision": REVISION,
        "original_hash": "f" * 64,
    }
    resolver = lambda ref: {"state": "current", "citation": {"source_id": names[-1]}}
    note.remember("Password note", [reference], resolve_reference=resolver)
    assert len(note.search("Password", resolve_reference=resolver, source_ids=names)["results"]) == 1


def test_round_robin_limits_and_source_failure_do_not_leak_results(federation):
    router, adapters = federation
    result = research(router, limit=1)
    assert len(result["results"]) == 1 and result["truncated"]
    before = router.stores["fixture_b"].catalog()
    adapters["fixture_a"].failure = True
    failed = router.research_sources("Password", source_ids=["fixture_a"], freshness="refresh")
    assert all(item["source_id"] == "fixture_a" for item in failed["results"])
    assert router.stores["fixture_b"].catalog() == before


def test_global_disk_threshold_stops_next_fetch_and_preserves_offline(federation, monkeypatch):
    router, adapters = federation
    # The first source may finish within its own DB quota; recheck before the next.
    readings = iter((0, cache_router.GLOBAL_CACHE_BYTES))
    monkeypatch.setattr(router, "_cache_bytes", lambda: next(readings))
    result = research(router)
    assert adapters["fixture_a"].calls == 2
    assert adapters["fixture_b"].calls == 0
    assert result["sources"]["fixture_b"]["remote_status"] == "offline"
    assert result["warnings"]
    monkeypatch.setattr(router, "_cache_bytes", lambda: cache_router.GLOBAL_CACHE_BYTES + 1)
    assert len(research(router, freshness="offline")["results"]) == 1
    assert adapters["fixture_a"].calls == 2
    catalog = router.catalog()
    assert catalog["global_cache_bytes"] > catalog["global_cache_limit_bytes"]


@pytest.mark.parametrize(
    "query, expected",
    [
        ("AML.T0001", ["atlas"]),
        ("T1059.001", ["attack", "attack-mobile", "attack-ics"]),
        ("T0800", ["attack", "attack-mobile", "attack-ics"]),
        ("CVE-2021-44228", ["cve", "kev", "nvd"]),
        ("CWE-79", ["cwe"]),
        ("CAPEC-100", ["capec"]),
    ],
)
def test_identifier_routes_only_registered_sources(tmp_path, monkeypatch, query, expected):
    names = {"atlas", "attack", "attack-mobile", "attack-ics", "cve", "kev", "nvd", "cwe", "capec"}
    monkeypatch.setattr(cache_router, "SOURCES", {name: SimpleNamespace(subjects=()) for name in names})
    router = CacheRouter(tmp_path)
    assert router.route(query, None, "auto") == expected
    monkeypatch.setattr(cache_router, "SOURCES", {expected[0]: SimpleNamespace(subjects=())})
    assert router.route(query, None, "auto") == expected[:1]
    assert not (tmp_path / "ondemand").exists()


def test_shared_deadline_stops_following_source_and_reserves_owasp(federation, monkeypatch):
    router, _ = federation
    now = [100.0]
    monkeypatch.setattr(cache_router.time, "monotonic", lambda: now[0])
    calls = []

    def delayed(query, **kwargs):
        calls.append(kwargs["deadline"])
        now[0] = kwargs["deadline"]
        return {"results": [], "warnings": [], "remote_status": "verified"}

    monkeypatch.setattr(router.stores["fixture_a"], "research", delayed)
    result = research(router, deadline=150.0)
    assert calls == [150.0]
    assert result["sources"]["fixture_b"]["remote_status"] == "budget_exhausted"
    now[0] = 135.0
    assert (
        router.research_sources("Password", source_ids=["owasp"], deadline=150.0)["sources"]["owasp"][
            "remote_status"
        ]
        == "budget_exhausted"
    )
    assert router._owasp is None


def test_global_excerpt_budget_covers_all_layers_and_keeps_citations_consistent():
    def evidence(prefix):
        return {
            "results": [
                {"document_id": f"{prefix}{index}", "passages": [{"text": "x" * 1800}, {"text": "y" * 1800}]}
                for index in range(3)
            ],
            "citations": [{"document_id": f"{prefix}{index}"} for index in range(3)],
        }

    layers = {
        "snapshot": evidence("snapshot"),
        "source_cache": evidence("cache"),
        "memory": {"results": [{"text": "z" * 1200} for _ in range(3)]},
    }
    assert _bound_evidence(layers)
    count = sum(
        len(passage["text"])
        for name in ("snapshot", "source_cache")
        for item in layers[name]["results"]
        for passage in item["passages"]
    )
    count += sum(len(item["text"]) for item in layers["memory"]["results"])
    assert count == 24000
    limited = {"snapshot": evidence("snapshot")}
    assert _bound_evidence(limited, maximum=100)
    assert len(limited["snapshot"]["results"]) == len(limited["snapshot"]["citations"]) == 1


@pytest.mark.parametrize("explicit", [True, False])
def test_default_research_with_more_than_twenty_sources_keeps_memory_available(
    tmp_path, monkeypatch, explicit
):
    from cyber_rag import research as research_module

    names = [f"fixture_{index}" for index in range(64)]
    names[-1] = "nvd"
    listing = lambda: [{"source_id": name} for name in names]
    monkeypatch.setattr(cache_router, "source_catalog", listing)
    monkeypatch.setattr(research_module, "source_catalog", listing)
    service = KnowledgeService(tmp_path)
    try:
        response = service.dispatch(
            "knowledge_research",
            {"query": "Password", "freshness": "offline", **({"source_ids": names} if explicit else {})},
        )
        assert response["layers"]["memory"]["status"] == "no_results"
        assert response["layers"]["source_cache"]["selected_sources"] == (names if explicit else [])
        assert "error" not in response["layers"]["source_cache"]
    finally:
        service.close()


def test_expired_reference_budget_is_unknown_without_opening_cache(federation, monkeypatch):
    router, _ = federation
    evidence = research(router)["results"][0]
    monkeypatch.setattr(cache_router.time, "monotonic", lambda: 100.0)
    assert router.resolve_reference(evidence["evidence_reference"], deadline=99.0)["state"] == "unknown"
    assert (
        router.latest_state(
            evidence["document_id"], REVISION, evidence["original_hash"], "fixture_a", deadline=99.0
        )
        == "unknown"
    )
    assert all(item["error_code"] == "TIMEOUT" for item in router.catalog(deadline=99.0)["sources"].values())


def test_federation_caps_excerpts_across_three_documents(federation, monkeypatch):
    router, _ = federation
    response = research(router)
    sample = response["results"][0]
    items = [
        {
            **sample,
            "document_id": "doc_" + str(index) * 32,
            "passages": [{"text": "x" * 2000} for _ in range(10)],
        }
        for index in range(3)
    ]
    monkeypatch.setattr(
        router.stores["fixture_a"],
        "research",
        lambda *args, **kwargs: {"results": items, "remote_status": "offline"},
    )
    result = router.research_sources("Password", source_ids=["fixture_a"], freshness="offline")
    assert len(result["results"]) == 3
    assert result["truncated"]
    assert sum(len(p["text"]) for item in result["results"] for p in item["passages"]) == 7200


def test_empty_status_advertises_current_contract_and_sources(tmp_path):
    from cyber_rag.source_registry import SOURCES

    service = KnowledgeService(tmp_path)
    try:
        status = service.dispatch("knowledge_status", {})["results"][0]
        assert status["tool_contract"] == 3
        assert set(status["on_demand_source_ids"]) == {"owasp", *SOURCES}
    finally:
        service.close()


def test_catalog_bounds_path_previews_without_losing_counts(federation, monkeypatch):
    router, _ = federation
    router._owasp = SimpleNamespace(catalog=lambda: {"paths": []})
    monkeypatch.setattr(router.stores["fixture_a"], "catalog", lambda: {
        "paths": [f"rules/{i}.yml" for i in range(200)], "known_paths": 5000,
    })
    catalog = router.catalog()["sources"]["fixture_a"]
    assert catalog["known_paths"] == 5000
    assert len(catalog["paths_preview"]) == 5
    assert catalog["paths_preview_truncated"] is True
    assert "paths" not in catalog


@pytest.mark.parametrize("identifier", ["AML.T0001", "AML.TA0001", "AML.M0001", "AML.CS0001"])
def test_atlas_identifiers_do_not_route_to_attack(tmp_path, identifier):
    assert CacheRouter(tmp_path).route(identifier, None, "auto") == ["atlas"]
