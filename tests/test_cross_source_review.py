"""Offline regressions found during the federation review."""

import json
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from cyber_rag.cache_router import CacheRouter
from cyber_rag.memory import MemoryStore
from cyber_rag.models import Document
from cyber_rag.ondemand import COMMIT_URL, FetchResponse, OnDemandStore, RemoteError
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.research import ResearchService
from cyber_rag.service import KnowledgeService
from cyber_rag.snapshot import ingest_documents
from cyber_rag.source_adapters import GithubAdapter, PublicAdapter, RecordAdapter, bounded_json_loads
from cyber_rag.source_registry import SOURCES, SourceSpec

URL = "https://fixture.example/catalog.json"
RAW = b'{"name":"Password guidance","description":"Use unique salts"}'


def public_spec(**changes):
    return replace(
        SourceSpec(
            "review-public",
            "Review fixture",
            "",
            "",
            ("catalog.json",),
            ("password",),
            discovery="public",
            format="json",
            urls=(("catalog.json", URL),),
            homepage="https://fixture.example/",
            license_url="https://fixture.example/license",
        ),
        **changes,
    )


def test_public_changed_url_cannot_reuse_fresh_catalog_without_verifying_new_origin(tmp_path):
    original = RemoteStore(
        tmp_path, PublicAdapter(public_spec(), fetcher=lambda *a, **kw: FetchResponse(200, RAW))
    )
    old = original.research("Password")["results"][0]
    calls = []
    new_url = "https://fixture.example/replacement.json"

    def fetch(url, **kwargs):
        calls.append(url)
        return FetchResponse(200, RAW)

    updated = RemoteStore(
        tmp_path, PublicAdapter(public_spec(urls=(("catalog.json", new_url),)), fetcher=fetch)
    )
    result = updated.research("Password")["results"][0]
    assert calls == [new_url]
    assert result["url"] == new_url
    assert result["revision"] != old["revision"]
    assert updated.resolve_reference(old["evidence_reference"])["state"] == "superseded"


def test_public_changed_configuration_failure_preserves_unknown_original(tmp_path):
    original = RemoteStore(
        tmp_path, PublicAdapter(public_spec(), fetcher=lambda *a, **kw: FetchResponse(200, RAW))
    )
    old = original.research("Password")["results"][0]

    def unavailable(*args, **kwargs):
        raise RemoteError("http_503")

    updated = RemoteStore(
        tmp_path,
        PublicAdapter(public_spec(urls=(("catalog.json", URL + "?new"),)), fetcher=unavailable),
    )
    result = updated.research("Password")
    assert result["remote_status"] == "failed"
    assert result["results"][0]["freshness"] == "unknown"
    assert updated.resolve_reference(old["evidence_reference"])["state"] == "unknown"
    document = updated.get_document(old["document_id"], old["revision"])
    assert document["original_hash"] == old["original_hash"]


def test_public_removed_url_is_not_current_for_offline_memory(tmp_path):
    original = RemoteStore(
        tmp_path, PublicAdapter(public_spec(), fetcher=lambda *a, **kw: FetchResponse(200, RAW))
    )
    evidence = original.research("Password")["results"][0]
    memory = MemoryStore(tmp_path)
    memory.remember(
        "Password guidance", [evidence["evidence_reference"]], resolve_reference=original.resolve_reference
    )
    replacement = public_spec(urls=(("replacement.json", "https://fixture.example/replacement.json"),))
    updated = RemoteStore(
        tmp_path,
        PublicAdapter(
            replacement, fetcher=lambda *a, **kw: (_ for _ in ()).throw(AssertionError("offline HTTP"))
        ),
    )
    assert updated.resolve_reference(evidence["evidence_reference"])["state"] != "current"
    assert not memory.search("Password", resolve_reference=updated.resolve_reference)["results"]


def test_public_updated_license_is_visible_after_explicit_refresh(tmp_path):
    original = RemoteStore(
        tmp_path, PublicAdapter(public_spec(), fetcher=lambda *a, **kw: FetchResponse(200, RAW))
    )
    original.research("Password")
    changed_license = "https://fixture.example/revised-license"
    updated = RemoteStore(
        tmp_path,
        PublicAdapter(
            public_spec(license_url=changed_license), fetcher=lambda *a, **kw: FetchResponse(200, RAW)
        ),
    )
    result = updated.research("Password", freshness="refresh")["results"][0]
    assert result["citation"]["license_reference"] == changed_license


def test_html_boolean_style_attribute_is_controlled(tmp_path):
    raw = b"<html><body><p style>Current password guidance with enough explanatory prose to exceed the minimum document length.</p></body></html>"
    store = RemoteStore(
        tmp_path, PublicAdapter(public_spec(format="html"), fetcher=lambda *a, **kw: FetchResponse(200, raw))
    )
    response = store.research("Password")
    assert response["remote_status"] in {"verified", "failed"}


def test_deep_json_cannot_escape_as_uncaught_recursion_error(tmp_path):
    raw = b"[" * 1500 + b"0" + b"]" * 1500
    store = RemoteStore(
        tmp_path, PublicAdapter(public_spec(), fetcher=lambda *a, **kw: FetchResponse(200, raw))
    )
    response = store.research("Password")
    assert response["remote_status"] == "failed"
    assert response["results"] == []


@pytest.mark.parametrize("value", ["[" * 300, '{"x": "[\\\\\\"[]"}', "\\\\\\\\[{}]", 'a\\q"x'])
def test_bounded_json_counts_only_containers_not_escaped_string_characters(value):
    payload = {"content": value, "nested": [{"ordinary": "text"}]}
    assert bounded_json_loads(json.dumps(payload)) == payload


def test_bounded_json_rejects_excess_containers_before_pretty_printing():
    assert bounded_json_loads("[" * 128 + "0" + "]" * 128)
    with pytest.raises(RemoteError, match="json_nesting_limit"):
        bounded_json_loads("[" * 129 + "0" + "]" * 129)


def github_spec(**changes):
    return replace(
        public_spec(
            source_id="review-github",
            discovery="fixed",
            repository="fixture/repository",
            branch="main",
            paths=("catalog.json", "second.json"),
            format="text",
            urls=(),
        ),
        **changes,
    )


def pinned_fetch(raw=RAW):
    def fetch(url, **kwargs):
        if "/git/ref/" in url:
            return FetchResponse(200, json.dumps({"object": {"sha": "a" * 40}}).encode())
        return FetchResponse(200, raw)

    return fetch


def test_github_same_commit_config_change_rebuilds_projection_and_keeps_original_identity(tmp_path):
    old = RemoteStore(tmp_path, GithubAdapter(github_spec(), fetcher=pinned_fetch()))
    one = old.research("Password", path="catalog.json")["results"][0]
    two = old.research("Password", path="second.json")["results"][0]
    new = RemoteStore(
        tmp_path,
        GithubAdapter(github_spec(format="json", license_url=URL + "/new-license"), fetcher=pinned_fetch()),
    )
    assert new.resolve_reference(one["evidence_reference"])["state"] == "unknown"
    item = new.research("Password", path="catalog.json")["results"][0]
    assert item["evidence_reference"] == one["evidence_reference"]
    assert item["metadata"]["representation"] == "derived_json_text"
    assert item["license_reference"] == URL + "/new-license"
    assert item["freshness"] == "current"
    assert new.resolve_reference(two["evidence_reference"])["state"] == "unknown"
    assert new.catalog()["cached_versions"] == 2
    assert new.research("Password", path="second.json")["results"][0]["freshness"] == "current"


def test_github_config_change_preserves_original_without_a_second_content_fetch(tmp_path):
    old = RemoteStore(tmp_path, GithubAdapter(github_spec(), fetcher=pinned_fetch()))
    evidence = old.research("Password", path="catalog.json")["results"][0]
    changed = RemoteStore(
        tmp_path, GithubAdapter(github_spec(format="json"), fetcher=pinned_fetch(RAW + b"\n"))
    )
    item = changed.research("Password", path="catalog.json")["results"][0]
    assert item["original_hash"] == evidence["original_hash"]
    assert changed.resolve_reference(evidence["evidence_reference"])["state"] == "current"
    assert changed.get_document(evidence["document_id"])["original_hash"] == evidence["original_hash"]


def test_cache_revision_mismatch_only_supersedes_a_snapshot_observed_before_it(tmp_path):
    now = [datetime.now(UTC) - timedelta(hours=2)]
    store = RemoteStore(
        tmp_path,
        PublicAdapter(public_spec(), fetcher=lambda *a, **kw: FetchResponse(200, RAW)),
        clock=lambda: now[0],
    )
    evidence = store.research("Password")["results"][0]
    reference_checked = now[0] + timedelta(hours=1)
    now[0] += timedelta(hours=2)
    args = (evidence["document_id"], "b" * 64, "c" * 64)
    assert store.latest_state(*args, reference_checked_at=reference_checked.isoformat()) is None
    store.research("Password", freshness="refresh")
    assert store.latest_state(*args, reference_checked_at=reference_checked.isoformat()) == "superseded"


@pytest.mark.parametrize("logical_record", [False, True])
def test_router_orders_observations_for_cached_and_snapshot_only_ids(tmp_path, logical_record):
    now = [datetime.now(UTC) - timedelta(hours=2)]
    store = RemoteStore(
        tmp_path, GithubAdapter(github_spec(source_id="attack"), fetcher=pinned_fetch()), clock=lambda: now[0]
    )
    evidence = store.research("Password", path="catalog.json")["results"][0]
    router = CacheRouter(tmp_path)
    router.stores["attack"] = store
    document_id = "doc_" + "f" * 32 if logical_record else evidence["document_id"]
    verified = (now[0] + timedelta(hours=1)).isoformat()
    now[0] += timedelta(hours=2)
    assert (
        router.latest_state(document_id, "b" * 40, "c" * 64, "attack", reference_checked_at=verified) is None
    )
    store.research("Password", path="catalog.json", freshness="refresh")
    assert (
        router.latest_state(document_id, "b" * 40, "c" * 64, "attack", reference_checked_at=verified)
        == "superseded"
    )


def test_per_record_observation_does_not_inherit_another_records_later_check(tmp_path):
    now = [datetime.now(UTC) - timedelta(hours=2)]
    descriptions = {
        "CVE-2024-1234": "Original password vulnerability",
        "CVE-2024-5678": "Other password vulnerability",
    }

    def fetch(url, **kwargs):
        identifier = url.rsplit("=", 1)[-1]
        return FetchResponse(
            200,
            json.dumps(
                {
                    "vulnerabilities": [
                        {"cve": {"id": identifier, "descriptions": [{"value": descriptions[identifier]}]}}
                    ]
                }
            ).encode(),
        )

    adapter = RecordAdapter(replace(SOURCES["nvd"], min_interval_seconds=0), fetcher=fetch)
    store = RemoteStore(tmp_path, adapter, clock=lambda: now[0])
    evidence = store.research("CVE-2024-1234")["results"][0]
    verified = (now[0] + timedelta(hours=1)).isoformat()
    now[0] += timedelta(hours=2)
    store.research("CVE-2024-5678")
    args = (evidence["document_id"], "b" * 64, "c" * 64)
    assert store.latest_state(*args, reference_checked_at=verified) is None
    descriptions["CVE-2024-1234"] = "Updated password vulnerability"
    store.research("CVE-2024-1234", freshness="refresh")
    assert store.latest_state(*args, reference_checked_at=verified) == "superseded"


@pytest.mark.parametrize("value", ["invalid", "2035-01-01T00:00:00+00:00", "2026-01-01T00:00:00"])
def test_malformed_snapshot_observation_timestamp_never_permanently_invalidates(tmp_path, value):
    store = RemoteStore(
        tmp_path, PublicAdapter(public_spec(), fetcher=lambda *a, **kw: FetchResponse(200, RAW))
    )
    evidence = store.research("Password")["results"][0]
    assert (
        store.latest_state(evidence["document_id"], "b" * 64, "c" * 64, reference_checked_at=value)
        == "unknown"
    )
    with closing(store._connect()) as db, db:
        store._put(db, "observed_at", value)
    assert (
        store.latest_state(
            evidence["document_id"], "b" * 64, "c" * 64, reference_checked_at=datetime.now(UTC).isoformat()
        )
        == "unknown"
    )


def test_stale_cache_does_not_hide_newer_snapshot_with_same_document_id(tmp_path):
    path = "cheatsheets/Password_Storage_Cheat_Sheet.md"
    revision = "a" * 40
    old_raw = b"# Password Storage\nUse previous password guidance."
    now = [datetime.now(UTC)]

    def fetch(url, **kwargs):
        if url == COMMIT_URL:
            return FetchResponse(200, json.dumps({"sha": revision}).encode(), '"head"')
        if "/contents/" in url:
            return FetchResponse(
                200, json.dumps([{"path": path, "type": "file", "size": len(old_raw)}]).encode()
            )
        return FetchResponse(200, old_raw)

    service = KnowledgeService(tmp_path)
    research = ResearchService(service)
    research.cache = OnDemandStore(tmp_path, fetcher=fetch, clock=lambda: now[0])
    service._research = research
    try:
        request = {"query": "Password", "source_ids": ["owasp"]}
        cached = service.dispatch("knowledge_research", request)["layers"]["source_cache"]["results"][0]
        now[0] += timedelta(days=8)
        raw = b"# Password Storage\nUse the updated password guidance, now including a stronger password recommendation."
        doc = Document(
            "owasp",
            path,
            "b" * 40,
            "https://example.org/new",
            "Password Storage",
            "text/markdown",
            raw.decode(),
            raw,
            {"checked_at": datetime.now(UTC).isoformat()},
        )
        ingest_documents(
            tmp_path,
            [doc],
            {"owasp": {"revision": doc.revision, "checked_at": datetime.now(UTC).isoformat()}},
        )
        result = service.dispatch("knowledge_research", {**request, "freshness": "offline"})
        assert cached["document_id"] == doc.document_id
        assert result["layers"]["source_cache"]["results"][0]["freshness"] == "stale"
        assert result["layers"]["snapshot"]["citations"][0]["revision"] == "b" * 40
        snapshot = result["layers"]["snapshot"]["results"][0]
        assert snapshot["cache_observation"] == "not_observed"
        saved = service.dispatch(
            "knowledge_remember",
            {"text": "Updated password guidance", "references": [snapshot["evidence_reference"]]},
        )
        assert saved["status"] == "ok"
        # A new remote observation can establish an actual rollback/change.
        refreshed = service.dispatch("knowledge_research", {**request, "freshness": "refresh"})
        assert not refreshed["layers"]["memory"]["results"]
        assert refreshed["layers"]["memory"]["suppressed"] == {"superseded": 1}
    finally:
        service.close()
