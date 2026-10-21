import base64
import json
import sqlite3
import time
from datetime import UTC, datetime, timedelta

import pytest

from cyber_rag import remote_cache
from cyber_rag.models import KnowledgeError, digest
from cyber_rag.ondemand import RemoteError
from cyber_rag.remote_cache import RemoteStore

A, B = "a" * 40, "b" * 64
BODY = b'{"id":"T1059.001","description":"Use PowerShell"}'
TEXT = "# T1059.001 PowerShell\n\nPowerShell command execution uses scripts.\n"


class Adapter:
    source_id = "fixture"
    ttl_seconds = 86400
    max_bytes = 80 * 1024 * 1024

    def __init__(self):
        self.revision = A
        self.entries = [{"path": "catalog/techniques.json", "title": "PowerShell techniques"}]
        self.raw = BODY
        self.text = TEXT
        self.failure = None
        self.load_failure = None
        self.discoveries = 0
        self.loads = 0
        self.now = datetime(2026, 10, 21, 12, tzinfo=UTC)

    def discover(self, old, deadline):
        self.discoveries += 1
        if self.failure:
            raise self.failure
        return {"revision": self.revision, "entries": self.entries, "etag": "fixture-etag"}

    def candidates(self, query, catalog, limit, path):
        return catalog.get("entries", [])[:limit]

    def load(self, entry, revision, deadline):
        self.loads += 1
        if self.load_failure:
            raise self.load_failure
        return {
            "raw": self.raw,
            "text": self.text,
            "title": entry["title"],
            "url": f"https://example.org/{revision}/{entry['path']}",
            "license_reference": "https://example.org/license",
            "metadata": {"raw_representation": "original_json", "text_representation": "parsed_records"},
        }


@pytest.fixture
def prepared(tmp_path):
    adapter = Adapter()
    return RemoteStore(tmp_path, adapter, clock=lambda: adapter.now), adapter


def query(store, **kwargs):
    return store.research("PowerShell T1059.001", **kwargs)


def test_first_load_cache_hit_and_offline(prepared):
    store, adapter = prepared
    first = query(store)
    item = first["results"][0]
    assert item["document_id"] == "doc_" + digest(b"fixture:catalog/techniques.json")[:32]
    assert item["source_id"] == "fixture"
    assert item["freshness"] == "current" and first["remote_status"] == "verified"
    assert item["metadata"]["raw_representation"] == "original_json"
    assert "T1059.001" in item["passages"][0]["text"]
    assert query(store)["remote_status"] == "cache_hit"
    assert query(store, freshness="offline")["remote_status"] == "offline"
    assert adapter.discoveries == adapter.loads == 1
    assert store.has_document(item["document_id"])
    assert not store.has_document("doc_" + "f" * 32)
    assert not store.has_document("../secrets")


def test_immutable_versions_and_changed_reference(prepared):
    store, adapter = prepared
    old = query(store)["results"][0]
    adapter.revision = B
    adapter.raw += b"\n"
    adapter.text += "\nReview new guidance.\n"
    new = query(store, freshness="refresh")["results"][0]
    assert new["revision"] == B
    assert new["original_hash"] != old["original_hash"]
    assert store.resolve_reference(old["evidence_reference"])["state"] == "superseded"
    assert store.resolve_reference(new["evidence_reference"])["state"] == "current"
    assert base64.b64decode(store.get_document(old["document_id"], A)["content"]) == BODY
    assert store.catalog()["cached_versions"] == 2


def test_failure_preserves_previous_without_freshening(prepared):
    store, adapter = prepared
    original = query(store)["results"][0]
    adapter.now += timedelta(days=2)
    adapter.failure = RemoteError("http_503")
    result = query(store, freshness="refresh")
    assert result["remote_status"] == "failed"
    assert result["results"][0]["freshness"] == "unknown"
    assert result["results"][0]["original_hash"] == original["original_hash"]
    assert result["results"][0]["checked_at"] == original["checked_at"]
    assert query(store)["remote_status"] == "cooldown"
    assert adapter.discoveries == 2
    adapter.now += timedelta(minutes=2)
    adapter.failure = None
    assert query(store)["results"][0]["freshness"] == "current"
    assert adapter.loads == 1


def test_no_cache_first_failure_is_unknown_for_snapshot_references(prepared):
    store, adapter = prepared
    adapter.failure = RemoteError("http_503")
    assert query(store)["remote_status"] == "failed"
    assert store.latest_state("doc_" + "1" * 32, A, "0" * 64) == "unknown"


def test_observed_new_revision_invalidates_even_when_catalog_invalid(prepared):
    store, adapter = prepared
    old = query(store)["results"][0]
    adapter.revision = B
    adapter.entries = [{"path": "../secret", "title": "bad"}]
    result = query(store, freshness="refresh")
    assert result["remote_status"] == "failed"
    assert result["results"][0]["freshness"] == "superseded"
    assert store.source_revision()["revision"] == B
    assert store.resolve_reference(old["reference"])["state"] == "superseded"


def test_download_failure_does_not_publish_new_revision_bytes(prepared):
    store, adapter = prepared
    old = query(store)["results"][0]
    adapter.revision = B
    adapter.load_failure = RemoteError("http_404")
    result = query(store, freshness="refresh")
    assert result["remote_status"] == "failed"
    assert result["results"][0]["revision"] == A
    assert store.catalog()["cached_versions"] == 1
    assert store.latest_state(old["document_id"], A, old["original_hash"]) == "superseded"


def test_stale_and_clock_rollback_offline(prepared):
    store, adapter = prepared
    query(store)
    adapter.now += timedelta(days=2)
    assert query(store, freshness="offline")["results"][0]["freshness"] == "stale"
    adapter.now -= timedelta(days=4)
    assert query(store, freshness="offline")["results"][0]["freshness"] == "unknown"
    assert adapter.discoveries == 1


@pytest.mark.parametrize("column,value", [("raw", b"corrupt"), ("text", "Poisoned derived text")])
def test_corrupt_original_or_derived_text_is_not_returned(prepared, column, value):
    store, _ = prepared
    result = query(store)["results"][0]
    with sqlite3.connect(store.path) as db:
        db.execute(f"UPDATE versions SET {column}=?", (value,))
    with pytest.raises(KnowledgeError, match="integridade"):
        store.get_document(result["document_id"])


def test_pagination_fixed_revision_and_hash(prepared):
    store, adapter = prepared
    adapter.raw = ("á" * 10000).encode()
    item = query(store)["results"][0]
    parts, offset = [], 0
    while True:
        part = store.get_document(item["document_id"], A, offset)
        content = base64.b64decode(part["content"])
        assert digest(content) == part["part_hash"]
        parts.append(content)
        if part["last_part"]:
            break
        offset = part["next_offset"]
    assert b"".join(parts) == adapter.raw
    with pytest.raises(KnowledgeError):
        store.get_document(item["document_id"], offset=9000)
    with pytest.raises(KnowledgeError):
        store.get_document(item["document_id"], A, len(adapter.raw))


def test_capacity_preserves_active(prepared):
    store, adapter = prepared
    original = query(store)["results"][0]
    store.max_versions = 1
    adapter.revision = B
    result = query(store, freshness="refresh")
    assert result["remote_status"] == "failed"
    assert result["catalog"]["last_failure"]["code"] == "cache_capacity_reached"
    assert result["results"][0]["original_hash"] == original["original_hash"]
    assert store.catalog()["cached_versions"] == 1


@pytest.mark.parametrize(
    "path",
    [
        "../secret",
        "/tmp/secret",
        "a//b",
        "a/./b",
        "https://example.org/file",
        "a\\b",
        "a?query",
        "a#fragment",
    ],
)
def test_unsafe_path_rejected_before_adapter(prepared, path):
    store, adapter = prepared
    with pytest.raises(KnowledgeError):
        query(store, path=path)
    assert adapter.discoveries == adapter.loads == 0


def test_unknown_path_never_fetches_arbitrary_file(prepared):
    store, adapter = prepared
    result = query(store, path="unregistered.md")
    assert not result["results"] and result["warnings"]
    assert adapter.loads == 0


def test_selector_cannot_add_unregistered_entries(prepared):
    store, adapter = prepared
    adapter.candidates = lambda *args: [{"path": "private.md"}]
    result = query(store)
    assert result["remote_status"] == "failed"
    assert adapter.loads == 0
    assert result["catalog"]["last_failure"]["code"] == "unregistered_candidate"


def test_exact_missing_id_never_returns_similar_cached_record(prepared):
    store, _ = prepared
    query(store)
    assert store.research("T1059.002", freshness="offline")["results"] == []
    assert store.research("T1059", freshness="offline")["results"] == []


@pytest.mark.parametrize(
    "identifier", ["AML.T0040", "AML.T0040.001", "AML.TA0001", "AML.M0001", "AML.CS0001", "D3-NTA"]
)
def test_atlas_and_d3fend_identifiers_match_as_complete_identifiers(prepared, identifier):
    store, adapter = prepared
    adapter.text = f"# {identifier} PowerShell\n\nPowerShell evidence for this identifier.\n"
    result = store.research(identifier)
    assert result["results"][0]["freshness"] == "current"
    assert identifier in result["results"][0]["passages"][0]["text"]
    if identifier.startswith("AML.T"):
        assert store.research(identifier.removeprefix("AML."), freshness="offline")["results"] == []


def test_source_isolation_with_same_path(tmp_path):
    first_adapter, second_adapter = Adapter(), Adapter()
    second_adapter.source_id = "another"
    first = RemoteStore(tmp_path, first_adapter)
    second = RemoteStore(tmp_path, second_adapter)
    a = query(first)["results"][0]
    b = query(second)["results"][0]
    assert a["document_id"] != b["document_id"]
    assert not first.has_document(b["document_id"])
    assert first.resolve_reference(b["reference"])["state"] == "missing"
    assert first.path != second.path


def test_catalog_listing_is_bounded(prepared):
    store, adapter = prepared
    adapter.entries = [{"path": f"record/{i}.md", "title": str(i)} for i in range(201)]
    store.research("nothing", limit=1)
    public = store.catalog()
    assert public["known_paths"] == 201
    assert len(public["paths"]) == 200 and public["paths_truncated"]


def test_deadline_checked_after_adapter(prepared):
    store, adapter = prepared
    original = adapter.discover

    def late(old, deadline):
        result = original(old, deadline)
        deadline = time.monotonic() - 1
        store._deadline(deadline)
        return result

    adapter.discover = late
    result = query(store)
    assert result["remote_status"] == "failed"
    assert result["catalog"]["last_failure"]["code"] == "deadline_exceeded"
    assert adapter.loads == 0


def test_invalid_raw_or_provenance_not_persisted(prepared):
    store, adapter = prepared
    original = adapter.load

    def invalid(*args):
        return {**original(*args), "url": "file:///private"}

    adapter.load = invalid
    result = query(store)
    assert result["remote_status"] == "failed"
    assert result["catalog"]["cached_versions"] == 0


def test_reference_rejects_forged_fields(prepared):
    store, _ = prepared
    reference = query(store)["results"][0]["reference"]
    with pytest.raises(KnowledgeError):
        store.resolve_reference({**reference, "url": "https://example.org/forged"})
    assert store.resolve_reference({**reference, "original_hash": "0" * 64})["state"] == "missing"


def test_source_namespace_cannot_escape_directory(tmp_path):
    adapter = Adapter()
    adapter.source_id = "../bad"
    with pytest.raises(ValueError):
        RemoteStore(tmp_path, adapter)


def test_has_document_missing_database_does_not_create_file(prepared):
    store, _ = prepared
    store.path.unlink()
    assert not store.has_document("doc_" + "a" * 32)
    assert not store.path.exists()


def test_adapter_catalog_must_be_json_serializable_and_no_duplicate_paths(prepared):
    store, adapter = prepared
    adapter.entries *= 2
    result = query(store)
    assert result["remote_status"] == "failed"
    assert not result["results"]
    assert json.dumps(result)


def test_prepare_refreshes_dynamic_catalog_without_expiring_old_entries(prepared):
    store, adapter = prepared
    old = query(store)["results"][0]
    calls = []

    def prepare(query_text, path, catalog):
        calls.append((query_text, path))
        assert catalog["entries"][0]["path"] == "catalog/techniques.json"
        if path and not any(entry["path"] == path for entry in catalog["entries"]):
            adapter.entries = [*catalog["entries"], {"path": path, "title": "PowerShell second record"}]
            return True
        return False

    adapter.prepare = prepare
    result = query(store, path="catalog/second.json")
    assert result["results"][0]["path"] == "catalog/second.json"
    assert result["catalog"]["known_paths"] == 2
    assert adapter.discoveries == 2 and adapter.loads == 2
    assert store.resolve_reference(old["reference"])["state"] == "current"
    query(store, path="catalog/second.json", freshness="offline")
    assert len(calls) == 1


def test_prepare_input_failure_does_not_mark_source_unavailable(prepared):
    store, adapter = prepared
    old = query(store)["results"][0]

    def reject(*args):
        raise RemoteError("exact_identifier_required")

    adapter.prepare = reject
    result = query(store)
    assert result["remote_status"] == "failed"
    assert result["catalog"]["last_failure"] is None
    assert result["catalog"]["retry_at"] is None
    assert store.resolve_reference(old["reference"])["state"] == "current"
    assert adapter.discoveries == adapter.loads == 1


def test_document_404_does_not_invalidate_or_block_other_documents(prepared):
    store, adapter = prepared
    old = query(store)["results"][0]
    missing_path = "catalog/missing.json"
    adapter.entries.append({"path": missing_path, "title": "PowerShell absent record"})
    adapter.load_failure = RemoteError("http_404")
    result = query(store, freshness="refresh", path=missing_path)
    assert not result["results"]
    assert result["catalog"]["last_failure"] is None
    assert result["catalog"]["retry_at"] is None
    assert result["catalog"]["document_failures"] == 1
    assert store.resolve_reference(old["reference"])["state"] == "current"
    missing_id = "doc_" + digest(f"fixture:{missing_path}".encode())[:32]
    assert store.latest_state(missing_id, A, "0" * 64) == "unknown"
    loads = adapter.loads
    query(store, path=missing_path)
    assert adapter.loads == loads  # Negative cache is scoped to this document.
    assert query(store, path=old["path"])["results"][0]["freshness"] == "current"
    adapter.load_failure = None
    adapter.now += timedelta(seconds=61)
    assert query(store, path=missing_path)["results"][0]["freshness"] == "current"
    assert store.catalog()["document_failures"] == 0


def test_global_deadline_prevents_remote_work_and_still_returns_cache(prepared):
    store, adapter = prepared
    query(store)
    adapter.prepare = lambda *args: pytest.fail("Expired deadline must prevent prepare")
    result = query(store, freshness="refresh", deadline=time.monotonic() - 1)
    assert result["remote_status"] == "failed"
    assert result["results"][0]["freshness"] == "current"
    assert adapter.discoveries == adapter.loads == 1


def test_global_deadline_passes_unchanged_to_adapter(prepared):
    store, adapter = prepared
    deadline = time.monotonic() + 10
    seen = []
    discover, load = adapter.discover, adapter.load

    def capture_discover(old, value):
        seen.append(value)
        return discover(old, value)

    def capture_load(entry, revision, value):
        seen.append(value)
        return load(entry, revision, value)

    adapter.discover, adapter.load = capture_discover, capture_load
    query(store, deadline=deadline)
    assert seen == [deadline, deadline]


@pytest.mark.parametrize("deadline", [True, "10", float("inf"), float("nan")])
def test_invalid_deadline_rejected(prepared, deadline):
    store, adapter = prepared
    with pytest.raises(KnowledgeError):
        query(store, deadline=deadline)
    assert adapter.discoveries == adapter.loads == 0


def test_paginated_original_reuses_verified_bytes_without_loading_large_fields(prepared, monkeypatch):
    store, adapter = prepared
    adapter.raw = b"original " * 4000
    item = query(store)["results"][0]
    original_verify, original_connect = store._verify, store._connect
    checks, statements = [], []

    def verify(row):
        checks.append(row["id"])
        original_verify(row)

    def connect():
        db = original_connect()
        db.set_trace_callback(statements.append)
        return db

    monkeypatch.setattr(store, "_verify", verify)
    monkeypatch.setattr(store, "_connect", connect)
    first = store.get_document(item["document_id"], A)
    statements.clear()
    second = store.get_document(item["document_id"], A, first["next_offset"])
    assert len(checks) == 1
    assert not any("SELECT * FROM versions" in sql for sql in statements)
    assert second["integrity"]["read_from_verified_buffer"]
    assert not first["integrity"]["read_from_verified_buffer"]
    assert first["integrity"]["original_verified_at"] == second["integrity"]["original_verified_at"]
    assert base64.b64decode(second["content"]) == adapter.raw[9000:18000]
    # An immutable read already in progress remains consistent even if the DB
    # changes; starting a new read rechecks stored bytes and detects corruption.
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE versions SET raw=?", (b"corrupt",))
    continued = store.get_document(item["document_id"], A, 18000)
    assert base64.b64decode(continued["content"]) == adapter.raw[18000:27000]
    with pytest.raises(KnowledgeError, match="integridade"):
        store.get_document(item["document_id"], A)


def test_read_buffer_expiry_reverifies_original(prepared, monkeypatch):
    store, adapter = prepared
    adapter.raw = b"a" * 19000
    item = query(store)["results"][0]
    store.get_document(item["document_id"], A)
    monkeypatch.setattr(remote_cache, "READ_BUFFER_TTL", -1)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE versions SET raw=?", (b"corrupt",))
    with pytest.raises(KnowledgeError, match="integridade"):
        store.get_document(item["document_id"], A, 9000)


def test_read_buffer_budget_is_shared_and_evicts_least_recent(prepared, monkeypatch):
    store, adapter = prepared
    adapter.raw = b"a" * 19000
    monkeypatch.setattr(remote_cache, "READ_BUFFER_BYTES", 20000)
    old = query(store)["results"][0]
    store.get_document(old["document_id"], A)
    adapter.revision = B
    adapter.raw = b"b" * 19000
    new = query(store, freshness="refresh")["results"][0]
    store.get_document(new["document_id"], B)
    assert sum(len(value[0]) for value in remote_cache._READ_BUFFERS.values()) <= 20000
    reloaded = store.get_document(old["document_id"], A, 9000)
    assert not reloaded["integrity"]["read_from_verified_buffer"]
    assert base64.b64decode(reloaded["content"]) == b"a" * 9000


class PerDocumentAdapter(Adapter):
    per_document_revisions = True

    def __init__(self):
        super().__init__()
        self.records = {
            "one.json": {"revision": A, "raw": BODY},
            "two.json": {"revision": B, "raw": BODY + b"\n"},
        }
        self.requested_paths = []
        self.document_errors = {}

    def prepare(self, query_text, path, old):
        self.requested_paths = [path or "one.json"]
        known = {entry["path"] for entry in (old or {}).get("entries", [])}
        return any(path not in known for path in self.requested_paths)

    def discover(self, old, deadline):
        self.discoveries += 1
        entries = {entry["path"]: dict(entry) for entry in (old or {}).get("entries", [])}
        for path in self.requested_paths:
            if path in self.document_errors:
                error = RemoteError(self.document_errors[path])
                error.document_path = path
                raise error
            record = self.records[path]
            entries[path] = {
                "path": path,
                "title": "PowerShell " + path,
                "revision": record["revision"],
                "_checked": True,
            }
        revision = digest(json.dumps([(e["path"], e["revision"]) for e in entries.values()]).encode())
        return {"revision": revision, "entries": list(entries.values())}

    def candidates(self, query_text, catalog, limit, path):
        return [entry for entry in catalog.get("entries", []) if entry["path"] in self.requested_paths][
            :limit
        ]

    def load(self, entry, revision, deadline):
        assert revision == self.records[entry["path"]]["revision"]
        result = super().load(entry, revision, deadline)
        result["raw"] = self.records[entry["path"]]["raw"]
        return result


@pytest.fixture
def per_document(tmp_path):
    adapter = PerDocumentAdapter()
    return RemoteStore(tmp_path, adapter, clock=lambda: adapter.now), adapter


def test_querying_new_document_does_not_invalidate_or_freshen_previous_document(per_document):
    store, adapter = per_document
    one = query(store, path="one.json")["results"][0]
    adapter.now += timedelta(minutes=10)
    two = query(store, path="two.json")["results"][0]
    assert one["revision"] == A and two["revision"] == B
    assert store.source_revision() is None
    assert store.catalog()["revision_scope"] == "document"
    previous = store.resolve_reference(one["reference"])
    assert previous["state"] == "current"
    assert previous["citation"]["checked_at"] == one["checked_at"]
    assert two["checked_at"] != one["checked_at"]
    assert store.latest_state(one["document_id"], A, one["original_hash"]) == "current"
    with sqlite3.connect(store.path) as db:
        entries = json.loads(db.execute("SELECT value FROM metadata WHERE key='catalog'").fetchone()[0])[
            "entries"
        ]
    assert all("_checked" not in entry for entry in entries)


def test_updating_one_document_does_not_invalidate_second_document(per_document):
    store, adapter = per_document
    old = query(store, path="one.json")["results"][0]
    two = query(store, path="two.json")["results"][0]
    adapter.records["one.json"] = {"revision": "c" * 64, "raw": BODY + b"new version"}
    adapter.now += timedelta(minutes=1)
    new = query(store, path="one.json", freshness="refresh")["results"][0]
    assert new["revision"] == "c" * 64
    assert store.resolve_reference(old["reference"])["state"] == "superseded"
    assert store.latest_state(old["document_id"], A, old["original_hash"]) == "superseded"
    assert store.resolve_reference(two["reference"])["state"] == "current"
    assert store.resolve_reference(two["reference"])["citation"]["checked_at"] == two["checked_at"]


def test_per_document_ttl_controls_refresh_despite_recent_catalog_activity(per_document):
    store, adapter = per_document
    one = query(store, path="one.json")["results"][0]
    adapter.now += timedelta(days=2)
    two = query(store, path="two.json")["results"][0]
    assert store.resolve_reference(one["reference"])["state"] == "stale"
    current = query(store, path="one.json")["results"][0]
    assert current["freshness"] == "current"
    assert current["checked_at"] != one["checked_at"]
    assert store.resolve_reference(two["reference"])["state"] == "current"
    assert adapter.discoveries == 3 and adapter.loads == 2


def test_same_document_revision_retains_first_original_response(per_document):
    store, adapter = per_document
    old = query(store, path="one.json")["results"][0]
    adapter.records["one.json"]["raw"] = BODY + b" changed envelope timestamp"
    adapter.now += timedelta(minutes=1)
    new = query(store, path="one.json", freshness="refresh")["results"][0]
    assert new["original_hash"] == old["original_hash"]
    assert new["checked_at"] != old["checked_at"]
    assert base64.b64decode(store.get_document(old["document_id"], A)["content"]) == BODY
    assert store.catalog()["cached_versions"] == adapter.loads == 1


@pytest.mark.parametrize("error", ["http_404", "http_503", "invalid_api_record"])
def test_discovery_failure_for_one_document_preserves_other_documents(per_document, error):
    store, adapter = per_document
    one = query(store, path="one.json")["results"][0]
    two = query(store, path="two.json")["results"][0]
    adapter.document_errors["one.json"] = error
    result = query(store, path="one.json", freshness="refresh")
    assert result["remote_status"] == "failed"
    assert result["results"][0]["freshness"] == "unknown"
    assert result["catalog"]["last_failure"] is None
    assert result["catalog"]["retry_at"] is None
    assert store.latest_state(one["document_id"], A, one["original_hash"]) == "unknown"
    assert query(store, path="two.json")["results"][0]["freshness"] == "current"
    assert store.resolve_reference(two["reference"])["state"] == "current"
    discoveries = adapter.discoveries
    assert query(store, path="one.json")["remote_status"] == "cooldown"
    assert adapter.discoveries == discoveries
    adapter.now += timedelta(seconds=61)
    adapter.document_errors.clear()
    assert query(store, path="one.json")["results"][0]["freshness"] == "current"


def test_scoped_failure_for_never_loaded_document_is_unknown_not_removed(per_document):
    store, adapter = per_document
    adapter.document_errors["missing.json"] = "http_404"
    result = query(store, path="missing.json")
    assert not result["results"]
    assert result["catalog"]["last_failure"] is None
    document_id = "doc_" + digest(b"fixture:missing.json")[:32]
    assert store.latest_state(document_id, A, "0" * 64) == "unknown"
    assert not store.has_document(document_id)
    assert query(store, path="two.json")["results"][0]["freshness"] == "current"


def test_new_document_bytes_failing_load_does_not_fail_other_records(per_document):
    store, adapter = per_document
    one = query(store, path="one.json")["results"][0]
    two = query(store, path="two.json")["results"][0]
    adapter.records["one.json"]["revision"] = "d" * 64
    adapter.load_failure = RemoteError("invalid_record_bytes")
    failed = query(store, path="one.json", freshness="refresh")
    assert failed["remote_status"] == "failed"
    assert failed["catalog"]["last_failure"] is None
    assert store.resolve_reference(one["reference"])["state"] == "superseded"
    assert store.resolve_reference(two["reference"])["state"] == "current"


@pytest.mark.parametrize("revision", [None, "invalid", "a" * 39, "g" * 64, 1])
def test_document_revision_must_be_a_valid_hash(per_document, revision):
    store, adapter = per_document
    adapter.records["one.json"]["revision"] = revision
    failed = query(store, path="one.json")
    assert failed["remote_status"] == "failed"
    assert failed["catalog"]["last_failure"]["code"] == "invalid_document_revision"
    assert failed["catalog"]["cached_versions"] == 0


def test_unchecked_entry_cannot_forge_a_recent_validation_time(per_document):
    store, adapter = per_document
    old = query(store, path="one.json")["results"][0]
    original_discover = adapter.discover

    def unchecked(previous, deadline):
        result = original_discover(previous, deadline)
        result["entries"][0].pop("_checked")
        result["entries"][0]["checked_at"] = adapter.now.isoformat()
        return result

    adapter.discover = unchecked
    adapter.now += timedelta(days=2)
    result = query(store, path="one.json", freshness="refresh")["results"][0]
    assert result["freshness"] == "stale" and result["checked_at"] == old["checked_at"]


@pytest.mark.parametrize("bad_path", ["../private", "unknown.json", "https://evil.example/x"])
def test_document_error_cannot_claim_an_unregistered_unrequested_path(per_document, bad_path):
    store, adapter = per_document

    def failure(*args):
        error = RemoteError("http_404")
        error.document_path = bad_path
        raise error

    adapter.discover = failure
    result = query(store, path="one.json")
    assert result["catalog"]["document_failures"] == 0
    assert result["catalog"]["last_failure"]["code"] == "http_404"
