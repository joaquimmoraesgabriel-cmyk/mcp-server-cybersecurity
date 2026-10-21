import sqlite3
from datetime import UTC, datetime

import pytest

from cyber_rag import memory
from cyber_rag.memory import MemoryStore
from cyber_rag.models import KnowledgeError

REFERENCE = {"store": "cache", "document_id": "doc_password", "revision": "a" * 40, "original_hash": "b" * 64}


class Clock:
    def __init__(self):
        self.value = 1_800_000_000.0

    def __call__(self):
        return self.value


class Resolver:
    def __init__(self):
        self.state = "current"
        self.calls = []

    def __call__(self, reference):
        self.calls.append(reference)
        return {
            "state": self.state,
            "citation": {
                "source_id": "owasp",
                "url": "https://github.com/OWASP/CheatSheetSeries",
                "revision": reference["revision"],
                "original_hash": reference["original_hash"],
            },
        }


@pytest.fixture
def store(tmp_path):
    clock = Clock()
    return MemoryStore(tmp_path, clock=clock), clock, Resolver()


def save(store, resolver, text="Argon2id password storage requires a unique salt.", **kwargs):
    return store.remember(text, [REFERENCE], resolve_reference=resolver, **kwargs)


def test_memory_is_derived_and_provenance_is_resolved(store):
    notes, _, resolver = store
    saved = save(notes, resolver)
    assert saved["result"]["trust"] == "derived_unverified"
    assert saved["result"]["citations"][0]["url"].startswith("https://github.com/")
    assert resolver.calls == [REFERENCE]
    result = notes.search("Argon2id", resolve_reference=resolver)
    assert result["results"][0]["memory_id"] == saved["result"]["memory_id"]
    assert result["results"][0]["evidence_state"] == "current"
    assert result["warnings"]


@pytest.mark.parametrize(
    "reference",
    [
        {},
        {**REFERENCE, "url": "https://attacker.invalid"},
        {**REFERENCE, "store": "memory"},
        {**REFERENCE, "original_hash": "invalid"},
        {**REFERENCE, "snapshot_id": "fake"},
        {**REFERENCE, "store": "snapshot"},
        {key: value for key, value in REFERENCE.items() if key != "revision"},
    ],
)
def test_rejects_forged_reference_shape_before_resolution(store, reference):
    notes, _, resolver = store
    with pytest.raises(KnowledgeError, match="."):
        notes.remember("Claim", [reference], resolve_reference=resolver)
    assert not resolver.calls


@pytest.mark.parametrize("state", ["stale", "superseded", "missing", "unknown"])
def test_rejects_note_without_current_evidence(store, state):
    notes, _, resolver = store
    resolver.state = state
    with pytest.raises(KnowledgeError) as exc:
        save(notes, resolver)
    assert exc.value.code == "EVIDENCE_NOT_CURRENT"
    assert notes.status()["notes"] == 0


def test_snapshot_reference_is_required_and_preserved(store):
    notes, _, resolver = store
    ref = {**REFERENCE, "store": "snapshot", "snapshot_id": "snapshot-one"}
    saved = notes.remember("Claim", [ref], resolve_reference=resolver)
    assert saved["result"]["references"] == [ref]


def test_deduplication_does_not_extend_expiry_and_is_order_independent(store):
    notes, clock, resolver = store
    second = {**REFERENCE, "document_id": "doc_other"}
    first = notes.remember("Same claim", [REFERENCE, second], resolve_reference=resolver, ttl_days=1)
    clock.value += 3600
    again = notes.remember("Same claim", [second, REFERENCE, second], resolve_reference=resolver, ttl_days=90)
    assert again["deduplicated"]
    assert first["result"]["memory_id"] == again["result"]["memory_id"]
    assert first["result"]["expires_at"] == again["result"]["expires_at"]
    assert notes.status()["notes"] == 1


@pytest.mark.parametrize("state", ["superseded", "missing"])
def test_invalidation_is_permanent_even_if_resolver_later_reverts(store, state):
    notes, _, resolver = store
    save(notes, resolver)
    resolver.state = state
    result = notes.search("password", resolve_reference=resolver)
    assert not result["results"]
    assert result["suppressed"] == {state: 1}
    resolver.state = "current"
    assert not notes.search("password", resolve_reference=resolver)["results"]
    with pytest.raises(KnowledgeError) as exc:
        save(notes, resolver)
    assert exc.value.code == "MEMORY_INVALIDATED"
    assert notes.status()["invalidated_notes"] == 1


def test_stale_and_unknown_are_suppressed_and_can_revalidate(store):
    notes, _, resolver = store
    save(notes, resolver)
    for state in ("stale", "unknown"):
        resolver.state = state
        assert not notes.search("salt", resolve_reference=resolver)["results"]
    resolver.state = "current"
    assert notes.search("salt", resolve_reference=resolver)["results"]


def test_resolver_failures_never_produce_current_notes(store):
    notes, _, resolver = store
    save(notes, resolver)

    def unavailable(_):
        raise OSError("offline")

    result = notes.search("password", resolve_reference=unavailable)
    assert result["suppressed"] == {"unknown": 1}
    for invalid in ({}, {"state": "current"}, {"state": "bogus", "citation": {}}, {"state": []}):
        with pytest.raises(KnowledgeError):
            save(notes, lambda _, value=invalid: value)


def test_forget_removes_text_and_fts_and_is_idempotent(store):
    notes, _, resolver = store
    saved = save(notes, resolver)
    assert notes.forget(saved["result"]["memory_id"])["deleted"]
    assert not notes.forget(saved["result"]["memory_id"])["deleted"]
    assert not notes.search("password", resolve_reference=resolver)["results"]
    with sqlite3.connect(notes.path) as db:
        assert db.execute("SELECT count(*) FROM notes").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM notes_fts").fetchone()[0] == 0
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "delete"


def test_expiry_removes_database_and_index_rows(store):
    notes, clock, resolver = store
    save(notes, resolver, ttl_days=1)
    clock.value += 86400
    result = notes.search("password", resolve_reference=resolver)
    assert result["expired_removed"] == 1
    assert not result["results"]
    assert notes.status()["notes"] == 0
    with sqlite3.connect(notes.path) as db:
        assert db.execute("SELECT count(*) FROM notes_fts").fetchone()[0] == 0


def test_clock_rollback_never_revives_or_validates_future_note(store):
    notes, clock, resolver = store
    save(notes, resolver)
    clock.value -= 60
    assert notes.search("password", resolve_reference=resolver)["suppressed"] == {"clock_rollback": 1}
    with pytest.raises(KnowledgeError):
        save(notes, resolver)


def test_quota_and_expiry_recovery(store, monkeypatch):
    notes, clock, resolver = store
    monkeypatch.setattr(memory, "MAX_NOTES", 1)
    save(notes, resolver, ttl_days=1)
    with pytest.raises(KnowledgeError) as exc:
        save(notes, resolver, text="A different note")
    assert exc.value.code == "MEMORY_CAPACITY"
    clock.value += 86400
    assert save(notes, resolver, text="New note")["status"] == "ok"


def test_text_byte_quota_uses_utf8_bytes(store, monkeypatch):
    notes, _, resolver = store
    monkeypatch.setattr(memory, "MAX_TEXT_BYTES", 5)
    with pytest.raises(KnowledgeError):
        save(notes, resolver, text="ééé")
    assert notes.status()["notes"] == 0


def test_search_escapes_fts_operators_and_limits_text(store):
    notes, _, resolver = store
    save(notes, resolver, text="Argon2id " + "long text " * 300)
    result = notes.search('"Argon2id" OR * : () NOT nope', resolve_reference=resolver)
    assert result["results"]
    assert len(result["results"][0]["text"]) == 1200
    assert result["results"][0]["text_truncated"]
    assert not notes.search('" * : ()', resolve_reference=resolver)["results"]


@pytest.mark.parametrize("ttl", [0, 91, True, 1.5, "30"])
def test_invalid_ttl(store, ttl):
    notes, _, resolver = store
    with pytest.raises(KnowledgeError):
        save(notes, resolver, ttl_days=ttl)


def test_input_limits(store):
    notes, _, resolver = store
    for text in (None, "", "x" * 4001, "a\x00b"):
        with pytest.raises(KnowledgeError):
            save(notes, resolver, text=text)
    for refs in ([], [REFERENCE] * 9, {}, None):
        with pytest.raises(KnowledgeError):
            notes.remember("Claim", refs, resolve_reference=resolver)
    for limit in (0, 11, True, 2.5):
        with pytest.raises(KnowledgeError):
            notes.search("query", resolve_reference=resolver, limit=limit)
    with pytest.raises(KnowledgeError):
        notes.forget("../../other")


def test_aware_datetime_clock_is_supported(tmp_path):
    notes = MemoryStore(tmp_path, clock=lambda: datetime(2026, 10, 21, tzinfo=UTC))
    assert save(notes, Resolver())["result"]["created_at"] == "2026-10-21T00:00:00Z"


def test_source_filter_requires_every_reference_before_limiting(store):
    notes, _, resolver = store
    other_ref = {**REFERENCE, "document_id": "doc_mitre"}

    def mixed(reference):
        result = resolver(reference)
        if reference["document_id"] == "doc_mitre":
            result["citation"]["source_id"] = "attack"
        return result

    notes.remember("password mixed claim", [REFERENCE, other_ref], resolve_reference=mixed)
    saved = save(notes, mixed)
    result = notes.search("password", resolve_reference=mixed, limit=1, source_ids=["owasp"])
    assert len(result["results"]) == 1
    assert result["results"][0]["memory_id"] == saved["result"]["memory_id"]
    assert not notes.search("password", resolve_reference=mixed, source_ids=["cve"])["results"]


def test_rejects_nonstring_store_and_source_filter(store):
    notes, _, resolver = store
    for invalid in ([], {}, 1):
        with pytest.raises(KnowledgeError):
            notes.remember("Claim", [{**REFERENCE, "store": invalid}], resolve_reference=resolver)
    for invalid in ([], "owasp", [None]):
        with pytest.raises(KnowledgeError):
            notes.search("Claim", resolve_reference=resolver, source_ids=invalid)


def test_status_never_creates_or_prunes_memory(store):
    notes, clock, resolver = store
    assert notes.status()["notes"] == 0
    assert not notes.path.exists()
    save(notes, resolver, ttl_days=1)
    before = notes.path.read_bytes()
    clock.value += 86400
    state = notes.status()
    assert state["notes"] == 0
    assert state["expired_pending"] == 1
    assert state["stored_text_bytes"] > 0
    assert notes.path.read_bytes() == before
    assert notes.search("password", resolve_reference=resolver)["expired_removed"] == 1
    assert notes.status()["expired_pending"] == 0
