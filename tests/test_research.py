from __future__ import annotations

import base64
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest

from cyber_rag.models import Document, digest
from cyber_rag.ondemand import COMMIT_URL, FetchResponse, OnDemandStore
from cyber_rag.research import ResearchService
from cyber_rag.service import KnowledgeService
from cyber_rag.snapshot import ingest_documents

PATH = "cheatsheets/Password_Storage_Cheat_Sheet.md"
RAW = b"# Password Storage\n\nUse Argon2id with a unique salt to store passwords.\n"
REVISION = "a" * 40


class Remote:
    def __init__(self):
        self.revision = REVISION
        self.raw = RAW
        self.calls = []
        self.failure = False

    def __call__(self, url, **kwargs):
        self.calls.append(url)
        if self.failure:
            return FetchResponse(503)
        if url == COMMIT_URL:
            return FetchResponse(200, json.dumps({"sha": self.revision}).encode(), '"head"')
        if "/contents/" in url:
            return FetchResponse(
                200, json.dumps([{"path": PATH, "type": "file", "size": len(self.raw)}]).encode()
            )
        return FetchResponse(200, self.raw)


@pytest.fixture
def rig(tmp_path):
    service = KnowledgeService(tmp_path)
    research = ResearchService(service)
    remote = Remote()
    research.cache = OnDemandStore(tmp_path, fetcher=remote)
    service._research = research
    yield service, research, remote
    service.close()


def ask(service, **kwargs):
    return service.dispatch(
        "knowledge_research", {"query": "armazenamento de senhas password", "source_ids": ["owasp"], **kwargs}
    )


def test_empty_install_research_and_roundtrip_memory(rig):
    service, _, remote = rig
    assert service.dispatch("knowledge_status", {})["results"][0]["document_count"] == 0
    catalog = service.dispatch("knowledge_catalog", {})
    assert {"attack", "owasp", "sigma", "cve", "kev"} <= {item["source_id"] for item in catalog["results"]}
    assert not remote.calls
    response = ask(service)
    assert response["status"] == "partial"  # no snapshot is explicitly reported
    result = response["layers"]["source_cache"]["results"][0]
    assert result["revision"] == REVISION
    reference = result["evidence_reference"]
    saved = service.dispatch(
        "knowledge_remember",
        {
            "text": "Armazenamento de senhas: conferir parâmetros de Argon2id na OWASP.",
            "references": [reference],
        },
    )
    assert saved["status"] == "ok", saved
    assert saved["results"][0]["trust"] == "derived_unverified"
    count = len(remote.calls)
    offline = ask(service, freshness="offline")
    assert len(remote.calls) == count
    assert len(offline["layers"]["memory"]["results"]) == 1
    page = service.dispatch(
        "knowledge_get_cached_document", {"document_id": result["document_id"], "revision": REVISION}
    )
    assert base64.b64decode(page["results"][0]["content"]) == RAW
    forgotten = service.dispatch("knowledge_forget", {"memory_id": saved["results"][0]["memory_id"]})
    assert forgotten["results"][0]["deleted"]
    assert not ask(service, freshness="offline")["layers"]["memory"]["results"]


def test_change_invalidates_note_and_preserves_original(rig):
    service, _, remote = rig
    result = ask(service)["layers"]["source_cache"]["results"][0]
    assert (
        service.dispatch(
            "knowledge_remember",
            {"text": "Senhas password Argon2id", "references": [result["evidence_reference"]]},
        )["status"]
        == "ok"
    )
    remote.revision = "b" * 40
    remote.raw += b"\nReview new guidance.\n"
    updated = ask(service, freshness="refresh")
    assert updated["layers"]["source_cache"]["results"][0]["revision"] == remote.revision
    assert not updated["layers"]["memory"]["results"]
    assert updated["layers"]["memory"]["suppressed"]["superseded"] == 1
    old = service.dispatch(
        "knowledge_get_cached_document", {"document_id": result["document_id"], "revision": REVISION}
    )
    assert base64.b64decode(old["results"][0]["content"]) == RAW


def test_failure_keeps_bytes_and_suppresses_note(rig):
    service, _, remote = rig
    result = ask(service)["layers"]["source_cache"]["results"][0]
    service.dispatch(
        "knowledge_remember",
        {"text": "Senhas password Argon2id", "references": [result["evidence_reference"]]},
    )
    remote.failure = True
    response = ask(service, freshness="refresh")
    cache = response["layers"]["source_cache"]
    assert response["status"] == "partial" and cache["remote_status"] == "failed"
    assert cache["results"][0]["original_hash"] == digest(RAW)
    assert cache["results"][0]["freshness"] == "unknown"
    assert not response["layers"]["memory"]["results"]


def test_source_filter_does_not_call_remote(rig):
    service, _, remote = rig
    response = ask(service, source_ids=["attack"])
    assert response["layers"]["source_cache"]["remote_status"] == "not_requested"
    assert not remote.calls


def test_snapshot_duplicate_and_memory_bytes(rig):
    service, _, _ = rig
    doc = Document(
        "owasp",
        PATH,
        REVISION,
        "https://example.org/test",
        "Password Storage",
        "text/markdown",
        RAW.decode(),
        RAW,
        {"checked_at": datetime.now(UTC).isoformat()},
    )
    manifest = ingest_documents(
        service.data_dir,
        [doc],
        {"owasp": {"revision": REVISION, "checked_at": datetime.now(UTC).isoformat()}},
    )
    response = ask(service)
    assert response["layers"]["source_cache"]["results"]
    assert not response["layers"]["snapshot"]["results"]
    reference = {
        "store": "snapshot",
        "snapshot_id": manifest["snapshot_id"],
        "document_id": doc.document_id,
        "revision": REVISION,
        "original_hash": doc.original_hash,
    }
    saved = service.dispatch("knowledge_remember", {"text": "Password test", "references": [reference]})
    assert saved["status"] == "ok", saved
    (service.data_dir / "originals" / doc.original_hash).write_bytes(b"tampered")
    rejected = service.dispatch(
        "knowledge_remember", {"text": "Another password test", "references": [reference]}
    )
    assert rejected["error"]["code"] == "EVIDENCE_NOT_CURRENT"


@pytest.mark.parametrize(
    "name,args",
    [
        ("knowledge_research", {}),
        ("knowledge_remember", {"text": "x"}),
        ("knowledge_forget", {}),
        ("knowledge_get_cached_document", {}),
        ("knowledge_research", {"query": "x", "path": "../secret"}),
        ("knowledge_research", {"query": "x", "source_ids": ["unknown"]}),
        ("knowledge_research", {"query": "x", "source_ids": ["attack"], "path": PATH}),
    ],
)
def test_invalid_input_does_not_fetch(rig, name, args):
    service, _, remote = rig
    assert service.dispatch(name, args)["error"]["code"] == "INVALID_ARGUMENT"
    assert not remote.calls


def test_remote_wait_does_not_hold_snapshot_lock(rig):
    service, research, remote = rig
    entered, release = threading.Event(), threading.Event()

    def slow(url, **kwargs):
        entered.set()
        assert release.wait(5)
        return remote(url, **kwargs)

    research.cache.fetcher = slow
    with ThreadPoolExecutor(2) as pool:
        pending = pool.submit(ask, service)
        try:
            assert entered.wait(3)
            assert pool.submit(service.dispatch, "knowledge_status", {}).result(timeout=1)["status"] == "ok"
            assert ask(service)["error"]["code"] == "BUSY"
        finally:
            release.set()
        assert pending.result(timeout=3)["layers"]["source_cache"]["results"]


def test_cache_database_failure_preserves_snapshot(rig, monkeypatch):
    service, research, _ = rig
    doc = Document(
        "owasp",
        PATH,
        REVISION,
        "https://example.org/test",
        "Password Storage",
        "text/markdown",
        RAW.decode(),
        RAW,
    )
    ingest_documents(service.data_dir, [doc], {"owasp": {"revision": REVISION}})

    def broken(*args, **kwargs):
        raise sqlite3.DatabaseError("internal marker")

    monkeypatch.setattr(research.cache, "research", broken)
    monkeypatch.setattr(research.cache, "latest_state", broken)
    response = ask(service)
    assert response["status"] == "partial"
    assert response["layers"]["snapshot"]["results"][0]["document_id"] == doc.document_id
    assert "internal marker" not in json.dumps(response)


def test_non_owasp_snapshot_and_exact_reference_without_network(rig):
    service, _, remote = rig
    doc = Document(
        "attack",
        "technique.md",
        "test-version",
        "https://example.org/test",
        "Password discovery",
        "text/markdown",
        RAW.decode(),
        RAW,
        {"checked_at": datetime.now(UTC).isoformat()},
    )
    manifest = ingest_documents(
        service.data_dir,
        [doc],
        {"attack": {"revision": "test-version", "checked_at": datetime.now(UTC).isoformat()}},
    )
    response = ask(service, source_ids=["attack"])
    assert response["status"] == "ok", response
    evidence = response["layers"]["snapshot"]["results"][0]["evidence_reference"]
    assert evidence == {
        "store": "snapshot",
        "snapshot_id": manifest["snapshot_id"],
        "document_id": doc.document_id,
        "revision": "test-version",
        "original_hash": doc.original_hash,
    }
    assert not remote.calls


def test_transient_snapshot_failure_does_not_permanently_invalidate_note(rig, monkeypatch):
    service, _, _ = rig
    doc = Document(
        "attack",
        "technique.md",
        "test-version",
        "https://example.org/test",
        "Password discovery",
        "text/markdown",
        RAW.decode(),
        RAW,
        {"checked_at": datetime.now(UTC).isoformat()},
    )
    ingest_documents(
        service.data_dir,
        [doc],
        {"attack": {"revision": "test-version", "checked_at": datetime.now(UTC).isoformat()}},
    )
    reference = ask(service, source_ids=["attack"])["layers"]["snapshot"]["results"][0]["evidence_reference"]
    assert (
        service.dispatch("knowledge_remember", {"text": "Senhas password", "references": [reference]})[
            "status"
        ]
        == "ok"
    )
    import cyber_rag.research as module

    def broken(*args, **kwargs):
        raise OSError("temporary failure")

    with monkeypatch.context() as patch:
        patch.setattr(module, "connect_snapshot", broken)
        failed = ask(service, source_ids=["attack"])
        assert failed["layers"]["memory"]["suppressed"] == {"unknown": 1}
    assert ask(service, source_ids=["attack"])["layers"]["memory"]["results"]


def test_first_remote_failure_suppresses_snapshot_note(rig):
    service, _, remote = rig
    doc = Document(
        "owasp",
        PATH,
        REVISION,
        "https://example.org/test",
        "Password Storage",
        "text/markdown",
        RAW.decode(),
        RAW,
        {"checked_at": datetime.now(UTC).isoformat()},
    )
    ingest_documents(
        service.data_dir,
        [doc],
        {"owasp": {"revision": REVISION, "checked_at": datetime.now(UTC).isoformat()}},
    )
    reference = ask(service, freshness="offline")["layers"]["snapshot"]["results"][0]["evidence_reference"]
    assert (
        service.dispatch("knowledge_remember", {"text": "Senhas password", "references": [reference]})[
            "status"
        ]
        == "ok"
    )
    remote.failure = True
    response = ask(service, freshness="refresh")
    assert response["layers"]["snapshot"]["results"]
    assert not response["layers"]["memory"]["results"]
    assert response["layers"]["memory"]["suppressed"] == {"unknown": 1}
