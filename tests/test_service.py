import base64
from dataclasses import replace
from pathlib import Path

import pytest

from cyber_rag.ingestion import load_manifest
from cyber_rag.models import Document, KnowledgeError, digest
from cyber_rag.service import KnowledgeService
from cyber_rag.snapshot import ingest_documents


@pytest.fixture
def prepared(tmp_path):
    docs, sources = load_manifest(Path(__file__).parent / "fixtures" / "sources.json")
    meta = ingest_documents(tmp_path, docs, sources)
    service = KnowledgeService(tmp_path)
    yield service, docs, sources, meta
    service.close()


def test_exact_missing_is_not_substituted(prepared):
    service, _, _, _ = prepared
    for tool, key in (("knowledge_get_entity", "entity_id"), ("knowledge_search", "query")):
        result = service.dispatch(tool, {key: "cve:CVE-2099-999999"})
        assert result["status"] == "no_results" or result.get("error", {}).get("code") == "NOT_FOUND"
        assert result["results"] == []


def test_lexical_warmup_needs_no_embedding(prepared):
    service, _, _, manifest = prepared
    assert service.warmup() == {"snapshot_id": manifest["snapshot_id"], "profile": "lexical"}
    assert service._embedding is None
    assert service._vectors is None
    assert service.dispatch("knowledge_search", {"query": "PowerShell"})["results"]


def test_warmup_without_base_fails_explicitly(tmp_path):
    service = KnowledgeService(tmp_path)
    with pytest.raises(KnowledgeError):
        service.warmup()


def test_rejected_records_excluded_from_general_search_but_exact_preserved(prepared):
    service, _, _, _ = prepared
    general = service.dispatch("knowledge_search", {"query": "CVE", "limit": 20})
    assert general["status"] in {"ok", "partial"}
    assert all("cve:CVE-2099-10002" not in r["entity_ids"] for r in general["results"])
    exact = service.dispatch("knowledge_get_entity", {"entity_id": "cve:CVE-2099-10002"})
    assert exact["results"][0]["records"][0]["status"] == "REJECTED"


def test_source_filter_and_injection_are_data(prepared):
    service, _, _, _ = prepared
    result = service.dispatch(
        "knowledge_search", {"query": "PowerShell", "filters": {"source_ids": ["sigma"]}}
    )
    assert result["results"]
    assert all(r["source_id"] == "sigma" for r in result["results"])
    injected = service.dispatch("knowledge_search", {"query": "' OR 1=1; DROP TABLE entities; --"})
    assert injected["status"] in {"ok", "partial", "no_results"}
    assert service.dispatch("knowledge_get_entity", {"entity_id": "attack:T1059.001"})["status"] == "ok"


@pytest.mark.parametrize(
    "filters",
    [
        {"unknown": True},
        {"source_ids": []},
        {"kev_presence": "false"},
        {"published_from": "2026-01-01"},
        {"published_from": "2026-02-01T00:00:00Z", "published_to": "2026-01-01T00:00:00Z"},
        {"cvss": {"version": "3.1", "provider": "CNA", "value": 9, "operator": "unknown"}},
    ],
)
def test_invalid_filters_fail_explicitly(prepared, filters):
    response = prepared[0].dispatch("knowledge_search", {"query": "PowerShell", "filters": filters})
    assert response["error"]["code"] == ("UNSUPPORTED_FILTER" if "unknown" in filters else "INVALID_ARGUMENT")


def test_snapshot_pinned_cursor_and_original_byte_fidelity(tmp_path):
    raw = b"\xef\xbb\xbf# Sigma-like original\r\n" + "ação\r\n".encode() * 6000
    doc = Document(
        "sigma",
        "rule.yml",
        "r1",
        "https://example.invalid/rule",
        "Rule",
        "application/yaml",
        raw.decode("utf-8-sig"),
        raw,
    )
    sources = {"sigma": {"checked_at": "2026-01-01T00:00:00Z"}}
    original = ingest_documents(tmp_path, [doc], sources)
    service = KnowledgeService(tmp_path)
    first = service.dispatch("knowledge_get_document", {"document_id": doc.document_id})
    assert first["status"] == "partial"
    assert not first["results"][0]["complete"]
    new = ingest_documents(tmp_path, [replace(doc, raw=b"new", text="new", revision="r2")], sources)
    assert new["snapshot_id"] != original["snapshot_id"]
    buffer = base64.b64decode(first["results"][0]["content"])
    cursor = first["next_cursor"]
    while cursor:
        page = service.dispatch("knowledge_get_document", {"document_id": doc.document_id, "cursor": cursor})
        assert page["snapshot_id"] == original["snapshot_id"]
        part = page["results"][0]
        assert part["byte_start"] == len(buffer)
        assert not part["complete"]
        assert part["text"].encode("utf-8") == base64.b64decode(part["content"])
        buffer += base64.b64decode(part["content"])
        cursor = page["next_cursor"]
    assert buffer == raw and digest(buffer) == doc.original_hash
    assert (
        service.dispatch("knowledge_get_document", {"document_id": doc.document_id})["snapshot_id"]
        == new["snapshot_id"]
    )
    mismatched = service.dispatch(
        "knowledge_get_document", {"document_id": "another", "cursor": first["next_cursor"]}
    )
    assert mismatched["error"]["code"] == "INVALID_CURSOR"


def test_quarantine_or_failed_build_preserves_active_snapshot(prepared, monkeypatch):
    service, docs, sources, meta = prepared
    bad_sources = {**sources, "cve": {**sources["cve"], "quarantine": [{"reason": "bad input"}]}}
    with pytest.raises(KnowledgeError):
        ingest_documents(service.data_dir, docs, bad_sources)
    with pytest.raises(KnowledgeError):
        ingest_documents(service.data_dir, docs + [docs[0]], sources)
    status = service.dispatch("knowledge_status", {})
    assert status["snapshot_id"] == meta["snapshot_id"]
    assert status["results"][0]["last_ingestion"]["status"] == "failed"


def test_corrupt_original_is_not_returned(prepared):
    service, docs, _, _ = prepared
    doc = next(d for d in docs if d.source_id == "sigma")
    (service.data_dir / "originals" / doc.original_hash).write_bytes(b"tampered")
    result = service.dispatch("knowledge_get_document", {"document_id": doc.document_id})
    assert result["error"]["code"] == "INDEX_UNAVAILABLE"
    assert not result["results"]


def test_partial_kev_cannot_prove_absence(prepared):
    service, docs, sources, _ = prepared
    sources["kev"]["catalog_complete"] = False
    ingest_documents(service.data_dir, docs, sources)
    result = service.dispatch("knowledge_search", {"query": "CVE", "filters": {"kev_presence": False}})
    assert result["error"]["code"] == "SOURCE_UNAVAILABLE"


def test_search_budget_and_pagination(tmp_path):
    docs = [
        Document(
            "owasp",
            f"{i}.md",
            "r1",
            "https://example.invalid/source",
            f"SQL {i}",
            "text/markdown",
            "SQL parameterized query " * 160,
            b"original" + str(i).encode(),
        )
        for i in range(20)
    ]
    ingest_documents(tmp_path, docs, {"owasp": {}})
    service = KnowledgeService(tmp_path)
    seen, cursor = set(), None
    while True:
        args = {"query": "SQL", "limit": 20}
        if cursor:
            args["cursor"] = cursor
        result = service.dispatch("knowledge_search", args)
        assert sum(len(p["text"]) for r in result["results"] for p in r["passages"]) <= 24000
        for row in result["results"]:
            assert row["document_id"] not in seen
            seen.add(row["document_id"])
        cursor = result["next_cursor"]
        if not cursor:
            break
    assert len(seen) == 20


def test_document_id_cannot_read_arbitrary_file(prepared):
    result = prepared[0].dispatch("knowledge_get_document", {"document_id": "../../secret.txt"})
    assert result["error"]["code"] == "NOT_FOUND"
    assert result["results"] == []


def test_oversized_source_metadata_is_explicitly_summarized(tmp_path):
    import json

    doc = Document(
        "attack",
        "oversized.json",
        "r1",
        "https://example.invalid/source",
        "T" * 90000,
        "application/json",
        "PowerShell",
        b"original",
        metadata={"platforms": ["X" * 90000]},
        entities=[
            {
                "entity_id": "attack:T1059.001",
                "name": "N" * 90000,
                "attributes": {"large": "V" * 90000},
                "status": "current",
            }
        ],
    )
    ingest_documents(tmp_path, [doc], {"attack": {}})
    service = KnowledgeService(tmp_path)
    entity = service.dispatch("knowledge_get_entity", {"entity_id": "attack:T1059.001"})
    record = entity["results"][0]["records"][0]
    assert record["metadata_truncated"] and record["attributes_truncated"] and record["name_truncated"]
    assert len(json.dumps(entity)) < 24000
    document = service.dispatch("knowledge_get_document", {"document_id": doc.document_id})
    assert document["results"][0]["metadata_truncated"]
    assert document["results"][0]["title_truncated"]
    assert len(json.dumps(document)) < 24000


def test_non_utf8_original_makes_progress_without_fabricating_text(tmp_path):
    doc = Document(
        "owasp",
        "notice.txt",
        "r1",
        "https://example.invalid/source",
        "Notice",
        "application/octet-stream",
        "Searchable notice metadata",
        b"\xff",
    )
    ingest_documents(tmp_path, [doc], {"owasp": {}})
    response = KnowledgeService(tmp_path).dispatch("knowledge_get_document", {"document_id": doc.document_id})
    part = response["results"][0]
    assert part["text"] is None
    assert base64.b64decode(part["content"]) == b"\xff"
    assert part["complete"] and not response["next_cursor"]


def test_archive_only_update_cannot_replace_searchable_base(prepared):
    service, docs, sources, meta = prepared
    archive = replace(docs[0], text="", entities=[], metadata={"indexable": False})
    with pytest.raises(KnowledgeError):
        ingest_documents(service.data_dir, [archive], sources)
    assert service.dispatch("knowledge_status", {})["snapshot_id"] == meta["snapshot_id"]
