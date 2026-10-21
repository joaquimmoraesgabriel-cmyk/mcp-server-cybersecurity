import base64
import hashlib
import io
import json
import time

import pytest

from cyber_rag.models import digest
from cyber_rag.ondemand import FetchResponse, RemoteError
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.source_adapters import GithubAdapter, make_adapter
from cyber_rag.source_registry import SOURCES

REVISION = "c" * 40
PDF_PATH = "An Alternative Method To Enumerate Processes.pdf"
TXT_PATH = "The Fake Entry Point Trick.txt"


def synthetic_pdf():
    from pypdf import PdfWriter
    from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

    writer = PdfWriter()
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"), NameObject("/BaseFont"): NameObject("/Helvetica")})
    page = writer.add_blank_page(width=300, height=300)
    page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): writer._add_object(font)})})
    contents = DecodedStreamObject()
    contents.set_data(b"BT /F1 12 Tf 10 100 Td (Research documentation: enumerate processes.) Tj ET")
    page[NameObject("/Contents")] = writer._add_object(contents)
    writer.add_attachment("excluded.txt", b"EXCLUDED_ATTACHMENT_TEXT" * 1000)
    target = io.BytesIO()
    writer.write(target)
    return target.getvalue()


def fake_fetcher(path, raw, calls):
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\x00" + raw).hexdigest()

    def fetch(url, **kwargs):
        assert kwargs["allowed"](url)
        calls.append(url)
        if "/git/ref/" in url:
            return FetchResponse(200, json.dumps({"object": {"sha": REVISION}}).encode())
        if "/git/trees/" in url:
            rows = [
                {"path": name, "type": "blob", "mode": "100644", "size": len(raw), "sha": blob}
                for name in [path, "README.md", "Hells Gate/implementation.c", "Hells Gate/unknown.pdf"]
            ]
            return FetchResponse(200, json.dumps({"truncated": False, "tree": rows}).encode())
        return FetchResponse(200, raw)

    return fetch


def test_vx_accepts_only_reviewed_papers_and_ranks_by_query():
    adapter = make_adapter(SOURCES["vx-papers"])
    assert isinstance(adapter, GithubAdapter)
    assert len(adapter.spec.paths) == 15
    assert all(adapter.accepts(path) for path in adapter.spec.paths)
    for path in ["README.md", "Hells Gate/implementation.c", "Hells Gate/unknown.pdf", "malware.exe", "../" + PDF_PATH]:
        assert not adapter.accepts(path)
    catalog = {"entries": [{"path": path, "title": path} for path in adapter.spec.paths]}
    assert adapter.candidates("enumerate processes", catalog, 1, None)[0]["path"] == PDF_PATH
    assert adapter.candidates("fake entry point", catalog, 1, None)[0]["path"] == TXT_PATH


def test_vx_pdf_derived_text_and_original_paginated_bytes(tmp_path):
    raw, calls = synthetic_pdf(), []
    store = RemoteStore(tmp_path, make_adapter(SOURCES["vx-papers"], fetcher=fake_fetcher(PDF_PATH, raw, calls)))
    response = store.research("enumerate processes", limit=1)
    assert response["catalog"]["known_paths"] == 1
    item = response["results"][0]
    assert item["source_id"] == "vx-papers" and item["original_hash"] == digest(raw)
    assert item["metadata"]["representation"] == "derived_pdf_text"
    passages = " ".join(part["text"] for part in item["passages"])
    assert "enumerate processes" in passages and "EXCLUDED_ATTACHMENT_TEXT" not in passages
    assert item["citation"]["license_reference"] == "https://github.com/vxunderground/VXUG-Papers"
    offline = store.research("enumerate processes", freshness="offline", limit=1)
    assert len(calls) == 3 and offline["results"][0]["original_hash"] == item["original_hash"]
    chunks, offset = [], 0
    while True:
        page = store.get_document(item["document_id"], REVISION, offset=offset)
        assert page["original_hash"] == digest(raw)
        chunks.append(base64.b64decode(page["content"]))
        offset = page["next_offset"]
        if offset is None:
            break
    assert len(chunks) >= 2 and b"".join(chunks) == raw


def test_vx_text_article_does_not_use_pdf_parser(tmp_path, monkeypatch):
    raw, calls = b"The Fake Entry Point Trick: a synthetic research text fixture.", []
    monkeypatch.setattr("cyber_rag.pdf_extract.extract_pdf", lambda *a, **k: pytest.fail("text used PDF parser"))
    store = RemoteStore(tmp_path, make_adapter(SOURCES["vx-papers"], fetcher=fake_fetcher(TXT_PATH, raw, calls)))
    response = store.research("fake entry point", limit=1)
    item = response["results"][0]
    assert item["original_hash"] == digest(raw)
    offline = store.research("fake entry point", freshness="offline", limit=1)
    assert len(calls) == 3 and offline["results"][0]["document_id"] == item["document_id"]
    assert base64.b64decode(store.get_document(item["document_id"], REVISION)["content"]) == raw


def test_vx_invalid_pdf_does_not_become_evidence(tmp_path):
    calls = []
    store = RemoteStore(tmp_path, make_adapter(SOURCES["vx-papers"], fetcher=fake_fetcher(PDF_PATH, b"not a PDF", calls)))
    result = store.research("enumerate processes", limit=1)
    assert not result["results"]
    assert any("pdf_invalid" in warning for warning in result["warnings"])
    assert store.catalog()["cached_versions"] == 0


def test_vx_passes_total_deadline_to_pdf_extractor(monkeypatch):
    deadline, calls = time.monotonic() + 1, []
    adapter = make_adapter(SOURCES["vx-papers"], fetcher=fake_fetcher(PDF_PATH, b"%PDF-1.7", calls))

    def expired(raw, **kwargs):
        assert kwargs["deadline"] == deadline
        raise RemoteError("deadline_exceeded")

    monkeypatch.setattr("cyber_rag.pdf_extract.extract_pdf", expired)
    with pytest.raises(RemoteError, match="deadline_exceeded"):
        adapter.load({"path": PDF_PATH, "title": PDF_PATH}, REVISION, deadline)
