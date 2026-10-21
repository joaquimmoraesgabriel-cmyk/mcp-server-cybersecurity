import base64
import csv
import io
from dataclasses import replace

import pytest

from cyber_rag import iso_metadata
from cyber_rag.ondemand import FetchResponse, RemoteError
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.source_adapters import GithubAdapter, PublicAdapter, RecordAdapter, normalize
from cyber_rag.source_registry import SOURCES


def csv_bytes(records, fields=None):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields or list(iso_metadata.FIELDS))
    writer.writeheader()
    writer.writerows(records)
    return stream.getvalue().encode("utf-8-sig")


def test_iso_only_matching_standard_and_supplement_metadata_are_indexed():
    records = [
        {"id": 1, "reference": "ISO 9001:2015", "title.en": "Excluded"},
        {"id": 2, "reference": "ISO/IEC 27001:2022", "title.en": "Information security"},
        {"id": 3, "reference": "ISO/IEC 27001:2022/Amd 1:2024", "currentStage": 6060},
        {"id": 4, "reference": "ISO/IEC 270010:2025", "title.en": "Excluded neighbor"},
    ]
    text, metadata = normalize(csv_bytes(records), "iso-metadata")
    assert "Excluded" not in text
    assert "Amd 1:2024" in text
    assert metadata["scanned_records"] == 4 and metadata["indexed_records"] == 2
    assert metadata["original_format"] == "csv"
    assert "no normative full text" in metadata["coverage"]
    assert "ODC" in metadata["attribution"]


def test_csv_bom_multiline_quotes_and_original_bytes_are_preserved(tmp_path):
    raw = csv_bytes([
        {"id": 1, "reference": "ISO/IEC 27001:2022", "scope.en": 'Information, security\n"controle" é metadado.'},
        {"id": 2, "reference": "ISO 9001:2015", "title.en": "Unrelated original data"},
    ])
    calls = []

    def fetch(url, **kwargs):
        calls.append(url)
        return FetchResponse(200, raw)

    store = RemoteStore(tmp_path, PublicAdapter(SOURCES["iso27001"], fetcher=fetch))
    result = store.research("ISO 27001")["results"][0]
    assert "Unrelated original data" not in str(result["passages"])
    original = store.get_document(result["document_id"], result["revision"])
    assert base64.b64decode(original["content"]) == raw
    assert store.research("ISO 27001", freshness="offline")["results"]
    assert len(calls) == 1


@pytest.mark.parametrize("raw", [
    b"{}", b"[]", b'{"id":1,"reference":"ISO/IEC 27001:2022"}',
    b"id,id,reference\n1,1,ISO/IEC 27001:2022\n",
    b"id,reference\n1,ISO/IEC 27001:2022,extra\n",
    b"id,reference\n1\n",
    b"id,reference\ntrue,ISO/IEC 27001:2022\n",
    b"id,reference\n1,\n",
    b"id,reference\n1,ISO/IEC 27001:2022\x00\n",
    b"id,reference\n1,ISO/IEC 27001:2022\xff\n",
    b'id,reference\n1,"ISO/IEC 27001:2022\n',
])
def test_iso_rejects_wrong_schema_and_jsonl(raw):
    with pytest.raises(RemoteError, match="invalid_iso_metadata"):
        normalize(raw, "iso-metadata")


def test_csv_does_not_substitute_neighbor_standard():
    with pytest.raises(RemoteError, match="iso_27001_metadata_missing"):
        normalize(csv_bytes([{"id": 1, "reference": "ISO/IEC 270010:2025"}]), "iso-metadata")


@pytest.mark.parametrize("bound, value", [
    ("MAX_INPUT_BYTES", 10), ("MAX_RECORDS", 1), ("MAX_ROW_CHARS", 10),
    ("MAX_FIELD_CHARS", 10), ("MAX_SELECTED_RECORDS", 1), ("MAX_TEXT_BYTES", 10),
])
def test_csv_limits_are_enforced(monkeypatch, bound, value):
    monkeypatch.setattr(iso_metadata, bound, value)
    raw = csv_bytes([
        {"id": 1, "reference": "ISO/IEC 27001:2022"},
        {"id": 2, "reference": "ISO/IEC 27001:2022/Amd 1:2024"},
    ])
    with pytest.raises(RemoteError, match="iso_metadata_limit"):
        normalize(raw, "iso-metadata")


def test_csv_rejects_oversized_field_without_altering_process_csv_limit():
    previous_limit = csv.field_size_limit()
    raw = csv_bytes([{"id": 1, "reference": "ISO/IEC 27001:2022", "scope.en": "x" * (128 * 1024 + 1)}])
    with pytest.raises(RemoteError):
        normalize(raw, "iso-metadata")
    assert csv.field_size_limit() == previous_limit


def test_iso_does_not_accept_paid_standard_or_arbitrary_blob_url():
    adapter = PublicAdapter(SOURCES["iso27001"])
    assert adapter.allowed(SOURCES["iso27001"].urls[0][1])
    assert not adapter.allowed("https://www.iso.org/standard/27001")
    assert not adapter.allowed(SOURCES["iso27001"].urls[0][1] + "?other=1")
    assert adapter.request_budget_seconds == 90


@pytest.mark.parametrize("source, adapter_cls", [("attack", GithubAdapter), ("iso27001", PublicAdapter), ("nvd", RecordAdapter)])
def test_request_budget_change_does_not_invalidate_content_fingerprint(source, adapter_cls):
    spec = SOURCES[source]
    original = adapter_cls(spec)
    updated = adapter_cls(replace(spec, request_budget_seconds=45))
    assert original.fingerprint == updated.fingerprint
    assert original.fingerprint != adapter_cls(replace(spec, license_url="https://example.org/revised-license")).fingerprint
