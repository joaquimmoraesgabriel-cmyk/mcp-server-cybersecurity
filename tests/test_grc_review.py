"""Offline checks for final GRC identity and configuration regressions."""

import json
from dataclasses import replace

import pytest

from cyber_rag.ondemand import FetchResponse, RemoteError
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.source_adapters import RecordAdapter, normalize
from cyber_rag.source_registry import SOURCES


def test_record_configuration_change_revalidates_every_requested_entry(tmp_path):
    calls = []

    def fetch(url, **kwargs):
        identifier = url.rsplit("=", 1)[-1]
        calls.append(identifier)
        raw = json.dumps(
            {
                "vulnerabilities": [
                    {"cve": {"id": identifier, "descriptions": [{"value": "Password evidence"}]}}
                ]
            }
        ).encode()
        return FetchResponse(200, raw)

    spec = replace(SOURCES["nvd"], min_interval_seconds=0, ttl_seconds=86400)
    original = RemoteStore(tmp_path, RecordAdapter(spec, fetcher=fetch))
    original.research("CVE-2024-1234")
    old_b = original.research("CVE-2024-5678")["results"][0]
    updated = RemoteStore(
        tmp_path,
        RecordAdapter(replace(spec, license_url="https://fixture.example/revised-license"), fetcher=fetch),
    )
    assert updated.research("CVE-2024-1234")["results"][0]["freshness"] == "current"
    result = updated.research("CVE-2024-5678")
    assert result["remote_status"] != "failed", result["warnings"]
    assert result["results"][0]["freshness"] == "current"
    assert result["results"][0]["revision"] != old_b["revision"]
    assert calls == ["CVE-2024-1234", "CVE-2024-5678", "CVE-2024-1234", "CVE-2024-5678"]


@pytest.mark.parametrize(
    "kind, content",
    [
        (
            "gdpr",
            "Regulation (EU) 2016/679. This incomplete archive lists Article 10 and Article 990 only; the original regulation is unavailable.",
        ),
        (
            "lgpd",
            "Lei 13.709. Esta página de arquivo menciona dados pessoais e Art. 100, mas não contém o texto da legislação solicitada.",
        ),
    ],
)
def test_legal_document_identity_does_not_accept_different_article_number_prefix(kind, content):
    raw = ("<html><meta charset='utf-8'><body><p>" + content + "</p></body></html>").encode()
    with pytest.raises(RemoteError, match="invalid_.*_document"):
        normalize(raw, kind)


@pytest.mark.parametrize("identifier", [0, 19, 99, -1, "01", "1/../../other"])
def test_cis_control_url_cannot_expand_outside_explicit_number_range(identifier):
    adapter = RecordAdapter(SOURCES["cis-controls"])
    with pytest.raises(RemoteError, match="invalid_record_path"):
        adapter.url(f"control-{identifier}.html")
    assert not adapter.allowed(SOURCES["cis-controls"].url_template.format(id=identifier))


def test_iso_metadata_selection_preserves_only_27001_derivative():
    raw = (b"id,reference,title.en\n"
           b"1,ISO/IEC 27001:2022,Information security systems\n"
           b"2,ISO/IEC 27002:2022,Not requested\n"
           b"3,ISO/IEC 27001:2022/Amd 1:2024,Amendment metadata\n")
    text, metadata = normalize(raw, "iso-metadata")
    assert "27002" not in text and "Not requested" not in text
    assert metadata["indexed_records"] == 2 and metadata["scanned_records"] == 3
    assert "no normative full text" in metadata["coverage"]


@pytest.mark.parametrize(
    "record", [[], {"id": True, "reference": "ISO/IEC 27001:2022"}, {"id": 1, "reference": None}]
)
def test_iso_metadata_schema_failure_is_controlled(record):
    with pytest.raises(RemoteError, match="invalid_iso_metadata"):
        normalize(json.dumps(record).encode(), "iso-metadata")
