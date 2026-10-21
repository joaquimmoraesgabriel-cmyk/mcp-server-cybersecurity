import base64
import json

import pytest

from cyber_rag.models import digest
from cyber_rag.ondemand import FetchResponse
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.source_adapters import GithubAdapter, make_adapter
from cyber_rag.source_registry import SOURCES

REVISION = "d" * 40
NIST_CASES = [
    ("nist-csf", "GV.OC", "Organizational Context"),
    ("nist-800-53", "ac-2", "Account Management"),
]


@pytest.mark.parametrize("source_id,identifier,title", NIST_CASES)
def test_nist_catalog_scope_and_pinned_offline_original(tmp_path, source_id, identifier, title):
    spec = SOURCES[source_id]
    path = spec.paths[0]
    raw = json.dumps({"catalog": {
        "metadata": {"title": spec.title, "version": "test"},
        "groups": [{"id": identifier, "title": title}],
    }}, ensure_ascii=False).encode()
    calls = []

    def fetch(url, **kwargs):
        assert kwargs["allowed"](url)
        calls.append(url)
        if "/git/ref/" in url:
            return FetchResponse(200, json.dumps({"object": {"sha": REVISION}}).encode())
        assert url == f"https://raw.githubusercontent.com/usnistgov/oscal-content/{REVISION}/{path}"
        return FetchResponse(200, raw)

    adapter = make_adapter(spec, fetcher=fetch)
    assert isinstance(adapter, GithubAdapter)
    assert adapter.accepts(path)
    for rejected in ["README.md", "LICENSE.md", path.replace(".json", ".xml"), "other.json", "../" + path]:
        assert not adapter.accepts(rejected), rejected
    store = RemoteStore(tmp_path, adapter)
    response = store.research(spec.sample_query, limit=1)
    assert response["catalog"]["known_paths"] == 1
    item = response["results"][0]
    assert item["original_hash"] == digest(raw) and item["source_id"] == source_id
    assert item["metadata"]["representation"] == "derived_json_text"
    assert item["citation"]["license_reference"] == f"https://github.com/usnistgov/oscal-content/blob/{REVISION}/LICENSE.md"
    assert len(calls) == 2
    offline = store.research(spec.sample_query, freshness="offline", limit=1)
    assert len(calls) == 2 and offline["results"][0]["original_hash"] == item["original_hash"]
    assert base64.b64decode(store.get_document(item["document_id"], REVISION)["content"]) == raw
