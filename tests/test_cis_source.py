import pytest

from cyber_rag.ondemand import FetchResponse, RemoteError
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.source_adapters import RecordAdapter
from cyber_rag.source_registry import SOURCES


def test_cis_ids_are_bounded_and_url_is_exact(tmp_path):
    adapter = RecordAdapter(SOURCES["cis-controls"])
    assert adapter.select_paths("Control 1 inventory e controle 18", None) == ["control-1.html", "control-18.html"]
    assert adapter.allowed("https://cas.docs.cisecurity.org/en/latest/source/Controls1/")
    for value in ["0", "19", "01", "../1", "1?x=1", "%31"]:
        assert not adapter.allowed(f"https://cas.docs.cisecurity.org/en/latest/source/Controls{value}/")
        with pytest.raises(RemoteError):
            adapter.url(f"control-{value}.html")
    assert not adapter.select_paths("control 19", None)


def test_cis_html_cache_and_provenance(tmp_path):
    raw = b"<html><body><h1>Control 1 Inventory</h1><p>" + b"Enterprise assets inventory evidence. " * 5 + b"</p></body></html>"
    calls = []
    def fetch(url, **kwargs):
        assert kwargs["allowed"](url)
        calls.append(url)
        return FetchResponse(200, raw)
    store = RemoteStore(tmp_path, RecordAdapter(SOURCES["cis-controls"], fetcher=fetch))
    first = store.research("Control 1 inventory")["results"][0]
    offline = store.research("Control 1 inventory", freshness="offline")["results"][0]
    assert first["original_hash"] == offline["original_hash"]
    assert first["citation"]["license_reference"].endswith("terms-of-use/")
    assert len(calls) == 1
