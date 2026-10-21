import base64
import hashlib
import json

from cyber_rag.models import digest
from cyber_rag.ondemand import FetchResponse
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.source_adapters import GithubAdapter, make_adapter
from cyber_rag.source_registry import SOURCES

REVISION = "b" * 40
PATH = "anti-analysis/anti-debugging/debugger-detection/check-for-debugger-via-api.yml"
RAW = b"rule:\n  meta:\n    name: check for debugger via API\n  features:\n    - api: kernel32.CheckRemoteDebuggerPresent\n"


def test_capa_discovery_excludes_workflows_config_and_nonrules():
    adapter = make_adapter(SOURCES["capa"])
    assert isinstance(adapter, GithubAdapter)
    assert adapter.accepts(PATH)
    assert adapter.accepts("nursery/example.yml")
    for path in [
        ".github/workflows/tests.yml",
        "tests/example.yml",
        "doc/example.yml",
        "config.yml",
        "anti-analysis/example.exe",
        "anti-analysis/example.yml.exe",
        "anti-analysis/../.github/workflows/tests.yml",
        "anti-analysis-other/example.yml",
    ]:
        assert not adapter.accepts(path), path
    assert "experimental nursery" in SOURCES["capa"].access_note


def test_capa_pinned_yaml_original_and_offline_roundtrip(tmp_path):
    calls = []
    blob = hashlib.sha1(b"blob " + str(len(RAW)).encode() + b"\x00" + RAW).hexdigest()

    def fetch(url, **kwargs):
        assert kwargs["allowed"](url)
        calls.append(url)
        if "/git/ref/" in url:
            return FetchResponse(200, json.dumps({"object": {"sha": REVISION}}).encode())
        if "/git/trees/" in url:
            rows = [
                {"path": path, "type": "blob", "mode": "100644", "size": len(RAW), "sha": blob}
                for path in [PATH, ".github/workflows/tests.yml", "doc/example.yml", "config.yml"]
            ]
            rows.append(
                {"path": "anti-analysis/link.yml", "type": "blob", "mode": "120000", "size": len(RAW), "sha": blob}
            )
            return FetchResponse(200, json.dumps({"truncated": False, "tree": rows}).encode())
        assert url == f"https://raw.githubusercontent.com/mandiant/capa-rules/{REVISION}/{PATH}"
        return FetchResponse(200, RAW)

    store = RemoteStore(tmp_path, make_adapter(SOURCES["capa"], fetcher=fetch))
    response = store.research("check for debugger via API", limit=1)
    assert response["catalog"]["known_paths"] == 1
    item = response["results"][0]
    assert item["source_id"] == "capa" and item["original_hash"] == digest(RAW)
    assert item["revision"] == REVISION
    assert item["citation"]["license_reference"] == f"https://github.com/mandiant/capa-rules/blob/{REVISION}/LICENSE.txt"
    assert len(calls) == 3
    offline = store.research("check for debugger via API", freshness="offline", limit=1)
    assert len(calls) == 3 and offline["results"][0]["original_hash"] == item["original_hash"]
    assert base64.b64decode(store.get_document(item["document_id"], REVISION)["content"]) == RAW
