import base64
import hashlib
import json

from cyber_rag.models import digest
from cyber_rag.ondemand import FetchResponse
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.source_adapters import GithubAdapter, make_adapter
from cyber_rag.source_registry import SOURCES

REVISION = "a" * 40
PATH = "Techniques/API Obfuscation/description.txt"
RAW = b"API Obfuscation changes how function names appear in program analysis. This is a synthetic documentation fixture, never executable content.\n"


def test_unprotect_registers_only_technique_description_text():
    adapter = make_adapter(SOURCES["unprotect"])
    assert isinstance(adapter, GithubAdapter)
    assert adapter.accepts(PATH)
    for path in [
        "Techniques/API Obfuscation/code.cpp",
        "Techniques/API Obfuscation/info.yaml",
        "Techniques/API Obfuscation/Snippets/C___Unprotect/description.txt",
        "Techniques/API Obfuscation/rule.yar",
        "Techniques/API Obfuscation/sample.exe",
        "Techniques/API Obfuscation/not-description.txt",
        "Techniques/API Obfuscation/description.txt.exe",
        "Rules/description.txt",
        "../Techniques/API Obfuscation/description.txt",
    ]:
        assert not adapter.accepts(path), path
    assert "not complete coverage" in SOURCES["unprotect"].access_note
    assert SOURCES["unprotect"].license_url == "https://unprotect.it/page/terms-and-conditions/"


def test_unprotect_pinned_text_and_offline_roundtrip(tmp_path):
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
                for path in [
                    PATH,
                    "Techniques/API Obfuscation/code.cpp",
                    "Techniques/API Obfuscation/info.yaml",
                    "Rules/description.txt",
                ]
            ]
            rows.append(
                {
                    "path": "Techniques/Link/description.txt",
                    "type": "blob",
                    "mode": "120000",
                    "size": 10,
                    "sha": blob,
                }
            )
            return FetchResponse(200, json.dumps({"truncated": False, "tree": rows}).encode())
        assert url.endswith(f"/{REVISION}/Techniques/API%20Obfuscation/description.txt")
        return FetchResponse(200, RAW)

    store = RemoteStore(tmp_path, make_adapter(SOURCES["unprotect"], fetcher=fetch))
    response = store.research("API Obfuscation", limit=1)
    assert response["catalog"]["known_paths"] == 1
    item = response["results"][0]
    assert item["source_id"] == "unprotect" and item["original_hash"] == digest(RAW)
    assert item["revision"] == REVISION
    assert item["citation"]["license_reference"] == SOURCES["unprotect"].license_url
    assert len(calls) == 3
    offline = store.research("API Obfuscation", freshness="offline", limit=1)
    assert len(calls) == 3 and offline["results"][0]["original_hash"] == item["original_hash"]
    assert base64.b64decode(store.get_document(item["document_id"], REVISION)["content"]) == RAW
