import json
import time

import pytest

from cyber_rag.ondemand import FetchResponse, RemoteError
from cyber_rag.source_adapters import GithubAdapter, cve_path, normalize, valid_path
from cyber_rag.source_registry import SOURCES


def test_attack_pins_commit_and_preserves_original():
    revision = "a" * 40
    raw = json.dumps({"type": "bundle", "objects": [
        {"type": "attack-pattern", "id": "attack-pattern--example", "name": "PowerShell", "description": "Technique evidence", "external_references": [{"external_id": "T1059.001"}]},
        {"type": "attack-pattern", "name": "Old entry", "revoked": True},
    ]}).encode()
    calls = []

    def fetch(url, **kwargs):
        assert kwargs["allowed"](url)
        calls.append(url)
        if "/git/ref/" in url:
            return FetchResponse(200, json.dumps({"object": {"sha": revision}}).encode(), '"commit"')
        return FetchResponse(200, raw)

    adapter = GithubAdapter(SOURCES["attack"], fetcher=fetch)
    catalog = adapter.discover(None, time.monotonic() + 30)
    item = adapter.load(catalog["entries"][0], revision, time.monotonic() + 30)
    assert item["raw"] == raw
    assert "T1059.001 PowerShell" in item["text"]
    assert "Old entry" not in item["text"]
    assert item["metadata"]["representation"] == "derived_stix_search_text"
    assert item["metadata"]["indexed_records"] == 1
    assert f"/{revision}/" in calls[-1]


@pytest.mark.parametrize("path", ["../secret", "a/../secret", "/absolute", "a\\b", "a%2fb", "a?b", "a//b"])
def test_remote_paths_reject_ambiguity(path):
    assert not valid_path(path)


def test_attack_allowlist_is_specific():
    adapter = GithubAdapter(SOURCES["attack"])
    for url in ["http://localhost/", "https://raw.githubusercontent.com/evil/repo/" + "a" * 40 + "/x", "https://api.github.com/repos/mitre-attack/attack-stix-data/issues", "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/" + "a" * 40 + "/LICENSE.txt"]:
        assert not adapter.allowed(url)


def test_invalid_stix_fails_closed():
    with pytest.raises(RemoteError):
        normalize(b'{"objects":[]}', "stix")


def test_cve_path_and_catalog_expand_without_losing_previous_entries():
    adapter = GithubAdapter(SOURCES["cve"], fetcher=lambda *a, **k: FetchResponse(304, etag='"v1"'))
    assert cve_path("CVE-2021-44228") == "cves/2021/44xxx/CVE-2021-44228.json"
    assert cve_path("CVE-2024-1234") == "cves/2024/1xxx/CVE-2024-1234.json"
    old = {"revision": "a" * 40, "etag": '"v1"', "entries": [{"path": cve_path("CVE-2021-44228"), "title": "Log4Shell"}]}
    old["adapter_fingerprint"] = adapter.fingerprint
    assert adapter.prepare("CVE-2024-1234", None, old)
    expanded = adapter.discover(old, time.monotonic() + 30)
    assert len(expanded["entries"]) == 2
    assert adapter.candidates("CVE-2024-1234", expanded, 1, None)[0]["path"] == cve_path("CVE-2024-1234")
    assert not adapter.accepts("cves/2020/44xxx/CVE-2021-44228.json")
    assert not adapter.prepare("CVE-2021-44228", None, expanded)


def test_cve_wrong_identity_is_rejected():
    raw = json.dumps({"dataType": "CVE_RECORD", "cveMetadata": {"cveId": "CVE-2024-1234"}}).encode()
    adapter = GithubAdapter(SOURCES["cve"], fetcher=lambda *a, **k: FetchResponse(200, raw))
    with pytest.raises(RemoteError, match="cve_identity_mismatch"):
        adapter.load({"path": cve_path("CVE-2021-44228"), "title": "CVE"}, "a" * 40, time.monotonic() + 30)


def test_sigma_tree_excludes_links_and_binds_blob_hash():
    import hashlib
    raw = b"title: Encoded PowerShell\ndetection: test\n"
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    path = "rules/windows/powershell.yml"
    def fetch(url, **kwargs):
        if "/git/ref/" in url:
            return FetchResponse(200, json.dumps({"object": {"sha": "b" * 40}}).encode())
        if "/git/trees/" in url:
            return FetchResponse(200, json.dumps({"truncated": False, "tree": [
                {"type": "blob", "mode": "100644", "size": len(raw), "sha": blob, "path": path},
                {"type": "blob", "mode": "120000", "size": 10, "sha": blob, "path": "rules/link.yml"},
            ]}).encode())
        return FetchResponse(200, raw)
    adapter = GithubAdapter(SOURCES["sigma"], fetcher=fetch)
    catalog = adapter.discover(None, time.monotonic() + 30)
    assert len(catalog["entries"]) == 1
    assert adapter.load(catalog["entries"][0], catalog["revision"], time.monotonic() + 30)["raw"] == raw
    with pytest.raises(RemoteError, match="git_blob_mismatch"):
        adapter.load({**catalog["entries"][0], "blob_sha": "0" * 40}, catalog["revision"], time.monotonic() + 30)


@pytest.mark.parametrize("payload", [None, [], {}, {"object": None}, {"object": {}}, {"object": {"sha": 1}}])
def test_malformed_github_head_is_controlled(payload):
    adapter = GithubAdapter(SOURCES["attack"], fetcher=lambda *a, **k: FetchResponse(200, json.dumps(payload).encode()))
    with pytest.raises(RemoteError):
        adapter.discover(None, time.monotonic() + 30)


@pytest.mark.parametrize("kind,payload", [("kev", []), ("kev", {"count": 1, "vulnerabilities": [{}]}), ("cve", {"dataType": "CVE_RECORD", "cveMetadata": None}), ("stix", {"type": "bundle", "objects": [{"type": "attack-pattern", "external_references": None}]})])
def test_malformed_source_payload_is_controlled(kind, payload):
    with pytest.raises(RemoteError):
        normalize(json.dumps(payload).encode(), kind)


def test_failed_discovery_has_no_candidates():
    assert GithubAdapter(SOURCES["sigma"]).candidates("powershell", {}, 1, None) == []


def test_sql_original_words_outrank_nosql_camelcase_fragment():
    adapter = GithubAdapter(SOURCES["payloads"])
    paths = ["NoSQL Injection/README.md", "SQL Injection/README.md", "SQL Injection/BigQuery Injection.md"]
    catalog = {"entries": [{"path": path, "title": path} for path in paths]}
    chosen = adapter.candidates("sql injection", catalog, 1, None)
    assert chosen[0]["path"] == "SQL Injection/BigQuery Injection.md"
    assert adapter.candidates("nosql injection", catalog, 1, None)[0]["path"] == "NoSQL Injection/README.md"


@pytest.mark.parametrize("query,path", [
    ("powershell", "rules/windows/PowerShell_EncodedCommand.yml"),
    ("power shell", "rules/windows/PowerShell_EncodedCommand.yml"),
    ("wannacry", "malware/Ransomware_WannaCry.yar"),
    ("wanna cry", "malware/Ransomware_WannaCry.yar"),
])
def test_original_and_camelcase_name_matching_remain_available(query, path):
    adapter = GithubAdapter(SOURCES["sigma"])
    catalog = {"entries": [{"path": path, "title": path}, {"path": "unrelated/item.yml", "title": "Other"}]}
    assert adapter.candidates(query, catalog, 1, None)[0]["path"] == path


def test_atlas_does_not_index_symlink_text():
    with pytest.raises(RemoteError, match="invalid_atlas_document"):
        normalize(b"v6/ATLAS-latest.yaml", "atlas")


def test_legacy_catalog_is_rediscovered_even_when_head_unchanged():
    calls = []
    def fetch(url, **kwargs):
        calls.append((url, kwargs.get("etag")))
        if "/git/ref/" in url:
            return FetchResponse(200, json.dumps({"object": {"sha": "b" * 40}}).encode())
        return FetchResponse(200, json.dumps({"truncated": False, "tree": [
            {"type": "blob", "mode": "100644", "size": 20, "sha": "c" * 40,
             "path": "rules/windows/real.yml"},
        ]}).encode())
    adapter = GithubAdapter(SOURCES["sigma"], fetcher=fetch)
    old = {"revision": "b" * 40, "etag": "legacy", "entries": [
        {"path": "rules/removed.yml", "title": "Old adapter selection"},
    ]}
    current = adapter.discover(old, time.monotonic() + 30)
    assert calls[0][1] is None
    assert len(calls) == 2
    assert current["entries"][0]["path"] == "rules/windows/real.yml"
