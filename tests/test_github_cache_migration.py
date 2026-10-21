import hashlib
import json
import sqlite3
import time
from contextlib import closing
from dataclasses import replace

import pytest

from cyber_rag.models import KnowledgeError, digest
from cyber_rag.ondemand import FetchResponse
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.source_adapters import GithubAdapter, PublicAdapter
from cyber_rag.source_registry import SOURCES, SourceSpec

REVISION = "a" * 40
PATH = "catalog.json"
RAW = b'{"title":"Password guidance","description":"Use unique salts"}'
SPEC = SourceSpec("migration", "Migration fixture", "fixture/repo", "main", (PATH,), ("password",))


def fetcher(calls, *, tree=False, blob=None):
    def fetch(url, **kwargs):
        assert kwargs["allowed"](url)
        calls.append(url)
        if "/git/ref/" in url:
            return FetchResponse(200, json.dumps({"object": {"sha": REVISION}}).encode())
        if tree and "/git/trees/" in url:
            return FetchResponse(200, json.dumps({"truncated": False, "tree": [{
                "path": PATH, "type": "blob", "mode": "100644", "size": len(RAW),
                "sha": blob or hashlib.sha1(b"blob " + str(len(RAW)).encode() + b"\x00" + RAW).hexdigest(),
            }]}).encode())
        return FetchResponse(200, RAW)

    return fetch


def test_missing_fingerprint_reprocesses_local_original_and_updates_fts(tmp_path):
    calls = []
    old = RemoteStore(tmp_path, GithubAdapter(SPEC, fetcher=fetcher(calls)))
    first = old.research("Password")["results"][0]
    with closing(sqlite3.connect(old.path)) as db:
        catalog = json.loads(db.execute("SELECT value FROM metadata WHERE key='catalog'").fetchone()[0])
        catalog.pop("adapter_fingerprint")
        db.execute("UPDATE metadata SET value=? WHERE key='catalog'", (json.dumps(catalog),))
        legacy_text = "Password LEGACY_ONLY_TOKEN"
        db.execute("UPDATE versions SET metadata='{}',text=?,text_hash=?", (legacy_text, digest(legacy_text.encode())))
        db.execute("UPDATE evidence_fts SET text=?", (legacy_text,))
        db.commit()
    calls.clear()
    updated_spec = replace(SPEC, format="json", license_path="LICENSE.new")
    updated = RemoteStore(tmp_path, GithubAdapter(updated_spec, fetcher=fetcher(calls)))
    item = updated.research("Password")["results"][0]
    assert len(calls) == 1 and "/git/ref/" in calls[0]
    assert item["evidence_reference"] == first["evidence_reference"]
    assert item["metadata"]["representation"] == "derived_json_text"
    assert item["metadata"]["adapter_fingerprint"] == updated.adapter.fingerprint
    assert item["license_reference"].endswith("/LICENSE.new") and item["freshness"] == "current"
    assert updated.catalog()["cached_versions"] == 1
    with closing(sqlite3.connect(updated.path)) as db:
        assert db.execute("SELECT count(*) FROM evidence_fts WHERE evidence_fts MATCH 'LEGACY_ONLY_TOKEN'").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM evidence_fts WHERE evidence_fts MATCH 'salts'").fetchone()[0] == 1
        assert db.execute("SELECT raw FROM versions").fetchone()[0] == RAW


def test_changed_fingerprint_and_license_reuse_immutable_bytes(tmp_path):
    original = RemoteStore(tmp_path, GithubAdapter(SPEC, fetcher=fetcher([])))
    original.research("Password")
    calls = []
    updated = RemoteStore(tmp_path, GithubAdapter(
        replace(SPEC, license_url="https://example.org/new-license", format="json"), fetcher=fetcher(calls)
    ))
    result = updated.research("Password")["results"][0]
    assert len(calls) == 1 and "/git/ref/" in calls[0]
    assert result["license_reference"] == "https://example.org/new-license"
    assert result["original_hash"] == digest(RAW)


@pytest.mark.parametrize("url", [
    f"https://github.com/other/repo/blob/{REVISION}/{PATH}",
    f"https://github.com/fixture/repo/blob/main/{PATH}",
    f"https://github.com/fixture/repo/blob/{'b' * 40}/{PATH}",
    f"https://github.com/fixture/repo/blob/{REVISION}/other.json",
    f"https://github.com/fixture/repo/blob/{REVISION}/{PATH}?raw=1",
])
def test_nonmatching_or_mutable_url_requires_fetch(tmp_path, url):
    original = RemoteStore(tmp_path, GithubAdapter(SPEC, fetcher=fetcher([])))
    original.research("Password")
    with closing(sqlite3.connect(original.path)) as db:
        db.execute("UPDATE versions SET url=?", (url,))
        db.commit()
    calls = []
    updated = RemoteStore(tmp_path, GithubAdapter(replace(SPEC, format="json"), fetcher=fetcher(calls)))
    item = updated.research("Password")["results"][0]
    assert len(calls) == 2 and "raw.githubusercontent.com/fixture/repo/" in calls[-1]
    assert item["url"] == f"https://github.com/fixture/repo/blob/{REVISION}/{PATH}"


def test_changed_repository_requires_fetch(tmp_path):
    original = RemoteStore(tmp_path, GithubAdapter(SPEC, fetcher=fetcher([])))
    original.research("Password")
    calls = []
    updated = RemoteStore(tmp_path, GithubAdapter(replace(SPEC, repository="fixture/new-repo"), fetcher=fetcher(calls)))
    item = updated.research("Password")["results"][0]
    assert len(calls) == 2 and "/fixture/new-repo/" in calls[-1]
    assert item["url"].startswith("https://github.com/fixture/new-repo/blob/")


@pytest.mark.parametrize("column,value", [
    ("raw", RAW + b"modified"),
    ("text", "modified projection"),
    ("original_hash", "0" * 64),
    ("text_hash", "0" * 64),
])
def test_corrupt_bytes_or_hashes_fail_before_reprocessing(tmp_path, column, value):
    original = RemoteStore(tmp_path, GithubAdapter(SPEC, fetcher=fetcher([])))
    original.research("Password")
    with closing(sqlite3.connect(original.path)) as db:
        db.execute(f"UPDATE versions SET {column}=?", (value,))
        db.commit()
    calls = []
    updated = RemoteStore(tmp_path, GithubAdapter(replace(SPEC, format="json"), fetcher=fetcher(calls)))
    with pytest.raises(KnowledgeError) as caught:
        updated.research("Password")
    assert caught.value.code == "CACHE_INTEGRITY"
    assert len(calls) == 1 and "/git/ref/" in calls[0]


def test_reprocessing_checks_current_tree_blob_sha(tmp_path):
    tree_spec = replace(SPEC, discovery="tree", paths=(), prefixes=("",), suffixes=(".json",))
    original = RemoteStore(tmp_path, GithubAdapter(tree_spec, fetcher=fetcher([], tree=True)))
    first = original.research("Password", path=PATH)["results"][0]
    calls = []
    updated = RemoteStore(tmp_path, GithubAdapter(
        replace(tree_spec, format="json"), fetcher=fetcher(calls, tree=True, blob="0" * 40)
    ))
    failed = updated.research("Password", path=PATH)
    assert failed["remote_status"] == "failed"
    assert any("git_blob_mismatch" in warning for warning in failed["warnings"])
    assert len(calls) == 2 and all("raw.githubusercontent.com" not in url for url in calls)
    assert failed["results"][0]["original_hash"] == first["original_hash"]
    assert failed["results"][0]["freshness"] == "unknown"


@pytest.mark.parametrize("changed", [{"path": "other.json"}, {"revision": "b" * 40}])
def test_cached_path_and_revision_must_match(changed):
    adapter = GithubAdapter(SPEC)
    cached = {"path": PATH, "revision": REVISION, "raw": RAW, "original_hash": digest(RAW),
              "url": f"https://github.com/fixture/repo/blob/{REVISION}/{PATH}", **changed}
    assert adapter.load_cached({"path": PATH, "title": "title"}, REVISION, cached, time.monotonic() + 5) is None


def test_mutable_http_source_still_revalidates_bytes(tmp_path):
    url = "https://example.org/current.json"
    spec = replace(SPEC, repository="", branch="", discovery="public", urls=((PATH, url),), license_url=url)
    original = RemoteStore(tmp_path, PublicAdapter(spec, fetcher=lambda *a, **k: FetchResponse(200, RAW)))
    original.research("Password")
    calls = []

    def fetch(url, **kwargs):
        calls.append(url)
        return FetchResponse(200, RAW)

    updated = RemoteStore(tmp_path, PublicAdapter(replace(spec, format="json"), fetcher=fetch))
    assert updated.research("Password")["results"]
    assert calls == [url]


def test_sql_candidate_migrates_existing_bigquery_without_loading_nosql(tmp_path):
    path = "SQL Injection/BigQuery Injection.md"
    raw = b"# BigQuery SQL Injection\n\nSQL injection documentation for BigQuery.\n"
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\x00" + raw).hexdigest()
    calls = []

    def fetch(url, **kwargs):
        assert kwargs["allowed"](url)
        calls.append(url)
        if "/git/ref/" in url:
            return FetchResponse(200, json.dumps({"object": {"sha": REVISION}}).encode())
        if "/git/trees/" in url:
            entries = [{"path": name, "type": "blob", "mode": "100644", "size": len(raw), "sha": blob}
                       for name in ["NoSQL Injection/README.md", "SQL Injection/README.md", path]]
            return FetchResponse(200, json.dumps({"truncated": False, "tree": entries}).encode())
        assert url.endswith("/SQL%20Injection/BigQuery%20Injection.md"), "unrelated document fetched"
        return FetchResponse(200, raw)

    original = RemoteStore(tmp_path, GithubAdapter(SOURCES["payloads"], fetcher=fetch))
    first = original.research("sql injection", path=path, limit=1)["results"][0]
    with closing(sqlite3.connect(original.path)) as db:
        catalog = json.loads(db.execute("SELECT value FROM metadata WHERE key='catalog'").fetchone()[0])
        catalog.pop("adapter_fingerprint")
        db.execute("UPDATE metadata SET value=? WHERE key='catalog'", (json.dumps(catalog),))
        db.execute("UPDATE versions SET metadata='{}'")
        db.commit()
    calls.clear()
    updated = RemoteStore(tmp_path, GithubAdapter(SOURCES["payloads"], fetcher=fetch))
    item = updated.research("sql injection", limit=1)["results"][0]
    assert item["path"] == path and item["freshness"] == "current"
    assert item["evidence_reference"] == first["evidence_reference"]
    assert len(calls) == 2 and all("raw.githubusercontent.com" not in url for url in calls)
    assert updated.catalog()["cached_versions"] == 1
