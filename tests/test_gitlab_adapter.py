import base64
import csv
import io
import json
import time
from dataclasses import replace
from urllib.parse import unquote

import pytest

from cyber_rag.gitlab_adapter import API, CATALOG_BYTES, CATALOG_PATH, HEAD_URL, ExploitDbAdapter
from cyber_rag.models import digest
from cyber_rag.ondemand import FetchResponse, RemoteError
from cyber_rag.remote_cache import RemoteStore
from cyber_rag.source_adapters import make_adapter
from cyber_rag.source_registry import SOURCES

REVISION = "a" * 40
PATH = "exploits/linux/remote/45233.py"
SECOND_PATH = "exploits/linux/remote/452330.txt"
RAW = b"# Inert fixture: OpenSSH enumeration research.\nprint('not executed')\n"


def csv_bytes(rows=None, fields=None):
    fields = fields or ["id", "file", "description", "codes", "source_url"]
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    for row in (
        rows
        if rows is not None
        else [
            {
                "id": "45233",
                "file": PATH,
                "description": "OpenSSH username enumeration",
                "codes": "CVE-2018-15473",
                "source_url": "https://attacker.invalid/not-followed",
            },
            {
                "id": "452330",
                "file": SECOND_PATH,
                "description": "Unrelated fixture",
                "codes": "CVE-2020-1234",
                "source_url": "",
            },
        ]
    ):
        writer.writerow(row)
    return stream.getvalue().encode()


class Remote:
    def __init__(self):
        self.revision = REVISION
        self.csv = csv_bytes()
        self.files = {PATH: RAW, SECOND_PATH: b"Unrelated evidence.\n"}
        self.calls = []
        self.not_modified = False
        self.failure = False
        self.head = None

    def __call__(self, url, **kwargs):
        assert kwargs["allowed"](url)
        self.calls.append((url, kwargs))
        if self.failure:
            raise RemoteError("http_503")
        if url == HEAD_URL:
            if self.not_modified:
                return FetchResponse(304, etag='"head"')
            head = self.head if self.head is not None else {"name": "main", "commit": {"id": self.revision}}
            return FetchResponse(200, json.dumps(head).encode(), '"head"')
        assert url.endswith("/raw?ref=" + self.revision)
        path = unquote(url[len(API + "files/") :].split("/raw?ref=")[0])
        return FetchResponse(200, self.csv if path == CATALOG_PATH else self.files[path])


def setup_adapter(remote=None):
    remote = remote or Remote()
    return ExploitDbAdapter(SOURCES["exploit-db"], fetcher=remote), remote


def discover(adapter, old=None):
    return adapter.discover(old, time.monotonic() + 30)


def test_factory_pinned_csv_and_selected_text_with_provenance():
    remote = Remote()
    adapter = make_adapter(SOURCES["exploit-db"], fetcher=remote)
    assert isinstance(adapter, ExploitDbAdapter)
    catalog = discover(adapter)
    assert catalog["revision"] == REVISION and catalog["catalog_hash"] == digest(remote.csv)
    candidates = adapter.candidates("EDB-45233", catalog, 1, None)
    assert [entry["path"] for entry in candidates] == [PATH]
    loaded = adapter.load(candidates[0], REVISION, time.monotonic() + 30)
    assert loaded["raw"] == RAW
    assert "EDB-45233" in loaded["text"] and "CVE-2018-15473" in loaded["text"]
    assert loaded["text"].endswith(RAW.decode())
    assert loaded["metadata"]["representation"] == "derived_catalog_header_plus_original_text"
    assert loaded["metadata"]["original_encoding"] == "utf-8"
    assert loaded["metadata"]["execution"] == "never_executed"
    assert loaded["url"].endswith(f"/{REVISION}/{PATH}")
    assert loaded["license_reference"].endswith(f"/{REVISION}/LICENSE.md")
    assert len(remote.calls) == 3
    assert remote.calls[1][1]["max_bytes"] == CATALOG_BYTES
    assert all("attacker.invalid" not in url for url, _ in remote.calls)


@pytest.mark.parametrize(
    "query, paths",
    [
        ("CVE-2018-15473", [PATH]),
        ("EDB-45233", [PATH]),
        ("edb-45233", [PATH]),
        ("OpenSSH enumeration", [PATH]),
        ("CVE-2099-9999", []),
        ("EDB-99999", []),
        ("EDB-45233 CVE-2020-1234", []),
    ],
)
def test_selects_by_identifier_cve_or_description(query, paths):
    adapter, _ = setup_adapter()
    assert [entry["path"] for entry in adapter.candidates(query, discover(adapter), 3, None)] == paths


def test_catalog_paths_and_raw_allowlist_are_bound_to_revision_and_registration():
    adapter, _ = setup_adapter()
    catalog = discover(adapter)
    assert adapter.allowed(HEAD_URL)
    assert adapter.allowed(adapter._raw_url(PATH, REVISION))
    for url in [
        "http://localhost/",
        HEAD_URL + "?redirect=http://localhost",
        HEAD_URL.replace("gitlab.com", "evil.invalid"),
        adapter._raw_url(PATH, "main"),
        adapter._raw_url(PATH, "b" * 40),
        adapter._raw_url("files_shellcodes.csv", REVISION),
        adapter._raw_url("LICENSE.md", REVISION),
        adapter._raw_url("exploits/linux/remote/99999.py", REVISION),
        adapter._raw_url("shellcodes/linux/45233.py", REVISION),
        adapter._raw_url("exploits/linux/remote/../45233.py", REVISION),
        adapter._raw_url(PATH, REVISION).replace("%2F", "%2f"),
        adapter._raw_url(PATH, REVISION) + "&ref=main",
    ]:
        assert not adapter.allowed(url), url
    assert adapter.candidates("", catalog, 1, "exploits/linux/remote/99999.py") == []
    with pytest.raises(RemoteError, match="unregistered_exploit"):
        adapter.load({"path": "exploits/linux/remote/99999.py"}, REVISION, time.monotonic() + 30)
    with pytest.raises(RemoteError, match="unregistered_exploit"):
        adapter.load(catalog["entries"][0], "b" * 40, time.monotonic() + 30)


@pytest.mark.parametrize(
    "path",
    [
        "../secret",
        "https://example.com/a",
        "/absolute",
        "shellcodes/linux/1.c",
        "exploits/linux/remote/1.exe",
        "exploits/linux/remote/1.zip",
        "exploits/linux/remote/1.py%00",
    ],
)
def test_invalid_requested_path_never_fetches(path):
    adapter, remote = setup_adapter()
    with pytest.raises(RemoteError, match="path_rejected"):
        adapter.prepare("EDB-1", path, None)
    assert not remote.calls


def test_csv_excludes_shellcodes_binary_formats_and_mismatched_ids():
    adapter, remote = setup_adapter()
    base = {"id": "45233", "file": PATH, "description": "Valid fixture", "codes": "", "source_url": ""}
    rows = [base] + [
        {**base, "file": path}
        for path in [
            "shellcodes/linux/45233.c",
            "exploits/linux/remote/45233.exe",
            "exploits/linux/remote/45233.zip",
            "exploits/linux/remote/45233.pdf",
            "exploits/linux/remote/999.py",
            "exploits/linux/remote/../../secrets.txt",
        ]
    ]
    remote.csv = csv_bytes(rows)
    catalog = discover(adapter)
    assert len(catalog["entries"]) == 1 and catalog["excluded_entries"] == 6


@pytest.mark.parametrize(
    "head",
    [
        [],
        {},
        {"name": "main"},
        {"name": "main", "commit": None},
        {"name": "main", "commit": {}},
        {"name": "other", "commit": {"id": REVISION}},
        {"name": "main", "commit": {"id": 1}},
    ],
)
def test_malformed_branch_response_fails_controlled(head):
    adapter, remote = setup_adapter()
    remote.head = head
    with pytest.raises(RemoteError, match="invalid_gitlab_head"):
        discover(adapter)
    assert len(remote.calls) == 1


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"id,file,description\n1,a,b\n",
        b"id,id,file,description,codes\n1,1,a,b,c\n",
        b"id,file,description,codes\n1,a,b,c,unexpected\n",
        b"id,file,description,codes\n1,a\n",
        b"id,file,description,codes\n1,a,\x00,c\n",
        b"id,file,description,codes\n1,a,\xff,c\n",
    ],
)
def test_malformed_csv_fails_controlled(raw):
    adapter, remote = setup_adapter()
    remote.csv = raw
    with pytest.raises(RemoteError):
        discover(adapter)


def test_conflicting_duplicate_csv_ids_fail_closed():
    adapter, remote = setup_adapter()
    row = {"id": "45233", "file": PATH, "description": "Fixture", "codes": "", "source_url": ""}
    remote.csv = csv_bytes([row, {**row, "description": "Conflicting description"}])
    with pytest.raises(RemoteError, match="conflicting_exploit_csv_row"):
        discover(adapter)


def test_duplicate_csv_rows_with_only_unindexed_tags_are_deduplicated():
    adapter, remote = setup_adapter()
    row = {"id": "45233", "file": PATH, "description": "Fixture", "codes": "CVE-2018-15473", "tags": "first"}
    remote.csv = csv_bytes(
        [row, {**row, "tags": "second"}], fields=["id", "file", "description", "codes", "tags"]
    )
    catalog = discover(adapter)
    assert len(catalog["entries"]) == 1 and catalog["duplicate_metadata_rows"] == 1


@pytest.mark.parametrize(
    "raw",
    [b"", b"MZbinary", b"\x7fELFbinary", b"PK\x03\x04zip", b"%PDFtext", b"ordinary\x00binary", b"\x01" * 100],
)
def test_binary_disguised_as_text_is_rejected(raw):
    adapter, remote = setup_adapter()
    remote.files[PATH] = raw
    entry = discover(adapter)["entries"][0]
    with pytest.raises(RemoteError, match="non_text_evidence"):
        adapter.load(entry, REVISION, time.monotonic() + 30)


def test_latin1_text_is_declared_while_original_bytes_are_preserved():
    adapter, remote = setup_adapter()
    remote.files[PATH] = b"# Referencia: caf\xe9\n"
    entry = discover(adapter)["entries"][0]
    loaded = adapter.load(entry, REVISION, time.monotonic() + 30)
    assert loaded["metadata"]["original_encoding"] == "latin-1"
    assert loaded["raw"] == remote.files[PATH] and "café" in loaded["text"]


def test_same_revision_and_etag_avoid_csv_redownload():
    adapter, remote = setup_adapter()
    catalog = discover(adapter)
    assert len(remote.calls) == 2
    assert discover(adapter, catalog)["entries"] == catalog["entries"]
    assert len(remote.calls) == 3
    remote.not_modified = True
    assert discover(adapter, catalog)["entries"] == catalog["entries"]
    assert len(remote.calls) == 4 and remote.calls[-1][1]["etag"] == '"head"'
    fresh, _ = setup_adapter(remote)
    with pytest.raises(RemoteError, match="invalid_not_modified"):
        discover(fresh)


def test_cache_offline_exact_ids_and_new_instance_reuses_catalog(tmp_path):
    adapter, remote = setup_adapter()
    store = RemoteStore(tmp_path, adapter)
    first = store.research("EDB-45233", limit=1)["results"][0]
    assert first["source_id"] == "exploit-db" and first["freshness"] == "current"
    count = len(remote.calls)
    assert store.research("EDB-45233", freshness="offline")["results"][0]["original_hash"] == digest(RAW)
    assert not store.research("EDB-452330", freshness="offline")["results"]
    assert not store.research("EDB-99999", freshness="offline")["results"]
    assert len(remote.calls) == count
    newer = RemoteStore(tmp_path, ExploitDbAdapter(SOURCES["exploit-db"], fetcher=remote))
    second = newer.research("EDB-452330", limit=1)["results"][0]
    assert second["document_id"] != first["document_id"]
    assert len(remote.calls) == count + 1  # only the selected file, no catalog/branch request
    assert (
        newer.research("EDB-45233", freshness="offline", limit=3)["results"][0]["document_id"]
        == first["document_id"]
    )
    document = newer.get_document(first["document_id"], first["revision"])
    assert base64.b64decode(document["content"]) == RAW
    cve = newer.research("CVE-2018-15473", freshness="offline")["results"]
    assert len(cve) == 1 and cve[0]["document_id"] == first["document_id"]


def test_refresh_failure_keeps_raw_without_claiming_currency(tmp_path):
    adapter, remote = setup_adapter()
    store = RemoteStore(tmp_path, adapter)
    first = store.research("EDB-45233", limit=1)["results"][0]
    remote.failure = True
    failed = store.research("EDB-45233", freshness="refresh", limit=1)
    assert failed["remote_status"] == "failed"
    assert failed["results"][0]["original_hash"] == first["original_hash"]
    assert failed["results"][0]["freshness"] == "unknown"


def test_changed_commit_keeps_old_file_pinned(tmp_path):
    adapter, remote = setup_adapter()
    store = RemoteStore(tmp_path, adapter)
    first = store.research("EDB-45233", limit=1)["results"][0]
    remote.revision = "b" * 40
    remote.files[PATH] += b"# New revision\n"
    newer = store.research("EDB-45233", freshness="refresh", limit=1)["results"][0]
    assert newer["revision"] == remote.revision and newer["original_hash"] != first["original_hash"]
    assert store.resolve_reference(first["evidence_reference"])["state"] == "superseded"
    assert base64.b64decode(store.get_document(first["document_id"], first["revision"])["content"]) == RAW


def test_size_limits_deadlines_and_wrong_repository_are_enforced(monkeypatch):
    adapter, remote = setup_adapter()
    with pytest.raises(RemoteError, match="deadline_exceeded"):
        adapter.discover(None, time.monotonic() - 1)
    assert not remote.calls
    with pytest.raises(ValueError):
        ExploitDbAdapter(replace(SOURCES["exploit-db"], repository="attacker/evil"))
    monkeypatch.setattr("cyber_rag.gitlab_adapter.CATALOG_BYTES", 10)
    with pytest.raises(RemoteError, match="invalid_gitlab_response"):
        discover(adapter)


def test_edb_default_route_only_selects_registered_exploit_db(tmp_path):
    from cyber_rag.cache_router import CacheRouter

    assert CacheRouter(tmp_path).route("EDB-45233", None, "auto") == ["exploit-db"]
