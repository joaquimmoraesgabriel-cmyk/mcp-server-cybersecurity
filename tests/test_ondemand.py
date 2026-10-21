import base64
import io
import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from cyber_rag import ondemand
from cyber_rag.models import KnowledgeError, digest
from cyber_rag.ondemand import FetchResponse, OnDemandStore, RemoteError

PASSWORD = "cheatsheets/Password_Storage_Cheat_Sheet.md"
SQL = "cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md"
BODY = b"# Password Storage\n\n## Recommendations\n\nUse Argon2id and a unique salt per password.\n"
A = "a" * 40
B = "b" * 40


class World:
    def __init__(self):
        self.now = datetime(2026, 10, 21, 12, tzinfo=UTC)
        self.revision = A
        self.etag = '"head-a"'
        self.paths = [PASSWORD, SQL]
        self.content = BODY
        self.calls = []
        self.fail = None
        self.not_modified = False

    def clock(self):
        return self.now

    def fetch(self, url, *, etag=None, deadline=None):
        self.calls.append((url, etag))
        if self.fail:
            raise RemoteError(self.fail)
        if url == ondemand.COMMIT_URL:
            if self.not_modified:
                return FetchResponse(304, etag=self.etag)
            return FetchResponse(200, json.dumps({"sha": self.revision}).encode(), self.etag)
        if "/contents/" in url:
            listing = [
                {
                    "path": path,
                    "type": "file",
                    "size": len(self.content),
                    "download_url": "http://169.254.169.254/ignored",
                }
                for path in self.paths
            ]
            return FetchResponse(200, json.dumps(listing).encode())
        return FetchResponse(200, self.content)


@pytest.fixture
def store(tmp_path):
    world = World()
    return OnDemandStore(tmp_path, fetcher=world.fetch, clock=world.clock), world


def test_first_discovery_download_and_cache_hit_never_send_query(store):
    cache, world = store
    result = cache.research("recomendações sobre armazenamento seguro de senhas", limit=1)
    assert result["remote_status"] == "verified"
    assert len(world.calls) == 3
    first = result["results"][0]
    assert first["path"] == PASSWORD
    assert first["freshness"] == "current"
    assert first["document_id"] == "doc_" + digest(f"owasp:{PASSWORD}".encode())[:32]
    assert "Argon2id" in first["passages"][0]["text"]
    assert first["citation"]["license_reference"].endswith(f"/{A}/LICENSE.md")
    assert all("senha" not in url and "169.254" not in url for url, _ in world.calls)
    assert cache.research("password", limit=1)["results"][0]["original_hash"] == digest(BODY)
    assert len(world.calls) == 3
    assert cache.catalog()["cached_versions"] == 1


def test_conditional_304_revalidates_only_pinned_cached_commit(store):
    cache, world = store
    original = cache.research("password", limit=1)["results"][0]
    world.now += timedelta(days=2)
    world.not_modified = True
    current = cache.research("password", limit=1)["results"][0]
    assert len(world.calls) == 4
    assert world.calls[-1][1] == '"head-a"'
    assert current["revision"] == original["revision"]
    assert current["checked_at"] != original["checked_at"]
    assert current["freshness"] == "current"
    assert cache.catalog()["cached_versions"] == 1


def test_304_without_prior_catalog_is_rejected(store):
    cache, world = store
    world.not_modified = True
    result = cache.research("password")
    assert result["remote_status"] == "failed"
    assert not result["results"]
    assert cache.catalog()["revision"] is None
    assert len(world.calls) == 1


def test_changed_commit_preserves_old_bytes_and_invalidates_references(store):
    cache, world = store
    old = cache.research("password", limit=1)["results"][0]
    world.revision, world.etag = B, '"head-b"'
    world.content = BODY.replace(b"Argon2id", b"Updated Argon2id")
    new = cache.research("password", freshness="refresh", limit=1)["results"][0]
    assert new["revision"] == B and new["original_hash"] != old["original_hash"]
    assert cache.resolve_reference(old["reference"])["state"] == "superseded"
    assert cache.resolve_reference(new["reference"])["state"] == "current"
    original = cache.get_document(old["document_id"], A)
    assert base64.b64decode(original["content"]) == BODY
    assert cache.catalog()["cached_versions"] == 2
    assert cache.latest_state(old["document_id"], A, old["original_hash"]) == "superseded"


def test_offline_stale_and_failure_do_not_update_checked_at(store):
    cache, world = store
    old = cache.research("password", limit=1)["results"][0]
    world.now += timedelta(days=2)
    stale = cache.research("password", freshness="offline")["results"][0]
    assert stale["freshness"] == "stale" and len(world.calls) == 3
    world.fail = "network_unavailable"
    failed = cache.research("password", freshness="refresh")
    assert failed["remote_status"] == "failed"
    assert failed["results"][0]["checked_at"] == old["checked_at"]
    assert failed["results"][0]["freshness"] == "unknown"
    assert cache.resolve_reference(old["reference"])["state"] == "unknown"


def test_rate_limit_cooldown_persists_across_instances(store):
    cache, world = store
    world.fail = "http_429"
    cache.research("password")
    restarted = OnDemandStore(cache.path.parent.parent, fetcher=world.fetch, clock=world.clock)
    assert restarted.research("password", freshness="refresh")["remote_status"] == "cooldown"
    assert len(world.calls) == 1
    world.now += timedelta(minutes=16)
    world.fail = None
    assert restarted.research("password")["results"]


def test_failure_on_refresh_is_unknown_even_with_unexpired_ttl(store):
    cache, world = store
    old = cache.research("password", limit=1)["results"][0]
    world.fail = "http_403"
    result = cache.research("password", freshness="refresh")
    assert result["results"][0]["freshness"] == "unknown"
    assert result["results"][0]["checked_at"] == old["checked_at"]


def test_negative_clock_cannot_be_current(store):
    cache, world = store
    cache.research("password", limit=1)
    world.now -= timedelta(hours=1)
    assert cache.research("password", freshness="offline")["results"][0]["freshness"] == "unknown"


@pytest.mark.parametrize(
    "path",
    [
        "../secret",
        PASSWORD + "?x=1",
        "cheatsheets/../LICENSE.md",
        "https://evil.example/file",
        "cheatsheets/%2e.md",
        "cheatsheets/a\\b.md",
    ],
)
def test_paths_rejected_before_any_network(store, path):
    cache, world = store
    with pytest.raises(KnowledgeError, match="path"):
        cache.research("password", path=path)
    assert not world.calls


def test_unregistered_safe_path_is_not_downloaded(store):
    cache, world = store
    result = cache.research("password", path="cheatsheets/Unregistered.md")
    assert len(world.calls) == 2
    assert not result["results"]
    assert result["warnings"]


def test_unknown_topic_does_not_download_arbitrary_docs(store):
    cache, world = store
    result = cache.research("zqxwv")
    assert not result["results"] and len(world.calls) == 2


def test_removed_path_invalidates_old_evidence_without_deleting_it(store):
    cache, world = store
    old = cache.research("password", limit=1)["results"][0]
    world.revision = B
    world.paths = [SQL]
    cache.research("password", freshness="refresh")
    assert cache.resolve_reference(old["reference"])["state"] == "superseded"
    assert base64.b64decode(cache.get_document(old["document_id"], A)["content"]) == BODY


def test_new_head_invalidates_old_evidence_even_if_directory_fetch_fails(store):
    cache, world = store
    old = cache.research("password", limit=1)["results"][0]
    world.revision = B
    original_fetch = world.fetch

    def fetch(url, **kwargs):
        if "/contents/" in url:
            raise RemoteError("network_unavailable")
        return original_fetch(url, **kwargs)

    cache.fetcher = fetch
    result = cache.research("password", freshness="refresh")
    assert result["remote_status"] == "failed"
    assert cache.resolve_reference(old["reference"])["state"] == "superseded"
    assert cache.source_revision()["revision"] == B


def test_capacity_refuses_new_version_and_preserves_evidence(store, monkeypatch):
    cache, world = store
    old = cache.research("password", limit=1)["results"][0]
    world.revision = B
    monkeypatch.setattr(ondemand, "MAX_VERSIONS", 1)
    result = cache.research("password", freshness="refresh", limit=1)
    assert result["remote_status"] == "failed"
    assert "cache_capacity_reached" in result["warnings"][0]
    assert cache.catalog()["cached_versions"] == 1
    assert base64.b64decode(cache.get_document(old["document_id"], A)["content"]) == BODY


def test_invalid_remote_body_preserves_previous_version(store):
    cache, world = store
    old = cache.research("password", limit=1)["results"][0]
    world.revision = B
    world.content = b"<html>gateway error</html>"
    result = cache.research("password", freshness="refresh", limit=1)
    assert result["remote_status"] == "failed"
    assert result["results"][0]["original_hash"] == old["original_hash"]


def test_corrupt_cached_bytes_are_never_returned(store):
    cache, _ = store
    old = cache.research("password", limit=1)["results"][0]
    with sqlite3.connect(cache.path) as db:
        db.execute("UPDATE versions SET raw=?", (b"tampered",))
    with pytest.raises(KnowledgeError, match="integridade"):
        cache.get_document(old["document_id"], A)
    with pytest.raises(KnowledgeError):
        cache.research("password", freshness="offline")


def test_pagination_reconstructs_bytes_and_requires_revision(store):
    cache, world = store
    world.content = BODY + ("senha café\n" * 3000).encode()
    doc = cache.research("password", limit=1)["results"][0]
    pieces, offset = [], 0
    while True:
        part = cache.get_document(doc["document_id"], A, offset)
        raw = base64.b64decode(part["content"])
        assert digest(raw) == part["part_hash"]
        pieces.append(raw)
        if part["last_part"]:
            break
        offset = part["next_offset"]
    assert b"".join(pieces) == world.content
    with pytest.raises(KnowledgeError, match="revision"):
        cache.get_document(doc["document_id"], offset=9000)


def test_forged_reference_cannot_be_validated(store):
    cache, _ = store
    doc = cache.research("password", limit=1)["results"][0]
    forged = {**doc["reference"], "original_hash": "0" * 64}
    assert cache.resolve_reference(forged)["state"] == "missing"
    with pytest.raises(KnowledgeError):
        cache.resolve_reference({**doc["reference"], "url": "https://evil.example"})


def test_directory_limit_fails_explicitly_instead_of_assuming_complete(store):
    cache, world = store
    world.paths = [f"cheatsheets/File_{i}.md" for i in range(1000)]
    result = cache.research("password")
    assert result["remote_status"] == "failed"
    assert cache.catalog()["known_paths"] == 0


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/",
        "https://api.github.com/repos/OWASP/CheatSheetSeries/issues",
        ondemand.COMMIT_URL + "?x=1",
        "https://raw.githubusercontent.com/other/repo/main/x",
        f"https://raw.githubusercontent.com/OWASP/CheatSheetSeries/{A}/cheatsheets/../x.md",
    ],
)
def test_transport_allowlist(url):
    with pytest.raises(RemoteError, match="url_rejected"):
        ondemand.fetch_public(url)


def test_transport_disables_redirects():
    with pytest.raises(RemoteError, match="redirect_rejected"):
        ondemand._NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://evil.example")


def test_transport_rejects_oversize_body_and_disables_proxies(monkeypatch):
    handlers = []

    class Response(io.BytesIO):
        status = 200

        def __init__(self, body):
            super().__init__(body)
            self.headers = {}

    class Opener:
        def open(self, request, timeout):
            assert timeout <= 5
            assert "Authorization" not in request.headers
            return Response(b"12345")

    def build(*supplied):
        handlers.extend(supplied)
        return Opener()

    monkeypatch.setattr(ondemand.urllib.request, "build_opener", build)
    monkeypatch.setattr(ondemand, "MAX_BYTES", 4)
    with pytest.raises(RemoteError, match="response_too_large"):
        ondemand.fetch_public(ondemand.COMMIT_URL)
    proxy = next(item for item in handlers if isinstance(item, ondemand.urllib.request.ProxyHandler))
    assert proxy.proxies == {}


def test_deadline_expired_before_transport_never_calls_network():
    with pytest.raises(RemoteError, match="deadline_exceeded"):
        ondemand.fetch_public(ondemand.COMMIT_URL, deadline=0)


def test_etag_header_injection_is_rejected():
    with pytest.raises(RemoteError, match="invalid_etag"):
        ondemand.fetch_public(ondemand.COMMIT_URL, etag='"x"\r\nX-Injection: value')


def test_auto_recovers_after_failed_refresh_even_before_ttl_expires(store):
    cache, world = store
    cache.research("password", limit=1)
    world.fail = "network_unavailable"
    cache.research("password", freshness="refresh")
    world.now += timedelta(seconds=61)
    world.fail = None
    recovered = cache.research("password", limit=1)
    assert recovered["remote_status"] == "verified"
    assert recovered["results"][0]["freshness"] == "current"


def test_snapshot_reference_gets_unknown_on_failed_verification(store):
    cache, world = store
    cache.research("password", limit=1)
    sql_id = "doc_" + digest(f"owasp:{SQL}".encode())[:32]
    assert cache.latest_state(sql_id, A, "c" * 64) == "current"
    world.fail = "network_unavailable"
    cache.research("password", freshness="refresh")
    assert cache.latest_state(sql_id, A, "c" * 64) == "unknown"


def test_symlinks_and_submodules_cannot_be_remote_candidates(store):
    cache, world = store
    original_fetch = world.fetch

    def fetch(url, **kwargs):
        if "/contents/" in url:
            listing = [
                {"path": PASSWORD, "type": "file", "size": 10, "target": "../../outside"},
                {"path": SQL, "type": "file", "size": 10, "submodule_git_url": "https://evil.example"},
            ]
            return FetchResponse(200, json.dumps(listing).encode())
        return original_fetch(url, **kwargs)

    cache.fetcher = fetch
    result = cache.research("password")
    assert result["remote_status"] == "failed"
    assert not result["results"]
