"""Bounded OWASP retrieval with immutable, local evidence versions.

Only repository metadata and selected public files cross the network boundary.
Queries, local evidence and memory never leave this process through this adapter.
"""

from __future__ import annotations

import base64
import json
import re
import sqlite3
import time
import unicodedata
import urllib.error
import urllib.request
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import KnowledgeError, digest

REPOSITORY = "OWASP/CheatSheetSeries"
COMMIT_URL = f"https://api.github.com/repos/{REPOSITORY}/commits/master"
TTL_SECONDS = 24 * 3600
REQUEST_BUDGET = 20.0
MAX_BYTES = 1024 * 1024
MAX_CACHE_BYTES = 128 * 1024 * 1024
MAX_VERSIONS = 1000
PATH_RE = re.compile(r"cheatsheets/[A-Za-z0-9_-]+\.md\Z")
SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
HASH_RE = re.compile(r"[a-f0-9]{64}\Z")


@dataclass(frozen=True)
class FetchResponse:
    status: int
    body: bytes = b""
    etag: str | None = None
    retry_after: str | None = None


class RemoteError(RuntimeError):
    def __init__(self, code="unavailable", retry_after=None):
        super().__init__(code)
        self.code = code
        self.retry_after = retry_after


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RemoteError("redirect_rejected")


def _allowed_url(url):
    if url == COMMIT_URL:
        return True
    prefix = f"https://api.github.com/repos/{REPOSITORY}/contents/cheatsheets?ref="
    if url.startswith(prefix) and SHA_RE.fullmatch(url[len(prefix) :]):
        return True
    prefix = f"https://raw.githubusercontent.com/{REPOSITORY}/"
    if url.startswith(prefix):
        revision, _, path = url[len(prefix) :].partition("/")
        return bool(SHA_RE.fullmatch(revision) and PATH_RE.fullmatch(path))
    return False


def fetch_public(url, *, etag=None, deadline=None):
    """No redirects, environment proxies, cookies or authentication headers."""
    if not _allowed_url(url):
        raise RemoteError("url_rejected")
    deadline = deadline if deadline is not None else time.monotonic() + REQUEST_BUDGET
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RemoteError("deadline_exceeded")
    headers = {"User-Agent": "cyber-rag-local/0.1", "Accept-Encoding": "identity"}
    if etag is not None:
        if not isinstance(etag, str) or len(etag) > 512 or "\r" in etag or "\n" in etag:
            raise RemoteError("invalid_etag")
        headers["If-None-Match"] = etag
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(request, timeout=min(5.0, remaining)) as response:
            if response.status != 200:
                raise RemoteError("unexpected_status")
            if response.headers.get("Content-Encoding", "identity") not in {"", "identity"}:
                raise RemoteError("compressed_content_rejected")
            if int(response.headers.get("Content-Length", "0")) > MAX_BYTES:
                raise RemoteError("response_too_large")
            chunks, total = [], 0
            while True:
                if time.monotonic() >= deadline:
                    raise RemoteError("deadline_exceeded")
                chunk = response.read1(min(65536, MAX_BYTES - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BYTES:
                    raise RemoteError("response_too_large")
                chunks.append(chunk)
            return FetchResponse(200, b"".join(chunks), response.headers.get("ETag"))
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return FetchResponse(304, etag=exc.headers.get("ETag") or etag)
        raise RemoteError(f"http_{exc.code}", exc.headers.get("Retry-After")) from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RemoteError("network_unavailable") from exc


def _words(text):
    normalized = unicodedata.normalize("NFKD", text.casefold())
    normalized = "".join(char for char in normalized if not unicodedata.combining(char))
    words = re.findall(r"[a-z0-9]+", normalized)
    aliases = {
        "senha": ["password", "storage"],
        "senhas": ["password", "storage"],
        "armazenamento": ["storage"],
        "armazenar": ["storage"],
        "autenticacao": ["authentication"],
        "autorizacao": ["authorization"],
        "sessao": ["session"],
        "sessoes": ["session"],
        "injecao": ["injection"],
        "prevencao": ["prevention"],
        "prevenir": ["prevention"],
        "arquivos": ["file"],
        "arquivo": ["file"],
        "criptografia": ["cryptographic"],
        "segredos": ["secrets"],
        "deserializacao": ["deserialization"],
        "logs": ["logging"],
        "log": ["logging"],
        "xss": ["cross", "site", "scripting"],
        "ssrf": ["server", "side", "request", "forgery"],
    }
    excluded = {
        "a",
        "o",
        "as",
        "os",
        "de",
        "do",
        "da",
        "das",
        "dos",
        "e",
        "em",
        "no",
        "na",
        "the",
        "an",
        "and",
        "for",
        "of",
        "to",
        "in",
        "on",
        "how",
        "como",
        "que",
        "qual",
        "quais",
        "sobre",
        "recomendacoes",
        "seguro",
        "segura",
        "usar",
        "use",
    }
    expanded = []
    for word in words:
        if word not in excluded:
            expanded.extend([word, *aliases.get(word, [])])
    return list(dict.fromkeys(expanded))[:32]


def _stamp(value):
    return value.astimezone(UTC).isoformat()


def _parse(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must have timezone")
    return parsed.astimezone(UTC)


class OnDemandStore:
    def __init__(self, data_dir: Path, *, fetcher=None, clock=None):
        self.path = Path(data_dir) / "ondemand" / "cache.sqlite3"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fetcher = fetcher or fetch_public
        self.clock = clock or (lambda: datetime.now(UTC))
        with closing(self._connect()) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS versions(
                    id INTEGER PRIMARY KEY, document_id TEXT NOT NULL, path TEXT NOT NULL,
                    revision TEXT NOT NULL, original_hash TEXT NOT NULL, raw BLOB NOT NULL,
                    title TEXT NOT NULL, checked_at TEXT NOT NULL,
                    UNIQUE(document_id, revision));
                CREATE TABLE IF NOT EXISTS active(path TEXT PRIMARY KEY, version_id INTEGER NOT NULL);
                CREATE VIRTUAL TABLE IF NOT EXISTS evidence_fts USING fts5(title, text);
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        # Bound the actual database in addition to raw-content quotas. The rollback
        # journal is transient and is not an additional retained evidence version.
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        db.execute(f"PRAGMA max_page_count={128 * 1024 * 1024 // page_size}")
        return db

    @staticmethod
    def _meta(db, key, default=None):
        row = db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    @staticmethod
    def _put(db, key, value):
        db.execute("INSERT OR REPLACE INTO metadata VALUES(?, ?)", (key, json.dumps(value)))

    def _age(self, value):
        try:
            return (self.clock() - _parse(value)).total_seconds()
        except (TypeError, ValueError):
            return -1

    def _request(self, url, *, etag=None, deadline=None):
        if not _allowed_url(url):
            raise RemoteError("url_rejected")
        if deadline is not None and time.monotonic() >= deadline:
            raise RemoteError("deadline_exceeded")
        response = self.fetcher(url, etag=etag, deadline=deadline)
        if not isinstance(response, FetchResponse) or len(response.body) > MAX_BYTES:
            raise RemoteError("invalid_response")
        if response.status not in {200, 304}:
            raise RemoteError(f"http_{response.status}", response.retry_after)
        if response.etag is not None and (
            len(response.etag) > 512 or any(c in response.etag for c in "\r\n")
        ):
            raise RemoteError("invalid_etag")
        return response

    def _refresh_catalog(self, db, deadline):
        old = self._meta(db, "catalog")
        response = self._request(COMMIT_URL, etag=old.get("etag") if old else None, deadline=deadline)
        if response.status == 304:
            if not old or not old.get("paths") or not old.get("etag"):
                raise RemoteError("invalid_not_modified")
            revision = old["revision"]
        else:
            try:
                revision = json.loads(response.body)["sha"]
            except (ValueError, KeyError, TypeError):
                raise RemoteError("invalid_commit") from None
            if not isinstance(revision, str) or not SHA_RE.fullmatch(revision):
                raise RemoteError("invalid_commit")
        # A newly observed head invalidates old notes even if directory discovery fails.
        self._put(db, "observed_revision", revision)
        self._put(db, "observed_at", _stamp(self.clock()))
        db.commit()
        if old and old["revision"] == revision:
            paths = old["paths"]
        else:
            url = f"https://api.github.com/repos/{REPOSITORY}/contents/cheatsheets?ref={revision}"
            listing = self._request(url, deadline=deadline)
            if listing.status != 200:
                raise RemoteError("invalid_directory_status")
            try:
                entries = json.loads(listing.body)
            except ValueError:
                raise RemoteError("invalid_directory") from None
            if not isinstance(entries, list) or not 1 <= len(entries) < 1000:
                raise RemoteError("directory_incomplete_or_invalid")
            paths = []
            for entry in entries:
                if not isinstance(entry, dict):
                    raise RemoteError("invalid_directory_entry")
                if entry.get("target") or entry.get("submodule_git_url"):
                    continue
                path = entry.get("path")
                if entry.get("type") == "file" and isinstance(path, str) and PATH_RE.fullmatch(path):
                    if type(entry.get("size")) is not int or entry["size"] < 0:
                        raise RemoteError("invalid_directory_entry")
                    if entry["size"] > MAX_BYTES:
                        continue
                    paths.append(path)
            if not paths or len(set(paths)) != len(paths):
                raise RemoteError("invalid_directory_paths")
        catalog = {
            "revision": revision,
            "etag": response.etag,
            "checked_at": _stamp(self.clock()),
            "paths": sorted(paths),
        }
        self._put(db, "catalog", catalog)
        self._put(db, "last_failure", None)
        self._put(db, "retry_at", None)
        db.commit()
        return catalog

    def _failure(self, db, error):
        cooldown = 60
        try:
            cooldown = min(86400, max(60, int(error.retry_after)))
        except (ValueError, TypeError):
            if error.code in {"http_403", "http_429"}:
                cooldown = 900
        self._put(db, "last_failure", {"code": error.code, "at": _stamp(self.clock())})
        self._put(db, "retry_at", _stamp(self.clock() + timedelta(seconds=cooldown)))
        db.commit()

    def _download(self, db, path, catalog, deadline):
        revision = catalog["revision"]
        document_id = "doc_" + digest(f"owasp:{path}".encode())[:32]
        existing = db.execute(
            "SELECT * FROM versions WHERE document_id=? AND revision=?", (document_id, revision)
        ).fetchone()
        if existing:
            self._verify(existing)
            with db:
                db.execute("INSERT OR REPLACE INTO active VALUES(?, ?)", (path, existing["id"]))
            return
        response = self._request(
            f"https://raw.githubusercontent.com/{REPOSITORY}/{revision}/{path}", deadline=deadline
        )
        if response.status != 200:
            raise RemoteError("invalid_document_status")
        raw = response.body
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise RemoteError("invalid_document_encoding") from None
        if not text.strip() or "\x00" in text or not re.search(r"(?m)^#\s+\S", text):
            raise RemoteError("invalid_markdown_document")
        title = path.rsplit("/", 1)[1][:-3].replace("_", " ")
        with db:
            # BEGIN IMMEDIATE reserves writes before enforcing the shared quota.
            db.execute("BEGIN IMMEDIATE")
            count, size = db.execute("SELECT count(*), coalesce(sum(length(raw)),0) FROM versions").fetchone()
            if count >= MAX_VERSIONS or size + len(raw) > MAX_CACHE_BYTES:
                raise RemoteError("cache_capacity_reached")
            row = db.execute(
                "INSERT INTO versions(document_id,path,revision,original_hash,raw,title,checked_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (document_id, path, revision, digest(raw), raw, title, catalog["checked_at"]),
            )
            db.execute(
                "INSERT INTO evidence_fts(rowid,title,text) VALUES(?,?,?)", (row.lastrowid, title, text)
            )
            db.execute("INSERT OR REPLACE INTO active VALUES(?,?)", (path, row.lastrowid))

    @staticmethod
    def _verify(row):
        if digest(row["raw"]) != row["original_hash"]:
            raise KnowledgeError("CACHE_INTEGRITY", "A integridade de uma evidência em cache falhou.")

    def _state(self, db, row):
        catalog = self._meta(db, "catalog", {})
        observed = self._meta(db, "observed_revision")
        if observed and observed != row["revision"]:
            return "superseded"
        if row["path"] not in catalog.get("paths", []):
            return "superseded" if catalog else "unknown"
        if self._meta(db, "last_failure"):
            return "unknown"
        age = self._age(catalog.get("checked_at"))
        return "unknown" if age < 0 else "stale" if age > TTL_SECONDS else "current"

    def _citation(self, db, row):
        catalog = self._meta(db, "catalog", {})
        checked = (
            catalog.get("checked_at") if catalog.get("revision") == row["revision"] else row["checked_at"]
        )
        return {
            "store": "cache",
            "source_id": "owasp",
            "document_id": row["document_id"],
            "path": row["path"],
            "revision": row["revision"],
            "original_hash": row["original_hash"],
            "url": f"https://github.com/{REPOSITORY}/blob/{row['revision']}/{row['path']}",
            "license_reference": f"https://github.com/{REPOSITORY}/blob/{row['revision']}/LICENSE.md",
            "checked_at": checked,
            "freshness": self._state(db, row),
            "untrusted": True,
        }

    @staticmethod
    def _passages(text, terms):
        # Heading + body groups retain useful context without presenting lone headings as evidence.
        groups = re.split(r"(?m)(?=^#{1,6} )", text)
        candidates = []
        for index, group in enumerate(groups):
            body = re.sub(r"(?m)^#{1,6}[^\n]*$", "", group).strip()
            if not body:
                continue
            for start in range(0, min(len(group), MAX_BYTES), 1600):
                part = group[start : start + 1800]
                score = len(set(_words(part)) & set(terms))
                candidates.append((score, index, start, part))
        candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
        return [
            {"section_id": f"section-{index}:{start}", "text": part, "untrusted": True}
            for _, index, start, part in candidates[:2]
        ]

    def research(self, query, *, freshness="auto", limit=3, path=None):
        if not isinstance(query, str) or not query.strip() or len(query) > 4000:
            raise KnowledgeError("INVALID_ARGUMENT", "query deve conter 1 a 4000 caracteres.")
        if freshness not in {"auto", "refresh", "offline"}:
            raise KnowledgeError("INVALID_ARGUMENT", "freshness deve ser auto, refresh ou offline.")
        if type(limit) is not int or not 1 <= limit <= 3:
            raise KnowledgeError("INVALID_ARGUMENT", "limit deve estar entre 1 e 3.")
        if path is not None and (not isinstance(path, str) or not PATH_RE.fullmatch(path)):
            raise KnowledgeError("INVALID_ARGUMENT", "path deve ser um caminho OWASP registrado no catálogo.")
        terms = _words(query)
        warnings, remote_status = [], "offline" if freshness == "offline" else "cache_hit"
        with closing(self._connect()) as db:
            catalog = self._meta(db, "catalog")
            retry_at = self._meta(db, "retry_at")
            cooldown = retry_at and self._age(retry_at) < 0
            deadline = time.monotonic() + REQUEST_BUDGET
            if freshness != "offline":
                age = self._age(catalog.get("checked_at")) if catalog else -1
                needs_check = (
                    freshness == "refresh"
                    or not catalog
                    or not 0 <= age <= TTL_SECONDS
                    or self._meta(db, "last_failure") is not None
                )
                if cooldown:
                    remote_status = "cooldown"
                    warnings.append("Nova tentativa remota adiada após falha; cache não foi revalidado.")
                elif needs_check:
                    try:
                        catalog = self._refresh_catalog(db, deadline)
                        remote_status = "verified"
                    except (RemoteError, ValueError, TypeError, sqlite3.OperationalError) as exc:
                        if isinstance(exc, sqlite3.OperationalError) and "full" not in str(exc).lower():
                            raise
                        if isinstance(exc, sqlite3.OperationalError):
                            exc = RemoteError("cache_capacity_reached")
                        error = exc if isinstance(exc, RemoteError) else RemoteError("invalid_remote_data")
                        self._failure(db, error)
                        remote_status = "failed"
                        warnings.append(
                            f"Verificação remota falhou: {error.code}. Evidências locais podem estar desatualizadas."
                        )
            paths = catalog.get("paths", []) if catalog else []
            if path is not None and path not in paths:
                warnings.append(
                    "Caminho não encontrado no catálogo disponível; nenhum URL arbitrário foi acessado."
                )
                candidates = []
            else:
                ranked = sorted(
                    ((len(set(_words(item)) & set(terms)), item) for item in paths),
                    key=lambda pair: (-pair[0], pair[1]),
                )
                candidates = [path] if path else [item for score, item in ranked if score > 0][:limit]
            if freshness != "offline" and remote_status not in {"failed", "cooldown"}:
                for selected in candidates:
                    try:
                        self._download(db, selected, catalog, deadline)
                    except (RemoteError, ValueError, TypeError, sqlite3.OperationalError) as exc:
                        if isinstance(exc, sqlite3.OperationalError) and "full" not in str(exc).lower():
                            raise
                        if isinstance(exc, sqlite3.OperationalError):
                            exc = RemoteError("cache_capacity_reached")
                        error = exc if isinstance(exc, RemoteError) else RemoteError("invalid_remote_data")
                        self._failure(db, error)
                        remote_status = "failed"
                        warnings.append(
                            f"Coleta remota falhou: {error.code}; versões anteriores preservadas."
                        )
                        break
            rows = []
            if terms:
                match = " OR ".join('"' + term + '"' for term in terms)
                rows = list(
                    db.execute(
                        "SELECT v.*, bm25(evidence_fts) AS rank FROM evidence_fts "
                        "JOIN versions v ON v.id=evidence_fts.rowid JOIN active a ON a.version_id=v.id "
                        "WHERE evidence_fts MATCH ? ORDER BY rank LIMIT 20",
                        (match,),
                    )
                )
            # Explicit paths and newly discovered matches must remain reachable even if the body uses another vocabulary.
            for selected in candidates:
                row = db.execute(
                    "SELECT v.* FROM versions v JOIN active a ON a.version_id=v.id WHERE a.path=?",
                    (selected,),
                ).fetchone()
                if row and all(existing["document_id"] != row["document_id"] for existing in rows):
                    rows.append(row)
            if path is not None:
                rows = [row for row in rows if row["path"] == path]
            rows.sort(key=lambda row: (-len(set(_words(row["path"])) & set(terms)), row["path"]))
            results = []
            for row in rows[:limit]:
                self._verify(row)
                citation = self._citation(db, row)
                passages = self._passages(row["raw"].decode("utf-8"), terms)
                results.append(
                    {
                        **citation,
                        "title": row["title"],
                        "passages": passages,
                        "status": citation["freshness"],
                        "citation": citation,
                        "reference": {
                            key: citation[key]
                            for key in ("store", "document_id", "revision", "original_hash")
                        },
                    }
                )
                results[-1]["evidence_reference"] = dict(results[-1]["reference"])
            if any(result["freshness"] != "current" for result in results):
                warnings.append(
                    "Há evidências sem confirmação de atualidade; consulte freshness de cada resultado."
                )
            return {
                "results": results,
                "citations": [result["citation"] for result in results],
                "warnings": warnings,
                "remote_status": remote_status,
                "catalog": self._catalog(db),
                "retrieval_profile": "lexical_cache_and_path_discovery",
                "discovery_limit": "OWASP paths only; this is not a full semantic search of GitHub.",
            }

    def _catalog(self, db):
        catalog = self._meta(db, "catalog", {})
        count, size = db.execute("SELECT count(*), coalesce(sum(length(raw)),0) FROM versions").fetchone()
        return {
            "source_id": "owasp",
            "repository": REPOSITORY,
            "branch": "master",
            "revision": catalog.get("revision"),
            "checked_at": catalog.get("checked_at"),
            "known_paths": len(catalog.get("paths", [])),
            "paths": catalog.get("paths", []),
            "observed_revision": self._meta(db, "observed_revision"),
            "last_failure": self._meta(db, "last_failure"),
            "retry_at": self._meta(db, "retry_at"),
            "cached_versions": count,
            "cached_bytes": size,
            "ttl_seconds": TTL_SECONDS,
            "max_bytes": MAX_CACHE_BYTES,
            "max_versions": MAX_VERSIONS,
        }

    def catalog(self):
        with closing(self._connect()) as db:
            return self._catalog(db)

    def source_revision(self):
        with closing(self._connect()) as db:
            catalog = self._meta(db, "catalog", {})
            revision = self._meta(db, "observed_revision") or catalog.get("revision")
            if not revision:
                return None
            return {
                "revision": revision,
                "checked_at": self._meta(db, "observed_at"),
                "last_failure": self._meta(db, "last_failure"),
            }

    def get_document(self, document_id, revision=None, offset=0):
        if not isinstance(document_id, str) or not re.fullmatch(r"doc_[0-9a-f]{32}", document_id):
            raise KnowledgeError("INVALID_ARGUMENT", "Identificador de cache inválido.")
        if revision is not None and (not isinstance(revision, str) or not SHA_RE.fullmatch(revision)):
            raise KnowledgeError("INVALID_ARGUMENT", "revision deve ser um SHA de 40 caracteres.")
        if type(offset) is not int or offset < 0:
            raise KnowledgeError("INVALID_ARGUMENT", "offset deve ser inteiro não negativo.")
        if offset and revision is None:
            raise KnowledgeError("INVALID_ARGUMENT", "Paginação exige revision para manter a mesma versão.")
        with closing(self._connect()) as db:
            if revision:
                row = db.execute(
                    "SELECT * FROM versions WHERE document_id=? AND revision=?", (document_id, revision)
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT v.* FROM versions v JOIN active a ON a.version_id=v.id WHERE document_id=?",
                    (document_id,),
                ).fetchone()
            if row is None:
                raise KnowledgeError("NOT_FOUND", "Documento não encontrado no cache local.")
            self._verify(row)
            raw = row["raw"]
            if offset >= len(raw) and offset != 0:
                raise KnowledgeError("INVALID_ARGUMENT", "offset ultrapassa o documento.")
            piece = raw[offset : offset + 9000]
            end = offset + len(piece)
            citation = self._citation(db, row)
            return {
                **citation,
                "citation": citation,
                "evidence_reference": {
                    key: citation[key] for key in ("store", "document_id", "revision", "original_hash")
                },
                "content": base64.b64encode(piece).decode("ascii"),
                "text": piece.decode("utf-8", errors="replace"),
                "encoding": "base64",
                "offset": offset,
                "part_hash": digest(piece),
                "total_bytes": len(raw),
                "complete": offset == 0 and end == len(raw),
                "last_part": end == len(raw),
                "next_offset": end if end < len(raw) else None,
            }

    def resolve_reference(self, reference):
        if not isinstance(reference, dict) or set(reference) != {
            "store",
            "document_id",
            "revision",
            "original_hash",
        }:
            raise KnowledgeError(
                "INVALID_ARGUMENT", "Referência de cache exige store, document_id, revision e original_hash."
            )
        if (
            reference["store"] != "cache"
            or not isinstance(reference["original_hash"], str)
            or not HASH_RE.fullmatch(reference["original_hash"])
        ):
            raise KnowledgeError("INVALID_ARGUMENT", "Referência de cache inválida.")
        try:
            document = self.get_document(reference["document_id"], reference["revision"])
        except KnowledgeError as exc:
            if exc.code == "NOT_FOUND":
                return {"state": "missing", "reference": reference, "citation": None}
            raise
        if document["original_hash"] != reference["original_hash"]:
            return {"state": "missing", "reference": reference, "citation": None}
        return {"state": document["freshness"], "reference": reference, "citation": document["citation"]}

    def latest_state(self, document_id, revision, original_hash):
        """Return None if this cache knows nothing about this document/source revision."""
        with closing(self._connect()) as db:
            catalog = self._meta(db, "catalog", {})
            observed = self._meta(db, "observed_revision")
            if observed and observed != revision:
                return "superseded"
            row = db.execute(
                "SELECT v.* FROM versions v JOIN active a ON a.version_id=v.id WHERE document_id=?",
                (document_id,),
            ).fetchone()
            if row:
                self._verify(row)
                if row["revision"] != revision or row["original_hash"] != original_hash:
                    return "superseded"
                return self._state(db, row)
            if catalog:
                known_ids = {"doc_" + digest(f"owasp:{path}".encode())[:32] for path in catalog["paths"]}
                if document_id not in known_ids:
                    return "superseded"
                if self._meta(db, "last_failure"):
                    return "unknown"
                age = self._age(catalog.get("checked_at"))
                return "unknown" if age < 0 else "stale" if age > TTL_SECONDS else "current"
            if self._meta(db, "last_failure"):
                return "unknown"
            return None
