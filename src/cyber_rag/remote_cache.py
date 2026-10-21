"""Bounded, source-isolated evidence caches for trusted, narrow adapters.

Adapters own URL allowlists and parsing. This module never performs network I/O,
executes source text, or accepts a caller-supplied URL. A valid reference proves
the identity and currency of bytes, not the truth of a derived conclusion.
"""

from __future__ import annotations

import base64
import json
import math
import re
import sqlite3
import threading
import time
from collections import OrderedDict
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from .models import KnowledgeError, digest
from .ondemand import RemoteError, _words

REQUEST_BUDGET = 30.0
MAX_ENTRIES = 100_000
MAX_CATALOG_BYTES = 32 * 1024 * 1024
MAX_TEXT_BYTES = 64 * 1024 * 1024
DATABASE_BYTES = 512 * 1024 * 1024
READ_BUFFER_BYTES = 80 * 1024 * 1024
READ_BUFFER_TTL = 120.0
# Shared across sources: opening many large documents cannot allocate one
# permanent original-sized buffer for every configured source.
_READ_BUFFERS = OrderedDict()
_READ_BUFFER_LOCK = threading.RLock()
DOCUMENT_COLUMNS = (
    "id,document_id,path,revision,original_hash,text_hash,title,url,license_reference,metadata,checked_at"
)
REVISION_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
DOC_RE = re.compile(r"doc_[0-9a-f]{32}\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
EXACT_RE = re.compile(
    r"(?i)\b(?:AML\.(?:TA|T|M|CS)\d{4}(?:\.\d{3})?|D3-[A-Z][A-Z0-9-]*|"
    r"CVE-\d{4}-\d{4,}|EDB-\d+|TA\d{4}|T\d{4}(?:\.\d{3})?|CWE-\d+|CAPEC-\d+)\b"
)


def _stamp(value):
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("Clock must return an aware datetime")
    return value.astimezone(UTC).isoformat()


def observation_order(reference_checked_at, observed, *, now):
    """Order local verifications without inferring an order from commit hashes."""
    try:
        reference = datetime.fromisoformat(reference_checked_at)
        if reference.tzinfo is None or reference > now:
            return "unknown"
        failure = observed.get("last_failure")
        if failure:
            failed_at = datetime.fromisoformat(failure.get("at"))
            if failed_at.tzinfo is None or failed_at > now or failed_at >= reference:
                return "unknown"
        checked = datetime.fromisoformat(observed.get("checked_at"))
        if checked.tzinfo is None or checked > now:
            return "unknown"
        return "newer" if checked >= reference else "older"
    except (TypeError, ValueError):
        return "unknown"


def _path(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 512 or any(c in value for c in "\\\x00\r\n?#"):
        raise KnowledgeError("INVALID_ARGUMENT", "Caminho de fonte inválido.")
    if value.startswith("/") or ":" in value or any(part in {"", ".", ".."} for part in value.split("/")):
        raise KnowledgeError("INVALID_ARGUMENT", "Caminho de fonte inválido.")
    return value


def _https(value):
    if not isinstance(value, str) or len(value) > 2048:
        return False
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password
        )
    except ValueError:
        return False


def _exact_matches(text, ids):
    return not ids or any(
        re.search(r"(?<![\w.-])" + re.escape(value) + r"(?![\w.-])", text, re.IGNORECASE) for value in ids
    )


class RemoteStore:
    """Local cache bound to one trusted adapter and one source namespace.

    ``discover(old_catalog, deadline)`` returns a complete registered list with
    revision, entries (path/title), and optional etag. ``load(entry, revision,
    deadline)`` returns raw bytes, derived text, title, source URL, license URL
    and optional metadata. Optional ``candidates(query,catalog,limit,path)`` may
    select only registered entries. It cannot expand the remote allowlist.
    Optional ``prepare(query,path,old_catalog)`` performs local selection only
    and returns whether discovery is required; discovery owns merging dynamic
    entries with the previous catalog. It is never called in offline mode.
    ``per_document_revisions=True`` makes entries carry their own ``revision``.
    ``_checked=True`` marks only entries verified by the current discovery;
    timestamps of other entries are carried forward from stored metadata.
    """

    def __init__(self, data_dir, adapter, *, clock=None):
        self.adapter = adapter
        source_id = getattr(adapter, "source_id", None)
        if not isinstance(source_id, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,47}", source_id):
            raise ValueError("Invalid source namespace")
        self.source_id = source_id
        self.per_document_revisions = getattr(adapter, "per_document_revisions", False)
        if type(self.per_document_revisions) is not bool:
            raise ValueError("Invalid revision scope")
        self.path = Path(data_dir).resolve() / "ondemand" / "sources" / f"{source_id}.sqlite3"
        self.clock = clock or (lambda: datetime.now(UTC))
        self.ttl_seconds = getattr(adapter, "ttl_seconds", 86400)
        self.max_bytes = getattr(adapter, "max_bytes", 64 * 1024 * 1024)
        self.max_versions = getattr(adapter, "max_versions", 1000)
        self.cache_bytes = getattr(adapter, "cache_bytes", 256 * 1024 * 1024)
        self.request_budget_seconds = getattr(adapter, "request_budget_seconds", REQUEST_BUDGET)
        if type(self.request_budget_seconds) not in (int, float) or not math.isfinite(self.request_budget_seconds) or not 0 < self.request_budget_seconds <= 90:
            raise ValueError("Invalid adapter request budget")
        for value in (self.ttl_seconds, self.max_bytes, self.max_versions, self.cache_bytes):
            if type(value) is not int or value <= 0:
                raise ValueError("Invalid adapter resource limit")
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS versions(
                    id INTEGER PRIMARY KEY, document_id TEXT NOT NULL, path TEXT NOT NULL,
                    revision TEXT NOT NULL, original_hash TEXT NOT NULL, raw BLOB NOT NULL,
                    text TEXT NOT NULL, text_hash TEXT NOT NULL, title TEXT NOT NULL, url TEXT NOT NULL,
                    license_reference TEXT NOT NULL, metadata TEXT NOT NULL, checked_at TEXT NOT NULL,
                    UNIQUE(document_id,revision));
                CREATE TABLE IF NOT EXISTS active(path TEXT PRIMARY KEY, version_id INTEGER NOT NULL);
                CREATE VIRTUAL TABLE IF NOT EXISTS evidence_fts USING fts5(title,text);
            """)
            db.commit()

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        db.execute(f"PRAGMA max_page_count={DATABASE_BYTES // page_size}")
        return db

    @staticmethod
    def _meta(db, key, default=None):
        row = db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        if row is None:
            return default
        try:
            if not isinstance(row[0], (str, bytes)) or len(row[0]) > MAX_CATALOG_BYTES:
                raise ValueError("Invalid stored metadata size")
            value = json.loads(row[0])
            if key == "catalog":
                if (
                    not isinstance(value, dict)
                    or not isinstance(value.get("revision"), str)
                    or not REVISION_RE.fullmatch(value["revision"])
                    or not isinstance(value.get("entries"), list)
                    or len(value["entries"]) > MAX_ENTRIES
                ):
                    raise ValueError("Invalid stored catalog")
                seen = set()
                for entry in value["entries"]:
                    if not isinstance(entry, dict):
                        raise TypeError("Invalid stored catalog entry")
                    path = _path(entry.get("path"))
                    title = entry.get("title")
                    if path in seen or not isinstance(title, str) or not title.strip() or len(title) > 1024:
                        raise ValueError("Invalid stored catalog entry")
                    seen.add(path)
                    if "revision" in entry and (
                        not isinstance(entry["revision"], str) or not REVISION_RE.fullmatch(entry["revision"])
                    ):
                        raise ValueError("Invalid stored document revision")
                    if entry.get("checked_at") is not None and not isinstance(entry["checked_at"], str):
                        raise ValueError("Invalid stored document check")
            elif key == "document_failures":
                if not isinstance(value, dict) or len(value) > 1000:
                    raise ValueError("Invalid stored document failures")
                for path, failure in value.items():
                    _path(path)
                    if not isinstance(failure, dict) or any(
                        not isinstance(failure.get(field), str) for field in ("code", "at", "retry_at")
                    ):
                        raise ValueError("Invalid stored document failure")
                    if failure.get("revision") is not None and (
                        not isinstance(failure["revision"], str) or not REVISION_RE.fullmatch(failure["revision"])
                    ):
                        raise ValueError("Invalid stored failure revision")
            elif key == "last_failure" and value is not None:
                if not isinstance(value, dict) or any(
                    not isinstance(value.get(field), str) for field in ("code", "at")
                ):
                    raise ValueError("Invalid stored source failure")
            elif key in {"retry_at", "observed_at", "observed_revision"} and value is not None:
                if not isinstance(value, str):
                    raise ValueError("Invalid stored observation")
                if key == "observed_revision" and not REVISION_RE.fullmatch(value):
                    raise ValueError("Invalid stored revision")
        except (ValueError, TypeError, RecursionError, KnowledgeError):
            raise KnowledgeError("CACHE_INTEGRITY", "Metadados persistidos de uma fonte estão inválidos.") from None
        return value

    @staticmethod
    def _version_metadata(row):
        try:
            raw = row["metadata"]
            if not isinstance(raw, (str, bytes)) or len(raw) > 64 * 1024:
                raise ValueError("Invalid stored version metadata size")
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise TypeError("Invalid stored version metadata")
        except (ValueError, TypeError, RecursionError):
            raise KnowledgeError("CACHE_INTEGRITY", "Metadados persistidos da evidência estão inválidos.") from None
        return value

    @staticmethod
    def _put(db, key, value):
        db.execute("INSERT OR REPLACE INTO metadata VALUES(?,?)", (key, json.dumps(value)))

    def _age(self, value):
        try:
            stamp = datetime.fromisoformat(value)
            if stamp.tzinfo is None:
                return -1
            return (self.clock() - stamp).total_seconds()
        except (TypeError, ValueError):
            return -1

    @staticmethod
    def _deadline(deadline):
        if time.monotonic() >= deadline:
            raise RemoteError("deadline_exceeded")

    def _discover(self, db, deadline):
        self._deadline(deadline)
        old = self._meta(db, "catalog")
        discovered = self.adapter.discover(old, deadline)
        self._deadline(deadline)
        if (
            not isinstance(discovered, dict)
            or not isinstance(discovered.get("revision"), str)
            or not REVISION_RE.fullmatch(discovered["revision"])
        ):
            raise RemoteError("invalid_catalog_revision")
        # Publish an observed head immediately: failed parsing/discovery must not
        # leave old evidence looking current after a new revision was observed.
        self._put(db, "observed_revision", discovered["revision"])
        self._put(db, "observed_at", _stamp(self.clock()))
        db.commit()
        entries = discovered.get("entries")
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
            raise RemoteError("invalid_catalog_entries")
        normalized, seen = [], set()
        previous = {entry["path"]: entry for entry in (old or {}).get("entries", [])}
        for entry in entries:
            if not isinstance(entry, dict):
                raise RemoteError("invalid_catalog_entry")
            try:
                path = _path(entry.get("path"))
            except KnowledgeError:
                raise RemoteError("invalid_catalog_path") from None
            title = entry.get("title", path)
            if path in seen or not isinstance(title, str) or not title.strip() or len(title) > 1024:
                raise RemoteError("invalid_catalog_entry")
            seen.add(path)
            item = {**entry, "path": path, "title": title}
            if self.per_document_revisions:
                revision = item.get("revision")
                if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
                    raise RemoteError("invalid_document_revision")
                checked = item.pop("_checked", False)
                if type(checked) is not bool:
                    raise RemoteError("invalid_document_check")
                prior = previous.get(path, {})
                item["checked_at"] = (
                    _stamp(self.clock())
                    if checked
                    else prior.get("checked_at")
                    if prior.get("revision") == revision
                    else None
                )
            normalized.append(item)
        catalog = {**discovered, "entries": normalized, "checked_at": _stamp(self.clock())}
        if len(json.dumps(catalog, ensure_ascii=False).encode()) > MAX_CATALOG_BYTES:
            raise RemoteError("catalog_too_large")
        with db:
            self._put(db, "catalog", catalog)
            self._put(db, "last_failure", None)
            self._put(db, "retry_at", None)
        return catalog

    def _failure(self, db, exc):
        code = exc.code if isinstance(exc, RemoteError) else "source_unavailable"
        delay = 900 if code in {"http_403", "http_429"} else 60
        try:
            delay = max(60, min(86400, int(getattr(exc, "retry_after", None))))
        except (ValueError, TypeError):
            pass
        with db:
            self._put(db, "last_failure", {"code": code, "at": _stamp(self.clock())})
            self._put(db, "retry_at", _stamp(self.clock() + timedelta(seconds=delay)))
        return code

    def _document_failure(self, db, path, revision, code):
        failures = self._meta(db, "document_failures", {})
        failures.pop(path, None)
        failures[path] = {
            "revision": revision,
            "code": code,
            "at": _stamp(self.clock()),
            "retry_at": _stamp(self.clock() + timedelta(seconds=60)),
        }
        # Repeated misses must not grow an unbounded negative cache.
        while len(failures) > 1000:
            failures.pop(next(iter(failures)))
        with db:
            self._put(db, "document_failures", failures)

    def _document_recovered(self, db, path):
        failures = self._meta(db, "document_failures", {})
        if path in failures:
            failures.pop(path)
            self._put(db, "document_failures", failures)

    def _scoped_failure(self, db, exc, catalog, approved_paths):
        """Only explicit, allowlisted document failures bypass source cooldown."""
        path = getattr(exc, "document_path", None)
        if not self.per_document_revisions or path is None:
            return False
        try:
            _path(path)
        except KnowledgeError:
            return False
        entries = {item["path"]: item for item in (catalog or {}).get("entries", [])}
        if path not in entries and path not in approved_paths:
            return False
        revision = entries.get(path, {}).get("revision")
        code = exc.code if isinstance(exc, RemoteError) else "source_unavailable"
        self._document_failure(db, path, revision, code)
        return True

    def _entry_revision(self, entry, catalog):
        return entry["revision"] if self.per_document_revisions else catalog["revision"]

    def _candidates(self, query, catalog, limit, path):
        if not catalog:
            return []
        entries = catalog.get("entries", []) if catalog else []
        registered = {entry["path"]: entry for entry in entries}
        if path is not None:
            return [registered[path]] if path in registered else []
        selector = getattr(self.adapter, "candidates", None)
        if selector:
            selected = selector(query, catalog or {}, limit, path)
            if not isinstance(selected, list) or len(selected) > limit:
                raise RemoteError("invalid_candidates")
            # Return the registered version, never fields supplied by a selector.
            paths = [entry.get("path") if isinstance(entry, dict) else entry for entry in selected]
            if any(not isinstance(item, str) or item not in registered for item in paths):
                raise RemoteError("unregistered_candidate")
            return [registered[item] for item in dict.fromkeys(paths)]
        terms = set(_words(query))
        scored = [
            (len(terms & set(_words(entry["path"] + " " + entry["title"]))), entry) for entry in entries
        ]
        scored.sort(key=lambda pair: (-pair[0], pair[1]["path"]))
        return [entry for score, entry in scored if score][:limit]

    def _load(self, db, entry, catalog, deadline):
        self._deadline(deadline)
        path, revision = entry["path"], self._entry_revision(entry, catalog)
        document_id = "doc_" + digest(f"{self.source_id}:{path}".encode())[:32]
        row = db.execute(
            "SELECT * FROM versions WHERE document_id=? AND revision=?", (document_id, revision)
        ).fetchone()
        if row:
            self._verify(row)
            fingerprint = getattr(self.adapter, "fingerprint", None)
            if fingerprint is None or self._version_metadata(row).get("adapter_fingerprint") == fingerprint:
                with db:
                    db.execute("INSERT OR REPLACE INTO active VALUES(?,?)", (path, row["id"]))
                    self._document_recovered(db, path)
                return
        self._deadline(deadline)
        # Only an adapter that can prove immutable origin identity may rebuild
        # its current projection from a verified existing original.
        reprocess = getattr(self.adapter, "load_cached", None)
        loaded = reprocess(entry, revision, dict(row), deadline) if row and callable(reprocess) else None
        if loaded is None:
            loaded = self.adapter.load(entry, revision, deadline)
        self._deadline(deadline)
        if (
            not isinstance(loaded, dict)
            or not isinstance(loaded.get("raw"), bytes)
            or not 0 < len(loaded["raw"]) <= self.max_bytes
        ):
            raise RemoteError("invalid_source_bytes")
        raw, text = loaded["raw"], loaded.get("text")
        title = loaded.get("title", entry["title"])
        metadata = loaded.get("metadata", {})
        if (
            not isinstance(text, str)
            or not text.strip()
            or "\x00" in text
            or len(text.encode("utf-8")) > MAX_TEXT_BYTES
        ):
            raise RemoteError("invalid_source_text")
        if (
            not isinstance(title, str)
            or not title.strip()
            or len(title) > 1024
            or not isinstance(metadata, dict)
        ):
            raise RemoteError("invalid_source_metadata")
        fingerprint = getattr(self.adapter, "fingerprint", None)
        if fingerprint is not None:
            metadata = {**metadata, "adapter_fingerprint": fingerprint}
        encoded_meta = json.dumps(metadata, ensure_ascii=False)
        if (
            len(encoded_meta.encode()) > 64 * 1024
            or not _https(loaded.get("url"))
            or not _https(loaded.get("license_reference"))
        ):
            raise RemoteError("invalid_source_provenance")
        original_hash, text_hash = digest(raw), digest(text.encode("utf-8"))
        if row and original_hash != row["original_hash"]:
            raise KnowledgeError("CACHE_INTEGRITY", "Os bytes de uma revisão imutável foram alterados.")
        checked_at = (
            entry.get("checked_at") if self.per_document_revisions else catalog["checked_at"]
        ) or _stamp(self.clock())
        with db:
            db.execute("BEGIN IMMEDIATE")
            if row:
                # A revised adapter may derive different searchable text and
                # attribution from the same original. Preserve the original
                # identity/bytes while atomically refreshing that projection.
                db.execute(
                    "UPDATE versions SET text=?,text_hash=?,title=?,url=?,license_reference=?,metadata=?,checked_at=? WHERE id=?",
                    (
                        text,
                        text_hash,
                        title,
                        loaded["url"],
                        loaded["license_reference"],
                        encoded_meta,
                        checked_at,
                        row["id"],
                    ),
                )
                db.execute("UPDATE evidence_fts SET title=?,text=? WHERE rowid=?", (title, text, row["id"]))
                db.execute("INSERT OR REPLACE INTO active VALUES(?,?)", (path, row["id"]))
                self._document_recovered(db, path)
                return
            count, used = db.execute("SELECT count(*),coalesce(sum(length(raw)),0) FROM versions").fetchone()
            if count >= self.max_versions or used + len(raw) > self.cache_bytes:
                raise RemoteError("cache_capacity_reached")
            inserted = db.execute(
                "INSERT INTO versions(document_id,path,revision,original_hash,raw,text,text_hash,title,url,license_reference,metadata,checked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    document_id,
                    path,
                    revision,
                    original_hash,
                    raw,
                    text,
                    text_hash,
                    title,
                    loaded["url"],
                    loaded["license_reference"],
                    encoded_meta,
                    checked_at,
                ),
            )
            db.execute(
                "INSERT INTO evidence_fts(rowid,title,text) VALUES(?,?,?)", (inserted.lastrowid, title, text)
            )
            db.execute("INSERT OR REPLACE INTO active VALUES(?,?)", (path, inserted.lastrowid))
            self._document_recovered(db, path)

    @staticmethod
    def _verify(row):
        if (
            digest(row["raw"]) != row["original_hash"]
            or digest(row["text"].encode("utf-8")) != row["text_hash"]
        ):
            raise KnowledgeError("CACHE_INTEGRITY", "A integridade de uma evidência em cache falhou.")

    def _configuration_matches(self, catalog):
        fingerprint = getattr(self.adapter, "fingerprint", None)
        return fingerprint is None or catalog.get("adapter_fingerprint") == fingerprint

    def _state(self, db, row):
        observed = self._meta(db, "observed_revision")
        catalog = self._meta(db, "catalog", {})
        if not self._configuration_matches(catalog):
            return "unknown"
        entry = next((item for item in catalog.get("entries", []) if item["path"] == row["path"]), None)
        if self.per_document_revisions:
            if entry and entry["revision"] != row["revision"]:
                return "superseded"
        elif observed and observed != row["revision"]:
            return "superseded"
        if catalog and entry is None:
            return "superseded"
        fingerprint = getattr(self.adapter, "fingerprint", None)
        if fingerprint is not None and self._version_metadata(row).get("adapter_fingerprint") != fingerprint:
            return "unknown"
        if self._meta(db, "last_failure"):
            return "unknown"
        failure = self._meta(db, "document_failures", {}).get(row["path"])
        if failure and failure["revision"] in {None, row["revision"]}:
            return "unknown"
        age = self._age(
            (entry or {}).get("checked_at") if self.per_document_revisions else catalog.get("checked_at")
        )
        return "unknown" if age < 0 else "stale" if age > self.ttl_seconds else "current"

    def _citation(self, db, row):
        catalog = self._meta(db, "catalog", {})
        current = (
            next((entry for entry in catalog.get("entries", []) if entry["path"] == row["path"]), {})
            if self.per_document_revisions
            else catalog
        )
        return {
            "store": "cache",
            "source_id": self.source_id,
            "document_id": row["document_id"],
            "path": row["path"],
            "revision": row["revision"],
            "original_hash": row["original_hash"],
            "url": row["url"],
            "license_reference": row["license_reference"],
            "checked_at": current.get("checked_at")
            if current.get("revision") == row["revision"]
            else row["checked_at"],
            "freshness": self._state(db, row),
            "metadata": self._version_metadata(row),
            "untrusted": True,
        }

    @staticmethod
    def _passages(text, query):
        terms, ids = set(_words(query)), EXACT_RE.findall(query)
        candidates = []
        for index, group in enumerate(re.split(r"(?m)(?=^#{1,6} )", text)):
            if not re.sub(r"(?m)^#{1,6}[^\n]*$", "", group).strip():
                continue
            for start in range(0, len(group), 1000):
                part = group[start : start + 1200]
                exact = _exact_matches(part, ids)
                score = len(set(_words(part)) & terms) + (50 if ids and exact else 0)
                if ids and not exact:
                    continue
                candidates.append((score, index, start, part))
        candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
        return [
            {
                "section_id": f"section-{index}:{start}",
                "text": text,
                "untrusted": True,
                "representation": "derived_text_excerpt",
            }
            for _, index, start, text in candidates[:2]
        ]

    def research(self, query, *, freshness="auto", limit=3, path=None, deadline=None):
        if not isinstance(query, str) or not query.strip() or len(query) > 4000:
            raise KnowledgeError("INVALID_ARGUMENT", "query deve conter 1 a 4000 caracteres.")
        if not isinstance(freshness, str) or freshness not in {"auto", "refresh", "offline"}:
            raise KnowledgeError("INVALID_ARGUMENT", "freshness deve ser auto, refresh ou offline.")
        if type(limit) is not int or not 1 <= limit <= 3:
            raise KnowledgeError("INVALID_ARGUMENT", "limit deve estar entre 1 e 3.")
        if path is not None:
            _path(path)
        if deadline is not None and (type(deadline) not in {int, float} or not math.isfinite(deadline)):
            raise KnowledgeError("INVALID_ARGUMENT", "deadline deve ser um instante monotônico finito.")
        deadline = (
            min(deadline, time.monotonic() + self.request_budget_seconds)
            if deadline is not None
            else time.monotonic() + self.request_budget_seconds
        )
        with self._lock, closing(self._connect()) as db:
            warnings = []
            remote_status = "offline" if freshness == "offline" else "cache_hit"
            catalog = self._meta(db, "catalog")
            approved_paths, selected_before = set(), []
            if freshness != "offline":
                prepared = False
                try:
                    self._deadline(deadline)
                    prepare = getattr(self.adapter, "prepare", None)
                    if prepare is not None:
                        prepared = prepare(query, path, catalog)
                        if type(prepared) is not bool:
                            raise RemoteError("invalid_prepare_result")
                    if self.per_document_revisions:
                        requested = getattr(self.adapter, "requested_paths", [])
                        if not isinstance(requested, list) or len(requested) > 3:
                            raise RemoteError("invalid_requested_paths")
                        try:
                            approved_paths = {_path(item) for item in requested}
                        except KnowledgeError:
                            raise RemoteError("invalid_requested_paths") from None
                        selected_before = self._candidates(query, catalog, limit, path)
                    self._deadline(deadline)
                except (RemoteError, OSError, ValueError, TypeError) as exc:
                    # Preparing a selection is local input handling. Rejection
                    # does not establish an outage or invalidate other records.
                    code = exc.code if isinstance(exc, RemoteError) else "selection_unavailable"
                    remote_status = "failed"
                    warnings.append(f"Preparação da consulta falhou: {code}.")
                retry_at = self._meta(db, "retry_at")
                age = self._age(catalog.get("checked_at")) if catalog else -1
                needs_check = (
                    freshness == "refresh"
                    or prepared
                    or not catalog
                    or not 0 <= age <= self.ttl_seconds
                    or self._meta(db, "last_failure")
                    or self.per_document_revisions
                    and any(
                        not 0 <= self._age(entry.get("checked_at")) <= self.ttl_seconds
                        or entry["path"] in self._meta(db, "document_failures", {})
                        for entry in selected_before
                    )
                )
                requested = approved_paths | {entry["path"] for entry in selected_before}
                document_retry = self._meta(db, "document_failures", {})
                retrying_document = self.per_document_revisions and any(
                    item in document_retry and self._age(document_retry[item]["retry_at"]) < 0
                    for item in requested
                )
                if remote_status == "failed":
                    pass
                elif retrying_document:
                    remote_status = "cooldown"
                    warnings.append(
                        "Nova tentativa deste documento adiada; outros documentos permanecem disponíveis."
                    )
                elif retry_at and self._age(retry_at) < 0:
                    remote_status = "cooldown"
                    warnings.append("Nova tentativa remota adiada; cache não foi revalidado.")
                elif needs_check:
                    try:
                        catalog = self._discover(db, deadline)
                        remote_status = "verified"
                    except (RemoteError, OSError, ValueError, TypeError) as exc:
                        scoped = self._scoped_failure(db, exc, catalog, approved_paths)
                        code = (
                            (exc.code if isinstance(exc, RemoteError) else "source_unavailable")
                            if scoped
                            else self._failure(db, exc)
                        )
                        remote_status = "failed"
                        warnings.append(f"Verificação remota falhou: {code}; versões anteriores preservadas.")
            try:
                candidates = self._candidates(query, catalog, limit, path)
            except (RemoteError, ValueError, TypeError) as exc:
                code = self._failure(db, exc)
                candidates, remote_status = [], "failed"
                warnings.append(f"Seleção de fonte falhou: {code}.")
            if path is not None and not candidates:
                warnings.append(
                    "Caminho ausente do catálogo disponível; nenhum endereço arbitrário foi acessado."
                )
            if freshness != "offline" and remote_status not in {"failed", "cooldown"}:
                for candidate in candidates:
                    failure = self._meta(db, "document_failures", {}).get(candidate["path"])
                    if (
                        failure
                        and failure["revision"] in {None, self._entry_revision(candidate, catalog)}
                        and self._age(failure["retry_at"]) < 0
                    ):
                        remote_status = "failed"
                        warnings.append(
                            f"Coleta deste documento adiada: {failure['code']}; outros documentos permanecem disponíveis."
                        )
                        continue
                    try:
                        self._load(db, candidate, catalog, deadline)
                    except (RemoteError, OSError, ValueError, TypeError) as exc:
                        if (
                            isinstance(exc, RemoteError) and exc.code == "http_404"
                        ) or self.per_document_revisions:
                            code = exc.code if isinstance(exc, RemoteError) else "source_unavailable"
                            self._document_failure(
                                db, candidate["path"], self._entry_revision(candidate, catalog), code
                            )
                            remote_status = "failed"
                            warnings.append(
                                f"Coleta deste documento falhou: {code}; outros documentos permanecem disponíveis."
                            )
                            continue
                        code = self._failure(db, exc)
                        remote_status = "failed"
                        warnings.append(f"Coleta remota falhou: {code}; versões anteriores preservadas.")
                        break
            terms, ids = _words(query), EXACT_RE.findall(query)
            row_ids = []
            if terms:
                match = " OR ".join('"' + term + '"' for term in terms)
                row_ids = [
                    row[0]
                    for row in db.execute(
                        "SELECT v.id FROM evidence_fts JOIN versions v ON v.id=evidence_fts.rowid JOIN active a ON a.version_id=v.id WHERE evidence_fts MATCH ? ORDER BY bm25(evidence_fts) LIMIT 30",
                        (match,),
                    )
                ]
            for candidate in candidates:
                row = db.execute(
                    "SELECT version_id FROM active WHERE path=?", (candidate["path"],)
                ).fetchone()
                if row and row[0] not in row_ids:
                    row_ids.append(row[0])
            results = []
            for row_id in row_ids:
                # At most 30 candidate rows; large original BLOBs are loaded only
                # for rows whose derived text matches the requested identifiers.
                summary = db.execute("SELECT path,text FROM versions WHERE id=?", (row_id,)).fetchone()
                if (path is not None and summary["path"] != path) or not _exact_matches(summary["text"], ids):
                    continue
                passages = self._passages(summary["text"], query)
                if not passages:
                    continue
                row = db.execute("SELECT * FROM versions WHERE id=?", (row_id,)).fetchone()
                self._verify(row)
                citation = self._citation(db, row)
                reference = {
                    key: citation[key] for key in ("store", "document_id", "revision", "original_hash")
                }
                results.append(
                    {
                        **citation,
                        "title": row["title"],
                        "passages": passages,
                        "citation": citation,
                        "status": citation["freshness"],
                        "reference": reference,
                        "evidence_reference": reference,
                    }
                )
                if len(results) >= limit:
                    break
            if any(item["freshness"] != "current" for item in results):
                warnings.append(
                    "Há evidências sem confirmação de atualidade; consulte freshness de cada resultado."
                )
            return {
                "results": results,
                "citations": [item["citation"] for item in results],
                "warnings": warnings,
                "remote_status": remote_status,
                "catalog": self._catalog(db),
                "retrieval_profile": "lexical_cache_and_adapter_discovery",
                "discovery_limit": "Somente a cobertura declarada do adaptador; não é busca semântica de toda a internet.",
            }

    def _catalog(self, db):
        catalog = self._meta(db, "catalog", {})
        count, size = db.execute("SELECT count(*),coalesce(sum(length(raw)),0) FROM versions").fetchone()
        entries = catalog.get("entries", [])
        return {
            "source_id": self.source_id,
            "revision_scope": "document" if self.per_document_revisions else "source",
            "revision": catalog.get("revision"),
            "checked_at": catalog.get("checked_at"),
            "observed_revision": self._meta(db, "observed_revision"),
            "known_paths": len(entries),
            "paths": [entry["path"] for entry in entries[:200]],
            "paths_truncated": len(entries) > 200,
            "cached_versions": count,
            "cached_bytes": size,
            "ttl_seconds": self.ttl_seconds,
            "request_budget_seconds": self.request_budget_seconds,
            "max_bytes": self.cache_bytes,
            "max_versions": self.max_versions,
            "last_failure": self._meta(db, "last_failure")
            or (
                {"code": "source_configuration_changed"}
                if catalog and not self._configuration_matches(catalog)
                else None
            ),
            "retry_at": self._meta(db, "retry_at"),
            "document_failures": len(self._meta(db, "document_failures", {})),
        }

    def catalog(self):
        with self._lock, closing(self._connect()) as db:
            return self._catalog(db)

    def source_revision(self):
        if self.per_document_revisions:
            return None
        with self._lock, closing(self._connect()) as db:
            revision = self._meta(db, "observed_revision")
            catalog = self._meta(db, "catalog", {})
            return (
                {
                    "revision": revision,
                    "checked_at": self._meta(db, "observed_at"),
                    "last_failure": self._meta(db, "last_failure")
                    or (
                        {"code": "source_configuration_changed"}
                        if not self._configuration_matches(catalog)
                        else None
                    ),
                }
                if revision
                else None
            )

    def has_document(self, document_id):
        if not isinstance(document_id, str) or not DOC_RE.fullmatch(document_id) or not self.path.exists():
            return False
        with self._lock, closing(sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)) as db:
            return (
                db.execute("SELECT 1 FROM versions WHERE document_id=? LIMIT 1", (document_id,)).fetchone()
                is not None
            )

    def _read_original(self, db, row, offset):
        key = (str(self.path), row["document_id"], row["revision"], row["original_hash"], row["text_hash"])
        with _READ_BUFFER_LOCK:
            now = time.monotonic()
            for old_key, (_, verified_mono, _) in list(_READ_BUFFERS.items()):
                if not 0 <= now - verified_mono <= READ_BUFFER_TTL:
                    _READ_BUFFERS.pop(old_key)
            if offset and key in _READ_BUFFERS:
                raw, _, verified_at = _READ_BUFFERS[key]
                _READ_BUFFERS.move_to_end(key)
                return row, raw, verified_at, True
        # Page zero and a missing/expired buffer verify the full stored original
        # and derived text. Later pages return those same immutable bytes, not a
        # claim that the database original was reread and rehashed on every page.
        row = db.execute("SELECT * FROM versions WHERE id=?", (row["id"],)).fetchone()
        self._verify(row)
        raw, verified_at = row["raw"], _stamp(self.clock())
        key = (str(self.path), row["document_id"], row["revision"], row["original_hash"], row["text_hash"])
        with _READ_BUFFER_LOCK:
            _READ_BUFFERS.pop(key, None)
            if len(raw) <= READ_BUFFER_BYTES:
                used = sum(len(item[0]) for item in _READ_BUFFERS.values())
                while _READ_BUFFERS and used + len(raw) > READ_BUFFER_BYTES:
                    _, removed = _READ_BUFFERS.popitem(last=False)
                    used -= len(removed[0])
                _READ_BUFFERS[key] = (raw, time.monotonic(), verified_at)
        return row, raw, verified_at, False

    def get_document(self, document_id, revision=None, offset=0):
        if not isinstance(document_id, str) or not DOC_RE.fullmatch(document_id):
            raise KnowledgeError("INVALID_ARGUMENT", "Identificador de cache inválido.")
        if revision is not None and (not isinstance(revision, str) or not REVISION_RE.fullmatch(revision)):
            raise KnowledgeError("INVALID_ARGUMENT", "Revisão de cache inválida.")
        if type(offset) is not int or offset < 0 or (offset and revision is None):
            raise KnowledgeError("INVALID_ARGUMENT", "Paginação exige offset não negativo e revisão fixa.")
        with self._lock, closing(self._connect()) as db:
            if revision:
                row = db.execute(
                    f"SELECT {DOCUMENT_COLUMNS} FROM versions WHERE document_id=? AND revision=?",
                    (document_id, revision),
                ).fetchone()
            else:
                columns = ",".join(f"v.{column}" for column in DOCUMENT_COLUMNS.split(","))
                row = db.execute(
                    f"SELECT {columns} FROM versions v JOIN active a ON a.version_id=v.id WHERE document_id=?",
                    (document_id,),
                ).fetchone()
            if row is None:
                raise KnowledgeError("NOT_FOUND", "Documento não encontrado neste cache.")
            row, raw, verified_at, reused = self._read_original(db, row, offset)
            if offset and offset >= len(raw):
                raise KnowledgeError("INVALID_ARGUMENT", "offset ultrapassa o documento.")
            part = raw[offset : offset + 9000]
            end = offset + len(part)
            citation = self._citation(db, row)
            return {
                **citation,
                "citation": citation,
                "evidence_reference": {
                    key: citation[key] for key in ("store", "document_id", "revision", "original_hash")
                },
                "content": base64.b64encode(part).decode(),
                "text": part.decode("utf-8", errors="replace"),
                "encoding": "base64",
                "offset": offset,
                "part_hash": digest(part),
                "integrity": {
                    "original_verified_at": verified_at,
                    "read_from_verified_buffer": reused,
                    "part_hash_algorithm": "sha256",
                },
                "total_bytes": len(raw),
                "complete": offset == 0 and end == len(raw),
                "last_part": end == len(raw),
                "next_offset": end if end < len(raw) else None,
            }

    def resolve_reference(self, reference):
        if (
            not isinstance(reference, dict)
            or set(reference) != {"store", "document_id", "revision", "original_hash"}
            or reference.get("store") != "cache"
            or not isinstance(reference.get("original_hash"), str)
            or not HASH_RE.fullmatch(reference["original_hash"])
        ):
            raise KnowledgeError("INVALID_ARGUMENT", "Referência de cache inválida.")
        try:
            document = self.get_document(reference["document_id"], reference["revision"])
        except KnowledgeError as exc:
            if exc.code != "NOT_FOUND":
                raise
            return {"state": "missing", "citation": None, "reference": reference}
        if document["original_hash"] != reference["original_hash"]:
            return {"state": "missing", "citation": None, "reference": reference}
        return {"state": document["freshness"], "citation": document["citation"], "reference": reference}

    def latest_state(self, document_id, revision, original_hash, *, reference_checked_at=None):
        with self._lock, closing(self._connect()) as db:
            catalog = self._meta(db, "catalog", {})
            if catalog and not self._configuration_matches(catalog):
                return "unknown"
            if reference_checked_at is not None:
                entry = next(
                    (
                        item
                        for item in catalog.get("entries", [])
                        if document_id == "doc_" + digest(f"{self.source_id}:{item['path']}".encode())[:32]
                    ),
                    None,
                )
                if self.per_document_revisions and entry is None:
                    return None
                scoped_failure = self._meta(db, "document_failures", {}).get((entry or {}).get("path"))
                observation = {
                    "checked_at": (entry or {}).get("checked_at")
                    if self.per_document_revisions
                    else self._meta(db, "observed_at"),
                    "last_failure": self._meta(db, "last_failure") or scoped_failure,
                }
                order = observation_order(reference_checked_at, observation, now=self.clock())
                if order != "newer":
                    return None if order == "older" else "unknown"
            observed = self._meta(db, "observed_revision")
            if not self.per_document_revisions and observed and observed != revision:
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
            if self._meta(db, "last_failure"):
                return "unknown"
            catalog = self._meta(db, "catalog", {})
            for path, failure in self._meta(db, "document_failures", {}).items():
                if (
                    failure["revision"] in {None, revision}
                    and document_id == "doc_" + digest(f"{self.source_id}:{path}".encode())[:32]
                ):
                    return "unknown"
            if not catalog:
                return None
            if self.per_document_revisions:
                entry = next(
                    (
                        item
                        for item in catalog["entries"]
                        if document_id == "doc_" + digest(f"{self.source_id}:{item['path']}".encode())[:32]
                    ),
                    None,
                )
                if entry and entry["revision"] != revision:
                    return "superseded"
                # A registered entry without stored bytes cannot authenticate a
                # caller-supplied content hash or establish that evidence exists.
                return None
            known_ids = {
                "doc_" + digest(f"{self.source_id}:{entry['path']}".encode())[:32]
                for entry in catalog["entries"]
            }
            if document_id not in known_ids:
                return "superseded"
            age = self._age(catalog.get("checked_at"))
            return "unknown" if age < 0 else "stale" if age > self.ttl_seconds else "current"
