"""Local, explicitly submitted notes with evidence links, never trusted source facts.

Link validation establishes provenance, not truth or entailment. Notes are not used
to train a model. They remain local to this data directory until a client reads
them; the client may then send them to its own model provider. Expiry and deletion
remove live database/index records, not filesystem snapshots or external backups.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import threading
import time
from collections.abc import Callable
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path

from .models import KnowledgeError

MAX_NOTES = 1000
MAX_TEXT_BYTES = 8 * 1024 * 1024
REFERENCE_KEYS = {"store", "document_id", "revision", "original_hash", "snapshot_id"}
STATES = {"current", "stale", "superseded", "missing", "unknown"}
NOTICE = "Memória derivada não verificada: referências válidas não comprovam a conclusão da nota."


def _text(value, name, maximum):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise KnowledgeError("INVALID_ARGUMENT", f"{name} exige texto não vazio de até {maximum} caracteres.")
    return value.strip()


def _stamp(instant):
    return datetime.fromtimestamp(instant, UTC).isoformat().replace("+00:00", "Z")


def _references(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 8:
        raise KnowledgeError("INVALID_ARGUMENT", "references exige de 1 a 8 referências de evidência.")
    normalized = []
    for item in value:
        if not isinstance(item, dict) or set(item) - REFERENCE_KEYS:
            raise KnowledgeError(
                "INVALID_ARGUMENT", "Referência desconhecida; não forneça URLs ou citações livres."
            )
        if not {"store", "document_id", "revision", "original_hash"} <= set(item):
            raise KnowledgeError("INVALID_ARGUMENT", "Referência incompleta.")
        store = item.get("store")
        if not isinstance(store, str) or store not in {"snapshot", "cache"}:
            raise KnowledgeError("INVALID_ARGUMENT", "store deve ser snapshot ou cache.")
        reference = {
            "store": store,
            "document_id": _text(item.get("document_id"), "document_id", 128),
            "revision": _text(item.get("revision"), "revision", 256),
            "original_hash": _text(item.get("original_hash"), "original_hash", 64),
        }
        if not re.fullmatch(r"[0-9a-f]{64}", reference["original_hash"]):
            raise KnowledgeError(
                "INVALID_ARGUMENT", "original_hash deve ser um SHA256 hexadecimal minúsculo."
            )
        if store == "snapshot":
            reference["snapshot_id"] = _text(item.get("snapshot_id"), "snapshot_id", 128)
        elif "snapshot_id" in item:
            raise KnowledgeError("INVALID_ARGUMENT", "Referências cache não aceitam snapshot_id.")
        if reference not in normalized:
            normalized.append(reference)
    return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True))


def _resolve(resolver, reference):
    try:
        result = resolver(dict(reference))
    except (KnowledgeError, OSError, sqlite3.Error, ValueError, KeyError, TypeError):
        return {"state": "unknown", "citation": None}
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("state"), str)
        or result["state"] not in STATES
    ):
        return {"state": "unknown", "citation": None}
    if result["state"] == "current" and not isinstance(result.get("citation"), dict):
        return {"state": "unknown", "citation": None}
    return result


class MemoryStore:
    """A bounded lexical note store. The caller supplies a trusted evidence resolver.

    The resolver receives a canonical reference and returns ``{state, citation}``.
    Only ``current`` links may be saved or returned as usable notes. Superseded or
    missing links permanently invalidate the note; transient unknown/stale states
    suppress it until evidence can be verified again. Resolver metadata is never
    accepted directly from the MCP caller.
    """

    def __init__(self, data_dir: Path, *, clock: Callable[[], float] | None = None):
        self.path = Path(data_dir).resolve() / "memory" / "memory.sqlite3"
        self.clock = clock or time.time
        self._lock = threading.RLock()

    def _now(self):
        value = self.clock()
        if isinstance(value, datetime):
            if value.tzinfo is None:
                raise ValueError("Memory clock requires an aware datetime")
            value = value.timestamp()
        if type(value) not in {int, float} or not math.isfinite(value) or not 0 <= value < 253402300799:
            raise ValueError("Invalid memory clock")
        return value

    @contextmanager
    def _db(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            db = sqlite3.connect(self.path, timeout=5)
            db.row_factory = sqlite3.Row
            try:
                db.execute("PRAGMA journal_mode=DELETE")
                db.execute("PRAGMA secure_delete=ON")
                db.execute("""CREATE TABLE IF NOT EXISTS notes (
                    memory_id TEXT PRIMARY KEY, text TEXT NOT NULL, references_json TEXT NOT NULL,
                    created_at REAL NOT NULL, expires_at REAL NOT NULL,
                    invalid_reason TEXT, text_bytes INTEGER NOT NULL)""")
                db.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(memory_id UNINDEXED, text)"
                )
                db.commit()
                db.execute("BEGIN IMMEDIATE")
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()

    @staticmethod
    def _rebuild_index(db):
        # Drop/rebuild bounded index so deleted text does not remain in FTS merge
        # segments on older SQLite versions without FTS5 secure-delete support.
        db.execute("DROP TABLE notes_fts")
        db.execute("CREATE VIRTUAL TABLE notes_fts USING fts5(memory_id UNINDEXED, text)")
        db.execute("INSERT INTO notes_fts(memory_id,text) SELECT memory_id,text FROM notes")

    def _prune(self, db, now):
        deleted = db.execute("DELETE FROM notes WHERE expires_at <= ?", (now,)).rowcount
        if deleted:
            self._rebuild_index(db)
        return deleted

    @staticmethod
    def _record(row, citations=None, *, full_text=False):
        return {
            "memory_id": row["memory_id"],
            "text": row["text"] if full_text else row["text"][:1200],
            "text_truncated": not full_text and len(row["text"]) > 1200,
            "trust": "derived_unverified",
            "created_at": _stamp(row["created_at"]),
            "expires_at": _stamp(row["expires_at"]),
            "references": json.loads(row["references_json"]),
            "citations": citations or [],
            "evidence_state": "current" if citations else "not_checked",
        }

    def remember(self, text, references, *, resolve_reference, ttl_days=30):
        text = _text(text, "text", 4000)
        references = _references(references)
        if type(ttl_days) is not int or not 1 <= ttl_days <= 90:
            raise KnowledgeError("INVALID_ARGUMENT", "ttl_days deve ser inteiro de 1 a 90.")
        resolved = [_resolve(resolve_reference, ref) for ref in references]
        if any(item["state"] != "current" for item in resolved):
            raise KnowledgeError("EVIDENCE_NOT_CURRENT", "A nota exige referências verificáveis e atuais.")
        canonical = json.dumps(references, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        memory_id = "mem_" + hashlib.sha256((text + "\x00" + canonical).encode()).hexdigest()
        now = self._now()
        with self._db() as db:
            self._prune(db, now)
            existing = db.execute("SELECT * FROM notes WHERE memory_id=?", (memory_id,)).fetchone()
            if existing is not None:
                if existing["invalid_reason"] or existing["created_at"] > now:
                    raise KnowledgeError(
                        "MEMORY_INVALIDATED", "Esta nota foi invalidada; use evidências atuais."
                    )
                return {
                    "status": "ok",
                    "deduplicated": True,
                    "result": self._record(existing, [item["citation"] for item in resolved]),
                    "warnings": [NOTICE, "Nota já existente; a validade não foi prorrogada."],
                }
            count, used = db.execute("SELECT count(*),coalesce(sum(text_bytes),0) FROM notes").fetchone()
            text_bytes = len(text.encode("utf-8"))
            if count >= MAX_NOTES or used + text_bytes > MAX_TEXT_BYTES:
                raise KnowledgeError(
                    "MEMORY_CAPACITY", "Limite da memória atingido; remova notas ou aguarde a expiração."
                )
            db.execute(
                "INSERT INTO notes VALUES(?,?,?,?,?,NULL,?)",
                (memory_id, text, canonical, now, now + ttl_days * 86400, text_bytes),
            )
            db.execute("INSERT INTO notes_fts(memory_id,text) VALUES(?,?)", (memory_id, text))
            row = db.execute("SELECT * FROM notes WHERE memory_id=?", (memory_id,)).fetchone()
            return {
                "status": "ok",
                "deduplicated": False,
                "result": self._record(row, [item["citation"] for item in resolved]),
                "warnings": [NOTICE],
            }

    def search(self, query, *, resolve_reference, limit=5, source_ids=None):
        query = _text(query, "query", 4000)
        if type(limit) is not int or not 1 <= limit <= 10:
            raise KnowledgeError("INVALID_ARGUMENT", "limit deve estar entre 1 e 10.")
        if source_ids is not None:
            if not isinstance(source_ids, list) or not 1 <= len(source_ids) <= 64:
                raise KnowledgeError(
                    "INVALID_ARGUMENT", "source_ids exige uma lista não vazia de até 64 fontes."
                )
            source_ids = {_text(value, "source_id", 64) for value in source_ids}
        tokens = list(dict.fromkeys(re.findall(r"[^\W_]+", query, re.UNICODE)))[:32]
        now = self._now()
        results, suppressed = [], {}
        with self._db() as db:
            expired = self._prune(db, now)
            if not tokens:
                return {
                    "status": "no_results",
                    "results": [],
                    "warnings": [NOTICE],
                    "suppressed": {},
                    "expired_removed": expired,
                }
            expression = " OR ".join('"' + token.replace('"', '""') + '"' for token in tokens)
            # Bound resolver work independently of total store size. Suppression
            # can yield fewer results; it never causes unbounded revalidation.
            rows = db.execute(
                """SELECT n.* FROM notes_fts JOIN notes n USING(memory_id)
                WHERE notes_fts MATCH ? ORDER BY bm25(notes_fts),n.memory_id LIMIT 50""",
                (expression,),
            ).fetchall()
            for row in rows:
                reason = row["invalid_reason"]
                resolved = []
                if not reason and row["created_at"] > now:
                    reason = "clock_rollback"
                if not reason:
                    references = _references(json.loads(row["references_json"]))
                    resolved = [_resolve(resolve_reference, ref) for ref in references]
                    states = {item["state"] for item in resolved}
                    reason = next(
                        (state for state in ("superseded", "missing", "unknown", "stale") if state in states),
                        None,
                    )
                    if reason in {"superseded", "missing"}:
                        db.execute(
                            "UPDATE notes SET invalid_reason=? WHERE memory_id=?", (reason, row["memory_id"])
                        )
                if reason:
                    suppressed[reason] = suppressed.get(reason, 0) + 1
                    continue
                if source_ids is not None and any(
                    item["citation"].get("source_id") not in source_ids for item in resolved
                ):
                    suppressed["source_filter"] = suppressed.get("source_filter", 0) + 1
                    continue
                results.append(self._record(row, [item["citation"] for item in resolved]))
                if len(results) >= limit:
                    break
            warnings = [NOTICE]
            if suppressed:
                warnings.append("Notas fora das fontes selecionadas ou sem evidências atuais foram omitidas.")
            return {
                "status": "ok" if results else "no_results",
                "results": results,
                "warnings": warnings,
                "suppressed": suppressed,
                "expired_removed": expired,
                "retrieval_profile": "lexical",
                "candidate_limit": 50,
                "candidates_truncated": len(rows) == 50,
            }

    def forget(self, memory_id):
        memory_id = _text(memory_id, "memory_id", 68)
        if not re.fullmatch(r"mem_[0-9a-f]{64}", memory_id):
            raise KnowledgeError("INVALID_ARGUMENT", "memory_id inválido.")
        with self._db() as db:
            self._prune(db, self._now())
            deleted = db.execute("DELETE FROM notes WHERE memory_id=?", (memory_id,)).rowcount
            if deleted:
                self._rebuild_index(db)
        return {"status": "ok", "memory_id": memory_id, "deleted": bool(deleted)}

    def status(self):
        """Read counts without creating a store or purging expired rows.

        Expiry removes records on search/remember/forget. Catalog inspection only
        excludes expired notes from active counts and reports pending cleanup.
        """
        now = self._now()
        count = used = invalid = expired = stored = 0
        if self.path.is_file():
            with (
                self._lock,
                closing(sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=5)) as db,
            ):
                count, used, invalid = db.execute(
                    """SELECT count(*),coalesce(sum(text_bytes),0),
                    coalesce(sum(invalid_reason IS NOT NULL),0) FROM notes WHERE expires_at > ?""",
                    (now,),
                ).fetchone()
                expired, stored = db.execute(
                    """SELECT coalesce(sum(expires_at <= ?),0),
                    coalesce(sum(text_bytes),0) FROM notes""",
                    (now,),
                ).fetchone()
        return {
            "notes": count,
            "text_bytes": used,
            "invalidated_notes": invalid,
            "max_notes": MAX_NOTES,
            "max_text_bytes": MAX_TEXT_BYTES,
            "expired_pending": expired,
            "stored_text_bytes": stored,
            "retrieval_profile": "lexical",
            "trust": "derived_unverified",
            "evidence_revalidation": "on_retrieval",
            "warnings": [NOTICE],
        }
