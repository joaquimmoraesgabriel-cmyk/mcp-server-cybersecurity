"""Bounded federation; source failures and currency never bleed into other stores."""

import re
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from .catalog import source_catalog
from .models import KnowledgeError
from .ondemand import REQUEST_BUDGET as OWASP_BUDGET
from .ondemand import TTL_SECONDS as OWASP_TTL
from .ondemand import OnDemandStore, _words
from .remote_cache import RemoteStore, observation_order
from .source_adapters import make_adapter
from .source_registry import SOURCES

RESEARCH_BUDGET = 90.0
GLOBAL_CACHE_BYTES = 4 * 1024 * 1024 * 1024
CACHE_ERRORS = (KnowledgeError, OSError, sqlite3.Error, ValueError, TypeError, KeyError)


class CacheRouter:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self._owasp = None
        self.stores = {}

    @property
    def owasp(self):
        # Opening a damaged cache must not prevent the other stores from opening.
        if self._owasp is None:
            self._owasp = OnDemandStore(self.data_dir)
        return self._owasp

    def backend(self, source_id):
        if source_id == "owasp":
            return self.owasp
        if source_id not in SOURCES:
            return None
        if source_id not in self.stores:
            self.stores[source_id] = RemoteStore(self.data_dir, make_adapter(SOURCES[source_id]))
        return self.stores[source_id]

    def _cache_bytes(self):
        directory = self.data_dir / "ondemand"
        # Include journals and SQLite free pages, not only live evidence rows.
        paths = [*directory.glob("cache.sqlite3*"), *(directory / "sources").glob("*.sqlite3*")]
        return sum(path.stat().st_size for path in paths if path.is_file())

    def _existing_ids(self):
        if self._owasp is not None or (self.data_dir / "ondemand" / "cache.sqlite3").exists():
            yield "owasp"
        for source_id in SOURCES:
            if (
                source_id in self.stores
                or (self.data_dir / "ondemand" / "sources" / f"{source_id}.sqlite3").exists()
            ):
                yield source_id

    def route(self, query, source_ids, freshness):
        if source_ids is not None:
            known = {entry["source_id"] for entry in source_catalog()} | set(SOURCES) | {"owasp", "nvd"}
            if (
                not isinstance(source_ids, list)
                or not 1 <= len(source_ids) <= 64
                or any(not isinstance(value, str) or value not in known for value in source_ids)
            ):
                raise KnowledgeError("INVALID_ARGUMENT", "source_ids deve listar até 64 fontes cadastradas.")
            if len(source_ids) > 3 and freshness != "offline":
                raise KnowledgeError(
                    "INVALID_ARGUMENT",
                    "Selecione até três fontes por chamada remota; use chamadas separadas para as demais.",
                )
            return list(dict.fromkeys(source_ids))
        if freshness == "offline":
            return list(self._existing_ids())
        identifier_routes = (
            (r"\bAML\.(?:TA|T|M|CS)\d{4}(?:\.\d{3})?\b", ("atlas",)),
            (r"\bCVE-\d{4}-\d{4,}\b", ("cve", "kev", "nvd")),
            (r"\bEDB-\d+\b", ("exploit-db",)),
            (r"\bCWE-\d+\b", ("cwe",)),
            (r"\bCAPEC-\d+\b", ("capec",)),
            (r"\bT\d{4}(?:\.\d{3})?\b", ("attack", "attack-mobile", "attack-ics")),
        )
        for pattern, candidates in identifier_routes:
            if re.search(pattern, query, re.IGNORECASE):
                registered = [source_id for source_id in candidates if source_id in SOURCES]
                if registered:
                    return registered
        terms = set(_words(query))
        candidates = [
            (len(terms & set(_words(" ".join(spec.subjects)))), key) for key, spec in SOURCES.items()
        ]
        candidates.append(
            (
                len(terms & {"owasp", "password", "storage", "injection", "xss", "ssrf", "authentication"}),
                "owasp",
            )
        )
        candidates.sort(key=lambda pair: (-pair[0], pair[1]))
        return [key for score, key in candidates if score][:3] or ["owasp"]

    def research_sources(
        self, query, *, source_ids=None, freshness="auto", limit=3, path=None, deadline=None
    ):
        if type(limit) is not int or not 1 <= limit <= 3:
            raise KnowledgeError("INVALID_ARGUMENT", "limit deve estar entre 1 e 3.")
        if not isinstance(freshness, str) or freshness not in {"auto", "refresh", "offline"}:
            raise KnowledgeError("INVALID_ARGUMENT", "freshness: auto, refresh ou offline.")
        selected = self.route(query, source_ids, freshness)
        if path is not None and (source_ids is None or len(selected) != 1):
            raise KnowledgeError("INVALID_ARGUMENT", "path exige exatamente uma fonte explícita.")
        results, warnings, statuses = [], [], {}
        deadline = (
            min(deadline, time.monotonic() + RESEARCH_BUDGET)
            if deadline is not None
            else time.monotonic() + RESEARCH_BUDGET
        )
        for source_id in selected:
            # The legacy OWASP adapter has its own bounded deadline; reserve it
            # before starting. Other adapters inherit the shared deadline.
            reserve = OWASP_BUDGET if source_id == "owasp" and freshness != "offline" else 0
            if time.monotonic() + reserve >= deadline:
                statuses[source_id] = {"remote_status": "budget_exhausted"}
                warnings.append(f"{source_id}: orçamento da pesquisa esgotado; use uma chamada específica.")
                continue
            try:
                backend = self.backend(source_id)
                if backend is None:
                    statuses[source_id] = {"remote_status": "snapshot_only"}
                    continue
                extra = {} if source_id == "owasp" else {"deadline": deadline}
                effective_freshness = freshness
                if freshness != "offline" and self._cache_bytes() >= GLOBAL_CACHE_BYTES:
                    effective_freshness = "offline"
                    warnings.append(
                        f"{source_id}: limite global do cache atingido; somente evidências locais foram consultadas."
                    )
                response = backend.research(
                    query, freshness=effective_freshness, limit=limit, path=path, **extra
                )
                results.extend(response["results"])
                statuses[source_id] = {
                    "remote_status": response["remote_status"],
                    "catalog": {
                        k: v for k, v in response.get("catalog", {}).items() if k not in {"paths", "entries"}
                    },
                }
                warnings.extend(f"{source_id}: {w}" for w in response.get("warnings", []))
            except CACHE_ERRORS as exc:
                statuses[source_id] = {
                    "remote_status": "failed",
                    "error_code": getattr(exc, "code", "CACHE_UNAVAILABLE"),
                }
                warnings.append(f"{source_id}: fonte indisponível; outras fontes foram preservadas.")
        # Round robin by source preserves diversity without comparing incompatible BM25 scores.
        merged = []
        for index in range(limit):
            for source_id in selected:
                matches = [r for r in results if r["source_id"] == source_id]
                if index < len(matches):
                    merged.append(matches[index])
        trimmed = merged[:limit]
        for result in trimmed:
            remaining = 2400
            for passage in result.get("passages", []):
                original = passage["text"]
                passage["text"] = original[: min(1200, remaining)]
                remaining -= len(passage["text"])
                if len(passage["text"]) != len(original):
                    passage["truncated"] = result["truncated"] = True
            result["passages"] = [p for p in result.get("passages", []) if p["text"]]
        return {
            "results": trimmed,
            "citations": [r["citation"] for r in trimmed],
            "warnings": warnings,
            "remote_status": "federated",
            "sources": statuses,
            "selected_sources": selected,
            "truncated": len(merged) > limit or any(result.get("truncated", False) for result in trimmed),
            "retrieval_profile": "bounded_source_federation",
            "discovery_limit": "Metadata routing and lexical retrieval; retrieved selection is not complete corpus coverage.",
        }

    def _owner(self, document_id, deadline=None):
        if not isinstance(document_id, str) or not re.fullmatch(r"doc_[0-9a-f]{32}", document_id):
            raise KnowledgeError("INVALID_ARGUMENT", "Identificador inválido.")
        failed = False
        deadline = deadline if deadline is not None else time.monotonic() + RESEARCH_BUDGET
        for source_id in self._existing_ids():
            if time.monotonic() >= deadline:
                failed = True
                break
            try:
                backend = self.backend(source_id)
                if self._has_document(source_id, backend, document_id):
                    return backend
            except CACHE_ERRORS:
                failed = True
        if failed:
            # An inaccessible store is not proof that a cited document vanished.
            raise KnowledgeError("CACHE_UNAVAILABLE", "Não foi possível verificar todos os caches locais.")
        raise KnowledgeError("NOT_FOUND", "Documento ausente dos caches locais.")

    @staticmethod
    def _has_document(source_id, backend, document_id):
        if source_id == "owasp":
            with closing(backend._connect()) as db:
                return (
                    db.execute(
                        "SELECT 1 FROM versions WHERE document_id=? LIMIT 1", (document_id,)
                    ).fetchone()
                    is not None
                )
        return backend.has_document(document_id)

    def get_document(self, document_id, revision=None, offset=0, *, deadline=None):
        return self._owner(document_id, deadline).get_document(document_id, revision, offset)

    def resolve_reference(self, reference, *, deadline=None):
        try:
            backend = self._owner(reference["document_id"], deadline)
        except KnowledgeError as exc:
            if exc.code == "NOT_FOUND":
                return {"state": "missing", "citation": None}
            if exc.code == "CACHE_UNAVAILABLE":
                return {"state": "unknown", "citation": None}
            raise
        try:
            return backend.resolve_reference(reference)
        except CACHE_ERRORS:
            return {"state": "unknown", "citation": None}

    def latest_state(
        self,
        document_id,
        revision,
        original_hash,
        source_id="owasp",
        *,
        deadline=None,
        reference_checked_at=None,
    ):
        if deadline is not None and time.monotonic() >= deadline:
            return "unknown"
        if source_id not in set(self._existing_ids()):
            return None
        try:
            backend = self.backend(source_id)
            if self._has_document(source_id, backend, document_id):
                if source_id != "owasp":
                    return backend.latest_state(
                        document_id, revision, original_hash, reference_checked_at=reference_checked_at
                    )
                if reference_checked_at is not None:
                    observation = backend.source_revision()
                    if observation:
                        order = observation_order(reference_checked_at, observation, now=backend.clock())
                        if order != "newer":
                            return None if order == "older" else "unknown"
                return backend.latest_state(document_id, revision, original_hash)
            # A snapshot may split a STIX bundle into logical documents. Their
            # IDs/hashes need not exist in the cache of the original bundle.
            # Only source revision observations can establish their currency.
            observed = backend.source_revision()
            if not observed:
                return "unknown" if backend.catalog().get("last_failure") else None
            if reference_checked_at is not None:
                order = observation_order(reference_checked_at, observed, now=backend.clock())
                if order != "newer":
                    return None if order == "older" else "unknown"
            if observed["revision"] != revision:
                return "superseded"
            if observed.get("last_failure"):
                return "unknown"
            age = backend._age(observed.get("checked_at"))
            ttl = OWASP_TTL if source_id == "owasp" else backend.ttl_seconds
            return "unknown" if age < 0 else "stale" if age > ttl else "current"
        except CACHE_ERRORS:
            return "unknown"

    def catalog(self, *, deadline=None):
        sources = {}
        deadline = deadline if deadline is not None else time.monotonic() + RESEARCH_BUDGET
        for source_id in dict.fromkeys(["owasp", *self._existing_ids()]):
            if time.monotonic() >= deadline:
                sources[source_id] = {
                    "source_id": source_id,
                    "status": "unavailable",
                    "error_code": "TIMEOUT",
                }
                continue
            try:
                entry = dict(self.backend(source_id).catalog())
                if "paths" in entry:
                    paths = entry.pop("paths")
                    entry["paths_preview"] = paths[:5]
                    entry["paths_preview_truncated"] = len(paths) > 5
                sources[source_id] = entry
            except CACHE_ERRORS as exc:
                sources[source_id] = {
                    "source_id": source_id,
                    "status": "unavailable",
                    "error_code": getattr(exc, "code", "CACHE_UNAVAILABLE"),
                }
        try:
            cache_bytes = self._cache_bytes()
        except OSError:
            cache_bytes = None
        return {
            "sources": sources,
            "remote_source_ids": ["owasp", *SOURCES],
            "remote_sources_per_call": 3,
            "global_cache_results_per_call": 3,
            "research_budget_seconds": RESEARCH_BUDGET,
            "global_cache_bytes": cache_bytes,
            "global_cache_limit_bytes": GLOBAL_CACHE_BYTES,
            "cache_limit_policy": "Checked before each source fetch; one in-flight source may exceed the threshold within its own database limit. Offline reads remain available.",
        }
