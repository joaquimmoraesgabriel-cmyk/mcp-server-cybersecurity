"""Bounded connectors: discover metadata, retrieve pinned bytes, derive searchable text.

Never executes a retrieved rule, payload, script, macro or URL in a document.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict
from html.parser import HTMLParser

from .iso_fetch import fetch_iso_csv
from .iso_metadata import normalize_iso_csv
from .models import KnowledgeError
from .ondemand import FetchResponse, RemoteError, _NoRedirect, _words

SHA = re.compile(r"[0-9a-f]{40}\Z")
CVE = re.compile(r"(?i)\bCVE-(\d{4})-(\d{4,10})\b")


def cve_path(identifier):
    match = CVE.fullmatch(identifier)
    if not match:
        raise RemoteError("invalid_cve")
    year, number = match.groups()
    return f"cves/{year}/{number[:-3]}xxx/CVE-{year}-{number}.json"


def valid_path(path):
    return (isinstance(path, str) and 0 < len(path) <= 512 and not path.startswith("/")
            and not any(p in {"", ".", ".."} for p in path.split("/"))
            and not any(c in path for c in "\\\x00\r\n?#%")
            and all(ord(c) >= 32 for c in path))


def public_fetch(url, *, allowed, deadline, max_bytes, etag=None):
    if not allowed(url):
        raise RemoteError("url_rejected")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RemoteError("deadline_exceeded")
    headers = {"User-Agent": "cyber-rag-local/0.1", "Accept-Encoding": "identity"}
    if etag:
        if not isinstance(etag, str) or len(etag) > 512 or any(c in etag for c in "\r\n"):
            raise RemoteError("invalid_etag")
        headers["If-None-Match"] = etag
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        request = urllib.request.Request(url, headers=headers)
        with opener.open(request, timeout=min(8, remaining)) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") not in {"", "identity"}:
                raise RemoteError("unexpected_response")
            if int(response.headers.get("Content-Length", "0")) > max_bytes:
                raise RemoteError("response_too_large")
            parts, total = [], 0
            while True:
                if time.monotonic() >= deadline:
                    raise RemoteError("deadline_exceeded")
                piece = response.read1(min(65536, max_bytes - total + 1))
                if not piece:
                    break
                total += len(piece)
                if total > max_bytes:
                    raise RemoteError("response_too_large")
                parts.append(piece)
            return FetchResponse(200, b"".join(parts), response.headers.get("ETag"))
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return FetchResponse(304, etag=exc.headers.get("ETag") or etag)
        raise RemoteError(f"http_{exc.code}", exc.headers.get("Retry-After")) from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RemoteError("network_unavailable") from exc


class VisibleHTML(HTMLParser):
    """Extract prose without rendering, scripts, hidden or struck-out old text."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.parts = []
        self.nodes = 0

    def handle_starttag(self, tag, attrs):
        self.nodes += 1
        if self.nodes > 200_000 or len(self.stack) >= 256:
            raise RemoteError("html_complexity_exceeded")
        attrs = dict(attrs)
        style = (attrs.get("style") or "").replace(" ", "").lower()
        excluded = tag in {"script", "style", "noscript", "iframe", "del", "s", "strike", "svg"} or "hidden" in attrs or "display:none" in style or "line-through" in style
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append((tag, excluded))
        if not any(hidden for _, hidden in self.stack) and tag in {"p", "div", "section", "article", "br", "li", "tr", "h1", "h2", "h3", "h4"}:
            self.parts.append("\n\n")

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        if not any(hidden for _, hidden in self.stack):
            self.parts.append(data)


def normalize(raw, kind):
    if kind == "iso-metadata":
        return normalize_iso_csv(raw)
    if kind == "gdpr":
        text, metadata = normalize(raw, "html")
        flat = re.sub(r"\s+", " ", text).casefold()
        if not all(re.search(pattern, flat) for pattern in (r"(?<!\d)2016/679(?!\d)", r"\barticle\s+1\b", r"\barticle\s+99\b")):
            raise RemoteError("invalid_gdpr_document")
        return text, {**metadata, "document_identity": "Regulation (EU) 2016/679", "authority": "EU Publications Office Cellar"}
    if kind == "lgpd":
        text, metadata = normalize(raw, "html")
        flat = re.sub(r"\s+", " ", text).casefold()
        if not re.search(r"(?<!\d)13\.709(?!\d)", flat) or "dados pessoais" not in flat or not re.search(r"\bart\.\s*1(?!\d)", flat):
            raise RemoteError("invalid_lgpd_document")
        return text, {**metadata, "document_identity": "Brazil Law 13.709/2018", "authority": "Camara dos Deputados"}
    if kind == "html":
        match = re.search(rb"charset\s*=\s*[\"']?([a-zA-Z0-9_-]+)", raw[:4096], re.IGNORECASE)
        encoding = match[1].decode("ascii").lower() if match else "utf-8"
        if encoding not in {"utf-8", "utf8", "iso-8859-1", "windows-1252", "latin1"}:
            raise RemoteError("unsupported_charset")
        parser = VisibleHTML()
        parser.feed(raw.decode(encoding))
        text = re.sub(r"[ \t]+", " ", "".join(parser.parts)).strip()
        challenge_text = re.sub(r"\s+", " ", text).casefold().replace("\u2019", "'")
        challenge_markers = (
            "enable javascript and cookies to continue", "verify you are human",
            "checking your browser", "just a moment...",
            "verify that you're not a robot", "verify that you are not a robot",
        )
        if len(text) < 80 or any(marker in challenge_text for marker in challenge_markers):
            raise RemoteError("html_content_unavailable")
        return text, {"representation": "derived_visible_html_text", "charset": encoding, "excluded": "scripts, styles, hidden and struck-out text; original bytes preserved"}
    text = raw.decode("utf-8-sig")
    if not text.strip() or "\x00" in text:
        raise RemoteError("invalid_text")
    if text.startswith("version https://git-lfs.github.com/spec/"):
        raise RemoteError("lfs_pointer_not_content")
    if kind == "atlas" and ("format-version:" not in text or "\ntechniques:" not in text):
        raise RemoteError("invalid_atlas_document")
    if kind == "stix":
        bundle = bounded_json_loads(text)
        if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
            raise RemoteError("invalid_stix")
        sections = []
        for record in bundle["objects"]:
            if not isinstance(record, dict):
                raise RemoteError("invalid_stix_object")
            if record.get("revoked") or record.get("x_mitre_deprecated"):
                continue
            if record.get("type") not in {"attack-pattern", "course-of-action", "intrusion-set", "malware", "tool", "x-mitre-tactic", "campaign", "x-mitre-data-source", "x-mitre-data-component"}:
                continue
            references = record.get("external_references", [])
            if not isinstance(references, list):
                raise RemoteError("invalid_stix_references")
            identifiers = [str(r.get("external_id", "")) for r in references if isinstance(r, dict)]
            sections.append("# " + " ".join(identifiers) + " " + str(record.get("name", "")) + "\n" + json.dumps({k: record[k] for k in ("id", "type", "description", "x_mitre_platforms", "kill_chain_phases", "modified") if k in record}, ensure_ascii=False) + "\n")
        if not sections:
            raise RemoteError("empty_stix")
        return "\n".join(sections), {"representation": "derived_stix_search_text", "indexed_records": len(sections), "excluded": "relationships, revoked and deprecated objects are retained only in original bytes"}
    if kind in {"json", "cve", "kev"}:
        payload = bounded_json_loads(text)
        if kind == "cve" and (not isinstance(payload, dict) or payload.get("dataType") != "CVE_RECORD" or not isinstance(payload.get("cveMetadata"), dict) or not isinstance(payload["cveMetadata"].get("cveId"), str) or not CVE.fullmatch(payload["cveMetadata"]["cveId"])):
            raise RemoteError("invalid_cve_record")
        if kind == "kev":
            if not isinstance(payload, dict):
                raise RemoteError("invalid_kev_catalog")
            records = payload.get("vulnerabilities")
            if not isinstance(records, list) or payload.get("count") != len(records) or any(not isinstance(r, dict) or not isinstance(r.get("cveID"), str) or not CVE.fullmatch(r["cveID"]) for r in records):
                raise RemoteError("invalid_kev_catalog")
            return "\n\n".join("# " + r["cveID"] + "\n" + json.dumps(r, ensure_ascii=False, indent=2) for r in records), {"representation": "derived_kev_records", "indexed_records": len(records), "catalog_version": payload.get("catalogVersion")}
        return json.dumps(payload, ensure_ascii=False, indent=2), {"representation": "derived_json_text"}
    return text, {"representation": "original_text"}


def bounded_json_loads(text):
    """Bound nesting before decoding or pretty-printing untrusted JSON."""
    if isinstance(text, bytes):
        text = text.decode("utf-8-sig")
    depth, quoted, escaped = 0, False, False
    previous = -2
    for token in re.finditer(r'["\\{}\[\]]', text):
        char, position = token.group(), token.start()
        # Escape applies only to the immediately following character. Ordinary
        # text between structural tokens consumes it without a Python byte loop.
        if previous + 1 != position:
            escaped = False
        previous = position
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "{[":
            depth += 1
            if depth > 128:
                raise RemoteError("json_nesting_limit")
        elif char in "}]":
            depth -= 1
    try:
        return json.loads(text)
    except RecursionError:
        raise RemoteError("json_nesting_limit") from None


def source_fingerprint(spec):
    settings = asdict(spec)
    # Resource budgets do not change source identity, parsing or attribution.
    # Excluding this new field also preserves fingerprints of existing caches.
    settings.pop("request_budget_seconds", None)
    return hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()


class GithubAdapter:
    def __init__(self, spec, *, fetcher=None):
        self.spec = spec
        self.source_id = spec.source_id
        self.ttl_seconds = spec.ttl_seconds
        self.request_budget_seconds = spec.request_budget_seconds
        self.max_bytes = spec.max_bytes
        self.max_versions = 1000
        self.cache_bytes = 256 * 1024 * 1024
        self.fetcher = fetcher or public_fetch
        self.requested_paths = []
        self.fingerprint = source_fingerprint(spec)

    def prepare(self, query, path, old_catalog):
        if self.spec.discovery != "cve":
            return (old_catalog or {}).get("adapter_fingerprint") != self.fingerprint
        identifiers = [m.group().upper() for m in CVE.finditer(query)]
        requested = [path] if path else [cve_path(value) for value in identifiers[:3]]
        if not requested or any(not self.accepts(value) for value in requested):
            raise RemoteError("exact_cve_required")
        self.requested_paths = requested
        existing = {e["path"] for e in (old_catalog or {}).get("entries", [])}
        return any(value not in existing for value in requested) or (old_catalog or {}).get("adapter_fingerprint") != self.fingerprint

    def _with_requested(self, catalog):
        if self.spec.discovery != "cve":
            return catalog
        entries = {e["path"]: e for e in catalog.get("entries", [])}
        for path in self.requested_paths:
            entries[path] = {"path": path, "title": path.rsplit("/", 1)[-1]}
        return {**catalog, "entries": list(entries.values())}

    def allowed(self, url):
        base = f"https://api.github.com/repos/{self.spec.repository}/"
        if url == base + f"git/ref/heads/{self.spec.branch}":
            return True
        if url.startswith(base + "git/trees/"):
            return bool(re.fullmatch(r"[0-9a-f]{40}\?recursive=1", url[len(base + 'git/trees/'):]))
        raw = f"https://raw.githubusercontent.com/{self.spec.repository}/"
        if not url.startswith(raw):
            return False
        revision, _, encoded = url[len(raw):].partition("/")
        path = urllib.parse.unquote(encoded)
        return bool(SHA.fullmatch(revision) and valid_path(path) and urllib.parse.quote(path, safe="/") == encoded and self.accepts(path))

    def accepts(self, path):
        if not valid_path(path):
            return False
        if self.source_id == "vx-papers":
            return path in self.spec.paths
        if self.source_id == "unprotect" and not re.fullmatch(r"Techniques/[^/]+/description\.txt", path):
            return False
        if self.spec.discovery == "cve":
            match = re.fullmatch(r"cves/\d{4}/\d+xxx/(CVE-\d{4}-\d{4,10})\.json", path)
            return bool(match and cve_path(match[1]) == path)
        return path in self.spec.paths or (self.spec.discovery == "tree" and any(path.startswith(p) for p in self.spec.prefixes) and path.lower().endswith(self.spec.suffixes))

    def request(self, url, deadline, *, etag=None, max_bytes=None):
        response = self.fetcher(url, allowed=self.allowed, deadline=deadline, max_bytes=max_bytes or self.max_bytes, etag=etag)
        if not isinstance(response, FetchResponse) or len(response.body) > (max_bytes or self.max_bytes):
            raise RemoteError("invalid_response")
        return response

    def discover(self, old_catalog, deadline):
        previous = old_catalog or {}
        if previous.get("adapter_fingerprint") != self.fingerprint:
            previous = {}
        head = self.request(f"https://api.github.com/repos/{self.spec.repository}/git/ref/heads/{self.spec.branch}", deadline, etag=previous.get("etag"), max_bytes=1024 * 1024)
        if head.status == 304:
            if not previous.get("entries") or not previous.get("etag"):
                raise RemoteError("invalid_not_modified")
            return self._with_requested({**previous, "adapter_fingerprint": self.fingerprint})
        if head.status != 200:
            raise RemoteError(f"http_{head.status}")
        head_data = bounded_json_loads(head.body)
        if not isinstance(head_data, dict) or not isinstance(head_data.get("object"), dict):
            raise RemoteError("invalid_revision")
        revision = head_data["object"].get("sha")
        if not isinstance(revision, str) or not SHA.fullmatch(revision):
            raise RemoteError("invalid_revision")
        if previous.get("revision") == revision:
            return self._with_requested({**previous, "etag": head.etag, "adapter_fingerprint": self.fingerprint})
        if self.spec.discovery == "cve":
            entries = self._with_requested(previous).get("entries", [])
        elif self.spec.discovery == "fixed":
            entries = [{"path": path, "title": self.spec.title + ": " + path} for path in self.spec.paths]
        else:
            tree = self.request(f"https://api.github.com/repos/{self.spec.repository}/git/trees/{revision}?recursive=1", deadline, max_bytes=16 * 1024 * 1024)
            payload = bounded_json_loads(tree.body)
            if tree.status != 200 or not isinstance(payload, dict) or payload.get("truncated") is not False or not isinstance(payload.get("tree"), list):
                raise RemoteError("tree_incomplete")
            entries = []
            for row in payload["tree"]:
                if not isinstance(row, dict):
                    raise RemoteError("invalid_tree_entry")
                path = row.get("path")
                if row.get("type") != "blob" or row.get("mode") not in {"100644", "100755"} or not self.accepts(path):
                    continue
                if type(row.get("size")) is not int or not 0 < row["size"] <= self.max_bytes:
                    continue
                if not isinstance(row.get("sha"), str) or not SHA.fullmatch(row["sha"]):
                    raise RemoteError("invalid_blob_sha")
                entries.append({"path": path, "title": path.rsplit("/", 1)[-1], "blob_sha": row["sha"]})
            if self.spec.latest_only and entries:
                entries = [max(entries, key=lambda e: tuple(int(n) for n in re.findall(r"\d+", e["path"])))]
        if not entries:
            raise RemoteError("empty_catalog")
        return {"revision": revision, "entries": entries, "etag": head.etag, "adapter_fingerprint": self.fingerprint}

    def candidates(self, query, catalog, limit, path):
        entries = catalog.get("entries", [])
        if path is not None:
            return [entry for entry in entries if entry["path"] == path]
        if self.spec.discovery == "fixed" or self.spec.latest_only:
            return entries[:limit]
        if self.spec.discovery == "cve":
            paths = {cve_path(m.group().upper()) for m in CVE.finditer(query)}
            return [e for e in entries if e["path"] in paths][:limit]
        terms = set(_words(query))
        def score(entry):
            original = set(_words(entry["path"]))
            derived = set(_words(re.sub(r"(?<=[a-z])(?=[A-Z])", " ", entry["path"]))) - original
            # Exact original words outrank CamelCase fragments: SQL must not
            # tie with the SQL fragment inferred from NoSQL.
            prefixes = sum(any(word.startswith(term) for word in original | derived) for term in terms if len(term) >= 4)
            return len(original & terms), len(derived & terms), prefixes
        ranked = sorted(entries, key=lambda e: (tuple(-part for part in score(e)), e["path"]))
        return [e for e in ranked if any(score(e))][:limit]

    def load(self, entry, revision, deadline):
        if not self.accepts(entry["path"]) or not SHA.fullmatch(revision):
            raise RemoteError("path_rejected")
        raw_url = f"https://raw.githubusercontent.com/{self.spec.repository}/{revision}/{urllib.parse.quote(entry['path'], safe='/')}"
        response = self.request(raw_url, deadline)
        if response.status != 200:
            raise RemoteError(f"http_{response.status}")
        return self._project(entry, revision, response.body, deadline)

    def load_cached(self, entry, revision, cached, deadline):
        """Reprocess verified bytes only at this exact immutable GitHub identity.

        RemoteStore has verified both persisted hashes and the current catalog.
        A different URL, revision or path requires a normal source fetch.
        """
        if not self.accepts(entry["path"]) or not isinstance(revision, str) or not SHA.fullmatch(revision):
            raise RemoteError("path_rejected")
        expected_url = f"https://github.com/{self.spec.repository}/blob/{revision}/{urllib.parse.quote(entry['path'], safe='/')}"
        if (
            cached.get("url") != expected_url
            or cached.get("path") != entry["path"]
            or cached.get("revision") != revision
        ):
            return None
        raw = cached.get("raw")
        if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != cached.get("original_hash"):
            raise KnowledgeError("CACHE_INTEGRITY", "Os bytes locais de uma revisão imutável estão inválidos.")
        return self._project(entry, revision, raw, deadline)

    def _project(self, entry, revision, raw, deadline):
        if time.monotonic() >= deadline:
            raise RemoteError("deadline_exceeded")
        if not isinstance(raw, bytes) or not 0 < len(raw) <= self.max_bytes:
            raise RemoteError("invalid_source_bytes")
        if entry.get("blob_sha") and hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != entry["blob_sha"]:
            raise RemoteError("git_blob_mismatch")
        if self.spec.format == "paper" and entry["path"].lower().endswith(".pdf"):
            from .pdf_extract import extract_pdf

            text, metadata = extract_pdf(raw, deadline=deadline)
        else:
            text, metadata = normalize(raw, "text" if self.spec.format == "paper" else self.spec.format)
        if self.spec.format == "cve" and bounded_json_loads(raw)["cveMetadata"]["cveId"] + ".json" != entry["path"].rsplit("/", 1)[-1]:
            raise RemoteError("cve_identity_mismatch")
        return {"raw": raw, "text": text, "title": entry["title"],
                "url": f"https://github.com/{self.spec.repository}/blob/{revision}/{urllib.parse.quote(entry['path'], safe='/')}",
                "license_reference": self.spec.license_url or f"https://github.com/{self.spec.repository}/blob/{revision}/{self.spec.license_path}",
                "metadata": {**metadata, "adapter_fingerprint": self.fingerprint}}


class PublicAdapter:
    """Reviewed exact URLs. Hash-pinned local evidence; origin URLs may change."""

    def __init__(self, spec, *, fetcher=None):
        self.spec = spec
        self.source_id = spec.source_id
        self.ttl_seconds = spec.ttl_seconds
        self.request_budget_seconds = spec.request_budget_seconds
        self.max_bytes = spec.max_bytes
        self.cache_bytes = 256 * 1024 * 1024
        self.fetcher = fetcher or (fetch_iso_csv if spec.source_id == "iso27001" else public_fetch)
        self.pending = {}
        self.fingerprint = source_fingerprint(spec)

    def prepare(self, query, path, old_catalog):
        return (old_catalog or {}).get("adapter_fingerprint") != self.fingerprint

    def allowed(self, url):
        return url in dict(self.spec.urls).values()

    def discover(self, old_catalog, deadline):
        previous_catalog = old_catalog or {}
        if previous_catalog.get("adapter_fingerprint") != self.fingerprint:
            previous_catalog = {}
        previous = {e["path"]: e for e in previous_catalog.get("entries", [])}
        entries = []
        self.pending.clear()
        for path, url in self.spec.urls:
            old = previous.get(path, {})
            if old.get("url") != url:
                old = {}
            response = self.fetcher(url, allowed=self.allowed, deadline=deadline,
                                    max_bytes=self.max_bytes, etag=old.get("etag"))
            if response.status == 304 and old.get("content_hash") and old.get("etag"):
                entries.append(old)
                continue
            if response.status != 200 or not 0 < len(response.body) <= self.max_bytes:
                raise RemoteError("invalid_public_response")
            self.pending[path] = response.body
            entries.append({"path": path, "title": self.spec.title + ": " + path,
                            "url": url, "etag": response.etag,
                            "content_hash": hashlib.sha256(response.body).hexdigest()})
        revision = hashlib.sha256(json.dumps([self.fingerprint, [(e["path"], e["url"], e["content_hash"]) for e in entries]], sort_keys=True).encode()).hexdigest()
        return {"revision": revision, "entries": entries, "adapter_fingerprint": self.fingerprint}

    def candidates(self, query, catalog, limit, path):
        return [e for e in catalog.get("entries", []) if path is None or path == e["path"]][:limit]

    def load(self, entry, revision, deadline):
        if dict(self.spec.urls).get(entry["path"]) != entry.get("url"):
            raise RemoteError("url_rejected")
        raw = self.pending.pop(entry["path"], None)
        if raw is None:
            response = self.fetcher(entry["url"], allowed=self.allowed, deadline=deadline, max_bytes=self.max_bytes)
            if response.status != 200:
                raise RemoteError("public_source_unavailable")
            raw = response.body
        if hashlib.sha256(raw).hexdigest() != entry["content_hash"]:
            raise RemoteError("source_changed_during_fetch")
        text, metadata = normalize(raw, self.spec.format)
        return {"raw": raw, "text": text, "title": entry["title"], "url": entry["url"],
                "license_reference": self.spec.license_url or self.spec.homepage,
                "metadata": {**metadata, "origin_url_mutable": True, "content_hash": entry["content_hash"]}}


class RecordAdapter:
    """Exact IDs against a reviewed endpoint; each record has its own revision."""
    per_document_revisions = True

    def __init__(self, spec, *, fetcher=None):
        self.spec = spec
        self.source_id = spec.source_id
        self.ttl_seconds = spec.ttl_seconds
        self.request_budget_seconds = spec.request_budget_seconds
        self.max_bytes = spec.max_bytes
        self.cache_bytes = 128 * 1024 * 1024
        self.fetcher = fetcher or public_fetch
        self.pending = {}
        self.requested_paths = []
        self.next_request_at = 0.0
        self.fingerprint = source_fingerprint(spec)

    def request(self, path, deadline):
        wait = max(0.0, self.next_request_at - time.monotonic())
        if time.monotonic() + wait >= deadline:
            raise RemoteError("deadline_exceeded")
        if wait:
            time.sleep(wait)
        self.next_request_at = time.monotonic() + self.spec.min_interval_seconds
        return self.fetcher(self.url(path), allowed=self.allowed, deadline=deadline, max_bytes=self.max_bytes)

    def identifier(self, path):
        if self.spec.id_kind == "cis-control":
            match = re.fullmatch(r"control-([1-9]|1[0-8])\.html", path or "")
            if not match:
                raise RemoteError("invalid_record_path")
            return match[1]
        patterns = {"event": r"event-(\d{4})\.html", "cve": r"(CVE-\d{4}-\d{4,10})\.json", "cwe": r"CWE-([1-9]\d{0,5})\.json", "malapi": r"([A-Za-z_][A-Za-z0-9_]{0,127})\.html"}
        pattern = patterns.get(self.spec.id_kind)
        match = re.fullmatch(pattern, path) if pattern and isinstance(path, str) else None
        if not match:
            raise RemoteError("invalid_record_path")
        return match[1]

    def select_paths(self, query, path):
        if path is not None:
            self.identifier(path)
            return [path]
        if self.spec.id_kind == "cve":
            return list(dict.fromkeys(m.group().upper() + ".json" for m in CVE.finditer(query)))[:3]
        if self.spec.id_kind == "cis-control":
            ids = re.findall(r"(?i)\b(?:control|controle)\s+([1-9]|1[0-8])\b", query)
            return list(dict.fromkeys("control-" + value + ".html" for value in ids))[:3]
        if self.spec.id_kind == "cwe":
            return list(dict.fromkeys("CWE-" + value + ".json" for value in re.findall(r"(?i)\bCWE-([1-9]\d{0,5})\b", query)))[:3]
        if self.spec.id_kind == "malapi":
            # Exact API names avoid guessing from natural-language keywords.
            # A caller can always choose a single explicit ApiName.html path.
            cleaned = re.sub(r"(?i)\b(?:malapi|winapi|api)\b\s*:?\s*", " ", query).strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", cleaned):
                names = [cleaned]
            else:
                names = [name for name in re.findall(r"(?<![A-Za-z0-9_])([A-Z][A-Za-z0-9_]{1,127})(?![A-Za-z0-9_])", cleaned) if any(char.isupper() for char in name[1:])]
            return list(dict.fromkeys(name + ".html" for name in names))[:3]
        return list(dict.fromkeys("event-" + value + ".html" for value in re.findall(r"\b(\d{4})\b", query)))[:3]

    def url(self, path):
        return self.spec.url_template.format(id=self.identifier(path))

    def allowed(self, url):
        if not isinstance(url, str):
            return False
        prefix, suffix = self.spec.url_template.split("{id}")
        if not url.startswith(prefix) or (suffix and not url.endswith(suffix)):
            return False
        value = url[len(prefix):len(url)-len(suffix) if suffix else None]
        if self.spec.id_kind == "cis-control":
            return bool(re.fullmatch(r"[1-9]|1[0-8]", value))
        patterns = {"event": r"\d{4}", "cve": r"CVE-\d{4}-\d{4,10}", "cwe": r"[1-9]\d{0,5}", "malapi": r"[A-Za-z_][A-Za-z0-9_]{0,127}"}
        return bool(re.fullmatch(patterns[self.spec.id_kind], value))

    def prepare(self, query, path, old_catalog):
        self.requested_paths = self.select_paths(query, path)
        if not self.requested_paths:
            raise RemoteError("exact_identifier_required")
        if (old_catalog or {}).get("adapter_fingerprint") != self.fingerprint:
            return True
        old = {e["path"]: e for e in (old_catalog or {}).get("entries", [])}
        # Per-record TTL cannot be refreshed by another record's catalogue check.
        from datetime import UTC, datetime
        now = datetime.now(UTC)
        for record_path in self.requested_paths:
            entry = old.get(record_path)
            if not entry or entry.get("url") != self.url(record_path) or entry.get("adapter_fingerprint") != self.fingerprint:
                return True
            try:
                checked_at = datetime.fromisoformat(entry.get("checked_at"))
                if checked_at.tzinfo is None:
                    return True
                age = (now - checked_at).total_seconds()
            except (TypeError, ValueError):
                return True
            if not 0 <= age <= self.ttl_seconds:
                return True
        return False

    def projection(self, raw, path):
        if self.spec.format == "cwe":
            payload = bounded_json_loads(raw)
            records = payload.get("Weaknesses") if isinstance(payload, dict) else None
            if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict) or str(records[0].get("ID")) != self.identifier(path):
                raise RemoteError("invalid_cwe_record")
            record = records[0]
            canonical = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
            return "# CWE-" + str(record["ID"]) + "\n" + json.dumps(record, ensure_ascii=False, indent=2), {"representation": "derived_cwe_weakness", "status": record.get("Status")}, canonical
        if self.spec.format == "nvd":
            payload = bounded_json_loads(raw)
            records = payload.get("vulnerabilities") if isinstance(payload, dict) else None
            if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict) or not isinstance(records[0].get("cve"), dict) or records[0]["cve"].get("id") != self.identifier(path):
                raise RemoteError("invalid_nvd_record")
            record = records[0]["cve"]
            canonical = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
            return "# " + record["id"] + "\n" + json.dumps(record, ensure_ascii=False, indent=2), {"representation": "derived_nvd_cve", "excluded_from_revision": "API envelope, including volatile response timestamp", "last_modified": record.get("lastModified")}, canonical
        text, metadata = normalize(raw, self.spec.format)
        return text, metadata, raw

    def revision(self, raw, path):
        _, _, canonical = self.projection(raw, path)
        return hashlib.sha256(self.fingerprint.encode() + b"\0" + self.url(path).encode() + b"\0" + canonical).hexdigest()

    def discover(self, old_catalog, deadline):
        entries = {e["path"]: e for e in (old_catalog or {}).get("entries", [])}
        self.pending.clear()
        for path in self.requested_paths:
            try:
                response = self.request(path, deadline)
                if response.status != 200 or not 0 < len(response.body) <= self.max_bytes:
                    raise RemoteError("invalid_record_response")
                revision = self.revision(response.body, path)
                self.pending[path] = response.body
                entries[path] = {"path": path, "title": self.spec.title + ": " + path, "url": self.url(path), "revision": revision, "adapter_fingerprint": self.fingerprint, "_checked": True}
            except (RemoteError, ValueError, TypeError, OSError) as exc:
                # An earlier response may have established a changed revision.
                # Until partial observations can be committed atomically, fail
                # the discovery as a whole so old records cannot remain current.
                observed_any = bool(self.pending)
                self.pending.clear()
                error = RemoteError(exc.code, exc.retry_after) if isinstance(exc, RemoteError) else RemoteError("invalid_record")
                if not observed_any:
                    error.document_path = path
                raise error from exc
        revision = hashlib.sha256(json.dumps([(p, e["revision"]) for p, e in sorted(entries.items())]).encode()).hexdigest()
        return {"revision": revision, "entries": list(entries.values()), "adapter_fingerprint": self.fingerprint}

    def candidates(self, query, catalog, limit, path):
        paths = self.select_paths(query, path)
        return [e for e in catalog.get("entries", []) if e["path"] in paths][:limit]

    def load(self, entry, revision, deadline):
        path = entry["path"]
        if entry.get("url") != self.url(path):
            raise RemoteError("url_rejected")
        raw = self.pending.pop(path, None)
        if raw is None:
            response = self.request(path, deadline)
            if response.status != 200:
                raise RemoteError("record_unavailable")
            raw = response.body
        if self.revision(raw, path) != revision:
            raise RemoteError("source_changed_during_fetch")
        text, metadata, _ = self.projection(raw, path)
        return {"raw": raw, "text": text, "title": entry["title"], "url": self.url(path),
                "license_reference": self.spec.license_url,
                "metadata": {**metadata, "origin_url_mutable": True, "revision_scope": "record"}}


def make_adapter(spec, **kwargs):
    if spec.discovery == "gitlab-exploit-csv":
        from .gitlab_adapter import ExploitDbAdapter

        return ExploitDbAdapter(spec, **kwargs)
    if spec.discovery == "http-id":
        return RecordAdapter(spec, **kwargs)
    return PublicAdapter(spec, **kwargs) if spec.discovery == "public" else GithubAdapter(spec, **kwargs)
