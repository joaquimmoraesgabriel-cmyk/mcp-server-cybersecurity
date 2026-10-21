"""Exploit-DB metadata discovery and bounded textual evidence from official GitLab.

Only files selected from the commit-pinned exploits CSV can be fetched. Source
code is stored as evidence, never imported, compiled, executed or followed.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import time
from urllib.parse import quote, unquote

from .ondemand import FetchResponse, RemoteError, _words
from .source_adapters import CVE, SHA, public_fetch

PROJECT = "exploit-database/exploitdb"
HOMEPAGE = "https://gitlab.com/" + PROJECT
API = "https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb/repository/"
HEAD_URL = API + "branches/main"
CATALOG_PATH = "files_exploits.csv"
CATALOG_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 100_000
EDB = re.compile(r"(?i)(?<![\w-])EDB-([1-9][0-9]{0,9})(?![\w-])")
TEXT_SUFFIXES = frozenset(
    {
        "txt",
        "md",
        "py",
        "pl",
        "pm",
        "rb",
        "php",
        "sh",
        "bash",
        "ksh",
        "tcsh",
        "c",
        "cc",
        "cpp",
        "c++",
        "h",
        "hpp",
        "java",
        "js",
        "ts",
        "html",
        "htm",
        "xhtml",
        "xml",
        "asp",
        "aspx",
        "jsp",
        "vbs",
        "vb",
        "cs",
        "go",
        "ps1",
        "nse",
        "nasl",
        "lua",
        "sql",
        "patch",
        "diff",
        "pas",
        "bat",
        "cmd",
        "f",
        "m",
        "cfm",
        "xsl",
        "as",
        "ics",
        "svg",
        "eml",
        "cfg",
        "wsf",
    }
)
FILE_PATH = re.compile(
    r"exploits/[a-zA-Z0-9_-]+/(?:local|remote|webapps|dos)/([1-9][0-9]{0,9})\.([a-zA-Z0-9+]+)\Z"
)
MAGIC = (
    b"MZ",
    b"\x7fELF",
    b"PK\x03\x04",
    b"%PDF",
    b"\x89PNG",
    b"GIF87a",
    b"GIF89a",
    b"\xca\xfe\xba\xbe",
    b"\xff\xd8\xff",
    b"\x1f\x8b",
)


def _text_path(path):
    match = FILE_PATH.fullmatch(path) if isinstance(path, str) and len(path) <= 512 else None
    return match if match and match[2].lower() in TEXT_SUFFIXES else None


def _decode_text(raw):
    if not raw or b"\x00" in raw or raw.startswith(MAGIC):
        raise RemoteError("non_text_evidence")
    try:
        text, encoding = raw.decode("utf-8-sig"), "utf-8-sig" if raw.startswith(b"\xef\xbb\xbf") else "utf-8"
    except UnicodeDecodeError:
        text, encoding = raw.decode("latin-1"), "latin-1"
    controls = sum((ord(char) < 32 and char not in "\t\n\r\f") or 127 <= ord(char) < 160 for char in text)
    if not text.strip() or controls > max(1, len(text) // 100):
        raise RemoteError("non_text_evidence")
    return text, encoding


class ExploitDbAdapter:
    def __init__(self, spec, *, fetcher=None):
        if spec.source_id != "exploit-db" or spec.repository != PROJECT or spec.branch != "main":
            raise ValueError("Exploit-DB requires the reviewed official GitLab repository")
        self.spec = spec
        self.source_id = spec.source_id
        self.ttl_seconds = spec.ttl_seconds
        self.max_bytes = spec.max_bytes
        self.max_versions = 1000
        self.cache_bytes = 256 * 1024 * 1024
        self.fetcher = fetcher or public_fetch
        self.fingerprint = hashlib.sha256(b"exploit-db-gitlab-csv-text-v1").hexdigest()
        self._revision = None
        self._entries = {}
        self._catalog_hash = None

    @staticmethod
    def _raw_url(path, revision):
        return API + "files/" + quote(path, safe="") + "/raw?ref=" + revision

    def allowed(self, url):
        if not isinstance(url, str) or len(url) > 2048:
            return False
        if url == HEAD_URL:
            return True
        prefix = API + "files/"
        if not url.startswith(prefix):
            return False
        encoded, separator, revision = url[len(prefix) :].partition("/raw?ref=")
        if not separator or revision != self._revision or not SHA.fullmatch(revision):
            return False
        path = unquote(encoded)
        return quote(path, safe="") == encoded and (
            path == CATALOG_PATH or path in self._entries and bool(_text_path(path))
        )

    def _request(self, url, deadline, *, max_bytes, etag=None):
        if time.monotonic() >= deadline:
            raise RemoteError("deadline_exceeded")
        if not self.allowed(url):
            raise RemoteError("url_rejected")
        response = self.fetcher(url, allowed=self.allowed, deadline=deadline, max_bytes=max_bytes, etag=etag)
        if (
            not isinstance(response, FetchResponse)
            or not isinstance(response.body, bytes)
            or len(response.body) > max_bytes
        ):
            raise RemoteError("invalid_gitlab_response")
        return response

    def _restore(self, catalog):
        self._entries, self._revision, self._catalog_hash = {}, None, None
        if not catalog:
            return False
        if not isinstance(catalog, dict):
            raise RemoteError("invalid_exploit_catalog")
        if catalog.get("adapter_fingerprint") != self.fingerprint:
            return False
        revision, entries = catalog.get("revision"), catalog.get("entries")
        catalog_hash = catalog.get("catalog_hash")
        if (
            not isinstance(revision, str)
            or not SHA.fullmatch(revision)
            or not isinstance(entries, list)
            or not 1 <= len(entries) <= MAX_ENTRIES
            or not isinstance(catalog_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", catalog_hash)
        ):
            raise RemoteError("invalid_exploit_catalog")
        restored, identifiers = {}, set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise RemoteError("invalid_exploit_entry")
            path = entry.get("path")
            match = _text_path(path)
            identifier, cves, title = entry.get("edb_id"), entry.get("cve_ids"), entry.get("title")
            if (
                not match
                or identifier != "EDB-" + match[1]
                or path in restored
                or identifier in identifiers
                or not isinstance(title, str)
                or not title.strip()
                or len(title) > 1024
                or not isinstance(cves, list)
                or len(cves) > 64
                or any(not isinstance(cve, str) or not CVE.fullmatch(cve) for cve in cves)
            ):
                raise RemoteError("invalid_exploit_entry")
            restored[path] = entry
            identifiers.add(identifier)
        self._entries, self._revision, self._catalog_hash = restored, revision, catalog_hash
        return True

    def prepare(self, query, path, old_catalog):
        if path is not None and not _text_path(path):
            raise RemoteError("path_rejected")
        return not self._restore(old_catalog)

    def _parse_catalog(self, raw, deadline):
        if not raw or len(raw) > CATALOG_BYTES or b"\x00" in raw:
            raise RemoteError("invalid_exploit_csv")
        try:
            reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""), strict=True)
            fields = reader.fieldnames
            if (
                not fields
                or not {"id", "file", "description", "codes"} <= set(fields)
                or len(fields) != len(set(fields))
                or len(fields) > 32
            ):
                raise RemoteError("invalid_exploit_csv_header")
            entries, paths, identifiers, excluded, duplicates = [], {}, set(), 0, 0
            for index, row in enumerate(reader):
                if index >= MAX_ENTRIES or time.monotonic() >= deadline:
                    raise RemoteError("catalog_budget_exceeded")
                if None in row or any(value is None for value in row.values()):
                    raise RemoteError("invalid_exploit_csv_row")
                identifier, path, description, codes = (
                    row["id"],
                    row["file"],
                    row["description"],
                    row["codes"],
                )
                match = _text_path(path)
                if not match or match[1] != identifier:
                    excluded += 1
                    continue
                if (
                    not description.strip()
                    or len(codes) > 4096
                    or len(description) > 4096
                    or any(char in description for char in "\x00\r\n")
                ):
                    raise RemoteError("invalid_exploit_csv_row")
                cves = sorted({match.group().upper() for match in CVE.finditer(codes)})
                if len(cves) > 64:
                    raise RemoteError("invalid_exploit_csv_row")
                entry = {
                    "path": path,
                    "title": f"EDB-{identifier}: {description[:900]}",
                    "edb_id": "EDB-" + identifier,
                    "cve_ids": cves,
                    "description_truncated": len(description) > 900,
                }
                if path in paths:
                    # Upstream repeats rows for separate tags. Those tags are
                    # not indexed; the approved evidence fields must agree.
                    if paths[path] != entry:
                        raise RemoteError("conflicting_exploit_csv_row")
                    duplicates += 1
                    continue
                if identifier in identifiers:
                    raise RemoteError("conflicting_exploit_csv_row")
                entries.append(entry)
                paths[path] = entry
                identifiers.add(identifier)
            if not entries:
                raise RemoteError("empty_exploit_catalog")
            return entries, excluded, duplicates
        except (UnicodeError, csv.Error) as exc:
            raise RemoteError("invalid_exploit_csv") from exc

    def discover(self, old_catalog, deadline):
        previous = old_catalog if self._restore(old_catalog) else {}
        head = self._request(HEAD_URL, deadline, max_bytes=1024 * 1024, etag=previous.get("etag"))
        if head.status == 304:
            if not previous.get("etag") or not self._entries:
                raise RemoteError("invalid_not_modified")
            return previous
        if head.status != 200:
            raise RemoteError(f"http_{head.status}")
        try:
            data = json.loads(head.body)
        except ValueError as exc:
            raise RemoteError("invalid_gitlab_head") from exc
        if (
            not isinstance(data, dict)
            or data.get("name") != "main"
            or not isinstance(data.get("commit"), dict)
        ):
            raise RemoteError("invalid_gitlab_head")
        revision = data["commit"].get("id")
        if not isinstance(revision, str) or not SHA.fullmatch(revision):
            raise RemoteError("invalid_gitlab_head")
        if revision == self._revision:
            return {**previous, "etag": head.etag}
        self._revision, self._entries = revision, {}
        csv_url = self._raw_url(CATALOG_PATH, revision)
        response = self._request(csv_url, deadline, max_bytes=CATALOG_BYTES)
        if response.status != 200:
            raise RemoteError(f"http_{response.status}")
        entries, excluded, duplicates = self._parse_catalog(response.body, deadline)
        catalog = {
            "revision": revision,
            "entries": entries,
            "etag": head.etag,
            "adapter_fingerprint": self.fingerprint,
            "catalog_url": csv_url,
            "catalog_hash": hashlib.sha256(response.body).hexdigest(),
            "excluded_entries": excluded,
            "duplicate_metadata_rows": duplicates,
            "coverage": "CSV metadata for eligible textual exploits; only selected source files are cached. Shellcodes and binary formats excluded.",
        }
        self._restore(catalog)
        return catalog

    def candidates(self, query, catalog, limit, path):
        if not self._restore(catalog):
            return []
        if path is not None:
            return [self._entries[path]] if path in self._entries else []
        identifiers = {"EDB-" + match[1] for match in EDB.finditer(query)}
        cves = {match.group().upper() for match in CVE.finditer(query)}
        if identifiers or cves:
            return [
                entry
                for entry in self._entries.values()
                if (not identifiers or entry["edb_id"] in identifiers)
                and (not cves or cves.intersection(entry["cve_ids"]))
            ][:limit]
        terms = set(_words(query))
        scored = [(len(terms & set(_words(entry["title"]))), entry) for entry in self._entries.values()]
        scored.sort(key=lambda item: (-item[0], item[1]["edb_id"]))
        return [entry for score, entry in scored if score][:limit]

    def load(self, entry, revision, deadline):
        registered = self._entries.get(entry.get("path")) if isinstance(entry, dict) else None
        if not registered or revision != self._revision:
            raise RemoteError("unregistered_exploit")
        path = registered["path"]
        response = self._request(self._raw_url(path, revision), deadline, max_bytes=self.max_bytes)
        if response.status != 200:
            raise RemoteError(f"http_{response.status}")
        text, encoding = _decode_text(response.body)
        cves = registered["cve_ids"]
        header = f"# {registered['title']}\nCVE identifiers: {', '.join(cves) or 'not listed in catalogue'}\nSource file: {path}\n\n"
        return {
            "raw": response.body,
            "text": header + text,
            "title": registered["title"],
            "url": f"{HOMEPAGE}/-/blob/{revision}/{path}",
            "license_reference": f"{HOMEPAGE}/-/blob/{revision}/LICENSE.md",
            "metadata": {
                "edb_id": registered["edb_id"],
                "cve_ids": cves,
                "representation": "derived_catalog_header_plus_original_text",
                "original_encoding": encoding,
                "catalog_hash": self._catalog_hash,
                "catalog_url": self._raw_url(CATALOG_PATH, revision),
                "execution": "never_executed",
                "description_truncated": registered.get("description_truncated", False),
            },
        }
