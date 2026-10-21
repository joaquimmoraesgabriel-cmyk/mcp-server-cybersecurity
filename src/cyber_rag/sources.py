"""Explicit, bounded downloads from the initial sources; never follow references."""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path

MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
REQUEST_TIMEOUT = 30
DOWNLOAD_DEADLINE = 120
REPOSITORIES = {"mitre-attack/attack-stix-data", "OWASP/CheatSheetSeries", "SigmaHQ/sigma", "CVEProject/cvelistV5", "cisagov/kev-data"}

PILOT_SOURCES = (
    {"source_id": "attack", "repository": "mitre-attack/attack-stix-data", "branch": "master",
     "files": ["enterprise-attack/enterprise-attack.json", "README.md", "LICENSE.txt"], "notice_files": ["LICENSE.txt"],
     "include_entities": ["attack:T1059", "attack:T1059.001"],
     "license_path": "LICENSE.txt", "selection_policy": "pilot: T1059, T1059.001 and relationships between them; original Enterprise bundle preserved"},
    {"source_id": "owasp", "repository": "OWASP/CheatSheetSeries", "branch": "master",
     "files": ["cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md", "cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md",
               "cheatsheets/Password_Storage_Cheat_Sheet.md", "cheatsheets/File_Upload_Cheat_Sheet.md",
               "cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md", "LICENSE.md"],
     "notice_files": ["LICENSE.md"], "license_path": "LICENSE.md", "selection_policy": "pilot: five selected OWASP cheat sheets"},
    {"source_id": "sigma", "repository": "SigmaHQ/sigma", "branch": "master",
     "files": ["rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd_patterns.yml", "README.md", "LICENSE"],
     "notice_files": ["LICENSE"], "license_path": "LICENSE", "selection_policy": "pilot: one PowerShell process-creation rule, with README and license notice"},
    {"source_id": "cve", "repository": "CVEProject/cvelistV5", "branch": "main",
     "files": ["cves/2021/44xxx/CVE-2021-44228.json", "README.md"], "notice_files": [],
     "license_url": "https://www.cve.org/Legal/TermsOfUse", "selection_policy": "pilot: CVE-2021-44228 only; not the planned KEV union or 90-day window"},
    {"source_id": "kev", "repository": "cisagov/kev-data", "branch": "develop",
     "files": ["known_exploited_vulnerabilities.json", "README.md", "LICENSE"], "notice_files": ["LICENSE"],
     "license_path": "LICENSE", "selection_policy": "complete KEV catalog at the pinned commit"},
)


class SourceFetchError(RuntimeError):
    """An approved source could not be downloaded without relaxing constraints."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SourceFetchError("Source redirects are disabled; review the source URL")


def validate_source_url(url: str) -> None:
    """Permit only HTTPS URLs in the explicit repository allowlist."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.port not in {None, 443} or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise SourceFetchError("Source URL must be plain HTTPS without credentials, query or fragment")
        parts = parsed.path.strip("/").split("/")
        if any(part in {"", ".", ".."} for part in parts) or "%" in parsed.path or "\\" in url:
            raise SourceFetchError("Encoded or ambiguous source paths are disabled")
        if parsed.hostname == "raw.githubusercontent.com":
            repo = "/".join(parts[:2])
            if len(parts) < 4 or repo not in REPOSITORIES:
                raise SourceFetchError("Repository is not approved")
        elif parsed.hostname == "api.github.com":
            if len(parts) != 5 or parts[0] != "repos" or "/".join(parts[1:3]) not in REPOSITORIES or parts[3] != "commits":
                raise SourceFetchError("Only pinned-source GitHub commit lookup is approved")
        else:
            raise SourceFetchError("Source host is not approved")
    except ValueError as exc:
        raise SourceFetchError("Invalid source URL") from exc


def download_bytes(url: str, *, max_bytes: int = MAX_DOWNLOAD_BYTES) -> bytes:
    validate_source_url(url)
    opener = urllib.request.build_opener(_NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "cyber-rag-local/0.1", "Accept-Encoding": "identity"})
    for attempt in range(3):
        try:
            started = time.monotonic()
            with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
                if response.status != 200 or response.headers.get("Content-Encoding", "identity") not in {"", "identity"}:
                    raise SourceFetchError("Unexpected response status or compressed content")
                length = response.headers.get("Content-Length")
                if length and int(length) > max_bytes:
                    raise SourceFetchError("Download exceeds size limit")
                chunks = []
                total = 0
                while True:
                    if time.monotonic() - started > DOWNLOAD_DEADLINE:
                        raise SourceFetchError("Download deadline exceeded")
                    chunk = response.read(min(64 * 1024, max_bytes - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise SourceFetchError("Download exceeds size limit")
                    chunks.append(chunk)
                return b"".join(chunks)
        except urllib.error.HTTPError as exc:
            if exc.code in {429, 500, 502, 503, 504} and attempt < 2:
                time.sleep(2 ** attempt)
                continue
            raise SourceFetchError(f"Approved source returned HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise SourceFetchError(f"Source download failed ({type(exc).__name__})") from None
    raise SourceFetchError("Source retry limit exceeded")


def fetch_pilot(destination: Path) -> Path:
    """Download a real, deliberately limited corpus into a new immutable folder.

    The returned manifest exists only after every download succeeds. Failed
    .partial-* folders are retained for diagnosis, never returned or published.
    No shell, Git checkout, archive extraction, model, or source code is executed.
    """
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    suffix = uuid.uuid4().hex[:8]
    staging = destination / f".partial-{stamp}-{suffix}"
    staging.mkdir()
    entries = []
    for spec in PILOT_SOURCES:
        repo = spec["repository"]
        commit_data = json.loads(download_bytes(f"https://api.github.com/repos/{repo}/commits/{spec['branch']}", max_bytes=4 * 1024 * 1024))
        revision = commit_data.get("sha", "")
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise SourceFetchError("Commit lookup did not return a Git SHA")
        source_root = staging / spec["source_id"]
        source_root.mkdir()
        raw_base = f"https://raw.githubusercontent.com/{repo}/{revision}"
        hashes = {}
        for relative in spec["files"]:
            content = download_bytes(f"{raw_base}/{relative}")
            target = source_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            hashes[relative] = hashlib.sha256(content).hexdigest()
        checked_at = datetime.now(UTC).isoformat()
        entry = {"source_id": spec["source_id"], "root": spec["source_id"], "revision": revision,
                 "canonical_url": f"https://github.com/{repo}", "base_url": raw_base,
                 "checked_at": checked_at, "files": spec["files"], "file_hashes": hashes,
                 "notice_files": spec["notice_files"], "selection_policy": spec["selection_policy"],
                 "license_reference": spec.get("license_url") or f"https://github.com/{repo}/blob/{revision}/{spec['license_path']}"}
        if "include_entities" in spec:
            entry["include_entities"] = spec["include_entities"]
        entries.append(entry)
    manifest = {"manifest_version": 1, "profile": "pilot-real-sources", "created_at": datetime.now(UTC).isoformat(), "sources": entries}
    (staging / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    final = destination / f"pilot-{stamp}-{suffix}"
    _publish_directory(staging, final)
    return final / "manifest.json"


def _publish_directory(staging: Path, final: Path) -> None:
    """Keep atomic publication while tolerating brief Windows file-handle locks."""
    for attempt in range(6):
        try:
            staging.rename(final)
            return
        except PermissionError as exc:
            if getattr(exc, "winerror", None) not in {5, 32, 33} or attempt == 5:
                raise
            time.sleep(0.05 * 2 ** attempt)
