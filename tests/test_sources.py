import io
import json

import pytest

from cyber_rag import sources


@pytest.mark.parametrize("url", [
    "http://raw.githubusercontent.com/SigmaHQ/sigma/master/LICENSE",
    "https://localhost/private", "https://127.0.0.1/secrets", "https://169.254.169.254/latest/meta-data/",
    "https://raw.githubusercontent.com.attacker.test/SigmaHQ/sigma/master/LICENSE",
    "https://raw.githubusercontent.com/untrusted/repo/main/file",
    "https://raw.githubusercontent.com/SigmaHQ/sigma/master/../secret",
    "https://raw.githubusercontent.com/SigmaHQ/sigma/master/%2e%2e/secret",
    "https://user:pass@raw.githubusercontent.com/SigmaHQ/sigma/master/LICENSE",
    "https://raw.githubusercontent.com:8443/SigmaHQ/sigma/master/LICENSE",
    "https://raw.githubusercontent.com/SigmaHQ/sigma/master/LICENSE?redirect=http://localhost",
    "https://api.github.com/repos/SigmaHQ/sigma/issues/1",
])
def test_unapproved_source_urls_rejected(url):
    with pytest.raises(sources.SourceFetchError):
        sources.validate_source_url(url)


def test_explicit_source_url_accepted():
    sources.validate_source_url("https://raw.githubusercontent.com/SigmaHQ/sigma/" + "a" * 40 + "/LICENSE")
    sources.validate_source_url("https://api.github.com/repos/SigmaHQ/sigma/commits/master")


def test_redirect_is_never_followed():
    with pytest.raises(sources.SourceFetchError, match="redirect"):
        sources._NoRedirect().redirect_request(None, None, 302, "redirect", {}, "http://127.0.0.1")


class Response(io.BytesIO):
    status = 200

    def __init__(self, content):
        super().__init__(content)
        self.headers = {}


def test_download_enforces_stream_limit(monkeypatch):
    class Opener:
        def open(self, *args, **kwargs):
            return Response(b"too large")
    monkeypatch.setattr(sources.urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises(sources.SourceFetchError, match="size limit"):
        sources.download_bytes("https://raw.githubusercontent.com/SigmaHQ/sigma/master/LICENSE", max_bytes=4)


def test_fetch_pilot_pins_commit_and_hashes_every_download(tmp_path, monkeypatch):
    urls = []
    def download(url, **kwargs):
        urls.append(url)
        if "api.github.com" in url:
            return json.dumps({"sha": "a" * 40}).encode()
        return b"synthetic download fixture"
    monkeypatch.setattr(sources, "download_bytes", download)
    manifest_path = sources.fetch_pilot(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    assert manifest["profile"] == "pilot-real-sources"
    assert len(manifest["sources"]) == 5
    assert all(entry["revision"] == "a" * 40 for entry in manifest["sources"])
    assert all("/" + "a" * 40 + "/" in url for url in urls if "raw.githubusercontent" in url)
    assert all(len(entry["file_hashes"]) == len(entry["files"]) for entry in manifest["sources"])
    assert not manifest_path.parent.name.startswith(".partial")


def test_failed_fetch_never_publishes_manifest(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise sources.SourceFetchError("fixture network failure")
    monkeypatch.setattr(sources, "download_bytes", fail)
    with pytest.raises(sources.SourceFetchError):
        sources.fetch_pilot(tmp_path)
    assert not list(tmp_path.rglob("manifest.json"))
