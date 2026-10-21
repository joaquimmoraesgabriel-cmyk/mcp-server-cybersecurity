import io
import threading
import time
import urllib.error

import pytest

from cyber_rag import iso_fetch
from cyber_rag.iso_fetch import ISO_CSV_URL, fetch_iso_csv
from cyber_rag.ondemand import RemoteError

RAW = b"id,reference\n1,ISO/IEC 27001:2022\n" * 100
ETAG = '"official-version"'


class Response:
    def __init__(self, status, headers, body=b""):
        self.status, self.headers = status, headers
        self.body = io.BytesIO(body)
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def read1(self, size):
        return self.body.read(size)


class Opener:
    def __init__(self, mutate=None, failure=None):
        self.calls, self.responses = [], []
        self.mutate, self.failure = mutate, failure
        self.lock = threading.Lock()

    def open(self, request, timeout):
        with self.lock:
            self.calls.append((request, timeout))
        assert request.full_url == ISO_CSV_URL
        assert request.get_header("X-ms-version") == "2023-11-03"
        if self.failure:
            raise self.failure
        if request.method == "HEAD":
            response = Response(200, {"Content-Length": str(len(RAW)), "ETag": ETAG})
        else:
            first, last = map(int, request.get_header("Range").removeprefix("bytes=").split("-"))
            assert request.get_header("If-match") == ETAG
            body = RAW[first:last + 1]
            response = Response(206, {
                "Content-Length": str(len(body)), "Content-Range": f"bytes {first}-{last}/{len(RAW)}", "ETag": ETAG,
            }, body)
        if self.mutate:
            self.mutate(request, response)
        self.responses.append(response)
        return response


def fetch(opener, **kwargs):
    options = {"url": ISO_CSV_URL, "allowed": lambda url: url == ISO_CSV_URL,
               "deadline": time.monotonic() + 30, "max_bytes": len(RAW), "opener_factory": lambda: opener}
    return fetch_iso_csv(**(options | kwargs))


def test_parallel_ranges_reassemble_the_exact_original_and_close_all_responses():
    opener = Opener()
    response = fetch(opener)
    assert response.status == 200 and response.body == RAW and response.etag == ETAG
    assert len(opener.calls) == 9
    assert sum(request.method == "GET" for request, _ in opener.calls) == 8
    assert all(response.closed for response in opener.responses)


@pytest.mark.parametrize("header, value", [
    ("ETag", '"different-version"'), ("Content-Range", "bytes 1-2/999"),
    ("Content-Length", "99999"), ("Content-Encoding", "gzip"),
])
def test_wrong_range_or_mixed_version_never_returns_partial_original(header, value):
    def mutate(request, response):
        if request.method == "GET":
            response.headers[header] = value
    opener = Opener(mutate=mutate)
    with pytest.raises(RemoteError, match="invalid_iso_range"):
        fetch(opener)
    assert all(response.closed for response in opener.responses)


@pytest.mark.parametrize("body", [b"", RAW])
def test_short_or_oversized_range_body_rejected(body):
    def mutate(request, response):
        if request.method == "GET":
            response.body = io.BytesIO(body)
    with pytest.raises(RemoteError, match="invalid_iso_range_size"):
        fetch(Opener(mutate=mutate))


@pytest.mark.parametrize("header, value", [
    ("ETag", 'W/"weak"'), ("ETag", ""), ("Content-Length", "0"),
    ("Content-Length", "99999999999"), ("Content-Length", "bad"),
])
def test_invalid_head_stops_before_any_range(header, value):
    def mutate(request, response):
        response.headers[header] = value
    opener = Opener(mutate=mutate)
    with pytest.raises(RemoteError):
        fetch(opener)
    assert len(opener.calls) == 1


def test_304_only_accepted_after_conditional_request_with_matching_strong_etag():
    failure = urllib.error.HTTPError(ISO_CSV_URL, 304, "Not Modified", {"ETag": ETAG}, None)
    opener = Opener(failure=failure)
    result = fetch(opener, etag=ETAG)
    assert result.status == 304 and result.etag == ETAG
    assert opener.calls[0][0].get_header("If-none-match") == ETAG
    assert len(opener.calls) == 1
    with pytest.raises(RemoteError, match="invalid_iso_not_modified"):
        fetch(Opener(failure=failure))


def test_304_with_changed_etag_is_rejected():
    failure = urllib.error.HTTPError(ISO_CSV_URL, 304, "Not Modified", {"ETag": '"other"'}, None)
    with pytest.raises(RemoteError, match="invalid_iso_not_modified"):
        fetch(Opener(failure=failure), etag=ETAG)


def test_range_304_is_not_accepted_as_bytes():
    class NotModifiedRange(Opener):
        def open(self, request, timeout):
            if request.method == "GET":
                raise urllib.error.HTTPError(ISO_CSV_URL, 304, "Not Modified", {}, None)
            return super().open(request, timeout)
    with pytest.raises(RemoteError, match="http_304"):
        fetch(NotModifiedRange())


def test_all_concurrent_http_error_responses_are_closed_even_when_one_is_propagated():
    errors = []
    barrier = threading.Barrier(8)

    class FailedRanges(Opener):
        def open(self, request, timeout):
            if request.method == "GET":
                stream = io.BytesIO(b"error")
                errors.append(stream)
                barrier.wait(timeout=5)
                raise urllib.error.HTTPError(ISO_CSV_URL, 412, "Version changed", {}, stream)
            return super().open(request, timeout)

    with pytest.raises(RemoteError, match="http_412"):
        fetch(FailedRanges())
    assert len(errors) == 8 and all(stream.closed for stream in errors)


def test_expired_deadline_prevents_all_network_calls():
    opener = Opener()
    with pytest.raises(RemoteError, match="deadline_exceeded"):
        fetch(opener, deadline=time.monotonic() - 1)
    assert opener.calls == []


def test_deadline_after_head_prevents_range_calls(monkeypatch):
    now = [100]
    monkeypatch.setattr(iso_fetch.time, "monotonic", lambda: now[0])
    opener = Opener(mutate=lambda *args: now.__setitem__(0, 131))
    with pytest.raises(RemoteError, match="deadline_exceeded"):
        fetch(opener, deadline=130)
    assert len(opener.calls) == 1


def test_deadline_during_range_read_rejects_partial_bytes_and_closes_workers(monkeypatch):
    now = [100]
    monkeypatch.setattr(iso_fetch.time, "monotonic", lambda: now[0])

    def expire_on_read(request, response):
        if request.method == "GET":
            original_read = response.read1

            def read(size):
                now[0] = 131
                return original_read(size)

            response.read1 = read

    opener = Opener(mutate=expire_on_read)
    with pytest.raises(RemoteError, match="deadline_exceeded"):
        fetch(opener, deadline=130)
    assert all(response.closed for response in opener.responses)


@pytest.mark.parametrize("url", [ISO_CSV_URL + "?version=other", "https://evil.example/file.csv"])
def test_even_external_allow_callback_cannot_expand_the_fixed_iso_url(url):
    opener = Opener()
    with pytest.raises(RemoteError, match="url_rejected"):
        fetch(opener, url=url, allowed=lambda _: True)
    assert opener.calls == []


def test_fixed_absolute_byte_limit_cannot_be_overridden():
    opener = Opener(mutate=lambda request, response: response.headers.update({"Content-Length": str(iso_fetch.MAX_BYTES + 1)}))
    with pytest.raises(RemoteError, match="response_too_large"):
        fetch(opener, max_bytes=1024 * 1024 * 1024)
    assert len(opener.calls) == 1
