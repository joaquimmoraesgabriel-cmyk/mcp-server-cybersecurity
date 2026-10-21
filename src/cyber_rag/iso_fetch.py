"""Bounded, version-consistent parallel ranges for the single official ISO CSV."""

from __future__ import annotations

import math
import re
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from .ondemand import FetchResponse, RemoteError, _NoRedirect

ISO_CSV_URL = "https://isopublicstorageprod.blob.core.windows.net/opendata/_latest/iso_deliverables_metadata/csv/iso_deliverables_metadata.csv"
MAX_BYTES = 96 * 1024 * 1024
MAX_WORKERS = 8
STRONG_ETAG = re.compile(r'"[\x21\x23-\x7e]{1,500}"\Z')


def fetch_iso_csv(url, *, allowed, deadline, max_bytes, etag=None, opener_factory=None):
    if url != ISO_CSV_URL or not allowed(url):
        raise RemoteError("url_rejected")
    if etag is not None and (not isinstance(etag, str) or not STRONG_ETAG.fullmatch(etag)):
        raise RemoteError("invalid_etag")
    if type(max_bytes) is not int or max_bytes < 1:
        raise RemoteError("invalid_iso_limit")
    maximum = min(max_bytes, MAX_BYTES)
    stopped = threading.Event()

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise RemoteError("deadline_exceeded")
        if stopped.is_set():
            raise RemoteError("range_cancelled")
        return seconds

    def open_request(method, extra):
        opener = (opener_factory() if opener_factory else urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()))
        request = urllib.request.Request(url, method=method, headers={
            "User-Agent": "cyber-rag-local/0.1", "Accept-Encoding": "identity",
            # The legacy default Azure version emits an unquoted ETag. This
            # version returns the standard strong entity-tag on HEAD and GET.
            "x-ms-version": "2023-11-03", **extra,
        })
        try:
            return opener.open(request, timeout=min(8, remaining()))
        except urllib.error.HTTPError as error:
            if method == "GET":
                # Every worker owns its failed HTTP response. Closing here
                # also covers failures in futures discarded after cancellation.
                error.close()
                raise RemoteError(f"http_{error.code}", error.headers.get("Retry-After")) from None
            raise

    try:
        try:
            with open_request("HEAD", {"If-None-Match": etag} if etag else {}) as response:
                if response.status != 200 or response.headers.get("Content-Encoding", "identity") not in {"", "identity"}:
                    raise RemoteError("invalid_iso_head")
                size_text = response.headers.get("Content-Length", "")
                if not re.fullmatch(r"[0-9]{1,12}", size_text):
                    raise RemoteError("invalid_iso_size")
                total = int(size_text)
                revision = response.headers.get("ETag", "")
                if not 0 < total <= maximum:
                    raise RemoteError("response_too_large")
                if not STRONG_ETAG.fullmatch(revision):
                    raise RemoteError("invalid_iso_etag")
        except urllib.error.HTTPError as error:
            error.close()
            if error.code == 304:
                if not etag or error.headers.get("ETag", etag) != etag:
                    raise RemoteError("invalid_iso_not_modified") from None
                remaining()
                return FetchResponse(304, etag=etag)
            raise RemoteError(f"http_{error.code}", error.headers.get("Retry-After")) from None

        def fetch_range(start, end):
            with open_request("GET", {"Range": f"bytes={start}-{end}", "If-Match": revision}) as response:
                expected = end - start + 1
                if (response.status != 206 or response.headers.get("ETag") != revision
                    or response.headers.get("Content-Range") != f"bytes {start}-{end}/{total}"
                    or response.headers.get("Content-Length") != str(expected)
                    or response.headers.get("Content-Encoding", "identity") not in {"", "identity"}):
                    raise RemoteError("invalid_iso_range")
                parts, received = [], 0
                while True:
                    left = remaining()
                    # urllib exposes the live socket through HTTPResponse's
                    # buffered reader; tighten its timeout as the budget ends.
                    sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
                    if sock is not None:
                        sock.settimeout(min(8, left))
                    part = response.read1(min(65536, expected - received + 1))
                    if not part:
                        break
                    received += len(part)
                    if received > expected:
                        raise RemoteError("invalid_iso_range_size")
                    parts.append(part)
                remaining()
                if received != expected:
                    raise RemoteError("invalid_iso_range_size")
                return start, b"".join(parts)

        remaining()
        width = math.ceil(total / MAX_WORKERS)
        ranges = [(start, min(total - 1, start + width - 1)) for start in range(0, total, width)]
        pool = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="iso-csv")
        futures, chunks = [], {}
        try:
            futures = [pool.submit(fetch_range, start, end) for start, end in ranges]
            for future in as_completed(futures, timeout=remaining()):
                start, body = future.result()
                chunks[start] = body
            remaining()
        finally:
            stopped.set()
            for future in futures:
                future.cancel()
            pool.shutdown(wait=True, cancel_futures=True)
        body = b"".join(chunks[start] for start, _ in ranges)
        if len(body) != total or time.monotonic() >= deadline:
            raise RemoteError("deadline_exceeded" if time.monotonic() >= deadline else "invalid_iso_range_size")
        return FetchResponse(200, body, revision)
    except urllib.error.HTTPError as error:
        error.close()
        raise RemoteError(f"http_{error.code}", error.headers.get("Retry-After")) from None
    except TimeoutError:
        raise RemoteError("deadline_exceeded") from None
    except (urllib.error.URLError, OSError, ValueError):
        raise RemoteError("network_unavailable") from None
