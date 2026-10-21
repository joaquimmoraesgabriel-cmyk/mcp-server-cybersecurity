"""Extract PDF text in a resource-limited child process, not a security sandbox."""

from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import time
from pathlib import Path

from .ondemand import RemoteError

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_PAGES = 100
MAX_SECONDS = 10.0
MAX_MEMORY_BYTES = 512 * 1024 * 1024
# JSON can expand control characters to six bytes each.
MAX_OUTPUT_BYTES = MAX_TEXT_BYTES * 6 + 4096
WORKER_PATH = Path(__file__).with_name("_pdf_worker.py").resolve()
ERROR_CODES = frozenset({
    "pdf_invalid", "pdf_encrypted", "pdf_no_text", "pdf_page_limit",
    "pdf_text_limit", "pdf_stream_limit", "pdf_resource_limit",
    "pdf_resource_limit_unavailable", "pdf_dependency_unavailable",
})


def extract_pdf(raw: bytes, deadline: float | None = None) -> tuple[str, dict]:
    """Return derived text; original PDF bytes remain the caller's evidence.

    No rendering, OCR, JavaScript, attachment extraction or link opening is
    requested. The child has a memory ceiling and bounded runtime; it does not
    provide OS-level filesystem or network isolation.
    """
    if not isinstance(raw, bytes) or not raw.startswith(b"%PDF-"):
        raise RemoteError("pdf_invalid")
    if len(raw) > MAX_INPUT_BYTES:
        raise RemoteError("pdf_input_limit")
    if deadline is not None and (
        type(deadline) not in (int, float) or not math.isfinite(deadline)
    ):
        raise RemoteError("invalid_deadline")
    timeout = MAX_SECONDS if deadline is None else min(MAX_SECONDS, deadline - time.monotonic())
    if timeout <= 0:
        raise RemoteError("deadline_exceeded")
    # -I ignores PYTHONPATH/user-site; do not pass credentials into the parser.
    environment = {
        key: value for key, value in os.environ.items()
        if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL"}
    }
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    try:
        result = subprocess.run(
            [sys.executable, "-I", str(WORKER_PATH)], input=raw,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout,
            env=environment, close_fds=True, check=False, **options,
        )
    except subprocess.TimeoutExpired:
        # subprocess.run kills and waits for this child before raising.
        raise RemoteError("pdf_timeout") from None
    except OSError:
        raise RemoteError("pdf_worker_unavailable") from None
    if len(result.stdout) > MAX_OUTPUT_BYTES:
        raise RemoteError("pdf_invalid_output")
    try:
        payload = json.loads(result.stdout)
    except (ValueError, UnicodeError, RecursionError):
        raise RemoteError("pdf_worker_failed") from None
    if not isinstance(payload, dict):
        raise RemoteError("pdf_invalid_output")
    if payload.get("ok") is False:
        code = payload.get("error")
        raise RemoteError(code if isinstance(code, str) and code in ERROR_CODES else "pdf_worker_failed")
    text, pages, empty_pages = payload.get("text"), payload.get("pages"), payload.get("empty_pages")
    if (
        result.returncode != 0 or payload.get("ok") is not True
        or not isinstance(text, str) or not text.strip()
        or type(pages) is not int or not 1 <= pages <= MAX_PAGES
        or type(empty_pages) is not int or not 0 <= empty_pages < pages
        or payload.get("memory_limit_bytes") != MAX_MEMORY_BYTES
        or payload.get("resource_limit_method") not in {"windows_job", "posix_rlimit_as"}
    ):
        raise RemoteError("pdf_invalid_output")
    try:
        text_size = len(text.encode("utf-8"))
    except UnicodeError:
        raise RemoteError("pdf_invalid_output") from None
    if text_size > MAX_TEXT_BYTES:
        raise RemoteError("pdf_text_limit")
    return text, {
        "representation": "derived_pdf_text",
        "pages": pages,
        "pages_with_text": pages - empty_pages,
        "pages_without_text": empty_pages,
        "text_bytes": text_size,
        "extraction_notice": (
            "Text extraction may lose layout, columns, tables and reading order. "
            "Images are not OCRed; existing OCR text may contain errors. "
            "Original PDF bytes remain the authoritative representation."
        ),
        "resource_limits": {
            "memory_bytes": MAX_MEMORY_BYTES,
            "method": payload["resource_limit_method"],
            "maximum_seconds": MAX_SECONDS,
            "security_sandbox": False,
        },
    }
