"""Private isolated-mode entry point. Resource ceilings are not a security sandbox.

PDF bytes arrive on stdin; one bounded JSON response leaves on stdout. No source
URL, filesystem path or operation supplied by a document is executed.
"""

from __future__ import annotations

import io
import json
import logging
import os
import sys
from contextlib import contextmanager

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_MEMORY_BYTES = 512 * 1024 * 1024
MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_DECODED_STREAM_TOTAL = 32 * 1024 * 1024
MAX_PAGES = 100
_JOB_HANDLE = None


class PdfFailure(Exception):
    def __init__(self, code):
        self.code = code


def _limit_memory():
    """Fail closed if the OS cannot enforce a ceiling before pypdf is loaded."""
    global _JOB_HANDLE
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimits), ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.GetCurrentProcess.argtypes = []
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        job = kernel.CreateJobObjectW(None, None)
        if not job:
            raise PdfFailure("pdf_resource_limit_unavailable")
        limits = ExtendedLimits()
        # Process memory, active-process count, and kill-on-job-close.
        limits.BasicLimitInformation.LimitFlags = 0x100 | 0x8 | 0x2000
        limits.BasicLimitInformation.ActiveProcessLimit = 1
        limits.ProcessMemoryLimit = MAX_MEMORY_BYTES
        if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            kernel.CloseHandle(job)
            raise PdfFailure("pdf_resource_limit_unavailable")
        if not kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess()):
            kernel.CloseHandle(job)
            raise PdfFailure("pdf_resource_limit_unavailable")
        # Keep the handle for the entire lifetime; closing it terminates this job.
        _JOB_HANDLE = job
        return "windows_job"
    if os.name == "posix":
        import resource

        _, hard = resource.getrlimit(resource.RLIMIT_AS)
        cap = MAX_MEMORY_BYTES if hard == resource.RLIM_INFINITY else min(MAX_MEMORY_BYTES, hard)
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
        return "posix_rlimit_as"
    raise PdfFailure("pdf_resource_limit_unavailable")


def _deny_active_operations(event, args):
    # Defense in depth against accidental use of an optional external decoder.
    # Python audit hooks do not constitute an OS security sandbox.
    if event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "socket.connect"}:
        raise PdfFailure("pdf_invalid")


class _ExtractionLimits(logging.Handler):
    """Persist failures even when pypdf catches an exception inside an XForm."""

    def __init__(self):
        super().__init__(logging.WARNING)
        self.error = None
        self.warned = False
        self.decoded_bytes = 0
        self.visited_text_bytes = 0

    def emit(self, record):
        # A parser warning can mean a skipped Form/font. Do not accept silently
        # incomplete evidence, and never retain document-controlled diagnostics.
        self.warned = True

    def fail(self, code):
        self.error = self.error or code
        raise PdfFailure(self.error)

    def check(self):
        if self.error:
            raise PdfFailure(self.error)
        if self.warned:
            raise PdfFailure("pdf_invalid")

    def count_text(self, fragment, *_):
        self.check()
        self.visited_text_bytes += len(fragment.encode("utf-8"))
        if self.visited_text_bytes > MAX_TEXT_BYTES:
            self.fail("pdf_text_limit")


@contextmanager
def _bounded_decoding(limits):
    from pypdf import filters
    from pypdf.errors import LimitReachedError

    original_decode = filters.decode_stream_data
    logger = logging.getLogger("pypdf")
    previous_logging = logger.handlers[:], logger.level, logger.propagate, logging.root.manager.disable

    def decode(stream):
        limits.check()
        try:
            value = original_decode(stream)
        except LimitReachedError:
            limits.fail("pdf_stream_limit")
        except (MemoryError, RecursionError):
            limits.fail("pdf_resource_limit")
        except Exception:  # noqa: BLE001 - persist errors otherwise swallowed by XForms.
            limits.fail("pdf_invalid")
        limits.decoded_bytes += len(value)
        if len(value) > MAX_STREAM_BYTES or limits.decoded_bytes > MAX_DECODED_STREAM_TOTAL:
            limits.fail("pdf_stream_limit")
        return value

    # EncodedStreamObject dynamically imports this function for streams used by
    # page contents, Forms, fonts and PDF object/xref streams. Its decoded cache
    # avoids charging a repeated read of the same decoded bytes a second time.
    filters.decode_stream_data = decode
    logger.handlers = [limits]
    logger.setLevel(logging.WARNING)
    logger.propagate = False
    logging.disable(logging.NOTSET)
    try:
        yield
    finally:
        filters.decode_stream_data = original_decode
        logger.handlers, logger.level, logger.propagate, disabled = previous_logging
        logging.disable(disabled)


def _extract(raw):
    from pypdf import PdfReader
    from pypdf._configuration import apply_configuration
    from pypdf.errors import LimitReachedError

    # Public configuration API in the pinned pypdf 6.21 series. Limits apply
    # during decompression, before checking the resulting page content length.
    limits = _ExtractionLimits()
    with _bounded_decoding(limits), apply_configuration(
        maximum_declared_stream_length=MAX_STREAM_BYTES,
        array_based_stream_maximum_output_length=MAX_STREAM_BYTES,
        array_maximum_element_count=10_000,
        dictionary_maximum_element_count=10_000,
        jbig2_maximum_output_length=MAX_STREAM_BYTES,
        lzw_maximum_output_length=MAX_STREAM_BYTES,
        run_length_maximum_output_length=MAX_STREAM_BYTES,
        zlib_maximum_output_length=MAX_STREAM_BYTES,
        brotli_maximum_output_length=MAX_STREAM_BYTES,
        zlib_maximum_recovery_input_length=1024 * 1024,
        flate_maximum_columns=100_000,
        flate_maximum_row_length=MAX_STREAM_BYTES,
        image_maximum_buffer_size=MAX_STREAM_BYTES,
        stream_filters_maximum_length=4,
        # This pypdf setting is per stream. _bounded_decoding additionally
        # enforces a shared ceiling across every stream actually decoded.
        stream_decoding_work_maximum_length=MAX_DECODED_STREAM_TOTAL,
        stream_parsing_work_maximum_count=250_000,
        page_tree_maximum_entries=1000,
        page_tree_maximum_depth=32,
        xform_maximum_invocations_per_extraction=512,
        jbig2dec_binary=None,
        disable_legacy_handling=True,
    ):
        try:
            reader = PdfReader(io.BytesIO(raw), strict=True)
            if reader.is_encrypted:
                raise PdfFailure("pdf_encrypted")
            page_count = len(reader.pages)
            limits.check()
            if not 1 <= page_count <= MAX_PAGES:
                raise PdfFailure("pdf_page_limit")
            parts, page_stream_bytes, text_bytes, empty_pages = [], 0, 0, 0

            for number, page in enumerate(reader.pages, 1):
                contents = page.get_contents()
                size = len(contents.get_data()) if contents is not None else 0
                page_stream_bytes += size
                limits.check()
                if size > MAX_STREAM_BYTES or page_stream_bytes > MAX_DECODED_STREAM_TOTAL:
                    raise PdfFailure("pdf_stream_limit")
                value = (page.extract_text(visitor_text=limits.count_text) or "").strip().replace("\x00", "\ufffd")
                limits.check()
                if not value:
                    empty_pages += 1
                    continue
                part = f"# Page {number}\n{value}"
                text_bytes += len(part.encode("utf-8")) + (2 if parts else 0)
                if text_bytes > MAX_TEXT_BYTES:
                    raise PdfFailure("pdf_text_limit")
                parts.append(part)
            if not parts:
                raise PdfFailure("pdf_no_text")
            return {"ok": True, "text": "\n\n".join(parts), "pages": page_count, "empty_pages": empty_pages}
        except LimitReachedError:
            raise PdfFailure("pdf_stream_limit") from None


def main():
    output = sys.stdout.buffer
    # Library diagnostics must never become part of the evidence/protocol.
    sys.stdout = io.StringIO()
    logging.disable(logging.CRITICAL)
    try:
        try:
            method = _limit_memory()
        except (OSError, ValueError):
            raise PdfFailure("pdf_resource_limit_unavailable") from None
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if not raw.startswith(b"%PDF-") or len(raw) > MAX_INPUT_BYTES:
            raise PdfFailure("pdf_invalid")
        sys.addaudithook(_deny_active_operations)
        result = _extract(raw)
        result.update(memory_limit_bytes=MAX_MEMORY_BYTES, resource_limit_method=method)
    except PdfFailure as exc:
        result = {"ok": False, "error": exc.code}
    except ImportError:
        result = {"ok": False, "error": "pdf_dependency_unavailable"}
    except (MemoryError, RecursionError):
        result = {"ok": False, "error": "pdf_resource_limit"}
    except Exception:  # noqa: BLE001 - the private parser boundary returns no external exception text.
        result = {"ok": False, "error": "pdf_invalid"}
    output.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    output.flush()


if __name__ == "__main__":
    main()
