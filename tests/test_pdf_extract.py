import io
import os
import subprocess
import sys
import time
import zlib

import pytest

from cyber_rag import pdf_extract
from cyber_rag.ondemand import RemoteError


def make_pdf(contents=(b"BT /F1 12 Tf 10 100 Td (Evidence from PDF) Tj ET",), *, password=None, active=False, compressed=False):
    from pypdf import PdfWriter
    from pypdf.generic import DecodedStreamObject, DictionaryObject, EncodedStreamObject, NameObject

    writer = PdfWriter()
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"), NameObject("/BaseFont"): NameObject("/Helvetica")})
    for content in contents:
        page = writer.add_blank_page(width=300, height=300)
        page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): writer._add_object(font)})})
        if content is not None:
            stream = EncodedStreamObject() if compressed else DecodedStreamObject()
            if compressed:
                stream._data = zlib.compress(content)
                stream[NameObject("/Filter")] = NameObject("/FlateDecode")
            else:
                stream.set_data(content)
            page[NameObject("/Contents")] = writer._add_object(stream)
    if password is not None:
        writer.encrypt(password)
    if active:
        from pypdf.actions import JavaScript

        writer.add_open_action(JavaScript("app.alert('SCRIPT_MUST_NOT_BE_TEXT');"))
        writer.add_attachment("hidden.txt", b"ATTACHMENT_MUST_NOT_BE_TEXT")
    target = io.BytesIO()
    writer.write(target)
    return target.getvalue()


def make_pdf_forms(contents):
    from pypdf import PdfWriter
    from pypdf.generic import (
        ArrayObject,
        DecodedStreamObject,
        DictionaryObject,
        EncodedStreamObject,
        NameObject,
        NumberObject,
    )

    writer = PdfWriter()
    page = writer.add_blank_page(width=300, height=300)
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"), NameObject("/BaseFont"): NameObject("/Helvetica")})
    fonts = DictionaryObject({NameObject("/F1"): writer._add_object(font)})
    forms = DictionaryObject()
    for index, content in enumerate(contents):
        form = EncodedStreamObject()
        form._data = zlib.compress(content)
        form.update({
            NameObject("/Type"): NameObject("/XObject"),
            NameObject("/Subtype"): NameObject("/Form"),
            NameObject("/BBox"): ArrayObject([NumberObject(x) for x in (0, 0, 300, 300)]),
            NameObject("/Filter"): NameObject("/FlateDecode"),
            NameObject("/Resources"): DictionaryObject({NameObject("/Font"): fonts}),
        })
        forms[NameObject(f"/Fm{index}")] = writer._add_object(form)
    page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): fonts, NameObject("/XObject"): forms})
    stream = DecodedStreamObject()
    stream.set_data(b"BT /F1 12 Tf (Page evidence) Tj ET\n" + b"\n".join(f"/Fm{index} Do".encode() for index in range(len(contents))))
    page[NameObject("/Contents")] = writer._add_object(stream)
    target = io.BytesIO()
    writer.write(target)
    return target.getvalue()


def test_extracts_text_in_limited_process_without_active_content():
    raw = make_pdf(active=True)
    text, metadata = pdf_extract.extract_pdf(raw)
    assert "Evidence from PDF" in text
    assert "SCRIPT_MUST_NOT_BE_TEXT" not in text
    assert "ATTACHMENT_MUST_NOT_BE_TEXT" not in text
    assert metadata["representation"] == "derived_pdf_text"
    assert metadata["pages"] == metadata["pages_with_text"] == 1
    assert metadata["resource_limits"]["memory_bytes"] == 512 * 1024 * 1024
    assert metadata["resource_limits"]["security_sandbox"] is False
    assert "OCR" in metadata["extraction_notice"]


def test_blank_pages_are_reported_without_inventing_content():
    text, metadata = pdf_extract.extract_pdf(make_pdf((None, b"BT /F1 12 Tf (Second page) Tj ET")))
    assert "# Page 2" in text and "# Page 1" not in text
    assert metadata["pages"] == 2
    assert metadata["pages_without_text"] == 1


@pytest.mark.parametrize("raw", [b"", b"not a PDF", "%PDF-1.7", None])
def test_bad_magic_or_type_never_spawns(raw, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("must reject before spawning"))
    with pytest.raises(RemoteError, match="pdf_invalid"):
        pdf_extract.extract_pdf(raw)


def test_oversize_input_never_spawns(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("must reject before spawning"))
    with pytest.raises(RemoteError, match="pdf_input_limit"):
        pdf_extract.extract_pdf(b"%PDF-" + b" " * pdf_extract.MAX_INPUT_BYTES)


@pytest.mark.parametrize("deadline", [True, "10", float("inf"), float("nan")])
def test_invalid_deadline_is_controlled(deadline):
    with pytest.raises(RemoteError, match="invalid_deadline"):
        pdf_extract.extract_pdf(b"%PDF-1.7", deadline)


def test_expired_deadline_does_not_spawn(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("expired request spawned"))
    with pytest.raises(RemoteError, match="deadline_exceeded"):
        pdf_extract.extract_pdf(b"%PDF-1.7", time.monotonic() - 1)


@pytest.mark.parametrize("raw_factory,code", [
    (lambda: b"%PDF-1.7\ninvalid", "pdf_invalid"),
    (lambda: make_pdf((None,)), "pdf_no_text"),
    (lambda: make_pdf(password="secret"), "pdf_encrypted"),
    (lambda: make_pdf(password=""), "pdf_encrypted"),
    (lambda: make_pdf((None,) * 101), "pdf_page_limit"),
])
def test_unsupported_documents_fail_explicitly(raw_factory, code):
    with pytest.raises(RemoteError, match=code):
        pdf_extract.extract_pdf(raw_factory())


def test_decompression_bomb_is_rejected_before_text_extraction():
    from cyber_rag._pdf_worker import MAX_STREAM_BYTES

    raw = make_pdf((b"%" + b"X" * (MAX_STREAM_BYTES + 1),), compressed=True)
    assert len(raw) < 30_000
    with pytest.raises(RemoteError, match="pdf_stream_limit"):
        pdf_extract.extract_pdf(raw)


def test_forms_are_extracted_when_within_budget():
    text, _ = pdf_extract.extract_pdf(make_pdf_forms([b"BT /F1 12 Tf (Form evidence) Tj ET"]))
    assert "Page evidence" in text and "Form evidence" in text


def test_form_decompression_failure_cannot_be_swallowed_as_partial_success():
    from cyber_rag._pdf_worker import MAX_STREAM_BYTES

    raw = make_pdf_forms([b"%" + b"X" * (MAX_STREAM_BYTES + 1)])
    with pytest.raises(RemoteError, match="pdf_stream_limit"):
        pdf_extract.extract_pdf(raw)


def test_decoded_stream_budget_includes_all_forms():
    # Five individually permitted streams expand beyond the document budget.
    forms = [b"%" + bytes([65 + i]) * (7 * 1024 * 1024) + b"\nBT /F1 12 Tf (Form) Tj ET" for i in range(5)]
    raw = make_pdf_forms(forms)
    assert len(raw) < 50_000
    with pytest.raises(RemoteError, match="pdf_stream_limit"):
        pdf_extract.extract_pdf(raw)


def test_form_text_failure_cannot_be_swallowed_as_partial_success():
    # Page extraction catches Exception from a Form; the shared failure latch
    # must still reject the complete document instead of returning the page.
    fragment = b"BT /F1 12 Tf (" + b"A" * 30_000 + b") Tj ET\n"
    raw = make_pdf_forms([fragment * 71])
    with pytest.raises(RemoteError, match="pdf_text_limit"):
        pdf_extract.extract_pdf(raw)


def test_form_parser_warning_rejects_incomplete_evidence():
    # This unknown stream operator produces an extraction exception caught by
    # pypdf's Form handler. A warning must not become silent partial evidence.
    raw = make_pdf_forms([b"BT /F1 12 Tf (Form evidence) Tj ET\n/Unknown Do"])
    with pytest.raises(RemoteError, match="pdf_invalid"):
        pdf_extract.extract_pdf(raw)


def test_derived_text_limit():
    text = b"BT /F1 12 Tf (" + b"A" * 30_000 + b") Tj ET"
    with pytest.raises(RemoteError, match="pdf_text_limit"):
        pdf_extract.extract_pdf(make_pdf((text,) * 75, compressed=True))


def test_shared_deadline_kills_and_reaps_child(monkeypatch, tmp_path):
    worker = tmp_path / "slow_worker.py"
    worker.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
    monkeypatch.setattr(pdf_extract, "WORKER_PATH", worker)
    created = []
    original = subprocess.Popen

    def capture(*args, **kwargs):
        process = original(*args, **kwargs)
        created.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", capture)
    started = time.monotonic()
    with pytest.raises(RemoteError, match="pdf_timeout"):
        pdf_extract.extract_pdf(b"%PDF-1.7", started + 0.2)
    assert time.monotonic() - started < 3
    assert len(created) == 1 and created[0].poll() is not None


def test_child_uses_isolated_mode_absolute_worker_and_minimal_environment(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "must-not-pass")
    observed = {}

    def capture(command, **kwargs):
        observed.update(command=command, **kwargs)
        return subprocess.CompletedProcess(command, 0, b'{"ok":false,"error":"pdf_no_text"}')

    monkeypatch.setattr(subprocess, "run", capture)
    with pytest.raises(RemoteError, match="pdf_no_text"):
        pdf_extract.extract_pdf(b"%PDF-1.7", time.monotonic() + 100)
    assert observed["command"][:2] == [sys.executable, "-I"]
    assert os.path.isabs(observed["command"][2])
    assert observed["timeout"] == 10
    assert "OPENROUTER_API_KEY" not in observed["env"]
    assert observed["close_fds"] is True
    if os.name == "nt":
        assert observed["creationflags"] & subprocess.CREATE_NO_WINDOW


@pytest.mark.parametrize("payload", [b"not JSON", b"[]", b'{"ok":false,"error":"private traceback"}', b'{"ok":true,"text":"invented"}'])
def test_worker_protocol_failures_are_controlled(monkeypatch, payload):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 0, payload))
    with pytest.raises(RemoteError, match="pdf_(worker_failed|invalid_output)"):
        pdf_extract.extract_pdf(b"%PDF-1.7")


def test_real_os_memory_limit_blocks_large_allocation(tmp_path):
    worker_path = str(pdf_extract.WORKER_PATH)
    probe = tmp_path / "memory_probe.py"
    probe.write_text(
        "import runpy\n"
        f"worker = runpy.run_path({worker_path!r}, run_name='limit_probe')\n"
        "worker['_limit_memory']()\n"
        "try:\n    bytearray(600 * 1024 * 1024)\n"
        "except MemoryError:\n    print('limited')\n"
        "else:\n    raise SystemExit('memory limit not enforced')\n",
        encoding="utf-8",
    )
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    result = subprocess.run([sys.executable, "-I", str(probe)], capture_output=True, timeout=5, check=False, **options)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout.strip() == b"limited"
