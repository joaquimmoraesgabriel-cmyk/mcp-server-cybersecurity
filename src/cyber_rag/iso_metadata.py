"""Bounded projection of the official ISO metadata CSV; never normative text."""

from __future__ import annotations

import csv
import io
import json
import re

from .ondemand import RemoteError

MAX_INPUT_BYTES = 96 * 1024 * 1024
MAX_RECORDS = 150_000
MAX_ROW_CHARS = 1024 * 1024
MAX_FIELD_CHARS = 128 * 1024
MAX_SELECTED_RECORDS = 256
MAX_TEXT_BYTES = 2 * 1024 * 1024
FIELDS = (
    "id", "deliverableType", "supplementType", "reference", "title.en", "title.fr",
    "publicationDate", "edition", "icsCode", "ownerCommittee", "currentStage",
    "replaces", "replacedBy", "languages", "pages.en", "scope.en",
)
REFERENCE = re.compile(r"ISO/IEC(?: [A-Z]+)? 27001(?::[^\r\n]+)?\Z")


def normalize_iso_csv(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_INPUT_BYTES:
        raise RemoteError("iso_metadata_limit")
    parts, total, text_bytes = [], 0, 0
    # Streaming decoding avoids constructing another complete 60+ MB string.
    # csv's default field limit is retained; the explicit checks also protect
    # this parser if another library changes that process-wide setting.
    try:
        with io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8-sig", newline="") as stream:
            reader = csv.reader(stream, strict=True)
            header = next(reader, None)
            if (
                not header or len(header) > 64 or len(set(header)) != len(header)
                or any(not field or len(field) > 128 for field in header)
                or not {"id", "reference"} <= set(header)
            ):
                raise RemoteError("invalid_iso_metadata")
            for values in reader:
                if not values:
                    continue
                total += 1
                if total > MAX_RECORDS or sum(map(len, values)) > MAX_ROW_CHARS or any(len(value) > MAX_FIELD_CHARS for value in values):
                    raise RemoteError("iso_metadata_limit")
                if len(values) != len(header) or any("\x00" in value for value in values):
                    raise RemoteError("invalid_iso_metadata")
                record = dict(zip(header, values, strict=True))
                if not re.fullmatch(r"[0-9]{1,12}", record["id"]) or not 0 < len(record["reference"]) <= 1024:
                    raise RemoteError("invalid_iso_metadata")
                if not REFERENCE.fullmatch(record["reference"]):
                    continue
                if len(parts) >= MAX_SELECTED_RECORDS:
                    raise RemoteError("iso_metadata_limit")
                selected = {field: record[field] for field in FIELDS if record.get(field)}
                selected["id"] = int(record["id"])
                part = "# " + record["reference"] + "\n" + json.dumps(selected, ensure_ascii=False, indent=2)
                text_bytes += len(part.encode("utf-8")) + (2 if parts else 0)
                if text_bytes > MAX_TEXT_BYTES:
                    raise RemoteError("iso_metadata_limit")
                parts.append(part)
    except (csv.Error, UnicodeError):
        raise RemoteError("invalid_iso_metadata") from None
    if not parts:
        raise RemoteError("iso_27001_metadata_missing")
    return "\n\n".join(parts), {
        "representation": "derived_iso_27001_metadata",
        "dataset": "iso_deliverables_metadata",
        "original_format": "csv",
        "scanned_records": total,
        "indexed_records": len(parts),
        "coverage": "ISO/IEC 27001 metadata, editions and supplements only; no normative full text or control requirements",
        "attribution": "Based on ISO Open Data iso_deliverables_metadata, licensed ODC Attribution License (ODC-By) v1.0. Selection and text formatting are derived.",
    }
