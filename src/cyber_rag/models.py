"""Source-independent records. Original bytes never execute."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass
class Document:
    source_id: str
    path: str
    revision: str
    url: str
    title: str
    content_type: str
    text: str
    raw: bytes
    metadata: dict = field(default_factory=dict)
    entities: list[dict] = field(default_factory=list)
    relations: list[dict] = field(default_factory=list)

    @property
    def document_id(self) -> str:
        return "doc_" + digest(f"{self.source_id}:{self.path}".encode())[:32]

    @property
    def original_hash(self) -> str:
        return digest(self.raw)


class KnowledgeError(Exception):
    def __init__(self, code: str, message: str, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
